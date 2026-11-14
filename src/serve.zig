//! `chock serve`: a browser in front of a daemon.

const std = @import("std");
const builtin = @import("builtin");
const chock_auth = @import("chock-auth");
const chock_proto = @import("chock-proto");
const oauth = @import("oauth-core");
const daemon_state = @import("chock-daemon");

const Exit = @import("exit.zig").Exit;
const directory_help = @import("directory_help.zig");
const tty = @import("tty.zig");

const control = chock_proto.control;
const event = chock_proto.event;

const LoginResult = struct {
    identity_id: [36]u8,
    token: [43]u8,
    expires_ms: i64,
};

const OidcAuthorization = struct { url: []const u8, state: []const u8 };
const OidcSetupInput = struct {
    provider: []const u8,
    issuer: []const u8,
    discovery_url: ?[]const u8 = null,
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    admin_subject: []const u8,
};

fn daemonOidcSetup(serve: *Serve, arena: std.mem.Allocator, input: OidcSetupInput) !void {
    const json = try std.json.Stringify.valueAlloc(arena, input, .{ .emit_null_optional_fields = false });
    const encoded = try arena.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(json.len));
    const configuration = std.base64.url_safe_no_pad.Encoder.encode(encoded, json);
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        accepted: bool = false,
        refused: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => self.accepted = true,
                .failed => self.refused = true,
                .record => return error.UnexpectedOidcSetupRecord,
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &reader.interface,
        &writer.interface,
        .{ .auth_oidc_setup = .{ .configuration = configuration } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or !capture.accepted or capture.refused) return error.OidcSetupRefused;
}

fn daemonOidcBegin(serve: *Serve, arena: std.mem.Allocator, redirect_uri: []const u8) !OidcAuthorization {
    const payload = try std.json.Stringify.valueAlloc(arena, .{
        .redirect_uri = redirect_uri,
        .allow_http = serve.allow_http,
    }, .{});
    const encoded = try arena.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(payload.len));
    const body = std.base64.url_safe_no_pad.Encoder.encode(encoded, payload);
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        result: ?OidcAuthorization = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .failed => {
                    self.failed = true;
                    return false;
                },
                .ok => |value| {
                    var fields = std.mem.splitScalar(u8, value, '\t');
                    const url = fields.next() orelse return error.MalformedOidcAuthorization;
                    const state = fields.next() orelse return error.MalformedOidcAuthorization;
                    if (fields.next() != null or url.len == 0 or state.len != oauth.pkce.state_len)
                        return error.MalformedOidcAuthorization;
                    self.result = .{ .url = url, .state = state };
                    return false;
                },
                .record => return false,
            }
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_oidc_begin = .{ .input = body } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.OidcBeginRefused;
    const result = capture.result orelse return error.OidcBeginResponseMissing;
    // The control reply is backed by `read_buffer`, which is local to this
    // function. Copy it before returning so the HTTP response never reads
    // slices from a dead stack frame.
    return .{
        .url = try arena.dupe(u8, result.url),
        .state = try arena.dupe(u8, result.state),
    };
}

/// Send an OIDC code to the daemon for exchange and verification. Neither the
/// client secret nor access/ID tokens ever enter the browser gateway.
fn daemonOidcExchange(
    serve: *Serve,
    arena: std.mem.Allocator,
    target: []const u8,
    cookie_state: []const u8,
) !LoginResult {
    const exchange = try std.json.Stringify.valueAlloc(arena, .{
        .target = target,
        .cookie_state = cookie_state,
    }, .{});
    const encoded = try arena.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(exchange.len));
    const body = std.base64.url_safe_no_pad.Encoder.encode(encoded, exchange);

    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        result: ?LoginResult = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .failed => {
                    self.failed = true;
                    return false;
                },
                .ok => |value| {
                    self.result = try parseLoginResult(value);
                    return false;
                },
                .record => return false,
            }
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_oidc_exchange = .{ .exchange = body } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.OidcExchangeRefused;
    return capture.result orelse error.LoginResponseMissing;
}

fn parseLoginResult(text: []const u8) error{MalformedLoginResult}!LoginResult {
    var fields = std.mem.splitScalar(u8, text, '\t');
    const identity_id = fields.next() orelse return error.MalformedLoginResult;
    _ = fields.next() orelse return error.MalformedLoginResult; // role is currently returned for the app shell
    const token = fields.next() orelse return error.MalformedLoginResult;
    const expires = fields.next() orelse return error.MalformedLoginResult;
    if (fields.next() != null or identity_id.len != 36 or token.len != 43) return error.MalformedLoginResult;
    for (identity_id, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return error.MalformedLoginResult;
        } else if (!std.ascii.isHex(byte)) return error.MalformedLoginResult;
    }
    for (token) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.MalformedLoginResult;
    }
    var result: LoginResult = undefined;
    @memcpy(&result.identity_id, identity_id);
    @memcpy(&result.token, token);
    result.expires_ms = std.fmt.parseInt(i64, expires, 10) catch return error.MalformedLoginResult;
    return result;
}

const LocalAuthInput = struct { username: []const u8, password: []const u8 };

fn daemonAuthStatus(serve: *Serve, arena: std.mem.Allocator) ![]const u8 {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [1024]u8 = undefined;
    var writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        text: ?[]const u8 = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .failed => {
                    self.failed = true;
                    return false;
                },
                .ok => |value| {
                    self.text = value;
                    return false;
                },
                .record => return false,
            }
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(&reader.interface, &writer.interface, .{ .auth_status = {} }, &handshake, &capture, Capture.take);
    if (!handshake.ok() or capture.failed) return error.AuthStatusUnavailable;
    return try arena.dupe(u8, capture.text orelse return error.AuthStatusMissing);
}

const AuthMode = struct { oidc: bool, service: bool };

/// Only the daemon's own word "single-user" turns authentication off. Any other word it does not know is an error.
fn authModeOf(status: []const u8) ?AuthMode {
    if (std.mem.eql(u8, status, "single-user")) return .{ .oidc = false, .service = false };
    if (std.mem.eql(u8, status, "oidc")) return .{ .oidc = true, .service = true };
    inline for (.{ "local", "setup-required", "configured" }) |known| {
        if (std.mem.eql(u8, status, known)) return .{ .oidc = false, .service = true };
    }
    return null;
}

fn daemonAuthMode(serve: *Serve, arena: std.mem.Allocator) !AuthMode {
    const status = try daemonAuthStatus(serve, arena);
    return authModeOf(status) orelse error.AuthStatusUnrecognised;
}

fn daemonLocalAuth(serve: *Serve, arena: std.mem.Allocator, input: LocalAuthInput, setup: bool) !LoginResult {
    const json = try std.json.Stringify.valueAlloc(arena, .{
        .username = input.username,
        .password = input.password,
    }, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(json.len));
    const credentials = encoder.encode(encoded, json);
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [2048]u8 = undefined;
    var writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        result: ?LoginResult = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .failed => {
                    self.failed = true;
                    return false;
                },
                .ok => |value| {
                    self.result = try parseLoginResult(value);
                    return false;
                },
                .record => return false,
            }
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    const request: control.Request = if (setup)
        .{ .auth_local_setup = .{ .credentials = credentials } }
    else
        .{ .auth_local_login = .{ .credentials = credentials } };
    try control.exchange(&reader.interface, &writer.interface, request, &handshake, &capture, Capture.take);
    if (!handshake.ok() or capture.failed) return error.LocalLoginRefused;
    return capture.result orelse error.LocalLoginResponseMissing;
}

fn sendSetupPage(request: *std.http.Server.Request) !void {
    try sendMember(request, "index.html");
}

fn serveOidcSetup(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const mode = daemonAuthStatus(serve, arena) catch {
        try sendWhole(request, "authentication status unavailable\n", .{ .status = .bad_gateway });
        return;
    };
    if (!std.mem.eql(u8, mode, "setup-required")) {
        try sendWhole(request, "initial service setup has already been completed\n", .{ .status = .conflict });
        return;
    }
    if (serve.external_url == null or serve.callback_url == null) {
        try sendWhole(request, "configure CHOCK_EXTERNAL_URL before enabling OIDC\n", .{ .status = .service_unavailable });
        return;
    }
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "OIDC setup request could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(6 * 1024)) catch {
        try sendWhole(request, "OIDC setup request is too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(OidcSetupInput, arena, body, .{}) catch {
        try sendWhole(request, "OIDC setup details are malformed\n", .{ .status = .bad_request });
        return;
    };
    if (input.provider.len == 0 or input.provider.len > 32 or input.issuer.len == 0 or input.issuer.len > 2048 or
        input.client_id.len == 0 or input.client_id.len > 512 or input.admin_subject.len == 0 or input.admin_subject.len > 512 or
        (input.discovery_url != null and input.discovery_url.?.len > 2048) or
        (input.client_secret != null and input.client_secret.?.len > 4096))
    {
        try sendWhole(request, "OIDC setup details are invalid or too large\n", .{ .status = .bad_request });
        return;
    }
    daemonOidcSetup(serve, arena, input) catch {
        try sendWhole(request, "the daemon rejected OIDC discovery or configuration\n", .{ .status = .bad_gateway });
        return;
    };
    serve.oidc_enabled.store(true, .release);
    serve.service_auth.store(true, .release);
    try sendWhole(request, "OIDC configured; continue to sign in\n", .{ .status = .created });
}

fn serveAuthStatus(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const status = daemonAuthStatus(serve, arena) catch {
        try sendWhole(request, "authentication status unavailable\n", .{ .status = .bad_gateway });
        return;
    };
    if (std.mem.eql(u8, status, "setup-required")) {
        try sendWhole(request, "{\"mode\":\"local\",\"setup\":true}", .{ .extra_headers = &json_headers });
    } else if (std.mem.eql(u8, status, "local")) {
        try sendWhole(request, "{\"mode\":\"local\",\"setup\":false}", .{ .extra_headers = &json_headers });
    } else if (std.mem.eql(u8, status, "oidc")) {
        try sendWhole(request, "{\"mode\":\"oidc\",\"setup\":false}", .{ .extra_headers = &json_headers });
    } else {
        try sendWhole(request, "{\"mode\":\"single-user\",\"setup\":false}", .{ .extra_headers = &json_headers });
    }
}

fn serveLocalAuth(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    setup: bool,
    phantom_auth_response: bool,
) !void {
    if (serve.oidc_enabled.load(.acquire)) {
        try sendWhole(request, "local sign-in is disabled when OIDC is configured\n", .{ .status = .forbidden });
        return;
    }
    var body_buffer: [4096]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "request body could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(2048)) catch {
        try sendWhole(request, "request body could not be read\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(LocalAuthInput, arena, body, .{}) catch {
        try sendWhole(request, "username and password are required\n", .{ .status = .bad_request });
        return;
    };
    const mode = daemonAuthStatus(serve, arena) catch {
        try sendWhole(request, "authentication status unavailable\n", .{ .status = .bad_gateway });
        return;
    };
    if ((setup and !std.mem.eql(u8, mode, "setup-required")) or (!setup and !std.mem.eql(u8, mode, "local"))) {
        try sendWhole(request, "local authentication is not available in the current service state\n", .{ .status = .conflict });
        return;
    }
    const login = daemonLocalAuth(serve, arena, input, setup) catch {
        try sendWhole(request, "sign-in or initial setup was refused\n", .{ .status = .unauthorized });
        return;
    };
    serve.service_auth.store(true, .release);
    const secure = if (serve.external_url != null and std.mem.startsWith(u8, serve.external_url.?, "https://")) "; Secure" else "";
    const cookie = try std.fmt.allocPrint(arena, "chock_session={s}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{s}", .{ &login.token, secure });
    if (phantom_auth_response) {
        try sendWhole(request, "{\"authenticated\":true}", .{ .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "set-cookie", .value = cookie },
            .{ .name = "cache-control", .value = "no-store" },
        } });
        return;
    }
    const headers = [_]std.http.Header{
        .{ .name = "location", .value = "/" },
        .{ .name = "set-cookie", .value = cookie },
        .{ .name = "cache-control", .value = "no-store" },
    };
    try sendWhole(request, "", .{ .status = .see_other, .extra_headers = &headers });
}

const LocalPasswordInput = struct {
    current_password: []const u8,
    new_password: []const u8,
};

fn serveLocalPassword(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "password changes require service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .local_password, false);
        return;
    };
    const mode = daemonAuthStatus(serve, arena) catch {
        try sendWhole(request, "authentication status unavailable\n", .{ .status = .bad_gateway });
        return;
    };
    if (!std.mem.eql(u8, mode, "local")) {
        try sendWhole(request, "password changes are only available for Chock-managed accounts\n", .{ .status = .conflict });
        return;
    }
    var body_buffer: [4096]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "password change request could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(2048)) catch {
        try sendWhole(request, "password change request is too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(LocalPasswordInput, arena, body, .{}) catch {
        try sendWhole(request, "current_password and new_password are required\n", .{ .status = .bad_request });
        return;
    };
    if (input.current_password.len == 0 or input.current_password.len > 1024 or
        input.new_password.len < 12 or input.new_password.len > 1024)
    {
        try sendWhole(request, "current password is required and new password must be 12–1024 characters\n", .{ .status = .bad_request });
        return;
    }
    const encoded_json = try std.json.Stringify.valueAlloc(arena, .{
        .current_password = input.current_password,
        .new_password = input.new_password,
    }, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(encoded_json.len));
    const payload = encoder.encode(encoded, encoded_json);
    _ = daemonPeopleRequest(serve, arena, token, "change-local-password", payload) catch |err| {
        if (err == error.InvalidCurrentPassword) {
            try sendWhole(request, "the current password is incorrect\n", .{ .status = .forbidden });
            return;
        }
        if (err == error.LocalAuthDisabled) {
            try sendWhole(request, "password changes are only available for Chock-managed accounts\n", .{ .status = .conflict });
            return;
        }
        try sendWhole(request, "the local password could not be changed\n", .{ .status = .bad_gateway });
        return;
    };
    try sendWhole(request, "{\"changed\":true}", .{ .extra_headers = &json_headers });
}

/// The browser interface, built by `build/web_bundle.zig` and carried here.
///
/// A tar of the page, each member compressed on its own. Nothing is
/// decompressed on this side: a member goes to the browser as it is, with
/// `Content-Encoding: gzip`, and the browser does the work.
const web_bundle = @embedFile("web-bundle");

/// One file of the page, as the browser asks for it.
pub const Member = struct {
    name: []const u8,
    /// Still compressed. See `web_bundle`.
    bytes: []const u8,
};

/// The member a request names, or null. The name has no leading slash, so "/"
/// is asked for as "index.html".
pub fn memberNamed(wanted: []const u8) ?Member {
    var reading: std.Io.Reader = .fixed(web_bundle);
    var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&reading, .{
        .file_name_buffer = &name_buffer,
        .link_name_buffer = &link_buffer,
    });
    while (it.next() catch return null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, entry.name, wanted)) continue;
        const at = reading.seek;
        const size: usize = @intCast(entry.size);
        if (at + size > web_bundle.len) return null;
        return .{ .name = entry.name, .bytes = web_bundle[at..][0..size] };
    }
    return null;
}

pub const default_port: u16 = control.default_port + 1;

pub const socket_name = "serve.sock";

const max_connections: usize = 32;

const max_head_bytes: usize = 16 * 1024;

/// The longest name a file of the page may have. `routeOf` refuses anything
/// longer, so the dispatch below can decode into a buffer this size and the two
/// never disagree about what fits.
const max_asset_name: usize = 512;

const usage_text =
    \\Usage: chock serve [options]
    \\
    \\Puts a browser in front of a daemon. This owns no session: it is a client
    \\of `chock daemon`, which may be on this machine or on another one.
    \\
    \\Binds a unix socket in the state directory, and nothing else until --host
    \\names an address. The socket serves the user that started this command.
    \\--socket-group can also admit a reverse proxy group, which is the supported
    \\way to put nginx, Caddy or Authelia authentication in front of this.
    \\
    \\Options:
    \\  --daemon <address>  Where the daemon is. `unix:/path` or `host:port`.
    \\                      Default is the socket in the state directory, or
    \\                      $CHOCK_DAEMON when that is set.
    \\  --project <dir>     The project to show. Default is the working directory.
    \\  --socket <path>     The unix socket. Default is serve.sock in the state
    \\                      directory.
    \\  --socket-group <g>  Let this group connect to the unix socket. A group
    \\                      name or numeric gid. The socket is made mode 0660.
    \\  --host <addr>       Bind this address, over TCP, instead of the socket.
    \\                      Off by default. Requires CHOCK_EXTERNAL_URL,
    \\                      even on loopback; OIDC is optional for local accounts.
    \\  --port <n>          The TCP port, with --host. 0 asks the system for one
    \\                      and prints it. Default 7374.
    \\  --external-url <u>  Browser-facing base URL used to build the OIDC callback.
    \\  --allow-http        Permit a non-loopback HTTP external URL (unsafe).
    \\
    \\TCP-bound browser routes require an external URL so cookie origins can
    \\be checked. Use HTTPS; --allow-http is only for a trusted private network
    \\where the browser-facing URL itself is HTTP. Keep daemon control on its socket.
    \\
++ tty.options_text;

const Options = struct {
    daemon: ?[]const u8 = null,
    project: ?[]const u8 = null,
    socket: ?[]const u8 = null,
    socket_group: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: u16 = default_port,
    external_url: ?[]const u8 = null,
    allow_http: bool = false,
};

const Serve = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    daemon: control.Address,
    project: []const u8,
    owner_uid: std.posix.uid_t,
    oidc_enabled: std.atomic.Value(bool) = .init(false),
    callback_url: ?[]const u8 = null,
    external_url: ?[]const u8 = null,
    allow_http: bool = false,
    group_socket: bool = false,
    service_auth: std.atomic.Value(bool) = .init(false),
    auth_asked_ms: std.atomic.Value(i64) = .init(0),
    live: std.atomic.Value(usize) = .init(0),
};

fn authEnabled(serve: *const Serve) bool {
    return serve.service_auth.load(.acquire);
}

const auth_recheck_ms: i64 = 2000;

/// True for one caller per interval while this gateway still believes the daemon is single-user.
fn authRecheckDue(serve: *Serve, now_ms: i64) bool {
    if (serve.service_auth.load(.acquire)) return false;
    const last = serve.auth_asked_ms.load(.acquire);
    if (now_ms >= last and now_ms - last < auth_recheck_ms) return false;
    return serve.auth_asked_ms.cmpxchgStrong(last, now_ms, .acq_rel, .acquire) == null;
}

/// The daemon can gain identities behind this gateway, so a gateway that serves open keeps asking. It only ever turns authentication on.
fn recheckAuth(serve: *Serve, arena: std.mem.Allocator) void {
    if (!authRecheckDue(serve, std.Io.Timestamp.now(serve.io, .real).toMilliseconds())) return;
    const status = daemonAuthStatus(serve, arena) catch return;
    const mode = authModeOf(status) orelse AuthMode{ .oidc = false, .service = true };
    if (!mode.service) return;
    serve.oidc_enabled.store(mode.oidc, .release);
    serve.service_auth.store(true, .release);
}

pub fn main(
    init: std.process.Init,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map.*;

    _ = exe_path;

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => return Exit.usage.code(),
    };

    const daemon_text = options.daemon orelse env.get(control.address_env) orelse text: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| switch (err) {
            error.NoHomeDirectory => {
                directory_help.report("serve", .state);
                return Exit.usage.code();
            },
            error.OutOfMemory => return error.OutOfMemory,
        };
        const path = control.socketPathIn(arena, state) catch return Exit.faulted.code();
        break :text try std.fmt.allocPrint(arena, "unix:{s}", .{path});
    };
    const daemon = control.Address.parse(daemon_text) catch |err| {
        tty.print(
            .err,
            "chock serve: \"{s}\" is not a daemon address ({t}). Write `unix:/path` or `host:port`.\n",
            .{ daemon_text, err },
        );
        return Exit.usage.code();
    };

    const project = if (options.project) |named| absolute: {
        if (std.fs.path.isAbsolute(named)) break :absolute named;
        tty.print(
            .err,
            "chock serve: --project takes an absolute path, and \"{s}\" is not one.\n",
            .{named},
        );
        return Exit.usage.code();
    } else cwd: {
        var here = std.Io.Dir.cwd().openDir(io, ".", .{}) catch |err| {
            tty.print(.err, "chock serve: the working directory could not be opened: {t}\n", .{err});
            return Exit.usage.code();
        };
        defer here.close(io);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = here.realPath(io, &buffer) catch |err| {
            tty.print(.err, "chock serve: the working directory could not be read: {t}\n", .{err});
            return Exit.usage.code();
        };
        break :cwd try arena.dupe(u8, buffer[0..length]);
    };

    var serve_state = Serve{
        .gpa = gpa,
        .io = io,
        .daemon = daemon,
        .project = project,
        .owner_uid = std.posix.system.getuid(),
        .allow_http = options.allow_http,
    };

    if (options.external_url orelse env.get("CHOCK_EXTERNAL_URL")) |external| {
        if (!daemon_state.isWebBaseUrl(external, options.allow_http)) {
            tty.print(.err, "chock serve: the external URL must be browser-reachable HTTPS (or HTTP only on loopback; use --allow-http to opt in to remote HTTP), and cannot be a bind address such as 0.0.0.0.\n", .{});
            return Exit.usage.code();
        }
        serve_state.external_url = external;
        serve_state.callback_url = try std.fmt.allocPrint(arena, "{s}/auth/callback", .{std.mem.trimEnd(u8, external, "/")});
        if (options.allow_http and std.mem.startsWith(u8, external, "http://") and
            !daemon_state.isSecureWebBaseUrl(external))
        {
            tty.print(.warn, "chock serve: remote HTTP is enabled; browser credentials and OIDC callbacks are not protected in transit.\n", .{});
        }
    }
    if (options.host != null and serve_state.external_url == null) {
        tty.print(.err, "chock serve: binding TCP requires CHOCK_EXTERNAL_URL (or --external-url), using HTTPS unless --allow-http is set or the URL is loopback.\n", .{});
        return Exit.usage.code();
    }

    // Said before it is tried: std.Io.net cannot bound a connect, and an address that drops packets waits out the kernel's own timeout.
    tty.print(.plain, "chock serve: reaching the daemon at {f}\n", .{daemon});
    const probe = daemon.connect(io) catch |err| {
        var buffer: [1024]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        writer.writeAll("chock serve: ") catch {};
        control.refusalFor(&writer, daemon, err) catch {};
        tty.print(.err, "{s}", .{writer.buffered()});
        return Exit.usage.code();
    };
    probe.close(io);

    const auth_mode = daemonAuthMode(&serve_state, arena) catch |err| {
        tty.print(.err, "chock serve: the daemon's authentication mode could not be read ({t}), so nothing is served.\n", .{err});
        return Exit.usage.code();
    };
    serve_state.oidc_enabled.store(auth_mode.oidc, .release);
    serve_state.service_auth.store(auth_mode.service, .release);
    if (auth_mode.oidc and serve_state.callback_url == null) {
        tty.print(.err, "chock serve: configure CHOCK_EXTERNAL_URL (or --external-url) for the daemon's OIDC callback.\n", .{});
        return Exit.usage.code();
    }

    const socket_path = options.socket orelse path: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| switch (err) {
            error.NoHomeDirectory => {
                directory_help.report("serve", .state);
                return Exit.usage.code();
            },
            error.OutOfMemory => return error.OutOfMemory,
        };
        makeDirAll(io, state) catch |err| {
            tty.print(.err, "chock serve: {s} could not be made: {t}\n", .{ state, err });
            return Exit.usage.code();
        };
        break :path std.fs.path.join(arena, &.{ state, socket_name }) catch
            return Exit.faulted.code();
    };

    const bind = bindAddress(socket_path, options);
    // Keep the bind private until a requested group owns the socket. This
    // closes the interval between bind and chmod in which the process umask
    // might otherwise make a connection possible.
    const old_umask = if (options.socket_group != null and options.host == null)
        changeUmask(0o077)
    else
        null;
    var listener = bind.listen(io) catch |err| {
        if (old_umask) |mode| _ = changeUmask(mode);
        tty.print(.err, "chock serve: {f} could not be listened on: {t}\n", .{ bind, err });
        if (err == error.PathTooLong) tty.print(
            .err,
            "chock serve: a unix socket path is at most {d} bytes on this platform. " ++
                "Name a shorter one with --socket.\n",
            .{control.max_socket_path},
        );
        return Exit.usage.code();
    };
    if (old_umask) |mode| _ = changeUmask(mode);
    defer listener.close(io);

    if (options.socket_group) |named| {
        const gid = groupId(arena, io, named) orelse {
            tty.print(.err, "chock serve: --socket-group names no group: {s}\n", .{named});
            return Exit.usage.code();
        };
        configureGroupSocket(arena, io, socket_path, gid) catch |err| {
            tty.print(
                .err,
                "chock serve: {s} could not be made available to group {s}: {t}\n",
                .{ socket_path, named, err },
            );
            return Exit.usage.code();
        };
        serve_state.group_socket = true;
    }

    if (options.host) |host| {
        tty.print(.plain, "chock serve: open http://{s}:{d}/\n", .{
            host,
            listener.server.socket.address.getPort(),
        });
    } else {
        tty.print(.plain, "chock serve: listening on {f}\n", .{bind});
        tty.print(
            .plain,
            "chock serve: a browser reaches this through a reverse proxy that proxies to " ++
                "that socket. For a browser to open it directly, run " ++
                "`chock serve --host 127.0.0.1`.\n",
            .{},
        );
    }
    tty.print(.plain, "chock serve: showing {s} from the daemon at {f}\n", .{ project, daemon });

    while (true) {
        var stream = listener.server.accept(io) catch |err| {
            tty.print(.warn, "chock serve: an incoming connection failed: {t}\n", .{err});
            continue;
        };

        if (listener.unix_path != null and !serve_state.group_socket and
            !control.peerAllowed(control.peerUid(stream.socket.handle), serve_state.owner_uid))
        {
            var buffer: [forbidden_response.len]u8 = undefined;
            var writer = stream.writer(io, &buffer);
            writer.interface.writeAll(forbidden_response) catch {};
            writer.interface.flush() catch {};
            tty.print(.warn, "chock serve: a client of another user was refused.\n", .{});
            stream.close(io);
            continue;
        }

        if (serve_state.live.load(.monotonic) >= max_connections) {
            stream.close(io);
            continue;
        }
        _ = serve_state.live.fetchAdd(1, .monotonic);
        const thread = std.Thread.spawn(.{}, runConnection, .{Connection{
            .serve = &serve_state,
            .stream = stream,
        }}) catch {
            _ = serve_state.live.fetchSub(1, .monotonic);
            stream.close(io);
            continue;
        };
        thread.detach();
    }
}

fn bindAddress(socket_path: []const u8, options: Options) control.Address {
    const host = options.host orelse return .{ .unix = socket_path };
    return .{ .ip = .{ .host = host, .port = options.port } };
}

fn changeUmask(mode: std.c.mode_t) std.c.mode_t {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.os.linux.syscall1(.umask, mode)),
        .macos => std.c.umask(mode),
        else => @compileError("chock serve has no unix socket support for this target"),
    };
}

fn groupId(gpa: std.mem.Allocator, io: std.Io, named: []const u8) ?std.c.gid_t {
    if (std.fmt.parseInt(std.c.gid_t, named, 10)) |gid| return gid else |_| {}
    if (named.len == 0) return null;
    const text = std.Io.Dir.readFileAlloc(.cwd(), io, "/etc/group", gpa, .limited(1 << 20)) catch return null;
    defer gpa.free(text);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const gid_text = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, named)) continue;
        return std.fmt.parseInt(std.c.gid_t, gid_text, 10) catch null;
    }
    return null;
}

fn configureGroupSocket(arena: std.mem.Allocator, io: std.Io, path: []const u8, gid: std.c.gid_t) !void {
    const path_z = try arena.dupeSentinel(u8, path, 0);
    const group_set = switch (builtin.os.tag) {
        .linux => std.posix.errno(std.os.linux.fchownat(
            std.posix.AT.FDCWD,
            path_z.ptr,
            std.math.maxInt(std.posix.uid_t),
            gid,
            std.posix.AT.SYMLINK_NOFOLLOW,
        )) == .SUCCESS,
        .macos => std.c.fchownat(
            std.posix.AT.FDCWD,
            path_z.ptr,
            std.math.maxInt(std.c.uid_t),
            gid,
            std.posix.AT.SYMLINK_NOFOLLOW,
        ) == 0,
        else => false,
    };
    if (!group_set) return error.AccessDenied;
    try std.Io.Dir.cwd().setFilePermissions(
        io,
        path,
        @fromBackingInt(@intCast(0o660)),
        .{ .follow_symlinks = false },
    );
}

const forbidden_response = forbidden: {
    const body = "this socket serves the user that started chock serve, " ++
        "and you are not that user\n";
    break :forbidden std.fmt.comptimePrint(
        "HTTP/1.1 403 Forbidden\r\n" ++
            "content-type: text/plain; charset=utf-8\r\n" ++
            "content-length: {d}\r\n" ++
            "connection: close\r\n" ++
            "\r\n{s}",
        .{ body.len, body },
    );
};

fn makeDirAll(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

const Connection = struct {
    serve: *Serve,
    stream: std.Io.net.Stream,
};

fn runConnection(conn: Connection) void {
    const serve = conn.serve;
    var stream = conn.stream;
    defer {
        stream.close(serve.io);
        _ = serve.live.fetchSub(1, .monotonic);
    }

    var arena = std.heap.ArenaAllocator.init(serve.gpa);
    defer arena.deinit();

    var read_buffer: [max_head_bytes]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [64 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var http = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    while (true) {
        var request = http.receiveHead() catch return;
        handle(serve, arena.allocator(), &request) catch return;
        _ = arena.reset(.retain_capacity);
    }
}

pub const Route = enum {
    setup_page,
    auth_status,
    local_setup,
    oidc_setup,
    local_login,
    local_password,
    auth_login,
    auth_callback,
    auth_logout,
    page,
    sessions,
    projects,
    teams,
    people,
    team_members,
    team_invites,
    acl_rules,
    providers,
    session_register,
    session_members,
    session_presence,
    session_host,
    worker_token,
    worker_revoke,
    worker_events,
    worker_commands,
    create,
    fork,
    review,
    select,
    undo_selection,
    prompt,
    events,
    /// The same events as `events`, read once and answered whole. A browser
    /// reads this: a page built on phantom's web backend gets one response per
    /// request and cannot hold a stream open.
    lines,
    export_session,
    export_account,
    export_instance,
    answer,
    agent_answer,
    cancel,
    asset,
};

fn beginLogin(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!serve.oidc_enabled.load(.acquire)) {
        try sendWhole(request, "sign-in is not configured\n", .{ .status = .service_unavailable });
        return;
    }
    const callback_url = serve.callback_url.?;
    const authorization = daemonOidcBegin(serve, arena, callback_url) catch {
        try sendWhole(request, "could not start sign-in\n", .{ .status = .bad_gateway });
        return;
    };
    const secure = if (std.mem.startsWith(u8, serve.external_url.?, "https://")) "; Secure" else "";
    const cookie = try std.fmt.allocPrint(arena, "chock_oidc_state={s}; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age=600{s}", .{ authorization.state, secure });
    const headers = [_]std.http.Header{
        .{ .name = "location", .value = authorization.url },
        .{ .name = "set-cookie", .value = cookie },
        .{ .name = "cache-control", .value = "no-store" },
    };
    try sendWhole(request, "", .{ .status = .found, .extra_headers = &headers });
}

fn finishLogin(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!serve.oidc_enabled.load(.acquire)) {
        try sendWhole(request, "sign-in is not configured\n", .{ .status = .service_unavailable });
        return;
    }
    const state = cookieValue(request, "chock_oidc_state") orelse {
        try sendWhole(request, "sign-in state is missing\n", .{ .status = .bad_request });
        return;
    };
    const login = daemonOidcExchange(serve, arena, request.head.target, state) catch {
        try sendWhole(request, "the daemon refused the OIDC callback\n", .{ .status = .bad_gateway });
        return;
    };
    const secure = if (std.mem.startsWith(u8, serve.external_url.?, "https://")) "; Secure" else "";
    const session_cookie = try std.fmt.allocPrint(arena, "chock_session={s}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{s}", .{ &login.token, secure });
    const clear_cookie = try std.fmt.allocPrint(arena, "chock_oidc_state=; Path=/auth/callback; HttpOnly; SameSite=Lax; Max-Age=0{s}", .{secure});
    const headers = [_]std.http.Header{
        .{ .name = "location", .value = "/" },
        .{ .name = "set-cookie", .value = session_cookie },
        .{ .name = "set-cookie", .value = clear_cookie },
        .{ .name = "cache-control", .value = "no-store" },
    };
    try sendWhole(request, "", .{ .status = .found, .extra_headers = &headers });
}

const CreateProjectInput = struct {
    action: []const u8 = "create",
    project_id: ?[]const u8 = null,
    status: ?[]const u8 = null,
    name: ?[]const u8 = null,
    root: ?[]const u8 = null,
    repository_url: ?[]const u8 = null,
};

const DaemonProjectCreation = union(enum) {
    registered: control.ProjectRow,
    refused: []const u8,
};

fn daemonSetProjectStatus(
    serve: *Serve,
    arena: std.mem.Allocator,
    token: []const u8,
    project_id: []const u8,
    status: []const u8,
) !void {
    const payload = try std.json.Stringify.valueAlloc(arena, .{
        .action = "set_status",
        .project_id = project_id,
        .status = status,
    }, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(payload.len));
    const project_json = encoder.encode(encoded, payload);
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        good: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => self.good = true,
                .failed, .record => {},
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_project_create = .{ .token = token, .project_json = project_json } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or !capture.good) return error.ProjectStatusRefused;
}

fn serveRegisterProject(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "project registration requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .projects, false);
        return;
    };
    const kept_token = try arena.dupe(u8, token);
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "project details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "project details are too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(CreateProjectInput, arena, body, .{}) catch {
        try sendWhole(request, "project details must be JSON with name and a local directory or repository URL\n", .{ .status = .bad_request });
        return;
    };
    if (std.mem.eql(u8, input.action, "set_status")) {
        const project_id = input.project_id orelse "";
        const status = input.status orelse "";
        if (project_id.len != 36 or !std.mem.eql(u8, status, "ready") and !std.mem.eql(u8, status, "archived")) {
            try sendWhole(request, "project status needs a project UUID and ready or archived state\n", .{ .status = .bad_request });
            return;
        }
        daemonSetProjectStatus(serve, arena, token, project_id, status) catch {
            try sendWhole(request, "the project status change was refused\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, "{\"updated\":true}", .{ .extra_headers = &json_headers });
        return;
    }
    if (!std.mem.eql(u8, input.action, "create")) {
        try sendWhole(request, "unknown project action\n", .{ .status = .bad_request });
        return;
    }
    const name_input = input.name orelse "";
    const name = std.mem.trim(u8, name_input, " \t\r\n");
    if (name.len == 0 or name.len > 128 or
        ((input.root == null) == (input.repository_url == null)) or
        (input.root != null and (input.root.?.len == 0 or input.root.?.len > 4096 or !std.fs.path.isAbsolute(input.root.?))) or
        (input.repository_url != null and !validRepositoryUrl(input.repository_url.?)))
    {
        try sendWhole(request, "project needs a name and exactly one absolute local directory or HTTPS repository URL\n", .{ .status = .bad_request });
        return;
    }
    const payload = try std.json.Stringify.valueAlloc(arena, .{ .name = name, .root = input.root, .repository_url = input.repository_url }, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(payload.len));
    const project_json = encoder.encode(encoded, payload);
    const created = daemonCreateProject(serve, arena, kept_token, project_json) catch |err| {
        try sendWhole(request, projectCreateFailureMessage(err), .{ .status = .bad_gateway });
        return;
    };
    const row = switch (created) {
        .registered => |registered| registered,
        .refused => |reason| {
            // The daemon's refusal is already a safe, user-facing explanation
            // (it never includes repository credentials or request tokens).
            // Preserve it across the gateway instead of collapsing every
            // provisioning failure into the same opaque 502. A valid
            // application refusal is not itself a gateway failure, though;
            // keep authorization and caller-input errors distinct from a
            // daemon-side clone/transport failure.
            try sendWhole(request, reason, .{ .status = projectRefusalStatus(reason) });
            return;
        },
    };
    const json = try row.toJson(arena);
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

fn projectCreateFailureMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.ProjectDaemonUnavailable => "the project daemon is unavailable; check that its control socket is running\n",
        error.ProjectDaemonVersionMismatch => "the project daemon does not support this request; restart the daemon and web service from the same Chock build\n",
        error.ProjectDaemonInvalidResponse => "the project daemon returned an invalid response; check that the daemon and web service use the same Chock build\n",
        error.ProjectDaemonRequestFailed => "the project daemon did not complete the request; check daemon logs and restart it if it is still running an older build\n",
        else => "the project daemon could not provision this project; check daemon logs for details\n",
    };
}

fn projectRefusalStatus(reason: []const u8) std.http.Status {
    if (std.mem.startsWith(u8, reason, "registering an existing daemon path is reserved for instance administrators") or
        std.mem.startsWith(u8, reason, "repository host is not allowed"))
        return .forbidden;
    if (std.mem.startsWith(u8, reason, "project clone requires") or
        std.mem.startsWith(u8, reason, "the daemon could not open the project directory") or
        std.mem.startsWith(u8, reason, "the project directory could not be resolved"))
        return .unprocessable_entity;
    return .bad_gateway;
}

const RegisterSessionInput = struct {
    session: []const u8,
    placement: []const u8 = "daemon",
};

fn serveRegisterSession(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "session registration requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .session_register, false);
        return;
    };
    const kept_token = try arena.dupe(u8, token);
    const project = try arena.dupe(u8, projectOf(serve, arena, request.head.target));
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "session details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "session details are too large\n", .{ .status = .payload_too_large });
        return;
    };
    const input = std.json.parseFromSliceLeaky(RegisterSessionInput, arena, body, .{}) catch {
        try sendWhole(request, "session details must be JSON with a session identifier\n", .{ .status = .bad_request });
        return;
    };
    if (!isSessionName(input.session) or !std.fs.path.isAbsolute(project) or
        (!std.mem.eql(u8, input.placement, "daemon") and !std.mem.eql(u8, input.placement, "client")))
    {
        try sendWhole(request, "a valid session, registered project, and daemon or client placement are required\n", .{ .status = .bad_request });
        return;
    }
    try askDaemon(serve, arena, request, .{ .auth_session_register_placed = .{
        .token = kept_token,
        .session = input.session,
        .project = project,
        .placement = input.placement,
    } }, "{\"registered\":true}");
}

const SessionMemberInput = struct {
    identity_id: []const u8,
    role: []const u8,
};

fn serveSessionMembers(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "session sharing requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .session_members, false);
        return;
    };
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "session membership needs a session identifier\n", .{ .status = .bad_request });
        return;
    };
    const session_copy = try arena.dupe(u8, session);
    if (request.head.method == .GET) {
        const people = daemonSessionPeople(serve, token, session_copy) catch {
            try sendWhole(request, "only a session owner can view the available people\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, people, .{ .extra_headers = &json_headers });
        return;
    }
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "membership details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "membership details are too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(SessionMemberInput, arena, body, .{}) catch {
        try sendWhole(request, "membership details must be JSON with identity_id and role\n", .{ .status = .bad_request });
        return;
    };
    if (!validUuid(input.identity_id) or
        (!std.mem.eql(u8, input.role, "editor") and !std.mem.eql(u8, input.role, "viewer") and
            !std.mem.eql(u8, input.role, "remove")))
    {
        try sendWhole(request, "a member needs a valid identity UUID and editor or viewer role\n", .{ .status = .bad_request });
        return;
    }
    daemonShareSession(serve, token, session_copy, input.identity_id, input.role) catch {
        try sendWhole(request, "only a session owner can update session membership\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, "{\"updated\":true}", .{ .extra_headers = &json_headers });
}

fn serveSessionPresence(serve: *Serve, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, if (request.head.method == .POST) "{\"present\":false}" else "[]", .{ .extra_headers = &json_headers });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .session_presence, false);
        return;
    };
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "session presence needs a session identifier\n", .{ .status = .bad_request });
        return;
    };
    if (!safeProtocolField(session) or !isSessionName(session)) {
        try sendWhole(request, "session presence needs a valid session identifier\n", .{ .status = .bad_request });
        return;
    }
    const action: []const u8 = if (request.head.method == .POST) "touch" else "list";
    const payload = daemonSessionPresence(serve, token, session, action) catch {
        try sendWhole(request, "session presence is unavailable or this identity cannot view the session\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, payload, .{ .extra_headers = &json_headers });
}

const SessionHostInput = struct {
    action: []const u8,
    session: []const u8,
    placement: []const u8 = "client",
    host_id: []const u8,
    generation: u64 = 0,
};

fn serveSessionHost(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "session host leases require service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = bearerToken(request) orelse cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .session_host, false);
        return;
    };
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "the session host request could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "the session host request is too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(SessionHostInput, arena, body, .{}) catch {
        try sendWhole(request, "the session host request must be valid JSON\n", .{ .status = .bad_request });
        return;
    };
    if (!safeProtocolField(input.session) or !validUuid(input.host_id) or
        (!std.mem.eql(u8, input.action, "claim") and !std.mem.eql(u8, input.action, "release")) or
        (std.mem.eql(u8, input.action, "claim") and
            !std.mem.eql(u8, input.placement, "client") and !std.mem.eql(u8, input.placement, "daemon")) or
        (std.mem.eql(u8, input.action, "release") and input.generation == 0))
    {
        try sendWhole(request, "a lease needs claim or release, a session, a host UUID, and the matching placement or generation\n", .{ .status = .bad_request });
        return;
    }
    const payload = daemonSessionHost(serve, arena, token, input) catch {
        try sendWhole(request, "the session host lease was refused or the daemon could not be reached\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, payload, .{ .extra_headers = &json_headers });
}

fn daemonSessionHost(
    serve: *Serve,
    arena: std.mem.Allocator,
    token: []const u8,
    input: SessionHostInput,
) ![]const u8 {
    if (!validCookieToken(token)) return error.InvalidLogin;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        payload: ?[]const u8 = null,
        released: bool = false,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |record| self.payload = record.payload,
                .ok => |text| self.released = std.mem.eql(u8, text, "host released"),
                .failed => self.failed = true,
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_session_host = .{
            .token = token,
            .action = input.action,
            .session = input.session,
            .placement = input.placement,
            .host_id = input.host_id,
            .generation = input.generation,
        } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.HostLeaseRefused;
    if (std.mem.eql(u8, input.action, "release")) {
        if (!capture.released) return error.HostLeaseRefused;
        return "{\"released\":true}";
    }
    return arena.dupe(u8, capture.payload orelse return error.HostLeaseMissing);
}

const WorkerTokenInput = struct { session: []const u8 };

fn serveWorkerRevoke(serve: *Serve, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "worker credential revocation requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = bearerToken(request) orelse {
        try sendWhole(request, "the worker bearer credential to revoke is required\n", .{ .status = .unauthorized, .extra_headers = &json_headers });
        return;
    };
    if (!(logoutBrowserSession(serve, token) catch false)) {
        try sendWhole(request, "the worker credential could not be revoked\n", .{ .status = .conflict, .extra_headers = &json_headers });
        return;
    }
    try sendWhole(request, "{\"revoked\":true}", .{ .extra_headers = &json_headers });
}

fn serveWorkerToken(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "worker credentials require service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try sendWhole(request, "a browser login is required to provision a worker credential\n", .{ .status = .unauthorized });
        return;
    };
    var body_buffer: [4096]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "the worker credential request could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(2048)) catch {
        try sendWhole(request, "the worker credential request is too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(WorkerTokenInput, arena, body, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the worker credential request is malformed\n", .{ .status = .bad_request });
        return;
    };
    if (!isSessionName(input.session)) {
        try sendWhole(request, "the worker session is invalid\n", .{ .status = .bad_request });
        return;
    }
    const response = daemonWorkerToken(serve, arena, token, input.session) catch {
        try sendWhole(request, "only the owner of a client-placed session may provision its worker\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, response, .{ .extra_headers = &json_headers });
}

fn daemonWorkerToken(serve: *Serve, arena: std.mem.Allocator, token: []const u8, session: []const u8) ![]const u8 {
    if (!validCookieToken(token) or !safeProtocolField(session)) return error.InvalidWorkerToken;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        payload: ?[]const u8 = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |record| self.payload = record.payload,
                .failed => self.failed = true,
                .ok => {},
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_worker_token = .{ .token = token, .session = session } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.WorkerTokenRefused;
    return arena.dupe(u8, capture.payload orelse return error.WorkerTokenMissing);
}

fn daemonSessionPeople(serve: *Serve, token: []const u8, session: []const u8) ![]const u8 {
    if (!validCookieToken(token) or !safeProtocolField(session)) return error.InvalidSessionPeople;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        payload: ?[]const u8 = null,
        failed: bool = false,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| self.payload = one.payload,
                .failed => self.failed = true,
                .ok => {},
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_session_people = .{ .token = token, .session = session } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.SessionPeopleRefused;
    return capture.payload orelse error.SessionPeopleMissing;
}

fn daemonSessionPresence(serve: *Serve, token: []const u8, session: []const u8, action: []const u8) ![]const u8 {
    if (!validCookieToken(token) or !safeProtocolField(session) or
        (!std.mem.eql(u8, action, "touch") and !std.mem.eql(u8, action, "list")))
        return error.InvalidSessionPresence;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        payload: ?[]const u8 = null,
        good: bool = false,
        failed: bool = false,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| self.payload = one.payload,
                .ok => |text| self.good = std.mem.eql(u8, text, "present"),
                .failed => self.failed = true,
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_session_presence = .{ .token = token, .action = action, .session = session } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.SessionPresenceRefused;
    if (std.mem.eql(u8, action, "touch")) {
        if (!capture.good) return error.SessionPresenceMissing;
        return "{\"present\":true}";
    }
    return capture.payload orelse error.SessionPresenceMissing;
}

fn daemonShareSession(serve: *Serve, token: []const u8, session: []const u8, identity_id: []const u8, role: []const u8) !void {
    if (!validCookieToken(token) or !safeProtocolField(session) or
        !validUuid(identity_id) or !safeProtocolField(role)) return error.InvalidSessionMember;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        updated: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => |text| self.updated = std.mem.eql(u8, text, "member updated") or std.mem.eql(u8, text, "member removed"),
                .failed => {},
                .record => {},
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_session_member = .{ .token = token, .session = session, .identity = identity_id, .role = role } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or !capture.updated) return error.SessionMemberRefused;
}

fn cookieValue(request: *std.http.Server.Request, name: []const u8) ?[]const u8 {
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        var pairs = std.mem.splitScalar(u8, header.value, ';');
        while (pairs.next()) |pair_raw| {
            const pair = std.mem.trim(u8, pair_raw, " \t");
            const equals = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
            if (std.mem.eql(u8, pair[0..equals], name)) return pair[equals + 1 ..];
        }
    }
    return null;
}

fn requestHeader(request: *std.http.Server.Request, wanted: []const u8) ?[]const u8 {
    var found: ?[]const u8 = null;
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, wanted)) continue;
        if (found != null) return null;
        found = header.value;
    }
    return found;
}

fn bearerToken(request: *std.http.Server.Request) ?[]const u8 {
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "authorization")) continue;
        if (!std.mem.startsWith(u8, header.value, "Bearer ")) return null;
        const token = header.value[7..];
        return if (validCookieToken(token)) token else null;
    }
    return null;
}

const WorkerEventInput = struct {
    session: []const u8,
    host_id: []const u8,
    generation: u64,
    event_id: u64,
    event: event.Event,
};
const WorkerAppendReply = struct { event_id: u64, next_offset: u64 };

fn serveWorkerEvent(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "worker event ingress requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = bearerToken(request) orelse {
        try sendWhole(request, "a valid worker bearer session is required\n", .{ .status = .unauthorized, .extra_headers = &json_headers });
        return;
    };
    var body_buffer: [16 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "the worker event could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(128 * 1024)) catch {
        try sendWhole(request, "the worker event is too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(WorkerEventInput, arena, body, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the worker event request is malformed\n", .{ .status = .bad_request });
        return;
    };
    if (!isSessionName(input.session) or !validUuid(input.host_id) or input.generation == 0) {
        try sendWhole(request, "the worker session lease identity is invalid\n", .{ .status = .bad_request });
        return;
    }
    const event_json = std.json.Stringify.valueAlloc(arena, input.event, .{}) catch {
        try sendWhole(request, "the worker event could not be encoded\n", .{ .status = .bad_request });
        return;
    };
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(event_json.len);
    const encoded = arena.alloc(u8, encoded_len) catch {
        try sendWhole(request, "the worker event could not be encoded\n", .{ .status = .internal_server_error });
        return;
    };
    _ = std.base64.url_safe_no_pad.Encoder.encode(encoded, event_json);
    const appended = daemonWorkerEvent(serve, token, input, encoded) catch {
        try sendWhole(request, "the worker lease was refused or the session log could not accept this offset\n", .{ .status = .conflict, .extra_headers = &json_headers });
        return;
    };
    const response = try std.json.Stringify.valueAlloc(arena, appended, .{});
    try sendWhole(request, response, .{ .extra_headers = &json_headers });
}

fn daemonWorkerEvent(
    serve: *Serve,
    token: []const u8,
    input: WorkerEventInput,
    encoded_event: []const u8,
) !WorkerAppendReply {
    if (!validCookieToken(token) or !safeProtocolField(input.session) or !safeProtocolField(encoded_event))
        return error.InvalidWorkerEvent;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        appended: ?WorkerAppendReply = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => |text| {
                    if (!std.mem.startsWith(u8, text, "event ")) return error.MalformedWorkerReply;
                    const next_at = std.mem.indexOf(u8, text, " next ") orelse return error.MalformedWorkerReply;
                    self.appended = .{
                        .event_id = std.fmt.parseInt(u64, text[6..next_at], 10) catch return error.MalformedWorkerReply,
                        .next_offset = std.fmt.parseInt(u64, text[next_at + " next ".len ..], 10) catch return error.MalformedWorkerReply,
                    };
                },
                .failed => self.failed = true,
                .record => return error.MalformedWorkerReply,
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_worker_event = .{
            .token = token,
            .session = input.session,
            .host_id = input.host_id,
            .generation = input.generation,
            .event_id = input.event_id,
            .event_json = encoded_event,
        } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok() or capture.failed) return error.WorkerEventRefused;
    return capture.appended orelse error.WorkerEventMissing;
}

fn serveWorkerCommands(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "worker command polling requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = bearerToken(request) orelse {
        try sendWhole(request, "a valid worker bearer session is required\n", .{ .status = .unauthorized, .extra_headers = &json_headers });
        return;
    };
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "a session is required\n", .{ .status = .bad_request });
        return;
    };
    const host_id = queryValue(request.head.target, "host_id") orelse {
        try sendWhole(request, "a host UUID is required\n", .{ .status = .bad_request });
        return;
    };
    const generation_text = queryValue(request.head.target, "generation") orelse {
        try sendWhole(request, "a lease generation is required\n", .{ .status = .bad_request });
        return;
    };
    const after_text = queryValue(request.head.target, "after") orelse "0";
    const generation = std.fmt.parseInt(u64, generation_text, 10) catch {
        try sendWhole(request, "the lease generation is invalid\n", .{ .status = .bad_request });
        return;
    };
    const after = std.fmt.parseInt(u64, after_text, 10) catch {
        try sendWhole(request, "the event cursor is invalid\n", .{ .status = .bad_request });
        return;
    };
    if (!isSessionName(session) or !validUuid(host_id) or generation == 0) {
        try sendWhole(request, "the worker session lease identity is invalid\n", .{ .status = .bad_request });
        return;
    }
    const response = workerRead(serve, arena, token, session, host_id, generation, after) catch {
        try sendWhole(request, "the worker lease was refused or the session events could not be read\n", .{ .status = .conflict, .extra_headers = &json_headers });
        return;
    };
    try sendWhole(request, response, .{ .extra_headers = &json_headers });
}

fn workerRead(
    serve: *Serve,
    arena: std.mem.Allocator,
    token: []const u8,
    session: []const u8,
    host_id: []const u8,
    generation: u64,
    after: u64,
) ![]const u8 {
    if (!validCookieToken(token) or !safeProtocolField(session)) return error.InvalidWorkerRead;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    var body: std.ArrayList(u8) = .empty;
    const Gather = struct {
        gpa: std.mem.Allocator,
        body: *std.ArrayList(u8),
        failed: bool = false,
        end_offset: ?u64 = null,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |record| {
                    if (self.body.items.len != 0) try self.body.append(self.gpa, ',');
                    const payload = try eventPayloadWithId(self.gpa, record.payload, record.id);
                    try self.body.appendSlice(self.gpa, payload);
                },
                .failed => self.failed = true,
                .ok => |text| {
                    if (!std.mem.startsWith(u8, text, "offset ")) return error.MalformedWorkerOffset;
                    self.end_offset = std.fmt.parseInt(u64, text[7..], 10) catch return error.MalformedWorkerOffset;
                    return false;
                },
            }
            return true;
        }
    };
    var gather = Gather{ .gpa = arena, .body = &body };
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_worker_read = .{
            .token = token,
            .session = session,
            .host_id = host_id,
            .generation = generation,
            .after = after,
        } },
        &handshake,
        &gather,
        Gather.take,
    );
    if (!handshake.ok() or gather.failed) return error.WorkerReadRefused;
    return std.fmt.allocPrint(
        arena,
        "{{\"events\":[{s}],\"end_offset\":{d}}}",
        .{ body.items, gather.end_offset orelse return error.WorkerOffsetMissing },
    );
}

const Access = enum { allow, deny, unauthenticated, unavailable };

fn daemonAuthorize(
    serve: *Serve,
    token: []const u8,
    resource_kind: []const u8,
    resource_id: []const u8,
    capability: daemon_state.Capability,
) !Access {
    if (!validCookieToken(token)) return .unauthenticated;
    if (!safeProtocolField(resource_kind) or !safeProtocolField(resource_id)) return .deny;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        decision: enum { allow, deny, unauthenticated, invalid } = .invalid,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .failed => |text| self.decision = if (std.mem.eql(u8, text, "the login session is invalid or expired")) .unauthenticated else .invalid,
                .record => {},
                .ok => |text| {
                    if (std.mem.eql(u8, text, "allow")) self.decision = .allow else if (std.mem.eql(u8, text, "deny")) self.decision = .deny else return error.MalformedAuthorizationResponse;
                },
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_authorize = .{
            .token = token,
            .resource_kind = resource_kind,
            .resource_id = resource_id,
            .capability = @tagName(capability),
        } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok()) return .unavailable;
    return switch (capture.decision) {
        .allow => .allow,
        .deny => .deny,
        .unauthenticated => .unauthenticated,
        .invalid => .unavailable,
    };
}

fn safeProtocolField(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| if (byte == '\t' or byte == '\n' or byte == '\r') return false;
    return true;
}

fn validCookieToken(token: []const u8) bool {
    if (token.len != 43) return false;
    for (token) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    }
    return true;
}

fn validUuid(text: []const u8) bool {
    if (text.len != 36) return false;
    for (text, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return false;
        } else if (!std.ascii.isHex(byte)) return false;
    }
    return true;
}

fn validRepositoryUrl(url: []const u8) bool {
    if (url.len < 13 or url.len > 2048 or !std.mem.startsWith(u8, url, "https://")) return false;
    if (std.mem.indexOfAny(u8, url, "\t\r\n\x00 \\?#") != null) return false;
    const authority_end = std.mem.indexOfScalarPos(u8, url, 8, '/') orelse url.len;
    const authority = url[8..authority_end];
    return authority.len != 0 and std.mem.indexOfScalar(u8, authority, '@') == null;
}

fn daemonCreateProject(
    serve: *Serve,
    arena: std.mem.Allocator,
    token: []const u8,
    project_json: []const u8,
) !DaemonProjectCreation {
    const stream = serve.daemon.connect(serve.io) catch return error.ProjectDaemonUnavailable;
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        arena: std.mem.Allocator,
        row: ?control.ProjectRow = null,
        failure: ?[]const u8 = null,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .failed => |reason| self.failure = try self.arena.dupe(u8, reason),
                .record => |record| {
                    self.row = std.json.parseFromSliceLeaky(control.ProjectRow, self.arena, record.payload, .{
                        .ignore_unknown_fields = true,
                    }) catch return error.MalformedProjectRecord;
                },
                .ok => return error.MalformedProjectResponse,
            }
            return false;
        }
    };
    var capture = Capture{ .arena = arena };
    var handshake: control.Handshake = .{ .unreadable = "" };
    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_project_create = .{ .token = token, .project_json = project_json } },
        &handshake,
        &capture,
        Capture.take,
    ) catch |err| return switch (err) {
        error.MalformedProjectRecord, error.MalformedProjectResponse => error.ProjectDaemonInvalidResponse,
        else => error.ProjectDaemonRequestFailed,
    };
    if (!handshake.ok()) return error.ProjectDaemonVersionMismatch;
    if (capture.failure) |reason| return .{ .refused = reason };
    return .{ .registered = capture.row orelse return error.ProjectDaemonInvalidResponse };
}

fn logoutBrowserSession(serve: *Serve, token: []const u8) !bool {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        good: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => self.good = true,
                .failed, .record => {},
            }
            return false;
        }
    };
    var capture = Capture{};
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_logout = .{ .token = token } },
        &handshake,
        &capture,
        Capture.take,
    );
    return handshake.ok() and capture.good;
}

pub fn routeOf(target: []const u8) ?Route {
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    if (std.mem.eql(u8, path, "/auth/login")) return .auth_login;
    if (std.mem.eql(u8, path, "/setup")) return .setup_page;
    if (std.mem.eql(u8, path, "/api/auth/status")) return .auth_status;
    if (std.mem.eql(u8, path, "/api/setup/local")) return .local_setup;
    if (std.mem.eql(u8, path, "/api/setup/oidc")) return .oidc_setup;
    if (std.mem.eql(u8, path, "/api/auth/local")) return .local_login;
    if (std.mem.eql(u8, path, "/api/auth/password")) return .local_password;
    if (std.mem.eql(u8, path, "/auth/callback")) return .auth_callback;
    if (std.mem.eql(u8, path, "/auth/logout")) return .auth_logout;
    if (std.mem.eql(u8, path, "/")) return .page;
    if (std.mem.eql(u8, path, "/account")) return .page;
    if (std.mem.eql(u8, path, "/api/sessions")) return .sessions;
    if (std.mem.eql(u8, path, "/api/projects")) return .projects;
    if (std.mem.eql(u8, path, "/api/teams")) return .teams;
    if (std.mem.eql(u8, path, "/api/people")) return .people;
    if (std.mem.eql(u8, path, "/api/team-members")) return .team_members;
    if (std.mem.eql(u8, path, "/api/team-invites")) return .team_invites;
    if (std.mem.eql(u8, path, "/api/acl-rules")) return .acl_rules;
    if (std.mem.eql(u8, path, "/api/providers")) return .providers;
    if (std.mem.eql(u8, path, "/api/session/register")) return .session_register;
    if (std.mem.eql(u8, path, "/api/session-members")) return .session_members;
    if (std.mem.eql(u8, path, "/api/session-presence")) return .session_presence;
    if (std.mem.eql(u8, path, "/api/session-host")) return .session_host;
    if (std.mem.eql(u8, path, "/api/worker/token")) return .worker_token;
    if (std.mem.eql(u8, path, "/api/worker/revoke")) return .worker_revoke;
    if (std.mem.eql(u8, path, "/api/worker/events")) return .worker_events;
    if (std.mem.eql(u8, path, "/api/worker/commands")) return .worker_commands;
    if (std.mem.eql(u8, path, "/api/create")) return .create;
    if (std.mem.eql(u8, path, "/api/events")) return .events;
    if (std.mem.eql(u8, path, "/api/lines")) return .lines;
    if (std.mem.eql(u8, path, "/api/export/session")) return .export_session;
    if (std.mem.eql(u8, path, "/api/export/account")) return .export_account;
    if (std.mem.eql(u8, path, "/api/export/instance")) return .export_instance;
    if (std.mem.eql(u8, path, "/api/answer")) return .answer;
    if (std.mem.eql(u8, path, "/api/agent-answer")) return .agent_answer;
    if (std.mem.eql(u8, path, "/api/cancel")) return .cancel;
    if (std.mem.eql(u8, path, "/api/fork")) return .fork;
    if (std.mem.eql(u8, path, "/api/workspace/review")) return .review;
    if (std.mem.eql(u8, path, "/api/workspace/select")) return .select;
    if (std.mem.eql(u8, path, "/api/workspace/undo")) return .undo_selection;
    if (std.mem.eql(u8, path, "/api/prompt")) return .prompt;
    // Everything else is a file of the page, or nothing. The name is matched
    // against the bundle rather than against a directory, so a request can
    // never reach outside what was built.
    // A browser escapes a name before it asks for it, so `fonts/Mesmerize Rg.otf`
    // arrives as `fonts/Mesmerize%20Rg.otf` and matches no member until it is
    // decoded.
    // The page's own routes. A browser asks for these on a reload or a link,
    // and the page sorts out what to draw from the address itself.
    if (std.mem.startsWith(u8, path, app_route) and isSessionName(path[app_route.len..])) return .page;

    if (path.len > 1 and path.len - 1 <= max_asset_name) {
        var room: [max_asset_name]u8 = undefined;
        const raw = path[1..];
        @memcpy(room[0..raw.len], raw);
        if (memberNamed(std.Uri.percentDecodeInPlace(room[0..raw.len])) != null) return .asset;
    }
    return null;
}

/// Where the page puts a session it has open.
const app_route = "/s/";

/// Whether what follows `/s/` could name a session. Not a check that the session
/// exists: the page asks the daemon that, and a name of the wrong shape is a
/// request for something this never serves.
fn isSessionName(said: []const u8) bool {
    if (said.len == 0 or said.len > 64) return false;
    for (said) |one| if (!std.ascii.isAlphanumeric(one)) return false;
    return true;
}

fn handle(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const route = routeOf(request.head.target) orelse {
        try sendWhole(request, "not found\n", .{ .status = .not_found });
        return;
    };
    recheckAuth(serve, arena);

    // A route that changes what a session does is a POST, so nothing that
    // prefetches a link can drive it.
    const wanted: std.http.Method = switch (route) {
        .auth_logout, .local_setup, .oidc_setup, .local_login, .local_password => .POST,
        .auth_callback => .GET,
        .answer, .agent_answer, .cancel, .create, .fork, .prompt, .select, .undo_selection, .session_register, .session_members, .session_presence, .session_host, .worker_token, .worker_revoke, .worker_events => .POST,
        .setup_page, .auth_status, .auth_login, .page, .asset, .sessions, .projects, .teams, .people, .team_members, .team_invites, .acl_rules, .providers, .events, .lines, .export_session, .export_account, .export_instance, .review, .worker_commands => .GET,
    };
    const method_ok = if (route == .people or route == .projects or route == .teams or route == .team_members)
        request.head.method == .GET or request.head.method == .POST or request.head.method == .HEAD
    else if (route == .team_invites)
        request.head.method == .GET or request.head.method == .POST or request.head.method == .DELETE
    else if (route == .acl_rules)
        request.head.method == .GET or request.head.method == .POST or request.head.method == .DELETE
    else if (route == .providers)
        request.head.method == .GET or request.head.method == .POST or request.head.method == .DELETE
    else if (route == .session_members)
        request.head.method == .GET or request.head.method == .POST
    else if (route == .session_presence)
        request.head.method == .GET or request.head.method == .POST
    else
        request.head.method == wanted or (wanted == .GET and request.head.method == .HEAD);
    if (!method_ok) {
        try sendWhole(request, "that route does not take that method\n", .{ .status = .method_not_allowed });
        return;
    }

    // Read this before any handler consumes the body and advances the request
    // reader past its headers. It changes only the response shape for Phantom's
    // fetch client; normal form/API callers keep the browser redirect.
    const phantom_auth_response = if (requestHeader(request, "x-chock-phantom-auth")) |value|
        std.mem.eql(u8, value, "true")
    else
        false;

    // OIDC browser sessions authenticate with ambient cookies. Check the
    // initiating origin before any state-changing route, including logout.
    // Bearer-only worker requests and native clients without browser metadata
    // remain usable; browsers that send Origin must match the configured
    // public origin exactly (the configured path prefix is not part of Origin).
    const has_bearer = bearerToken(request) != null;
    const browser_mutation = (request.head.method == .POST or request.head.method == .DELETE) and
        (cookieValue(request, "chock_session") != null or route == .local_setup or route == .oidc_setup or route == .local_login);
    if (browser_mutation and (route == .local_setup or route == .oidc_setup or route == .local_login or
        (authEnabled(serve) and cookieMutationNeedsOrigin(route, has_bearer))) and
        (serve.external_url == null or !requestOriginAllowed(request, serve.external_url.?, arena)))
    {
        try sendWhole(request, "request origin is not allowed\n", .{
            .status = .forbidden,
            .extra_headers = &.{.{ .name = "cache-control", .value = "no-store" }},
        });
        return;
    }

    if (route == .auth_logout) {
        try finishLogout(serve, arena, request);
        return;
    }

    if (authEnabled(serve) and requiresBrowserSession(route, bearerToken(request) != null)) {
        const token = cookieValue(request, "chock_session") orelse {
            try refuseUnauthenticated(serve, request, route, false);
            return;
        };
        const access = accessForRoute(serve, arena, route, request.head.target);
        const decision = if (access) |target|
            daemonAuthorize(serve, token, target.resource_kind, target.resource_id, target.capability) catch .unavailable
        else
            .allow;
        switch (decision) {
            .allow => {},
            .unauthenticated => {
                try refuseUnauthenticated(serve, request, route, true);
                return;
            },
            .deny => {
                try sendWhole(request, "access denied\n", .{ .status = .forbidden, .extra_headers = &.{.{ .name = "cache-control", .value = "no-store" }} });
                return;
            },
            .unavailable => {
                try sendWhole(request, "authorization service unavailable\n", .{ .status = .bad_gateway });
                return;
            },
        }
    }

    switch (route) {
        .setup_page => try sendSetupPage(request),
        .auth_status => try serveAuthStatus(serve, arena, request),
        .local_setup => try serveLocalAuth(serve, arena, request, true, phantom_auth_response),
        .oidc_setup => try serveOidcSetup(serve, arena, request),
        .local_login => try serveLocalAuth(serve, arena, request, false, phantom_auth_response),
        .local_password => try serveLocalPassword(serve, arena, request),
        .auth_login => {
            const mode = daemonAuthMode(serve, arena) catch {
                try sendWhole(request, "authentication status unavailable\n", .{ .status = .bad_gateway });
                return;
            };
            serve.oidc_enabled.store(mode.oidc, .release);
            serve.service_auth.store(mode.service, .release);
            if (mode.oidc)
                try beginLogin(serve, arena, request)
            else
                try sendMember(request, "index.html");
        },
        .auth_callback => try finishLogin(serve, arena, request),
        .auth_logout => unreachable,
        .page => try sendMember(request, "index.html"),
        .asset => {
            const target = request.head.target;
            const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
            var room: [max_asset_name]u8 = undefined;
            const raw = path[1..];
            @memcpy(room[0..raw.len], raw);
            try sendMember(request, std.Uri.percentDecodeInPlace(room[0..raw.len]));
        },
        .sessions => try serveSessions(serve, arena, request),
        .projects => if (request.head.method == .POST)
            try serveRegisterProject(serve, arena, request)
        else
            try serveProjects(serve, arena, request),
        .teams => try serveTeams(serve, arena, request),
        .people => try servePeople(serve, arena, request),
        .team_members => try serveTeamMembers(serve, arena, request),
        .team_invites => try serveTeamInvites(serve, arena, request),
        .acl_rules => try serveAclRules(serve, arena, request),
        .providers => try serveProviders(serve, arena, request),
        .session_register => try serveRegisterSession(serve, arena, request),
        .session_members => try serveSessionMembers(serve, arena, request),
        .session_presence => try serveSessionPresence(serve, request),
        .session_host => try serveSessionHost(serve, arena, request),
        .worker_token => try serveWorkerToken(serve, arena, request),
        .worker_revoke => try serveWorkerRevoke(serve, request),
        .worker_events => try serveWorkerEvent(serve, arena, request),
        .worker_commands => try serveWorkerCommands(serve, arena, request),
        .create => try serveCreate(serve, arena, request),
        .events => try serveEvents(serve, arena, request),
        .lines => try serveLines(serve, arena, request, false),
        .export_session => try serveLines(serve, arena, request, true),
        .export_account => try serveAccountExport(serve, arena, request),
        .export_instance => try serveInstanceExport(serve, arena, request),
        .answer => try serveAnswer(serve, arena, request),
        .agent_answer => try serveAgentAnswer(serve, arena, request),
        .cancel => try serveCancel(serve, arena, request),
        .fork => try serveFork(serve, arena, request),
        .review => try serveReview(serve, arena, request),
        .select => try serveSelect(serve, arena, request),
        .undo_selection => try serveUndoSelection(serve, arena, request),
        .prompt => try servePrompt(serve, arena, request),
    }
}

fn requestOriginAllowed(
    request: *std.http.Server.Request,
    external_url: []const u8,
    arena: std.mem.Allocator,
) bool {
    var origin: ?[]const u8 = null;
    var fetch_site: ?[]const u8 = null;
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "origin")) {
            if (origin != null) return false;
            origin = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "sec-fetch-site")) {
            if (fetch_site != null) return false;
            fetch_site = header.value;
        }
    }
    if (origin) |value| return originMatchesExternal(external_url, value, arena);
    // Native clients generally send neither header. A browser that does send
    // Fetch Metadata but omits Origin must not get a cross-site mutation pass.
    if (fetch_site) |value|
        return std.ascii.eqlIgnoreCase(value, "same-origin");
    return true;
}

fn originMatchesExternal(external_url: []const u8, origin_value: []const u8, arena: std.mem.Allocator) bool {
    const external = std.Uri.parse(external_url) catch return false;
    const origin = std.Uri.parse(origin_value) catch return false;
    if (origin.user != null or origin.password != null or origin.query != null or origin.fragment != null or
        !origin.path.isEmpty() or origin.host == null or external.host == null or
        !std.ascii.eqlIgnoreCase(origin.scheme, external.scheme))
        return false;
    if (!std.ascii.eqlIgnoreCase(origin.scheme, "http") and !std.ascii.eqlIgnoreCase(origin.scheme, "https"))
        return false;
    const origin_host = origin.host.?.toRawMaybeAlloc(arena) catch return false;
    const external_host = external.host.?.toRawMaybeAlloc(arena) catch return false;
    if (!std.ascii.eqlIgnoreCase(origin_host, external_host)) return false;
    return effectiveOriginPort(origin) == effectiveOriginPort(external);
}

fn effectiveOriginPort(uri: std.Uri) ?u16 {
    if (uri.port) |port| return port;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "http")) return 80;
    if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) return 443;
    return null;
}

fn requiresLogin(route: Route) bool {
    return switch (route) {
        .sessions, .projects, .teams, .people, .team_members, .team_invites, .acl_rules, .providers, .session_register, .session_members, .session_presence, .session_host, .worker_token, .worker_revoke, .worker_events, .worker_commands, .local_password, .create, .fork, .review, .select, .undo_selection, .prompt, .events, .lines, .export_session, .export_account, .export_instance, .answer, .agent_answer, .cancel => true,
        .setup_page, .auth_status, .local_setup, .oidc_setup, .local_login, .auth_login, .auth_callback, .auth_logout, .asset => false,
        .page => true,
    };
}

/// Worker bearer credentials are accepted by the session-host handler, where
/// the daemon further limits them to the credential's one client session.
/// Keep the browser-cookie gate from rejecting that bearer before dispatch.
fn requiresBrowserSession(route: Route, has_bearer: bool) bool {
    return requiresLogin(route) and route != .worker_events and route != .worker_commands and route != .worker_revoke and
        !(route == .session_host and has_bearer);
}

fn cookieMutationNeedsOrigin(route: Route, has_bearer: bool) bool {
    // These routes authenticate exclusively with a worker bearer. Session
    // host accepts either credential, and prefers bearer when one is present.
    if (route == .worker_events or route == .worker_commands or route == .worker_revoke)
        return false;
    if (route == .session_host and has_bearer) return false;
    return true;
}

const AccessTarget = struct {
    resource_kind: []const u8,
    resource_id: []const u8,
    capability: daemon_state.Capability,
};

fn accessForRoute(
    serve: *Serve,
    arena: std.mem.Allocator,
    route: Route,
    target: []const u8,
) ?AccessTarget {
    // The application shell holds no project data of its own, and everything it then
    // asks for is checked on its own. So a login is all it takes to see the page, and
    // a person with no project yet gets the interface instead of a refusal.
    if (route == .page and !std.mem.startsWith(u8, target, app_route)) return null;
    if (route == .sessions) {
        if (queryValue(target, "all") != null) return null;
        const resource_id = serve.project;
        return .{ .resource_kind = "project", .resource_id = resource_id, .capability = .project_view };
    }
    if (route == .create)
        return .{ .resource_kind = "project", .resource_id = projectOf(serve, arena, target), .capability = .project_manage };
    if (route == .session_register)
        return .{ .resource_kind = "project", .resource_id = projectOf(serve, arena, target), .capability = .project_manage };

    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    const session = queryValue(target, "session") orelse if (std.mem.startsWith(u8, path, app_route))
        path[app_route.len..]
    else
        return null;
    if (!isSessionName(session)) return null;
    const capability: daemon_state.Capability = switch (route) {
        .answer => .session_approve,
        .agent_answer => .session_prompt,
        .fork => .session_share,
        .prompt, .cancel, .select, .undo_selection => .session_prompt,
        .events, .lines, .export_session, .review, .session_presence, .page => .session_view,
        else => return null,
    };
    return .{ .resource_kind = "session", .resource_id = session, .capability = capability };
}

fn refuseUnauthenticated(
    serve: *Serve,
    request: *std.http.Server.Request,
    route: Route,
    had_cookie: bool,
) !void {
    const expire_cookie = "chock_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
    if (route == .page) {
        const headers = [_]std.http.Header{
            .{ .name = "location", .value = "/auth/login" },
            .{ .name = "cache-control", .value = "no-store" },
        };
        try sendWhole(request, "", .{ .status = .found, .extra_headers = &headers });
        return;
    }
    const headers = if (had_cookie) &[_]std.http.Header{
        .{ .name = "set-cookie", .value = expire_cookie },
        .{ .name = "cache-control", .value = "no-store" },
    } else &[_]std.http.Header{
        .{ .name = "cache-control", .value = "no-store" },
    };
    _ = serve;
    try sendWhole(request, "authentication required\n", .{ .status = .unauthorized, .extra_headers = headers });
}

fn finishLogout(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (cookieValue(request, "chock_session")) |token| if (validCookieToken(token)) {
        _ = logoutBrowserSession(serve, token) catch false;
    };
    const secure = if (serve.external_url) |external|
        (if (std.mem.startsWith(u8, external, "https://")) "; Secure" else "")
    else
        "";
    const cleared = try std.fmt.allocPrint(arena, "chock_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{s}", .{secure});
    const headers = [_]std.http.Header{
        .{ .name = "location", .value = "/" },
        .{ .name = "set-cookie", .value = cleared },
        .{ .name = "cache-control", .value = "no-store" },
    };
    try sendWhole(request, "", .{ .status = .found, .extra_headers = &headers });
}

/// Which project a request is about: the one it names, or the one this was
/// started for. A browser lists across projects, so it says which.
///
/// Copied into `arena`, and every caller reads it before touching the body or
/// the response. `std.http.Server` invalidates every string in the head the
/// moment a reader or a streaming response is made, so a target read after
/// either one is freed memory.
fn projectOf(serve: *Serve, arena: std.mem.Allocator, target: []const u8) []const u8 {
    const said = queryValue(target, "project") orelse return serve.project;
    const copy = arena.dupe(u8, said) catch return serve.project;
    return std.Uri.percentDecodeInPlace(copy);
}

fn serveSessions(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    // `all=1` asks past the project this was started for. A browser is not
    // inside one project, and the rows then say which one each belongs to.
    const everything = queryValue(request.head.target, "all") != null;
    const project = if (everything) "" else serve.project;
    try sendRecords(serve, arena, request, .{ .list = .{ .project = project } });
}

fn serveProjects(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .projects, false);
        return;
    };
    try sendRecords(serve, arena, request, .{ .auth_project_list = .{ .token = token } });
}

fn servePeople(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "the people directory requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .people, false);
        return;
    };
    if (request.head.method == .POST) {
        var body_buffer: [8 * 1024]u8 = undefined;
        const reader = request.readerExpectContinue(&body_buffer) catch {
            try sendWhole(request, "identity is required\n", .{ .status = .bad_request });
            return;
        };
        const body = reader.allocRemaining(arena, .limited(8 * 1024)) catch {
            try sendWhole(request, "request is too large\n", .{ .status = .bad_request });
            return;
        };
        const Input = struct {
            action: ?[]const u8 = null,
            identity_id: ?[]const u8 = null,
            role: ?[]const u8 = null,
            enabled: ?bool = null,
            username: ?[]const u8 = null,
            password: ?[]const u8 = null,
        };
        const input = std.json.parseFromSliceLeaky(Input, arena, body, .{}) catch {
            try sendWhole(request, "invalid people action\n", .{ .status = .bad_request });
            return;
        };
        if (input.action) |action| {
            if (std.mem.eql(u8, action, "create_local")) {
                const username = input.username orelse {
                    try sendWhole(request, "username is required\n", .{ .status = .bad_request });
                    return;
                };
                const password = input.password orelse {
                    try sendWhole(request, "password is required\n", .{ .status = .bad_request });
                    return;
                };
                const normalized_username = std.mem.trim(u8, username, " \t\r\n");
                var username_ok = normalized_username.len >= 3 and normalized_username.len <= 64;
                for (normalized_username) |byte| {
                    if (!(std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.')) username_ok = false;
                }
                if (!username_ok or password.len < 12 or password.len > 1024) {
                    try sendWhole(request, "username must be 3–64 letters, digits, dots, dashes, or underscores; password must be 12–1024 characters\n", .{ .status = .bad_request });
                    return;
                }
                const credential_json = try std.json.Stringify.valueAlloc(arena, .{ .username = username, .password = password }, .{});
                const encoder = std.base64.url_safe_no_pad.Encoder;
                const encoded = try arena.alloc(u8, encoder.calcSize(credential_json.len));
                const payload = encoder.encode(encoded, credential_json);
                const identity_id = daemonPeopleCreateLocal(serve, arena, token, payload) catch {
                    try sendWhole(request, "account creation was refused; check that the username is available and that this is an instance administrator in local-account mode\n", .{ .status = .forbidden });
                    return;
                };
                const json = try std.json.Stringify.valueAlloc(arena, .{ .identity_id = identity_id }, .{});
                try sendWhole(request, json, .{ .extra_headers = &json_headers });
                return;
            }
            if (std.mem.eql(u8, action, "reset_local_password")) {
                const identity_id = input.identity_id orelse {
                    try sendWhole(request, "identity_id is required\n", .{ .status = .bad_request });
                    return;
                };
                const password = input.password orelse {
                    try sendWhole(request, "password is required\n", .{ .status = .bad_request });
                    return;
                };
                if (!daemon_state.isUuid(identity_id) or password.len < 12 or password.len > 1024) {
                    try sendWhole(request, "identity_id must be a UUID and password must be 12–1024 characters\n", .{ .status = .bad_request });
                    return;
                }
                daemonPeopleResetPassword(serve, arena, token, identity_id, password) catch {
                    try sendWhole(request, "password reset was refused; local-account mode and administrator access are required\n", .{ .status = .forbidden });
                    return;
                };
                try sendWhole(request, "{\"reset\":true}\n", .{ .extra_headers = &json_headers });
                return;
            }
            if (std.mem.eql(u8, action, "set_local_account_enabled")) {
                const identity_id = input.identity_id orelse {
                    try sendWhole(request, "identity_id is required\n", .{ .status = .bad_request });
                    return;
                };
                const enabled = input.enabled orelse {
                    try sendWhole(request, "enabled is required\n", .{ .status = .bad_request });
                    return;
                };
                if (!daemon_state.isUuid(identity_id)) {
                    try sendWhole(request, "identity_id must be a UUID\n", .{ .status = .bad_request });
                    return;
                }
                daemonPeopleSetLocalAccountEnabled(serve, arena, token, identity_id, enabled) catch |err| {
                    try sendWhole(request, if (err == error.LastLocalAdministrator)
                        "the last enabled local administrator cannot be disabled\n"
                    else
                        "account status change was refused; local-account mode and administrator access are required\n", .{
                        .status = if (err == error.LastLocalAdministrator) .conflict else .forbidden,
                    });
                    return;
                };
                try sendWhole(request, if (enabled) "{\"enabled\":true}\n" else "{\"enabled\":false}\n", .{ .extra_headers = &json_headers });
                return;
            }
            if (std.mem.eql(u8, action, "set_instance_role")) {
                const identity_id = input.identity_id orelse {
                    try sendWhole(request, "identity_id is required\n", .{ .status = .bad_request });
                    return;
                };
                const role = input.role orelse {
                    try sendWhole(request, "role is required\n", .{ .status = .bad_request });
                    return;
                };
                if (!daemon_state.isUuid(identity_id) or
                    (!std.mem.eql(u8, role, "member") and !std.mem.eql(u8, role, "instance_admin")))
                {
                    try sendWhole(request, "identity_id or role is invalid\n", .{ .status = .bad_request });
                    return;
                }
                const action_name: []const u8 = if (std.mem.eql(u8, role, "instance_admin")) "promote" else "demote";
                _ = daemonPeopleRequest(serve, arena, token, action_name, identity_id) catch |err| {
                    try sendWhole(request, if (err == error.LastInstanceAdministrator)
                        "the last instance administrator cannot be demoted\n"
                    else
                        "instance role change was refused; administrator access is required\n", .{
                        .status = if (err == error.LastInstanceAdministrator) .conflict else .forbidden,
                    });
                    return;
                };
                const response = try std.json.Stringify.valueAlloc(arena, .{ .instance_role = role }, .{});
                try sendWhole(request, response, .{ .extra_headers = &json_headers });
                return;
            }
            try sendWhole(request, "unknown people action\n", .{ .status = .bad_request });
            return;
        }
        const identity_id = input.identity_id orelse {
            try sendWhole(request, "identity_id is required\n", .{ .status = .bad_request });
            return;
        };
        if (!daemon_state.isUuid(identity_id)) {
            try sendWhole(request, "identity_id must be a UUID\n", .{ .status = .bad_request });
            return;
        }
        const count = daemonPeopleRevoke(serve, token, identity_id) catch {
            try sendWhole(request, "credentials could not be revoked; administrator access is required\n", .{ .status = .forbidden });
            return;
        };
        const json = try std.json.Stringify.valueAlloc(arena, .{ .revoked = count }, .{});
        try sendWhole(request, json, .{ .extra_headers = &json_headers });
        return;
    }
    const rows = daemonPeople(serve, arena, token) catch |err| {
        if (err == error.PeopleDirectoryUnreadable) {
            try sendWhole(request, "the people directory could not be read\n", .{ .status = .internal_server_error });
            return;
        }
        try sendWhole(request, "only an instance administrator may view the people directory\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, rows, .{ .extra_headers = &json_headers });
}

fn daemonPeopleCreateLocal(serve: *Serve, arena: std.mem.Allocator, token: []const u8, payload: []const u8) ![]const u8 {
    const said = try daemonPeopleRequest(serve, arena, token, "create-local", payload);
    if (!daemon_state.isUuid(said)) return error.MalformedLocalAccountResponse;
    return said;
}

fn daemonPeopleResetPassword(
    serve: *Serve,
    arena: std.mem.Allocator,
    token: []const u8,
    identity_id: []const u8,
    password: []const u8,
) !void {
    const json = try std.json.Stringify.valueAlloc(arena, .{ .identity_id = identity_id, .password = password }, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(json.len));
    const payload = encoder.encode(encoded, json);
    const result = try daemonPeopleRequest(serve, arena, token, "reset-local-password", payload);
    if (!std.mem.eql(u8, result, "reset")) return error.MalformedPasswordResetResponse;
}

fn daemonPeopleSetLocalAccountEnabled(
    serve: *Serve,
    arena: std.mem.Allocator,
    token: []const u8,
    identity_id: []const u8,
    enabled: bool,
) !void {
    const action: []const u8 = if (enabled) "enable-local" else "disable-local";
    const result = try daemonPeopleRequest(serve, arena, token, action, identity_id);
    const expected: []const u8 = if (enabled) "enabled" else "disabled";
    if (!std.mem.eql(u8, result, expected)) return error.MalformedLocalAccountStatusResponse;
}

fn daemonPeople(serve: *Serve, arena: std.mem.Allocator, token: []const u8) ![]const u8 {
    return daemonPeopleRequest(serve, arena, token, "list", "");
}

fn daemonPeopleRevoke(serve: *Serve, token: []const u8, identity: []const u8) !u64 {
    var arena_state = std.heap.ArenaAllocator.init(serve.gpa);
    defer arena_state.deinit();
    const result = try daemonPeopleRequest(serve, arena_state.allocator(), token, "revoke-sessions", identity);
    return std.fmt.parseInt(u64, result, 10);
}

fn daemonPeopleRequest(serve: *Serve, arena: std.mem.Allocator, token: []const u8, action: []const u8, identity: []const u8) ![]const u8 {
    if (!validCookieToken(token)) return error.InvalidLogin;
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        arena: std.mem.Allocator,
        result: ?[]const u8 = null,
        failed: bool = false,
        failure: ?[]const u8 = null,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| self.result = try self.arena.dupe(u8, one.payload),
                .ok => |one| self.result = try self.arena.dupe(u8, one),
                .failed => |one| {
                    self.failed = true;
                    self.failure = try self.arena.dupe(u8, one);
                },
            }
            return false;
        }
    };
    var capture = Capture{ .arena = arena };
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .auth_people = .{ .token = token, .action = action, .identity = identity } },
        &handshake,
        &capture,
        Capture.take,
    );
    if (!handshake.ok()) return error.PeopleRequestRefused;
    if (capture.failed) {
        if (capture.failure) |failure| {
            if (std.mem.eql(u8, failure, "the last enabled local administrator cannot be disabled"))
                return error.LastLocalAdministrator;
            if (std.mem.eql(u8, failure, "the last instance administrator cannot be demoted"))
                return error.LastInstanceAdministrator;
            if (std.mem.eql(u8, failure, "the people directory could not be read"))
                return error.PeopleDirectoryUnreadable;
            if (std.mem.eql(u8, failure, "the current password is incorrect"))
                return error.InvalidCurrentPassword;
            if (std.mem.eql(u8, failure, "password changes are only available for Chock-managed accounts"))
                return error.LocalAuthDisabled;
        }
        return error.PeopleRequestRefused;
    }
    return capture.result orelse error.PeopleRequestMissing;
}

const TeamInput = struct { name: []const u8 };
const TeamMemberInput = struct { identity_id: []const u8, role: []const u8 };

fn serveTeams(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "team management requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .teams, false);
        return;
    };
    if (request.head.method == .GET) {
        const rows = daemonTeamRequest(serve, arena, .{ .token = token, .action = "list" }) catch {
            try sendWhole(request, "the team list could not be read\n", .{ .status = .bad_gateway });
            return;
        };
        try sendWhole(request, rows, .{ .extra_headers = &json_headers });
        return;
    }
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "team details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "team details are too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(TeamInput, arena, body, .{}) catch {
        try sendWhole(request, "team details must be JSON with a name\n", .{ .status = .bad_request });
        return;
    };
    const name = std.mem.trim(u8, input.name, " \t\r\n");
    if (name.len == 0 or name.len > 128) {
        try sendWhole(request, "team name must be 1 to 128 characters\n", .{ .status = .bad_request });
        return;
    }
    const payload = try std.json.Stringify.valueAlloc(arena, .{ .name = name }, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(payload.len));
    const team_json = encoder.encode(encoded, payload);
    const id = daemonTeamRequest(serve, arena, .{ .token = token, .action = "create", .payload = team_json }) catch {
        try sendWhole(request, "the daemon could not create this team\n", .{ .status = .forbidden });
        return;
    };
    const json = try std.json.Stringify.valueAlloc(arena, .{ .id = id[0..], .name = name }, .{});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

fn serveTeamMembers(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "team management requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .team_members, false);
        return;
    };
    const team = queryValue(request.head.target, "team") orelse {
        try sendWhole(request, "team membership needs a team UUID\n", .{ .status = .bad_request });
        return;
    };
    if (!validUuid(team)) {
        try sendWhole(request, "team must be a UUID\n", .{ .status = .bad_request });
        return;
    }
    if (request.head.method == .GET) {
        const people = daemonTeamRequest(serve, arena, .{ .token = token, .action = "people", .team = team }) catch {
            try sendWhole(request, "only a team owner can view membership\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, people, .{ .extra_headers = &json_headers });
        return;
    }
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "membership details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "membership details are too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(TeamMemberInput, arena, body, .{}) catch {
        try sendWhole(request, "membership details must be JSON with identity_id and role\n", .{ .status = .bad_request });
        return;
    };
    if (!validUuid(input.identity_id) or
        (!std.mem.eql(u8, input.role, "manager") and !std.mem.eql(u8, input.role, "member") and
            !std.mem.eql(u8, input.role, "remove")))
    {
        try sendWhole(request, "a team member needs a valid identity UUID and manager or member role\n", .{ .status = .bad_request });
        return;
    }
    _ = daemonTeamRequest(serve, arena, .{ .token = token, .action = "member", .team = team, .identity = input.identity_id, .role = input.role }) catch {
        try sendWhole(request, "only a team owner can update membership\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, "{\"updated\":true}", .{ .extra_headers = &json_headers });
}

const TeamInviteInput = struct {
    action: []const u8 = "create",
    team: []const u8 = "",
    role: []const u8 = "member",
    token: []const u8 = "",
};

fn serveTeamInvites(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "team invitations require service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .team_invites, false);
        return;
    };
    if (request.head.method == .GET) {
        const team = queryValue(request.head.target, "team") orelse "";
        if (!validUuid(team)) {
            try sendWhole(request, "listing invitations needs a team UUID\n", .{ .status = .bad_request });
            return;
        }
        const rows = daemonTeamRequest(serve, arena, .{ .token = token, .action = "list-invites", .team = team }) catch {
            try sendWhole(request, "only a team owner can view invitations\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, rows, .{ .extra_headers = &json_headers });
        return;
    }
    if (request.head.method == .DELETE) {
        const team = queryValue(request.head.target, "team") orelse "";
        const invitation = queryValue(request.head.target, "invitation") orelse "";
        if (!validUuid(team) or !validUuid(invitation)) {
            try sendWhole(request, "revoking an invitation needs team and invitation UUIDs\n", .{ .status = .bad_request });
            return;
        }
        _ = daemonTeamRequest(serve, arena, .{ .token = token, .action = "revoke-invite", .team = team, .identity = invitation }) catch {
            try sendWhole(request, "only a team owner can revoke an unused invitation\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, "{\"revoked\":true}", .{ .extra_headers = &json_headers });
        return;
    }

    var body_buffer: [4 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "invitation details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(2048)) catch {
        try sendWhole(request, "invitation details are too large\n", .{ .status = .payload_too_large });
        return;
    };
    const input = std.json.parseFromSliceLeaky(TeamInviteInput, arena, body, .{}) catch {
        try sendWhole(request, "invitation details must be JSON\n", .{ .status = .bad_request });
        return;
    };
    if (std.mem.eql(u8, input.action, "redeem")) {
        if (input.token.len != 43 or !validCookieToken(input.token)) {
            try sendWhole(request, "the invitation token is malformed\n", .{ .status = .bad_request });
            return;
        }
        _ = daemonTeamRequest(serve, arena, .{ .token = token, .action = "redeem-invite", .identity = input.token }) catch {
            try sendWhole(request, "the invitation is invalid, expired, revoked, or already used\n", .{ .status = .conflict });
            return;
        };
        try sendWhole(request, "{\"redeemed\":true}", .{ .extra_headers = &json_headers });
        return;
    }
    if (!std.mem.eql(u8, input.action, "create") or !validUuid(input.team) or
        !std.mem.eql(u8, input.role, "member"))
    {
        try sendWhole(request, "creating an invitation needs a team UUID and the member role\n", .{ .status = .bad_request });
        return;
    }
    const created = daemonTeamRequest(serve, arena, .{
        .token = token,
        .action = "create-invite",
        .team = input.team,
        .role = input.role,
    }) catch {
        try sendWhole(request, "only a team owner can create invitations\n", .{ .status = .forbidden });
        return;
    };
    try sendWhole(request, created, .{ .extra_headers = &json_headers });
}

const AclRuleInput = struct {
    resource_kind: []const u8,
    resource_id: []const u8,
    principal_kind: []const u8,
    principal_id: []const u8 = "",
    capability: []const u8,
    effect: []const u8,
};

fn serveAclRules(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "ACL management requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .acl_rules, false);
        return;
    };
    if (request.head.method == .GET) {
        const kind = queryValue(request.head.target, "resource_kind") orelse "";
        const id = queryValue(request.head.target, "resource_id") orelse "";
        if (!validAclResourceKind(kind) or !validAclResourceId(kind, id)) {
            try sendWhole(request, "ACL listing needs a valid resource kind and resource ID\n", .{ .status = .bad_request });
            return;
        }
        const rows = daemonAclRequest(serve, arena, .{ .token = token, .action = "list", .resource_kind = kind, .resource_id = id }) catch {
            try sendWhole(request, "only a resource manager can list its ACL rules\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, rows, .{ .extra_headers = &json_headers });
        return;
    }
    if (request.head.method == .DELETE) {
        const id = queryValue(request.head.target, "rule_id") orelse "";
        if (!validUuid(id)) {
            try sendWhole(request, "rule_id must be a UUID\n", .{ .status = .bad_request });
            return;
        }
        _ = daemonAclRequest(serve, arena, .{ .token = token, .action = "remove", .rule_id = id }) catch {
            try sendWhole(request, "the ACL rule could not be removed\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, "{\"removed\":true}", .{ .extra_headers = &json_headers });
        return;
    }
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "ACL rule details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(4096)) catch {
        try sendWhole(request, "ACL rule details are too large\n", .{ .status = .bad_request });
        return;
    };
    const input = std.json.parseFromSliceLeaky(AclRuleInput, arena, body, .{}) catch {
        try sendWhole(request, "ACL rule details must be JSON\n", .{ .status = .bad_request });
        return;
    };
    if (!validAclResourceKind(input.resource_kind) or
        !validAclResourceId(input.resource_kind, input.resource_id) or
        std.meta.stringToEnum(daemon_state.PrincipalKind, input.principal_kind) == null or
        std.meta.stringToEnum(daemon_state.Capability, input.capability) == null or
        std.meta.stringToEnum(daemon_state.Effect, input.effect) == null or
        (std.mem.eql(u8, input.principal_kind, "identity") or std.mem.eql(u8, input.principal_kind, "team")) and !validUuid(input.principal_id))
    {
        try sendWhole(request, "ACL resource IDs must match their resource type and principal mappings must use UUIDs\n", .{ .status = .bad_request });
        return;
    }
    const json = try std.json.Stringify.valueAlloc(arena, input, .{});
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(json.len));
    const payload = encoder.encode(encoded, json);
    const result = daemonAclRequest(serve, arena, .{ .token = token, .action = "set", .payload = payload }) catch {
        try sendWhole(request, "the ACL rule could not be set; check your resource permissions\n", .{ .status = .forbidden });
        return;
    };
    const response = try std.fmt.allocPrint(arena, "{{\"id\":{}}}", .{std.json.fmt(result, .{})});
    try sendWhole(request, response, .{ .extra_headers = &json_headers });
}

fn validAclResourceKind(kind: []const u8) bool {
    return std.mem.eql(u8, kind, "team") or std.mem.eql(u8, kind, "project") or
        std.mem.eql(u8, kind, "session") or std.mem.eql(u8, kind, "provider");
}

fn validAclResourceId(kind: []const u8, id: []const u8) bool {
    return if (std.mem.eql(u8, kind, "session")) isSessionName(id) else validUuid(id);
}

fn daemonAclRequest(serve: *Serve, arena: std.mem.Allocator, request: control.Request.AuthAcl) ![]const u8 {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        arena: std.mem.Allocator,
        result: ?[]const u8 = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| self.result = try self.arena.dupe(u8, one.payload),
                .ok => |one| self.result = try self.arena.dupe(u8, one),
                .failed => self.failed = true,
            }
            return false;
        }
    };
    var capture = Capture{ .arena = arena };
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(&stream_reader.interface, &stream_writer.interface, .{ .auth_acl = request }, &handshake, &capture, Capture.take);
    if (!handshake.ok() or capture.failed) return error.AclRequestRefused;
    return capture.result orelse error.AclRequestMissing;
}

fn serveProviders(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "provider management requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .providers, false);
        return;
    };
    if (request.head.method == .GET) {
        const rows = daemonProviderRequest(serve, arena, .{ .token = token, .action = "list" }) catch {
            try sendWhole(request, "providers could not be loaded\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, rows, .{ .extra_headers = &json_headers });
        return;
    }
    if (request.head.method == .DELETE) {
        const id = queryValue(request.head.target, "provider_id") orelse "";
        if (!validUuid(id)) {
            try sendWhole(request, "provider_id must be a UUID\n", .{ .status = .bad_request });
            return;
        }
        _ = daemonProviderRequest(serve, arena, .{ .token = token, .action = "remove", .provider_id = id }) catch {
            try sendWhole(request, "only a provider manager can remove this provider\n", .{ .status = .forbidden });
            return;
        };
        try sendWhole(request, "{\"removed\":true}", .{ .extra_headers = &json_headers });
        return;
    }
    var body_buffer: [20 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "provider details could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(18 * 1024)) catch {
        try sendWhole(request, "provider details are too large\n", .{ .status = .bad_request });
        return;
    };
    const Input = struct {
        name: []const u8,
        provider_kind: []const u8,
        scope_kind: []const u8,
        scope_id: []const u8 = "",
        configuration: []const u8,
        credential_ref: []const u8,
    };
    _ = std.json.parseFromSliceLeaky(Input, arena, body, .{}) catch {
        try sendWhole(request, "provider details must be JSON with a scope and credential reference\n", .{ .status = .bad_request });
        return;
    };
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded = try arena.alloc(u8, encoder.calcSize(body.len));
    const payload = encoder.encode(encoded, body);
    const id = daemonProviderRequest(serve, arena, .{ .token = token, .action = "create", .payload = payload }) catch {
        try sendWhole(request, "provider creation was refused; check your scope and credential reference\n", .{ .status = .forbidden });
        return;
    };
    const response = try std.fmt.allocPrint(arena, "{{\"id\":{}}}", .{std.json.fmt(id, .{})});
    try sendWhole(request, response, .{ .extra_headers = &json_headers });
}

fn daemonProviderRequest(serve: *Serve, arena: std.mem.Allocator, request: control.Request.AuthProvider) ![]const u8 {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        arena: std.mem.Allocator,
        result: ?[]const u8 = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| self.result = try self.arena.dupe(u8, one.payload),
                .ok => |one| self.result = try self.arena.dupe(u8, one),
                .failed => self.failed = true,
            }
            return false;
        }
    };
    var capture = Capture{ .arena = arena };
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(&stream_reader.interface, &stream_writer.interface, .{ .auth_provider = request }, &handshake, &capture, Capture.take);
    if (!handshake.ok() or capture.failed) return error.ProviderRequestRefused;
    return capture.result orelse error.ProviderRequestMissing;
}

fn daemonTeamRequest(serve: *Serve, arena: std.mem.Allocator, request: control.Request.AuthTeam) ![]const u8 {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    const Capture = struct {
        arena: std.mem.Allocator,
        result: ?[]const u8 = null,
        failed: bool = false,
        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| self.result = try self.arena.dupe(u8, one.payload),
                .ok => |one| self.result = try self.arena.dupe(u8, one),
                .failed => self.failed = true,
            }
            return false;
        }
    };
    var capture = Capture{ .arena = arena };
    var handshake: control.Handshake = .{ .unreadable = "" };
    try control.exchange(&stream_reader.interface, &stream_writer.interface, .{ .auth_team = request }, &handshake, &capture, Capture.take);
    if (!handshake.ok() or capture.failed) return error.TeamRequestRefused;
    return capture.result orelse error.TeamRequestMissing;
}

/// Ask the daemon something that answers in records, and send them as one JSON
/// array. The records are the daemon's own bytes, joined and not re-encoded.
fn sendRecords(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    asked: control.Request,
) !void {
    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var body: std.ArrayList(u8) = .empty;
    const Gather = struct {
        gpa: std.mem.Allocator,
        body: *std.ArrayList(u8),
        failed: ?[]const u8 = null,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| {
                    if (self.body.items.len != 0) try self.body.append(self.gpa, ',');
                    try self.body.appendSlice(self.gpa, one.payload);
                },
                .failed => |text| {
                    self.failed = text;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var gather = Gather{ .gpa = arena, .body = &body };
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        asked,
        &said,
        &gather,
        Gather.take,
    ) catch |err| {
        if (!said.ok()) {
            try respondHandshake(arena, request, serve.daemon, said);
            return;
        }
        try respondDaemonFault(arena, request, @errorName(err));
        return;
    };

    if (gather.failed) |text| {
        try respondDaemonRefusal(arena, request, text);
        return;
    }

    const project_listing = switch (asked) {
        .projects => true,
        else => false,
    };
    if (project_listing and authEnabled(serve)) {
        try sendVisibleProjectRecords(serve, arena, request, body.items);
        return;
    }
    const session_listing = switch (asked) {
        .list => true,
        else => false,
    };
    if (session_listing and authEnabled(serve)) {
        try sendVisibleSessionRecords(serve, arena, request, body.items);
        return;
    }

    const json = try std.fmt.allocPrint(arena, "[{s}]", .{body.items});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

fn sendVisibleProjectRecords(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    records: []const u8,
) !void {
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .projects, false);
        return;
    };
    const wrapped = try std.fmt.allocPrint(arena, "[{s}]", .{records});
    const rows = std.json.parseFromSliceLeaky([]const control.ProjectRow, arena, wrapped, .{
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the project list could not be read\n", .{ .status = .bad_gateway });
        return;
    };
    var visible: std.ArrayList(u8) = .empty;
    for (rows) |row| {
        if (!validUuid(row.id)) continue;
        const decision = daemonAuthorize(serve, token, "project", row.id, .project_view) catch .unavailable;
        switch (decision) {
            .allow => {},
            .deny => continue,
            .unauthenticated => {
                try refuseUnauthenticated(serve, request, .projects, true);
                return;
            },
            .unavailable => {
                try sendWhole(request, "authorization service unavailable\n", .{ .status = .bad_gateway });
                return;
            },
        }
        if (visible.items.len != 0) try visible.append(arena, ',');
        const json = try row.toJson(arena);
        try visible.appendSlice(arena, json);
    }
    const json = try std.fmt.allocPrint(arena, "[{s}]", .{visible.items});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

fn sendVisibleSessionRecords(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    records: []const u8,
) !void {
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .sessions, false);
        return;
    };
    const wrapped = try std.fmt.allocPrint(arena, "[{s}]", .{records});
    const rows = std.json.parseFromSliceLeaky([]const control.SessionRow, arena, wrapped, .{
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the session list could not be read\n", .{ .status = .bad_gateway });
        return;
    };
    var visible: std.ArrayList(u8) = .empty;
    for (rows) |row| {
        if (!isSessionName(row.id)) continue;
        const decision = daemonAuthorize(serve, token, "session", row.id, .session_view) catch .unavailable;
        switch (decision) {
            .allow => {},
            .deny => continue,
            .unauthenticated => {
                try refuseUnauthenticated(serve, request, .sessions, true);
                return;
            },
            .unavailable => {
                try sendWhole(request, "authorization service unavailable\n", .{ .status = .bad_gateway });
                return;
            },
        }
        if (visible.items.len != 0) try visible.append(arena, ',');
        const json = try row.toJson(arena);
        try visible.appendSlice(arena, json);
    }
    const json = try std.fmt.allocPrint(arena, "[{s}]", .{visible.items});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

/// Log lines carry zero in their JSON `id`: their byte offset is known only
/// after the line has been written and travels in the daemon record wrapper.
/// A whole-response reader has no SSE `id:` field, so put that offset back in
/// the envelope before handing it to the client.
fn eventPayloadWithId(arena: std.mem.Allocator, payload: []const u8, id: u64) ![]const u8 {
    var parsed = try event.fromJson(arena, payload);
    parsed.value.id = id;
    return event.toJson(arena, parsed.value);
}

/// One session's events after a point, answered whole and then closed.
///
/// `serveEvents` holds a stream open, which a browser on phantom's web backend
/// cannot read: there, one request is one whole response. The daemon already
/// answers a bounded read, so this asks for that rather than asking the page to
/// do something it cannot.
const max_session_export_bytes = 8 * 1024 * 1024;
const max_session_export_events = 100_000;

fn sessionExportWithinLimits(byte_count: usize, event_count: usize) bool {
    return byte_count <= max_session_export_bytes and event_count < max_session_export_events;
}

fn sessionExportJson(arena: std.mem.Allocator, session: []const u8, events_json: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{{\"format\":\"chock-session-export-v1\",\"session\":{f},\"events\":[{s}]}}", .{
        std.json.fmt(session, .{}), events_json,
    });
}

const max_account_export_bytes = 32 * 1024 * 1024;
const max_account_export_events = 200_000;
const max_account_export_sessions = 10_000;

const InstanceExportProject = struct {
    id: []const u8,
    name: []const u8,
    source_kind: []const u8,
    status: []const u8,
};

fn instanceExportProjectJson(arena: std.mem.Allocator, row: control.ProjectRow) std.mem.Allocator.Error![]u8 {
    return std.json.Stringify.valueAlloc(arena, InstanceExportProject{
        .id = row.id,
        .name = row.name,
        .source_kind = row.source_kind,
        .status = row.status,
    }, .{});
}

fn instanceExportJson(
    arena: std.mem.Allocator,
    exported_ms: i64,
    people_json: []const u8,
    projects_json: []const u8,
    providers_json: []const u8,
    access_json: []const u8,
    sessions_json: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        arena,
        "{{\"format\":\"chock-instance-export-v1\",\"exported_ms\":{d},\"people\":{s},\"projects\":[{s}],\"providers\":{s},\"access\":{s},\"sessions\":[{s}]}}",
        .{ exported_ms, people_json, projects_json, providers_json, access_json, sessions_json },
    );
}

fn accountExportWithinLimits(byte_count: usize, event_count: usize) bool {
    return byte_count <= max_account_export_bytes and event_count < max_account_export_events;
}

fn daemonRecords(serve: *Serve, arena: std.mem.Allocator, asked: control.Request) ![]const u8 {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    var body: std.ArrayList(u8) = .empty;
    const Gather = struct {
        arena: std.mem.Allocator,
        body: *std.ArrayList(u8),
        failed: bool = false,
        too_large: bool = false,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |record| {
                    const separator: usize = @intFromBool(self.body.items.len != 0);
                    if (self.body.items.len + separator + record.payload.len > max_account_export_bytes) {
                        self.too_large = true;
                        return false;
                    }
                    if (separator != 0) try self.body.append(self.arena, ',');
                    try self.body.appendSlice(self.arena, record.payload);
                },
                .failed => {
                    self.failed = true;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var gather = Gather{ .arena = arena, .body = &body };
    var handshake: control.Handshake = .{ .unreadable = "" };
    control.exchange(&stream_reader.interface, &stream_writer.interface, asked, &handshake, &gather, Gather.take) catch {
        if (gather.too_large) return error.ExportTooLarge;
        return error.DaemonRequestFailed;
    };
    if (!handshake.ok() or gather.failed) return error.DaemonRequestFailed;
    if (gather.too_large) return error.ExportTooLarge;
    return body.toOwnedSlice(arena);
}

fn sessionExportEvents(serve: *Serve, arena: std.mem.Allocator, session: []const u8) !struct { json: []const u8, event_count: usize } {
    const stream = try serve.daemon.connect(serve.io);
    defer stream.close(serve.io);
    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);
    var body: std.ArrayList(u8) = .empty;
    const Gather = struct {
        arena: std.mem.Allocator,
        body: *std.ArrayList(u8),
        event_count: usize = 0,
        failed: bool = false,
        too_large: bool = false,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |record| {
                    self.event_count += 1;
                    const payload = try eventPayloadWithId(self.arena, record.payload, record.id);
                    const separator: usize = @intFromBool(self.body.items.len != 0);
                    if (!sessionExportWithinLimits(self.body.items.len + separator + payload.len, self.event_count)) {
                        self.too_large = true;
                        return false;
                    }
                    if (separator != 0) try self.body.append(self.arena, ',');
                    try self.body.appendSlice(self.arena, payload);
                },
                .failed => {
                    self.failed = true;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var gather = Gather{ .arena = arena, .body = &body };
    var handshake: control.Handshake = .{ .unreadable = "" };
    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .read = .{ .session = session, .after = 0 } },
        &handshake,
        &gather,
        Gather.take,
    ) catch {
        if (gather.too_large) return error.ExportTooLarge;
        return error.DaemonRequestFailed;
    };
    if (!handshake.ok() or gather.failed) return error.DaemonRequestFailed;
    if (gather.too_large) return error.ExportTooLarge;
    return .{ .json = try body.toOwnedSlice(arena), .event_count = gather.event_count };
}

fn accountExportJson(
    arena: std.mem.Allocator,
    exported_ms: i64,
    projects_json: []const u8,
    sessions_json: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{{\"format\":\"chock-account-export-v1\",\"exported_ms\":{d},\"projects\":[{s}],\"sessions\":[{s}]}}", .{
        exported_ms, projects_json, sessions_json,
    });
}

fn serveAccountExport(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const token: ?[]const u8 = if (authEnabled(serve)) blk: {
        const token_header = cookieValue(request, "chock_session") orelse {
            try refuseUnauthenticated(serve, request, .export_account, false);
            return;
        };
        break :blk try arena.dupe(u8, token_header);
    } else null;
    if (token) |value| {
        // The result (allow or deny) is immaterial; daemonAuthorize resolves
        // the bearer first, so this sentinel resource is only a session check.
        const verified = daemonAuthorize(
            serve,
            value,
            "project",
            "00000000-0000-4000-8000-000000000000",
            .project_view,
        ) catch .unavailable;
        switch (verified) {
            .allow, .deny => {},
            .unauthenticated => {
                try refuseUnauthenticated(serve, request, .export_account, true);
                return;
            },
            .unavailable => {
                try sendWhole(request, "authorization service unavailable\n", .{ .status = .bad_gateway });
                return;
            },
        }
    }
    const projects_request: control.Request = if (token) |value|
        .{ .auth_project_list = .{ .token = value } }
    else
        .{ .projects = {} };
    const projects = daemonRecords(serve, arena, projects_request) catch |err| {
        const status: std.http.Status = if (err == error.ExportTooLarge) .payload_too_large else .bad_gateway;
        try sendWhole(request, "the accessible project records could not be exported within the account export limit\n", .{ .status = status });
        return;
    };
    const listed_sessions = daemonRecords(serve, arena, .{ .list = .{ .project = "" } }) catch |err| {
        const status: std.http.Status = if (err == error.ExportTooLarge) .payload_too_large else .bad_gateway;
        try sendWhole(request, "the session list could not be exported within the account export limit\n", .{ .status = status });
        return;
    };
    const wrapped = try std.fmt.allocPrint(arena, "[{s}]", .{listed_sessions});
    const rows = std.json.parseFromSliceLeaky([]const control.SessionRow, arena, wrapped, .{
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the session list could not be read\n", .{ .status = .bad_gateway });
        return;
    };

    var sessions: std.ArrayList(u8) = .empty;
    var total_events: usize = 0;
    var included_sessions: usize = 0;
    var failed = false;
    for (rows) |row| {
        if (!isSessionName(row.id)) continue;
        if (token) |value| {
            const access = daemonAuthorize(serve, value, "session", row.id, .session_view) catch .unavailable;
            switch (access) {
                .deny => continue,
                .unauthenticated => {
                    try refuseUnauthenticated(serve, request, .export_account, true);
                    return;
                },
                .unavailable => {
                    try sendWhole(request, "session authorization is unavailable\n", .{ .status = .bad_gateway });
                    return;
                },
                .allow => {},
            }
        }
        included_sessions += 1;
        if (included_sessions > max_account_export_sessions) {
            try sendWhole(request, "the account export exceeds 10,000 accessible session records\n", .{ .status = .payload_too_large });
            return;
        }
        if (!row.readable or !row.complete) {
            try sendWhole(request, "an accessible session history is incomplete; retry after it becomes readable\n", .{ .status = .conflict });
            return;
        }
        const transcript = sessionExportEvents(serve, arena, row.id) catch |err| {
            if (err == error.ExportTooLarge) {
                try sendWhole(request, "an accessible session exceeds its complete transcript export limit\n", .{ .status = .payload_too_large });
            } else {
                try sendWhole(request, "an accessible session transcript could not be exported\n", .{ .status = .bad_gateway });
            }
            return;
        };
        total_events += transcript.event_count;
        const session_record = try std.fmt.allocPrint(arena, "{{\"metadata\":{f},\"events\":[{s}]}}", .{
            std.json.fmt(row, .{}), transcript.json,
        });
        const added = session_record.len + @intFromBool(sessions.items.len != 0);
        if (!accountExportWithinLimits(sessions.items.len + added, total_events)) {
            failed = true;
            break;
        }
        if (sessions.items.len != 0) try sessions.append(arena, ',');
        try sessions.appendSlice(arena, session_record);
    }
    if (failed) {
        try sendWhole(request, "the account export exceeds 32 MiB or 200,000 session events\n", .{ .status = .payload_too_large });
        return;
    }
    if (projects.len + sessions.items.len > max_account_export_bytes) {
        try sendWhole(request, "the account export exceeds 32 MiB\n", .{ .status = .payload_too_large });
        return;
    }
    const json = try accountExportJson(
        arena,
        std.Io.Timestamp.now(serve.io, .real).toMilliseconds(),
        projects,
        sessions.items,
    );
    if (json.len > max_account_export_bytes) {
        try sendWhole(request, "the account export exceeds 32 MiB\n", .{ .status = .payload_too_large });
        return;
    }
    const headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json; charset=utf-8" },
        .{ .name = "content-disposition", .value = "attachment; filename=chock-account-export.json" },
        .{ .name = "cache-control", .value = "no-store" },
    };
    try sendWhole(request, json, .{ .extra_headers = &headers });
}

/// An instance archive crosses every project and session boundary, so it is
/// intentionally available only to an instance administrator. Project source
/// locators are omitted: they can contain repository credentials even though
/// the service rejects credentials for newly provisioned URLs.
fn serveInstanceExport(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "instance export requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const token = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .export_instance, false);
        return;
    };
    // The directory API is administrator-only and also resolves the login
    // token. Its contents are deliberately discarded; this request is solely
    // the authorization check for the archive.
    const people_json = daemonPeople(serve, arena, token) catch {
        try sendWhole(request, "only an instance administrator may export instance data\n", .{
            .status = .forbidden,
            .extra_headers = &.{.{ .name = "cache-control", .value = "no-store" }},
        });
        return;
    };
    const providers_json = daemonProviderRequest(serve, arena, .{ .token = token, .action = "list" }) catch {
        try sendWhole(request, "provider configuration could not be exported\n", .{ .status = .bad_gateway });
        return;
    };
    const access_json = daemonTeamRequest(serve, arena, .{ .token = token, .action = "export-instance-access" }) catch {
        try sendWhole(request, "team, sharing, and ACL configuration could not be exported\n", .{ .status = .bad_gateway });
        return;
    };

    const raw_projects = daemonRecords(serve, arena, .{ .projects = {} }) catch |err| {
        const status: std.http.Status = if (err == error.ExportTooLarge) .payload_too_large else .bad_gateway;
        try sendWhole(request, "the project records could not be exported within the instance export limit\n", .{ .status = status });
        return;
    };
    const wrapped_projects = try std.fmt.allocPrint(arena, "[{s}]", .{raw_projects});
    const project_rows = std.json.parseFromSliceLeaky([]const control.ProjectRow, arena, wrapped_projects, .{
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the project records could not be read\n", .{ .status = .bad_gateway });
        return;
    };
    var projects_json: std.ArrayList(u8) = .empty;
    for (project_rows) |row| {
        const encoded = try instanceExportProjectJson(arena, row);
        const separator: usize = @intFromBool(projects_json.items.len != 0);
        if (projects_json.items.len + separator + encoded.len > max_account_export_bytes) {
            try sendWhole(request, "the instance export exceeds 32 MiB\n", .{ .status = .payload_too_large });
            return;
        }
        if (separator != 0) try projects_json.append(arena, ',');
        try projects_json.appendSlice(arena, encoded);
    }

    const listed_sessions = daemonRecords(serve, arena, .{ .list = .{ .project = "" } }) catch |err| {
        const status: std.http.Status = if (err == error.ExportTooLarge) .payload_too_large else .bad_gateway;
        try sendWhole(request, "the session list could not be exported within the instance export limit\n", .{ .status = status });
        return;
    };
    const wrapped_sessions = try std.fmt.allocPrint(arena, "[{s}]", .{listed_sessions});
    const rows = std.json.parseFromSliceLeaky([]const control.SessionRow, arena, wrapped_sessions, .{
        .ignore_unknown_fields = true,
    }) catch {
        try sendWhole(request, "the session list could not be read\n", .{ .status = .bad_gateway });
        return;
    };

    var sessions: std.ArrayList(u8) = .empty;
    var total_events: usize = 0;
    var session_count: usize = 0;
    for (rows) |row| {
        if (!isSessionName(row.id)) continue;
        session_count += 1;
        if (session_count > max_account_export_sessions) {
            try sendWhole(request, "the instance export exceeds 10,000 session records\n", .{ .status = .payload_too_large });
            return;
        }
        if (!row.readable or !row.complete) {
            try sendWhole(request, "a session history is incomplete; retry after it becomes readable\n", .{ .status = .conflict });
            return;
        }
        const transcript = sessionExportEvents(serve, arena, row.id) catch |err| {
            if (err == error.ExportTooLarge) {
                try sendWhole(request, "a session exceeds its complete transcript export limit\n", .{ .status = .payload_too_large });
            } else {
                try sendWhole(request, "a session transcript could not be exported\n", .{ .status = .bad_gateway });
            }
            return;
        };
        total_events += transcript.event_count;
        const session_record = try std.fmt.allocPrint(arena, "{{\"metadata\":{f},\"events\":[{s}]}}", .{
            std.json.fmt(row, .{}), transcript.json,
        });
        const separator: usize = @intFromBool(sessions.items.len != 0);
        if (!accountExportWithinLimits(sessions.items.len + separator + session_record.len, total_events)) {
            try sendWhole(request, "the instance export exceeds 32 MiB or 200,000 session events\n", .{ .status = .payload_too_large });
            return;
        }
        if (separator != 0) try sessions.append(arena, ',');
        try sessions.appendSlice(arena, session_record);
    }
    const json = try instanceExportJson(
        arena,
        std.Io.Timestamp.now(serve.io, .real).toMilliseconds(),
        people_json,
        projects_json.items,
        providers_json,
        access_json,
        sessions.items,
    );
    if (json.len > max_account_export_bytes) {
        try sendWhole(request, "the instance export exceeds 32 MiB\n", .{ .status = .payload_too_large });
        return;
    }
    const headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json; charset=utf-8" },
        .{ .name = "content-disposition", .value = "attachment; filename=chock-instance-export.json" },
        .{ .name = "cache-control", .value = "no-store" },
    };
    try sendWhole(request, json, .{ .extra_headers = &headers });
}

fn serveLines(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request, download: bool) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "a session is required\n", .{ .status = .bad_request });
        return;
    };
    if (download and !isSessionName(session)) {
        try sendWhole(request, "the session identifier is invalid\n", .{ .status = .bad_request });
        return;
    }
    const after = if (download) 0 else parseAfter(queryValue(request.head.target, "after"));

    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var body: std.ArrayList(u8) = .empty;
    const Gather = struct {
        gpa: std.mem.Allocator,
        body: *std.ArrayList(u8),
        failed: ?[]const u8 = null,
        too_large: bool = false,
        event_count: usize = 0,
        limit: usize = 0,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| {
                    self.event_count += 1;
                    if (self.limit != 0 and self.event_count > max_session_export_events) {
                        self.too_large = true;
                        return false;
                    }
                    const payload = try eventPayloadWithId(self.gpa, one.payload, one.id);
                    const separator: usize = @intFromBool(self.body.items.len != 0);
                    if (self.limit != 0 and !sessionExportWithinLimits(
                        self.body.items.len + separator + payload.len,
                        self.event_count,
                    )) {
                        self.too_large = true;
                        return false;
                    }
                    if (separator != 0) try self.body.append(self.gpa, ',');
                    try self.body.appendSlice(self.gpa, payload);
                },
                .failed => |text| {
                    self.failed = text;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var gather = Gather{ .gpa = arena, .body = &body, .limit = if (download) max_session_export_bytes else 0 };
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .read = .{ .session = session, .after = after } },
        &said,
        &gather,
        Gather.take,
    ) catch |err| {
        if (!said.ok()) {
            try respondHandshake(arena, request, serve.daemon, said);
            return;
        }
        try respondDaemonFault(arena, request, @errorName(err));
        return;
    };

    // The daemon bounds a single read at max_events_per_read. If an export
    // reaches that ceiling, there may be later events that this response
    // cannot see, so refuse it instead of presenting a possibly truncated
    // archive as complete.
    if (download and !sessionExportWithinLimits(body.items.len, gather.event_count))
        gather.too_large = true;

    if (gather.too_large) {
        try sendWhole(request, "the session export reaches the download limit (8 MiB or 100,000 events)\n", .{ .status = .payload_too_large });
        return;
    }
    if (gather.failed) |text| {
        try respondDaemonRefusal(arena, request, text);
        return;
    }

    if (download) {
        const json = try sessionExportJson(arena, session, body.items);
        const disposition = try std.fmt.allocPrint(arena, "attachment; filename=\"chock-{s}.json\"", .{session});
        const headers = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "content-disposition", .value = disposition },
            .{ .name = "cache-control", .value = "no-store" },
        };
        try sendWhole(request, json, .{ .extra_headers = &headers });
    } else {
        const json = try std.fmt.allocPrint(arena, "[{s}]", .{body.items});
        try sendWhole(request, json, .{ .extra_headers = &json_headers });
    }
}

fn serveEvents(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    const after = lastEventId(request) orelse parseAfter(queryValue(request.head.target, "after"));
    const project = projectOf(serve, arena, request.head.target);
    // The head is freed once the response starts, so the cookie is copied first.
    const token: ?[]const u8 = if (authEnabled(serve)) if (cookieValue(request, "chock_session")) |value|
        try arena.dupe(u8, value)
    else
        null else null;

    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    var body_buffer: [64 * 1024]u8 = undefined;
    var body = try request.respondStreaming(&body_buffer, .{
        .respond_options = .{
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/event-stream" },
                .{ .name = "cache-control", .value = "no-cache" },
                .{ .name = "x-accel-buffering", .value = "no" },
            },
        },
    });

    const Pump = struct {
        out: *std.http.BodyWriter,
        serve: *Serve,
        token: ?[]const u8,
        session: []const u8,
        checked_ms: i64,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| {
                    if (self.token) |value| {
                        const now_ms = std.Io.Timestamp.now(self.serve.io, .real).toMilliseconds();
                        if (streamRecheckDue(self.checked_ms, now_ms)) {
                            const access = daemonAuthorize(self.serve, value, "session", self.session, .session_view) catch .unavailable;
                            if (!streamKeeps(access)) {
                                if (access != .unavailable) {
                                    self.out.writer.writeAll("event: refused\ndata: access to this session ended\n\n") catch {};
                                    self.out.flush() catch {};
                                }
                                return false;
                            }
                            self.checked_ms = now_ms;
                        }
                    }
                    writeFrame(&self.out.writer, one) catch return false;
                    self.out.flush() catch return false;
                },
                .failed => |text| {
                    self.out.writer.print("event: refused\ndata: {s}\n\n", .{text}) catch return false;
                    self.out.flush() catch return false;
                    return false;
                },
                .ok => {},
            }
            return true;
        }
    };
    var pump = Pump{
        .out = &body,
        .serve = serve,
        .token = token,
        .session = session,
        .checked_ms = std.Io.Timestamp.now(serve.io, .real).toMilliseconds(),
    };
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        .{ .watch = .{
            .project = project,
            .session = session,
            .after = after,
        } },
        &said,
        &pump,
        Pump.take,
    ) catch {};

    if (!said.ok()) {
        var text: std.Io.Writer.Allocating = .init(arena);
        defer text.deinit();
        if (control.handshakeRefusal(&text.writer, serve.daemon, said)) {
            body.writer.print("event: refused\ndata: {s}\n\n", .{
                std.mem.trimEnd(u8, text.written(), "\n"),
            }) catch {};
            body.flush() catch {};
        } else |_| {}
    }

    body.end() catch {};
}

/// An open event stream asks the daemon again at most this often. Revocation reaches a viewer within this bound.
const stream_recheck_ms: i64 = 5000;

fn streamRecheckDue(last_ms: i64, now_ms: i64) bool {
    return now_ms < last_ms or now_ms - last_ms >= stream_recheck_ms;
}

/// Only an explicit allow keeps a stream open. An unreachable daemon ends it, and the browser reconnects through the full check.
fn streamKeeps(access: Access) bool {
    return access == .allow;
}

pub fn writeFrame(writer: *std.Io.Writer, record: control.Reply.Record) std.Io.Writer.Error!void {
    try writer.print("id: {d}\ndata: {s}\n\n", .{ record.id, record.payload });
}

fn serveAnswer(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const asked = answerFrom(request.head.target, projectOf(serve, arena, request.head.target)) catch |err| {
        const text = switch (err) {
            error.NoSession => "that needs a session\n",
            error.NoRequest => "that needs the identifier of the approval it answers\n",
            error.NoDecision => "a decision is `yes` or `no`, and nothing else\n",
        };
        try sendWhole(request, text, .{ .status = .bad_request });
        return;
    };

    if (authEnabled(serve)) {
        const token = cookieValue(request, "chock_session") orelse {
            try refuseUnauthenticated(serve, request, .answer, false);
            return;
        };
        try askDaemon(serve, arena, request, .{ .auth_answer = .{
            .token = token,
            .project = asked.answer.project,
            .session = asked.answer.session,
            .request_id = asked.answer.request_id,
            .decision = asked.answer.decision,
        } }, "{\"answered\":true}");
    } else {
        try askDaemon(serve, arena, request, asked, "{\"answered\":true}");
    }
}

fn serveAgentAnswer(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    if (!authEnabled(serve)) {
        try sendWhole(request, "answering shared agent questions requires service authentication\n", .{ .status = .service_unavailable });
        return;
    }
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    const request_text = queryValue(request.head.target, "request") orelse {
        try sendWhole(request, "that needs the identifier of the agent question\n", .{ .status = .bad_request });
        return;
    };
    const request_id = std.fmt.parseInt(u64, request_text, 10) catch {
        try sendWhole(request, "the agent question identifier is invalid\n", .{ .status = .bad_request });
        return;
    };
    const token_header = cookieValue(request, "chock_session") orelse {
        try refuseUnauthenticated(serve, request, .agent_answer, false);
        return;
    };
    const token = try arena.dupe(u8, token_header);
    const encoded_session = try arena.dupe(u8, session);
    const project = try arena.dupe(u8, projectOf(serve, arena, request.head.target));
    var body_buffer: [8 * 1024]u8 = undefined;
    const body_reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "the answer could not be read\n", .{ .status = .bad_request });
        return;
    };
    const answer = body_reader.allocRemaining(arena, .limited(max_agent_answer_bytes)) catch {
        try sendWhole(request, "the answer is too long\n", .{ .status = .payload_too_large });
        return;
    };
    if (std.mem.trim(u8, answer, " \t\r\n").len == 0 or !std.unicode.utf8ValidateSlice(answer)) {
        try sendWhole(request, "the answer must be non-empty valid UTF-8\n", .{ .status = .bad_request });
        return;
    }
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_storage = try arena.alloc(u8, encoder.calcSize(answer.len));
    const encoded = encoder.encode(encoded_storage, answer);
    try askDaemon(serve, arena, request, .{ .auth_agent_answer = .{
        .token = token,
        .project = project,
        .session = encoded_session,
        .request_id = request_id,
        .answer = encoded,
    } }, "{\"answered\":true}");
}

fn serveCreate(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const placement = queryValue(request.head.target, "placement") orelse "daemon";
    if (!std.mem.eql(u8, placement, "daemon") and !std.mem.eql(u8, placement, "client")) {
        try sendWhole(request, "placement must be daemon or client\n", .{ .status = .bad_request });
        return;
    }
    const project = projectOf(serve, arena, request.head.target);
    if (!std.fs.path.isAbsolute(project)) {
        try sendWhole(request, "session creation needs a registered project directory\n", .{ .status = .bad_request });
        return;
    }
    try askDaemonWithPlacement(serve, arena, request, .{ .create = .{ .project = project } }, null, placement);
}

fn serveFork(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    const at = if (queryValue(request.head.target, "at")) |text|
        std.fmt.parseInt(u64, text, 10) catch {
            try sendWhole(request, "the fork point must be an event offset\n", .{ .status = .bad_request });
            return;
        }
    else
        null;
    const project = projectOf(serve, arena, request.head.target);
    try askDaemon(serve, arena, request, .{ .fork = .{
        .project = project,
        .session = session,
        .at = at,
    } }, null);
}

fn serveReview(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "a session is required\n", .{ .status = .bad_request });
        return;
    };
    const project = projectOf(serve, arena, request.head.target);
    try sendRecords(serve, arena, request, .{ .review = .{ .project = project, .session = session } });
}

fn serveSelect(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session_raw = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "a session is required\n", .{ .status = .bad_request });
        return;
    };
    const project = projectOf(serve, arena, request.head.target);
    const session = try arena.dupe(u8, session_raw);
    var body_buffer: [8 * 1024]u8 = undefined;
    const reader = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "the selection could not be read\n", .{ .status = .bad_request });
        return;
    };
    const body = reader.allocRemaining(arena, .limited(1024 * 1024)) catch {
        try sendWhole(request, "the selection could not be read\n", .{ .status = .bad_request });
        return;
    };
    try askDaemon(serve, arena, request, .{ .select = .{
        .project = project,
        .session = session,
        .payload = body,
    } }, "selected\n");
}

fn serveUndoSelection(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "a session is required\n", .{ .status = .bad_request });
        return;
    };
    const project = projectOf(serve, arena, request.head.target);
    try askDaemon(serve, arena, request, .{ .undo_selection = .{
        .project = project,
        .session = session,
    } }, "undone\n");
}

/// Put one request to the daemon and answer `good` when supplied, or pass the
/// daemon's success text through when the caller needs its result.
fn askDaemon(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    asked: control.Request,
    good: ?[]const u8,
) !void {
    return askDaemonWithPlacement(serve, arena, request, asked, good, "daemon");
}

fn askDaemonWithPlacement(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    asked: control.Request,
    good: ?[]const u8,
    placement: []const u8,
) !void {
    var forwarded = asked;
    if (asked == .create and authEnabled(serve)) {
        const cookie = cookieValue(request, "chock_session") orelse {
            try refuseUnauthenticated(serve, request, .create, false);
            return;
        };
        const token = try arena.dupe(u8, cookie);
        forwarded = .{ .auth_session_create = .{
            .token = token,
            .project = asked.create.project,
            .placement = placement,
        } };
    }
    const stream = serve.daemon.connect(serve.io) catch |err| {
        try respondUnreachable(arena, request, serve.daemon, err);
        return;
    };
    defer stream.close(serve.io);

    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(serve.io, &read_buffer);
    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(serve.io, &write_buffer);

    const Answered = struct {
        said: ?[]const u8 = null,
        good: bool = false,

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .ok => |text| {
                    self.good = true;
                    self.said = text;
                },
                .failed => |text| self.said = text,
                .record => {},
            }
            return false;
        }
    };
    var answered = Answered{};
    var said: control.Handshake = .{ .unreadable = "" };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        forwarded,
        &said,
        &answered,
        Answered.take,
    ) catch |err| {
        if (!said.ok()) {
            try respondHandshake(arena, request, serve.daemon, said);
            return;
        }
        try respondDaemonFault(arena, request, @errorName(err));
        return;
    };

    if (!answered.good) {
        try respondDaemonRefusal(arena, request, answered.said orelse "the daemon said nothing");
        return;
    }
    if (good) |body| {
        try sendWhole(request, body, .{ .extra_headers = &json_headers });
    } else {
        try sendWhole(request, answered.said orelse "", .{});
    }
}

/// The most one message may be. A prompt past this is not a person typing.
const max_message_bytes: usize = 128 * 1024;
const max_agent_answer_bytes: usize = 4096;

/// Send a message to a session that already exists.
///
/// The message is the request body and not a query value: a prompt is as long
/// as a person wants, and a URL is not.
fn servePrompt(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    // Both read before the body. Making a reader invalidates every string in
    // the head, so a target read after this point is freed memory.
    const project = projectOf(serve, arena, request.head.target);
    const asked = arena.dupe(u8, session) catch return;

    var body_buffer: [8 * 1024]u8 = undefined;
    const body = request.readerExpectContinue(&body_buffer) catch {
        try sendWhole(request, "the message could not be read\n", .{ .status = .bad_request });
        return;
    };
    const message = body.allocRemaining(arena, .limited(max_message_bytes)) catch {
        try sendWhole(request, "the message could not be read\n", .{ .status = .bad_request });
        return;
    };
    if (message.len == 0) {
        try sendWhole(request, "that needs a message\n", .{ .status = .bad_request });
        return;
    }

    if (authEnabled(serve)) {
        const token = cookieValue(request, "chock_session") orelse {
            try refuseUnauthenticated(serve, request, .prompt, false);
            return;
        };
        const encoder = std.base64.url_safe_no_pad.Encoder;
        const encoded = try arena.alloc(u8, encoder.calcSize(message.len));
        const payload = encoder.encode(encoded, message);
        try askDaemon(serve, arena, request, .{ .auth_prompt = .{
            .token = token,
            .project = project,
            .session = asked,
            .message = payload,
        } }, "{\"sent\":true}");
    } else {
        try askDaemon(serve, arena, request, .{ .prompt = .{
            .project = project,
            .session = asked,
            .message = message,
        } }, "{\"sent\":true}");
    }
}

fn serveCancel(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    if (!isSessionName(session)) {
        try sendWhole(request, "that session identifier is invalid\n", .{ .status = .bad_request });
        return;
    }
    const project = projectOf(serve, arena, request.head.target);
    const session_copy = try arena.dupe(u8, session);
    if (authEnabled(serve)) {
        const token = cookieValue(request, "chock_session") orelse {
            try refuseUnauthenticated(serve, request, .cancel, false);
            return;
        };
        try askDaemon(serve, arena, request, .{ .auth_cancel = .{
            .token = token,
            .project = project,
            .session = session_copy,
        } }, "{\"canceled\":true}");
    } else {
        try askDaemon(serve, arena, request, .{ .cancel = .{
            .project = project,
            .session = session_copy,
        } }, "{\"canceled\":true}");
    }
}

const json_headers = [_]std.http.Header{
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "cache-control", .value = "no-store" },
};

// std.http.Server.respond asserts the request declared a body length, and a POST with neither header is legal and crashed this.
/// Send one file of the page, still compressed, and let the browser expand it.
fn sendMember(request: *std.http.Server.Request, name: []const u8) !void {
    const one = memberNamed(name) orelse {
        try sendWhole(request, "not found\n", .{ .status = .not_found });
        return;
    };
    try sendWhole(request, one.bytes, .{ .extra_headers = &.{
        .{ .name = "content-type", .value = contentTypeOf(name) },
        .{ .name = "content-encoding", .value = "gzip" },
    } });
}

/// What a browser should read a member as. A name the page does not use answers
/// a stream of bytes rather than a guess.
fn contentTypeOf(name: []const u8) []const u8 {
    if (std.mem.endsWith(u8, name, ".html")) return "text/html; charset=utf-8";
    if (std.mem.endsWith(u8, name, ".js")) return "text/javascript; charset=utf-8";
    if (std.mem.endsWith(u8, name, ".wasm")) return "application/wasm";
    if (std.mem.endsWith(u8, name, ".otf")) return "font/otf";
    if (std.mem.endsWith(u8, name, ".json")) return "application/json";
    return "application/octet-stream";
}

fn sendWhole(
    request: *std.http.Server.Request,
    content: []const u8,
    options: std.http.Server.Request.RespondOptions,
) !void {
    var with = options;
    with.keep_alive = options.keep_alive and mayKeepAlive(
        request.head.method,
        request.head.transfer_encoding,
        request.head.content_length,
    );
    try request.respond(content, with);
}

pub fn mayKeepAlive(
    method: std.http.Method,
    transfer_encoding: std.http.TransferEncoding,
    content_length: ?u64,
) bool {
    if (!method.requestHasBody()) return true;
    return transfer_encoding != .none or content_length != null;
}

pub const AnswerError = error{ NoSession, NoRequest, NoDecision };

pub fn answerFrom(target: []const u8, project: []const u8) AnswerError!control.Request {
    const session = queryValue(target, "session") orelse return error.NoSession;
    const request_text = queryValue(target, "request") orelse return error.NoRequest;
    const request_id = std.fmt.parseInt(u64, request_text, 10) catch return error.NoRequest;
    const word = queryValue(target, "decision") orelse return error.NoDecision;
    const decision = control.Answer.parse(word) orelse return error.NoDecision;
    return .{ .answer = .{
        .project = project,
        .session = session,
        .request_id = request_id,
        .decision = decision,
    } };
}

pub fn queryValue(target: []const u8, name: []const u8) ?[]const u8 {
    const start = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var parts = std.mem.splitScalar(u8, target[start + 1 ..], '&');
    while (parts.next()) |part| {
        const equals = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        if (!std.mem.eql(u8, part[0..equals], name)) continue;
        const value = part[equals + 1 ..];
        if (value.len == 0) return null;
        return value;
    }
    return null;
}

fn parseAfter(text: ?[]const u8) u64 {
    const given = text orelse return 0;
    return std.fmt.parseInt(u64, given, 10) catch 0;
}

fn lastEventId(request: *std.http.Server.Request) ?u64 {
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "last-event-id")) continue;
        return std.fmt.parseInt(u64, header.value, 10) catch null;
    }
    return null;
}

fn respondUnreachable(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    address: control.Address,
    err: control.Address.ConnectError,
) !void {
    const text = try unreachableText(arena, address, err);
    try sendWhole(request, text, .{ .status = .bad_gateway, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

pub fn unreachableText(
    gpa: std.mem.Allocator,
    address: control.Address,
    err: control.Address.ConnectError,
) std.mem.Allocator.Error![]u8 {
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    control.refusalFor(&text.writer, address, err) catch return error.OutOfMemory;
    return text.toOwnedSlice();
}

fn respondHandshake(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    address: control.Address,
    said: control.Handshake,
) !void {
    const text = try handshakeText(arena, address, said);
    try sendWhole(request, text, .{ .status = .bad_gateway, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

pub fn handshakeText(
    gpa: std.mem.Allocator,
    address: control.Address,
    said: control.Handshake,
) std.mem.Allocator.Error![]u8 {
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    control.handshakeRefusal(&text.writer, address, said) catch return error.OutOfMemory;
    return text.toOwnedSlice();
}

fn respondDaemonRefusal(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    what: []const u8,
) !void {
    const text = try std.fmt.allocPrint(arena, "the daemon would not: {s}\n", .{what});
    try sendWhole(request, text, .{ .status = .conflict, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

fn respondDaemonFault(
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    what: []const u8,
) !void {
    const text = try std.fmt.allocPrint(arena, "the daemon could not be read: {s}\n", .{what});
    try sendWhole(request, text, .{ .status = .bad_gateway, .extra_headers = &.{
        .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
    } });
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var port_named = false;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--allow-http")) {
            options.allow_http = true;
            continue;
        }

        const takes_value = [_][]const u8{ "--daemon", "--project", "--socket", "--socket-group", "--host", "--port", "--external-url" };
        var named: ?[]const u8 = null;
        for (takes_value) |one| {
            if (std.mem.eql(u8, argument, one)) named = one;
        }
        if (named) |flag| {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock serve: {s} needs a value.\n\n", .{flag});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            const value = args[index];
            if (std.mem.eql(u8, flag, "--daemon")) options.daemon = value;
            if (std.mem.eql(u8, flag, "--project")) options.project = value;
            if (std.mem.eql(u8, flag, "--socket")) options.socket = value;
            if (std.mem.eql(u8, flag, "--socket-group")) options.socket_group = value;
            if (std.mem.eql(u8, flag, "--host")) options.host = value;
            if (std.mem.eql(u8, flag, "--external-url")) options.external_url = value;
            if (std.mem.eql(u8, flag, "--port")) {
                port_named = true;
                options.port = std.fmt.parseInt(u16, value, 10) catch {
                    tty.print(
                        .err,
                        "chock serve: --port takes a number, and \"{s}\" is not one.\n",
                        .{value},
                    );
                    return error.BadArguments;
                };
            }
            continue;
        }

        tty.print(.err, "chock serve: there is no option named {s}.\n\n", .{argument});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }

    if (port_named and options.host == null) {
        tty.print(
            .err,
            "chock serve: --port names the port of the TCP listener --host turns on, and there " ++
                "is no TCP listener without --host. Write `--host 127.0.0.1 --port <n>`, or drop " ++
                "--port and use the unix socket.\n",
            .{},
        );
        return error.BadArguments;
    }
    if (options.socket_group != null and options.host != null) {
        tty.print(
            .err,
            "chock serve: --socket-group controls a unix socket, and --host selects TCP. " ++
                "Use one or the other.\n",
            .{},
        );
        return error.BadArguments;
    }
    return options;
}

const testing = std.testing;

test "serve reaches a daemon and never a session on disk" {
    const source = @embedFile("serve.zig");
    const opening = "@im" ++ "port(\"";
    const forbidden = [_][]const u8{
        opening ++ "chock-broker\")",
        opening ++ "chock-core\")",
        opening ++ "chock-workspace\")",
        opening ++ "session.zig\")",
        opening ++ "sessions.zig\")",
        "Log." ++ "open",
        "." ++ "lock(",
        "paths" ++ "For(",
    };
    for (forbidden) |needle| {
        try testing.expect(std.mem.indexOf(u8, source, needle) == null);
    }

    try testing.expect(std.mem.indexOf(u8, source, "chock serve") != null);
    try testing.expect(std.mem.indexOf(u8, source, "control.exchange") != null);

    for ([_][]const u8{
        "SO" ++ ".PEERCRED",
        "LOCAL" ++ "_PEERCRED",
        "U" ++ "cred",
        "X" ++ "ucred",
    }) |copied| {
        try testing.expect(std.mem.indexOf(u8, source, copied) == null);
    }
    try testing.expect(std.mem.indexOf(u8, source, "control." ++ "peerUid") != null);
    try testing.expect(std.mem.indexOf(u8, source, "control." ++ "peerAllowed") != null);
}

test "nothing but the unix socket is bound until --host says so" {
    const plain = bindAddress("/state/serve.sock", .{});
    try testing.expect(plain == .unix);
    try testing.expectEqualStrings("/state/serve.sock", plain.unix);

    const direct = bindAddress("/state/serve.sock", .{ .host = "127.0.0.1", .port = 7374 });
    try testing.expect(direct == .ip);
    try testing.expectEqualStrings("127.0.0.1", direct.ip.host);
    try testing.expectEqual(@as(u16, 7374), direct.ip.port);

    const wide = bindAddress("/state/serve.sock", .{ .host = "0.0.0.0", .port = 8080 });
    try testing.expect(wide == .ip);
    try testing.expectEqualStrings("0.0.0.0", wide.ip.host);

    const named = bindAddress("/run/chock/other.sock", .{ .socket = "/run/chock/other.sock" });
    try testing.expect(named == .unix);
    try testing.expectEqualStrings("/run/chock/other.sock", named.unix);

    try testing.expect(!std.mem.eql(u8, socket_name, control.socket_name));
}

test "project refusals distinguish caller errors from gateway failures" {
    try testing.expectEqual(.forbidden, projectRefusalStatus(
        "registering an existing daemon path is reserved for instance administrators",
    ));
    try testing.expectEqual(.forbidden, projectRefusalStatus(
        "repository host is not allowed; add its exact hostname to CHOCK_GIT_ALLOWED_HOSTS",
    ));
    try testing.expectEqual(.unprocessable_entity, projectRefusalStatus(
        "the daemon could not open the project directory; verify it exists and is accessible to the daemon account",
    ));
    try testing.expectEqual(.bad_gateway, projectRefusalStatus(
        "Git could not clone the repository on the daemon; check repository access and daemon network access",
    ));
}

test "project provisioning handoff failures explain which daemon boundary failed" {
    try testing.expect(std.mem.startsWith(u8, projectCreateFailureMessage(error.ProjectDaemonUnavailable), "the project daemon is unavailable"));
    try testing.expect(std.mem.startsWith(u8, projectCreateFailureMessage(error.ProjectDaemonVersionMismatch), "the project daemon does not support this request"));
    try testing.expect(std.mem.startsWith(u8, projectCreateFailureMessage(error.ProjectDaemonInvalidResponse), "the project daemon returned an invalid response"));
    try testing.expect(std.mem.startsWith(u8, projectCreateFailureMessage(error.ProjectDaemonRequestFailed), "the project daemon did not complete the request"));
    try testing.expect(std.mem.startsWith(u8, projectCreateFailureMessage(error.OutOfMemory), "the project daemon could not provision this project"));
}

test "a peer that is not this user is refused on the socket, and a TCP peer is never claimed to be checked" {
    const mine = std.posix.system.getuid();
    try testing.expect(control.peerAllowed(mine, mine));
    try testing.expect(!control.peerAllowed(mine +% 1, mine));
    // An absent answer is a refusal and never a pass: a null uid must not read as allowed.
    try testing.expect(!control.peerAllowed(null, mine));

    const io = testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket_path = try std.fmt.bufPrint(
        &path_buffer,
        "{s}/serve.sock",
        .{dir_buffer[0..dir_len]},
    );

    var listener = try (control.Address{ .unix = socket_path }).listen(io);
    defer listener.close(io);
    try testing.expect(listener.unix_path != null);

    const client = try (control.Address{ .unix = socket_path }).connect(io);
    defer client.close(io);
    var served = try listener.server.accept(io);
    defer served.close(io);

    const said_uid = control.peerUid(served.socket.handle);
    try testing.expectEqual(@as(?std.posix.uid_t, mine), said_uid);
    try testing.expect(control.peerAllowed(said_uid, mine));
    try testing.expect(!control.peerAllowed(said_uid, mine +% 1));

    try testing.expect(std.mem.startsWith(u8, forbidden_response, "HTTP/1.1 403 Forbidden\r\n"));
    try testing.expect(std.mem.indexOf(u8, forbidden_response, "\r\n\r\n") != null);
    const head_end = std.mem.indexOf(u8, forbidden_response, "\r\n\r\n").? + 4;
    var length_buffer: [32]u8 = undefined;
    const declared = try std.fmt.bufPrint(
        &length_buffer,
        "content-length: {d}\r\n",
        .{forbidden_response.len - head_end},
    );
    try testing.expect(std.mem.indexOf(u8, forbidden_response, declared) != null);
}

test "a browser can decide exactly two things, and neither of them is the policy's" {
    const project = "/home/ross/chock";
    const id = "01JQ" ++ @as([22]u8, @splat('A'));

    const yes = try answerFrom("/api/answer?session=" ++ id ++ "&request=128&decision=yes", project);
    try testing.expectEqual(control.Answer.yes, yes.answer.decision);
    try testing.expectEqual(@as(u64, 128), yes.answer.request_id);
    try testing.expectEqualStrings(id, yes.answer.session);
    try testing.expectEqualStrings(project, yes.answer.project);

    const no = try answerFrom("/api/answer?session=" ++ id ++ "&request=1&decision=no", project);
    try testing.expectEqual(control.Answer.no, no.answer.decision);

    for ([_][]const u8{
        "allowed_by_policy",
        "approved_by_policy",
        "approved_by_review",
        "approved_by_user",
        "YES",
        "y",
        "true",
    }) |word| {
        var target_buffer: [256]u8 = undefined;
        const target = try std.fmt.bufPrint(
            &target_buffer,
            "/api/answer?session={s}&request=1&decision={s}",
            .{ id, word },
        );
        try testing.expectError(error.NoDecision, answerFrom(target, project));
    }

    try testing.expectError(
        error.NoSession,
        answerFrom("/api/answer?request=1&decision=yes", project),
    );
    try testing.expectError(
        error.NoRequest,
        answerFrom("/api/answer?session=" ++ id ++ "&decision=yes", project),
    );
    try testing.expectError(
        error.NoRequest,
        answerFrom("/api/answer?session=" ++ id ++ "&request=x&decision=yes", project),
    );
    try testing.expectError(
        error.NoDecision,
        answerFrom("/api/answer?session=" ++ id ++ "&request=1", project),
    );
}

test "a browser cannot name a project, so it cannot ask about a directory it was not shown" {
    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    const asked = try answerFrom(
        "/api/answer?session=" ++ id ++ "&request=1&decision=yes&project=/etc",
        "/home/ross/chock",
    );
    try testing.expectEqualStrings("/home/ross/chock", asked.answer.project);
}

test "every route is one the dispatch has a case for, and a query does not make a new one" {
    try testing.expectEqual(Route.page, routeOf("/").?);
    try testing.expectEqual(Route.page, routeOf("/account").?);
    try testing.expectEqual(Route.local_password, routeOf("/api/auth/password").?);
    // The page's own route, so a reload or a link lands back in the session.
    try testing.expectEqual(Route.page, routeOf("/s/01M2GPTA3SSYQ9X0KGRRNVY0MT").?);
    try testing.expectEqual(Route.page, routeOf("/s/01M2GPTA3SSYQ9X0KGRRNVY0MT?x=1").?);
    try testing.expectEqual(Route.sessions, routeOf("/api/sessions").?);
    try testing.expectEqual(Route.projects, routeOf("/api/projects").?);
    try testing.expectEqual(Route.people, routeOf("/api/people").?);
    try testing.expectEqual(Route.session_members, routeOf("/api/session-members?session=01JQ").?);
    try testing.expectEqual(Route.session_presence, routeOf("/api/session-presence?session=01JQ").?);
    try testing.expectEqual(Route.session_host, routeOf("/api/session-host").?);
    try testing.expectEqual(Route.worker_token, routeOf("/api/worker/token").?);
    try testing.expectEqual(Route.worker_revoke, routeOf("/api/worker/revoke").?);
    try testing.expectEqual(Route.worker_commands, routeOf("/api/worker/commands?session=01JQ").?);
    try testing.expectEqual(Route.create, routeOf("/api/create").?);
    try testing.expectEqual(Route.events, routeOf("/api/events").?);
    try testing.expectEqual(Route.answer, routeOf("/api/answer").?);
    try testing.expectEqual(Route.agent_answer, routeOf("/api/agent-answer?session=01JQ&request=128").?);
    try testing.expectEqual(Route.cancel, routeOf("/api/cancel?session=01JQ").?);
    try testing.expectEqual(Route.fork, routeOf("/api/fork?session=01JQ").?);
    try testing.expectEqual(Route.prompt, routeOf("/api/prompt?session=01JQ").?);

    try testing.expectEqual(Route.events, routeOf("/api/events?session=01&after=0").?);
    try testing.expectEqual(Route.sessions, routeOf("/api/sessions?").?);

    // A file of the page answers by its own name, because the name is matched
    // against the bundle.
    try testing.expectEqual(Route.asset, routeOf("/index.html").?);
    try testing.expectEqual(Route.asset, routeOf("/boot.js").?);
    try testing.expectEqual(Route.asset, routeOf("/chock-web.wasm").?);

    for ([_][]const u8{
        "/api",
        "/api/",
        "/api/sessions/1",
        // Nothing after `/s/`, and a name of a shape no session has.
        "/s/",
        "/s/not a session",
        "/s/../etc/passwd",
        // A name no member has, which is every path outside the page. Nothing
        // here reads a directory, so a traversal names nothing rather than
        // being cleaned up and then read.
        "/../etc/passwd",
        "/etc/passwd",
        "/fonts/",
        "",
    }) |target| try testing.expect(routeOf(target) == null);

    try testing.expectEqual(Route.lines, routeOf("/api/lines?session=01JQ&after=0").?);
    try testing.expectEqual(Route.export_session, routeOf("/api/export/session?session=01JQ").?);
    try testing.expectEqual(Route.export_account, routeOf("/api/export/account").?);
    try testing.expectEqual(Route.export_instance, routeOf("/api/export/instance").?);

    var reached = std.EnumSet(Route).empty;
    for ([_][]const u8{
        "/setup",
        "/api/auth/status",
        "/api/setup/local",
        "/api/setup/oidc",
        "/api/auth/local",
        "/api/auth/password",
        "/auth/login",
        "/auth/callback?code=x&state=y",
        "/auth/logout",
        "/",
        "/api/sessions",
        "/api/projects",
        "/api/teams",
        "/api/people",
        "/api/team-members?team=01JQ0000-0000-0000-0000-000000000000",
        "/api/team-invites?team=01JQ0000-0000-0000-0000-000000000000",
        "/api/acl-rules?resource_kind=project&resource_id=00000000-0000-4000-8000-000000000001",
        "/api/providers",
        "/api/session/register",
        "/api/session-members?session=01JQ",
        "/api/session-presence?session=01JQ",
        "/api/session-host",
        "/api/worker/token",
        "/api/worker/revoke",
        "/api/worker/events",
        "/api/worker/commands",
        "/api/create",
        "/api/events",
        "/api/lines",
        "/api/export/session?session=01JQ",
        "/api/export/account",
        "/api/export/instance",
        "/api/answer",
        "/api/agent-answer?session=01JQ&request=128",
        "/api/cancel?session=01JQ",
        "/api/fork",
        "/api/workspace/review",
        "/api/workspace/select",
        "/api/workspace/undo",
        "/api/prompt",
        "/boot.js",
    }) |target| {
        reached.insert(routeOf(target).?);
    }
    try testing.expectEqual(std.enums.values(Route).len, reached.count());
    try testing.expect(!requiresLogin(.setup_page));
    try testing.expect(!requiresLogin(.auth_status));
    try testing.expect(!requiresLogin(.local_setup));
    try testing.expect(!requiresLogin(.oidc_setup));
    try testing.expect(!requiresLogin(.local_login));
    try testing.expect(requiresLogin(.local_password));
    try testing.expect(requiresLogin(.projects));
    try testing.expect(requiresLogin(.teams));
    try testing.expect(requiresLogin(.people));
    try testing.expect(requiresLogin(.team_members));
    try testing.expect(requiresLogin(.team_invites));
    try testing.expect(requiresLogin(.acl_rules));
    try testing.expect(requiresLogin(.providers));
    try testing.expect(requiresLogin(.session_register));
    try testing.expect(requiresLogin(.session_members));
    try testing.expect(requiresLogin(.session_presence));
    try testing.expect(requiresLogin(.worker_commands));
    try testing.expect(requiresLogin(.worker_token));
    try testing.expect(requiresLogin(.session_host));
    try testing.expect(requiresBrowserSession(.session_host, false));
    try testing.expect(!requiresBrowserSession(.session_host, true));
    try testing.expect(!requiresBrowserSession(.worker_events, true));
    try testing.expect(!requiresBrowserSession(.worker_commands, true));
    try testing.expect(cookieMutationNeedsOrigin(.session_members, true));
    try testing.expect(cookieMutationNeedsOrigin(.session_presence, true));
    try testing.expect(cookieMutationNeedsOrigin(.providers, true));
    try testing.expect(cookieMutationNeedsOrigin(.session_host, false));
    try testing.expect(!cookieMutationNeedsOrigin(.session_host, true));
    try testing.expect(!cookieMutationNeedsOrigin(.worker_events, false));
    try testing.expect(!cookieMutationNeedsOrigin(.worker_commands, false));
    try testing.expect(!cookieMutationNeedsOrigin(.worker_revoke, false));
    try testing.expect(requiresLogin(.page));
    try testing.expect(requiresLogin(.cancel));
    try testing.expect(!requiresLogin(.auth_login));
    try testing.expect(!requiresLogin(.asset));
}

test "an unreadable or unrecognised daemon status leaves authentication on" {
    try std.testing.expect(!authModeOf("single-user").?.service);
    for ([_][]const u8{ "oidc", "local", "setup-required", "configured" }) |word| {
        try std.testing.expect(authModeOf(word).?.service);
    }
    try std.testing.expect(authModeOf("") == null);
    try std.testing.expect(authModeOf("Single-User") == null);
    try std.testing.expect(authModeOf("something-new") == null);
}

test "a gateway that serves open asks the daemon again, one caller per interval" {
    var serve: Serve = .{
        .gpa = undefined,
        .io = undefined,
        .daemon = undefined,
        .project = "",
        .owner_uid = 0,
    };
    try testing.expect(authRecheckDue(&serve, 10_000));
    try testing.expect(!authRecheckDue(&serve, 10_001));
    try testing.expect(!authRecheckDue(&serve, 10_000 + auth_recheck_ms - 1));
    try testing.expect(authRecheckDue(&serve, 10_000 + auth_recheck_ms));
    try testing.expect(authRecheckDue(&serve, 5_000));
    serve.service_auth.store(true, .release);
    try testing.expect(!authRecheckDue(&serve, 100_000));
}

test "an open event stream asks again on a bound and keeps only an allow" {
    try testing.expect(!streamRecheckDue(10_000, 10_000));
    try testing.expect(!streamRecheckDue(10_000, 10_000 + stream_recheck_ms - 1));
    try testing.expect(streamRecheckDue(10_000, 10_000 + stream_recheck_ms));
    try testing.expect(streamRecheckDue(10_000, 5_000));
    try testing.expect(streamKeeps(.allow));
    try testing.expect(!streamKeeps(.deny));
    try testing.expect(!streamKeeps(.unauthenticated));
    try testing.expect(!streamKeeps(.unavailable));
}

test "local service authentication activates the same gateway authorization boundary as OIDC" {
    var serve: Serve = .{
        .gpa = undefined,
        .io = undefined,
        .daemon = undefined,
        .project = "",
        .owner_uid = 0,
    };
    try testing.expect(!authEnabled(&serve));
    serve.service_auth.store(true, .release);
    try testing.expect(authEnabled(&serve));
    try testing.expect(requiresBrowserSession(.projects, false));
}

test "browser routes ask the daemon for resource-specific capabilities" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var serve: Serve = .{
        .gpa = testing.allocator,
        .io = testing.io,
        .daemon = .{ .unix = "/unused" },
        .project = "/work/project",
        .owner_uid = 0,
    };
    const view = accessForRoute(&serve, arena, .review, "/api/workspace/review?session=01JQ&project=%2Fwork%2Fproject").?;
    try testing.expectEqualStrings("session", view.resource_kind);
    try testing.expectEqualStrings("01JQ", view.resource_id);
    try testing.expectEqual(daemon_state.Capability.session_view, view.capability);

    const presence = accessForRoute(&serve, arena, .session_presence, "/api/session-presence?session=01JQ").?;
    try testing.expectEqualStrings("session", presence.resource_kind);
    try testing.expectEqualStrings("01JQ", presence.resource_id);
    try testing.expectEqual(daemon_state.Capability.session_view, presence.capability);

    const approval = accessForRoute(&serve, arena, .answer, "/api/answer?session=01JQ").?;
    try testing.expectEqualStrings("session", approval.resource_kind);
    try testing.expectEqualStrings("01JQ", approval.resource_id);
    try testing.expectEqual(daemon_state.Capability.session_approve, approval.capability);
    const agent_answer = accessForRoute(&serve, arena, .agent_answer, "/api/agent-answer?session=01JQ&request=128").?;
    try testing.expectEqualStrings("session", agent_answer.resource_kind);
    try testing.expectEqualStrings("01JQ", agent_answer.resource_id);
    try testing.expectEqual(daemon_state.Capability.session_prompt, agent_answer.capability);
    const cancel = accessForRoute(&serve, arena, .cancel, "/api/cancel?session=01JQ").?;
    try testing.expectEqual(daemon_state.Capability.session_prompt, cancel.capability);
    const export_access = accessForRoute(&serve, arena, .export_session, "/api/export/session?session=01JQ").?;
    try testing.expectEqualStrings("session", export_access.resource_kind);
    try testing.expectEqualStrings("01JQ", export_access.resource_id);
    try testing.expectEqual(daemon_state.Capability.session_view, export_access.capability);
    const project = accessForRoute(&serve, arena, .create, "/api/create").?;
    try testing.expectEqualStrings("/work/project", project.resource_id);
    try testing.expectEqual(daemon_state.Capability.project_manage, project.capability);
    const selected_project = accessForRoute(&serve, arena, .create, "/api/create?project=%2Fmanaged%2Fproject&placement=client").?;
    try testing.expectEqualStrings("/managed/project", selected_project.resource_id);
    try testing.expectEqual(daemon_state.Capability.project_manage, selected_project.capability);
    try testing.expect(accessForRoute(&serve, arena, .projects, "/api/projects") == null);
    const sessions = accessForRoute(&serve, arena, .sessions, "/api/sessions?project=/other").?;
    try testing.expectEqualStrings("/work/project", sessions.resource_id);

    // The shell is the same page whatever the person can reach, so a login is the
    // whole of its gate. A session page still names the session it opens.
    try testing.expect(accessForRoute(&serve, arena, .page, "/") == null);
    try testing.expect(accessForRoute(&serve, arena, .page, "/account") == null);
    const session_page = accessForRoute(&serve, arena, .page, "/s/01JQ").?;
    try testing.expectEqualStrings("session", session_page.resource_kind);
    try testing.expectEqualStrings("01JQ", session_page.resource_id);
    try testing.expectEqual(daemon_state.Capability.session_view, session_page.capability);
}

test "ACL resource IDs follow the resource's identifier format" {
    try testing.expect(validAclResourceId("session", "01JQ0000000000000000000000"));
    try testing.expect(!validAclResourceId("session", "not-a-session"));
    try testing.expect(validAclResourceId("project", "00000000-0000-4000-8000-000000000001"));
    try testing.expect(!validAclResourceId("project", "01JQ0000000000000000000000"));
}

test "browser mutation origins match the configured public origin and reject lookalikes" {
    const arena = testing.allocator;
    try testing.expect(originMatchesExternal("https://chock.example/service/", "https://chock.example", arena));
    try testing.expect(originMatchesExternal("https://CHOCK.example", "https://chock.example:443", arena));
    try testing.expect(originMatchesExternal("http://localhost:7374", "http://localhost:7374", arena));
    try testing.expect(!originMatchesExternal("https://chock.example", "https://chock.example.evil.test", arena));
    try testing.expect(!originMatchesExternal("https://chock.example", "http://chock.example", arena));
    try testing.expect(!originMatchesExternal("https://chock.example:8443", "https://chock.example", arena));
    try testing.expect(!originMatchesExternal("https://chock.example", "https://chock.example/admin", arena));
    try testing.expect(!originMatchesExternal("https://chock.example", "https://user@chock.example", arena));
    try testing.expect(!originMatchesExternal("https://chock.example", "null", arena));
}

test "session transcript exports are versioned JSON and stay inside complete-file limits" {
    const json = try sessionExportJson(testing.allocator, "01JQ\"quoted", "{\"id\":1}");
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"format\":\"chock-session-export-v1\",\"session\":\"01JQ\\\"quoted\",\"events\":[{\"id\":1}]}",
        json,
    );
    try testing.expect(sessionExportWithinLimits(max_session_export_bytes, max_session_export_events - 1));
    try testing.expect(!sessionExportWithinLimits(max_session_export_bytes + 1, 1));
    try testing.expect(!sessionExportWithinLimits(0, max_session_export_events));
}

test "account export is versioned and has aggregate byte and event limits" {
    const json = try accountExportJson(testing.allocator, 42, "{\"id\":\"project\"}", "{\"events\":[]}");
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"format\":\"chock-account-export-v1\",\"exported_ms\":42,\"projects\":[{\"id\":\"project\"}],\"sessions\":[{\"events\":[]}]}",
        json,
    );
    try testing.expect(accountExportWithinLimits(max_account_export_bytes, max_account_export_events - 1));
    try testing.expect(!accountExportWithinLimits(max_account_export_bytes + 1, 1));
    try testing.expect(!accountExportWithinLimits(1, max_account_export_events));
}

test "instance export omits project source locators" {
    const json = try instanceExportProjectJson(testing.allocator, .{
        .id = "123e4567-e89b-42d3-a456-426614174000",
        .name = "private project",
        .root = "/srv/chock/private project",
        .source_kind = "git",
        .source_locator = "https://user:secret@git.example/private.git",
        .status = "ready",
    });
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"id\":\"123e4567-e89b-42d3-a456-426614174000\",\"name\":\"private project\",\"source_kind\":\"git\",\"status\":\"ready\"}",
        json,
    );
    try testing.expect(std.mem.indexOf(u8, json, "secret") == null);
    try testing.expect(std.mem.indexOf(u8, json, "/srv/chock") == null);
}

test "instance export is versioned and carries explicit sections without secret handles" {
    const json = try instanceExportJson(
        testing.allocator,
        42,
        "[{\"identity_id\":\"person-id\"}]",
        "{\"id\":\"project-id\"}",
        "[{\"id\":\"provider-id\",\"has_credential\":true}]",
        "{\"teams\":[],\"team_members\":[],\"invitations\":[],\"session_members\":[],\"acl_rules\":[]}",
        "{\"metadata\":{\"id\":\"session-id\"},\"events\":[]}",
    );
    defer testing.allocator.free(json);
    try testing.expectEqualStrings(
        "{\"format\":\"chock-instance-export-v1\",\"exported_ms\":42,\"people\":[{\"identity_id\":\"person-id\"}],\"projects\":[{\"id\":\"project-id\"}],\"providers\":[{\"id\":\"provider-id\",\"has_credential\":true}],\"access\":{\"teams\":[],\"team_members\":[],\"invitations\":[],\"session_members\":[],\"acl_rules\":[]},\"sessions\":[{\"metadata\":{\"id\":\"session-id\"},\"events\":[]}]}",
        json,
    );
    try testing.expect(std.mem.indexOf(u8, json, "credential_ref") == null);
}

test "browser session cookies cannot inject daemon protocol fields" {
    try testing.expect(validCookieToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    try testing.expect(!validCookieToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\tprojects"));
    try testing.expect(!validCookieToken("short"));
}

test "a query value is read by name and an empty one is no value at all" {
    const target = "/api/events?session=01JQ&after=4096&empty=";
    try testing.expectEqualStrings("01JQ", queryValue(target, "session").?);
    try testing.expectEqualStrings("4096", queryValue(target, "after").?);
    try testing.expect(queryValue(target, "empty") == null);
    try testing.expect(queryValue(target, "missing") == null);
    try testing.expect(queryValue(target, "aft") == null);
    try testing.expect(queryValue(target, "sess") == null);
    try testing.expect(queryValue("/api/sessions", "session") == null);
}

test "a project query decodes the path the browser escaped" {
    var room = std.heap.ArenaAllocator.init(testing.allocator);
    defer room.deinit();
    var serve = Serve{
        .gpa = testing.allocator,
        .io = testing.io,
        .daemon = .{ .unix = "/nowhere" },
        .project = "/fallback",
        .owner_uid = 0,
    };

    try testing.expectEqualStrings(
        "/work/a & b/%23#one?two",
        projectOf(
            &serve,
            room.allocator(),
            "/api/fork?session=01JQ&project=%2Fwork%2Fa%20%26%20b%2F%2523%23one%3Ftwo",
        ),
    );
    try testing.expectEqualStrings(
        "/fallback",
        projectOf(&serve, room.allocator(), "/api/fork?session=01JQ"),
    );
}

test "an event frame carries the log's own identifier and the log's own bytes" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const line = "{\"id\":4096,\"session\":\"01JQ\",\"time_ms\":1,\"event\":{\"message\":{}}}";
    try writeFrame(&writer, .{ .id = 4096, .payload = line });

    try testing.expectEqualStrings("id: 4096\ndata: " ++ line ++ "\n\n", writer.buffered());
    try testing.expect(std.mem.endsWith(u8, writer.buffered(), "\n\n"));
}

test "a polled event carries the daemon record identifier" {
    var room = std.heap.ArenaAllocator.init(testing.allocator);
    defer room.deinit();

    const payload =
        \\{"id":0,"session":"01JQ","time_ms":1,"event":{"session.end":{"reason":"finished","detail":""}}}
    ;
    const with_id = try eventPayloadWithId(room.allocator(), payload, 4096);
    const parsed = try event.fromJson(room.allocator(), with_id);
    try testing.expectEqual(@as(u64, 4096), parsed.value.id);
    try testing.expect(parsed.value.event == .session_end);
}

test "a daemon that is not running is a plain refusal that names what to do" {
    const gpa = testing.allocator;

    const said = try unreachableText(
        gpa,
        .{ .unix = "/run/user/1000/chock/daemon.sock" },
        error.NotListening,
    );
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "chock daemon") != null);
    try testing.expect(std.mem.indexOf(u8, said, "daemon.sock") != null);

    const remote = try unreachableText(
        gpa,
        .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } },
        error.NotListening,
    );
    defer gpa.free(remote);
    try testing.expect(std.mem.indexOf(u8, remote, "10.0.0.4:7373") != null);
    try testing.expect(std.mem.indexOf(u8, remote, "--host") != null);
}

test "a daemon of another control protocol number reaches the browser as words" {
    const gpa = testing.allocator;

    const mismatch = try handshakeText(gpa, .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } }, .{
        .mismatch = .{ .ours = 1, .theirs = 4 },
    });
    defer gpa.free(mismatch);
    try testing.expect(std.mem.indexOf(u8, mismatch, "10.0.0.4:7373") != null);
    try testing.expect(std.mem.indexOf(u8, mismatch, " 4 ") != null);
    try testing.expect(std.mem.indexOf(u8, mismatch, " 1") != null);

    const refused = try handshakeText(
        gpa,
        .{ .unix = "/run/user/1000/chock/daemon.sock" },
        .{ .refused = control.no_verb_text },
    );
    defer gpa.free(refused);
    try testing.expect(std.mem.indexOf(u8, refused, control.no_verb_text) != null);
    try testing.expect(std.mem.indexOf(u8, refused, "daemon.sock") != null);
}

test "the options parse, and a value that is not one is refused by name" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const plain = try parseOptions(&.{});
    try testing.expect(plain.daemon == null);
    try testing.expect(plain.project == null);
    try testing.expect(plain.socket == null);
    try testing.expect(plain.socket_group == null);
    try testing.expect(plain.host == null);
    try testing.expectEqual(default_port, plain.port);
    try testing.expect(default_port != control.default_port);

    const named = try parseOptions(&.{
        "--daemon",     "10.0.0.4:7373",
        "--project",    "/home/ross/chock",
        "--socket",     "/run/chock/other.sock",
        "--host",       "0.0.0.0",
        "--port",       "8080",
        "--allow-http",
    });
    try testing.expectEqualStrings("10.0.0.4:7373", named.daemon.?);
    try testing.expectEqualStrings("/home/ross/chock", named.project.?);
    try testing.expectEqualStrings("/run/chock/other.sock", named.socket.?);
    try testing.expect(named.socket_group == null);
    try testing.expectEqualStrings("0.0.0.0", named.host.?);
    try testing.expectEqual(@as(u16, 8080), named.port);
    try testing.expect(named.allow_http);
    try testing.expectEqualStrings("", said.err());

    const grouped = try parseOptions(&.{ "--socket", "/run/chock/serve.sock", "--socket-group", "chock-web" });
    try testing.expectEqualStrings("/run/chock/serve.sock", grouped.socket.?);
    try testing.expectEqualStrings("chock-web", grouped.socket_group.?);

    for ([_][]const u8{ "--daemon", "--project", "--socket", "--socket-group", "--host", "--port" }) |flag| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{flag}));
        try testing.expect(std.mem.indexOf(u8, said.err(), flag) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--host", "127.0.0.1", "--port", "seventy" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "seventy") != null);

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "8080" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--host") != null);

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{
        "--host",
        "127.0.0.1",
        "--socket-group",
        "chock-web",
    }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--socket-group") != null);

    try testing.expectEqual(
        @as(u16, 0),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "0" })).port,
    );

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--nonsense") != null);
    try testing.expectEqualStrings("", said.out());
}

test "a numeric socket group is read exactly" {
    try testing.expectEqual(@as(std.c.gid_t, 123), groupId(testing.allocator, testing.io, "123").?);
    try testing.expect(groupId(testing.allocator, testing.io, "") == null);
    try testing.expect(groupId(
        testing.allocator,
        testing.io,
        "a-group-that-does-not-exist-in-this-test",
    ) == null);
}

test "a request whose body cannot be discarded gets an answer and not a panic" {
    try testing.expect(!mayKeepAlive(.POST, .none, null));
    try testing.expect(!mayKeepAlive(.PUT, .none, null));

    try testing.expect(mayKeepAlive(.POST, .none, 0));
    try testing.expect(mayKeepAlive(.POST, .none, 12));
    try testing.expect(mayKeepAlive(.POST, .chunked, null));

    try testing.expect(mayKeepAlive(.GET, .none, null));
    try testing.expect(mayKeepAlive(.HEAD, .none, null));
}

/// A member, expanded. Only a test does this: the server never decompresses.
fn expandedForTest(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    const one = memberNamed(name) orelse return error.MemberMissing;
    var reading: std.Io.Reader = .fixed(one.bytes);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var expand: std.compress.flate.Decompress = .init(&reading, .gzip, &window);
    return expand.reader.allocRemaining(gpa, .limited(32 * 1024 * 1024));
}

test "the page fetches nothing from anywhere else" {
    const gpa = testing.allocator;
    // The page and the script it loads. A dependency on a CDN would be a tool
    // call reaching the network through the interface rather than through the
    // broker, so it is refused here rather than reviewed by eye.
    for ([_][]const u8{ "index.html", "boot.js" }) |name| {
        const said = try expandedForTest(gpa, name);
        defer gpa.free(said);
        for ([_][]const u8{ "http://", "https://", "//cdn" }) |outside| {
            try testing.expect(std.mem.indexOf(u8, said, outside) == null);
        }
    }

    const page = try expandedForTest(gpa, "index.html");
    defer gpa.free(page);
    try testing.expect(std.mem.indexOf(u8, page, "<!doctype html>") != null or
        std.mem.indexOf(u8, page, "<!DOCTYPE html>") != null);
}

test "every file of the browser interface is in the bundle, still compressed" {
    // The page a browser loads first, and the two the page then asks for by
    // name. A rename on phantom's side fails here rather than at run time.
    for ([_][]const u8{ "index.html", "boot.js", "chock-web.wasm" }) |wanted| {
        const one = memberNamed(wanted) orelse return error.MemberMissing;
        try testing.expect(one.bytes.len != 0);
        // A gzip stream, so it goes to the browser untouched.
        try testing.expectEqual(@as(u8, 0x1f), one.bytes[0]);
        try testing.expectEqual(@as(u8, 0x8b), one.bytes[1]);
    }
    try testing.expectEqual(@as(?Member, null), memberNamed("nothing.here"));
}

test "login handoff accepts only a complete UUID and opaque bearer response" {
    const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const id = "123e4567-e89b-42d3-a456-426614174000";
    const result = try parseLoginResult(id ++ "\tmember\t" ++ token ++ "\t1800000000000");
    try testing.expectEqualStrings(id, &result.identity_id);
    try testing.expectEqualStrings(token, &result.token);
    try testing.expectEqual(@as(i64, 1_800_000_000_000), result.expires_ms);
    try testing.expectError(error.MalformedLoginResult, parseLoginResult("not-a-uuid\tmember\t" ++ token ++ "\t1"));
}

test "serve sends only callback target and cookie state to daemon using protocol v1" {
    const io = testing.io;
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    const Fixture = struct {
        io: std.Io,
        server: *std.Io.net.Server,
        accepted: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            var stream = self.server.accept(self.io) catch return;
            defer stream.close(self.io);
            var read_buffer: [8 * 1024]u8 = undefined;
            var reader = stream.reader(self.io, &read_buffer);
            var write_buffer: [4 * 1024]u8 = undefined;
            var writer = stream.writer(self.io, &write_buffer);
            const greeting_line = (reader.interface.takeDelimiter('\n') catch null) orelse return;
            const greeting = control.Greeting.parse(.ask, std.mem.trimEnd(u8, greeting_line, "\r")) catch return;
            if (greeting.version != 1) return;
            (control.Greeting{}).write(.answer, &writer.interface) catch return;
            writer.interface.flush() catch return;
            const request_line = (reader.interface.takeDelimiter('\n') catch null) orelse return;
            const request = control.Request.parse(std.mem.trimEnd(u8, request_line, "\r")) catch return;
            if (request != .auth_oidc_exchange) return;
            const exchange = request.auth_oidc_exchange.exchange;
            const decoder = std.base64.url_safe_no_pad.Decoder;
            const decoded_len = decoder.calcSizeForSlice(exchange) catch return;
            const decoded = testing.allocator.alloc(u8, decoded_len) catch return;
            defer testing.allocator.free(decoded);
            decoder.decode(decoded, exchange) catch return;
            if (std.mem.indexOf(u8, decoded, "\"target\":\"/auth/callback?code=one-time-code&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"") == null or
                std.mem.indexOf(u8, decoded, "\"cookie_state\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"") == null or
                std.mem.indexOf(u8, decoded, "verifier") != null or
                std.mem.indexOf(u8, decoded, "nonce") != null or
                std.mem.indexOf(u8, decoded, "client_secret") != null) return;
            self.accepted.store(true, .release);
            writer.interface.writeAll("ok 123e4567-e89b-42d3-a456-426614174000\tmember\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\t1800000000000\n") catch return;
            writer.interface.flush() catch return;
        }
    };
    var fixture = Fixture{ .io = io, .server = &server };
    const thread = try std.Thread.spawn(.{}, Fixture.run, .{&fixture});

    var serve: Serve = .{
        .gpa = testing.allocator,
        .io = io,
        .daemon = .{ .ip = .{ .host = "127.0.0.1", .port = server.socket.address.getPort() } },
        .project = "/project",
        .owner_uid = std.posix.system.getuid(),
    };
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const result = try daemonOidcExchange(
        &serve,
        arena.allocator(),
        "/auth/callback?code=one-time-code&state=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    thread.join();
    try testing.expect(fixture.accepted.load(.acquire));
    try testing.expectEqualStrings("123e4567-e89b-42d3-a456-426614174000", &result.identity_id);
    try testing.expectEqual(@as(i64, 1_800_000_000_000), result.expires_ms);
}
