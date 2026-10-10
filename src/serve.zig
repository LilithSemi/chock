//! `chock serve`: a browser in front of a daemon.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_proto = @import("chock-proto");

const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const control = chock_proto.control;

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
    \\names an address. The socket serves the user that started this command, and
    \\every other peer is refused by the credential the kernel puts on the
    \\connection. A reverse proxy such as nginx, Caddy or Authelia proxies to that
    \\socket, which is the supported way to put authentication in front of this.
    \\
    \\Options:
    \\  --daemon <address>  Where the daemon is. `unix:/path` or `host:port`.
    \\                      Default is the socket in the state directory, or
    \\                      $CHOCK_DAEMON when that is set.
    \\  --project <dir>     The project to show. Default is the working directory.
    \\  --socket <path>     The unix socket. Default is serve.sock in the state
    \\                      directory.
    \\  --host <addr>       Bind this address, over TCP, instead of the socket.
    \\                      Off by default. Write `--host 127.0.0.1` to point a
    \\                      browser straight at this.
    \\  --port <n>          The TCP port, with --host. 0 asks the system for one
    \\                      and prints it. Default 7374.
    \\
    \\Chock does no authentication over a network, and a TCP connection carries
    \\no credential to check. Anything that can route to a --host address can
    \\approve an action, so put a reverse proxy such as Authelia in front of it.
    \\
++ tty.options_text;

const Options = struct {
    daemon: ?[]const u8 = null,
    project: ?[]const u8 = null,
    socket: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: u16 = default_port,
};

const Serve = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    daemon: control.Address,
    project: []const u8,
    owner_uid: std.posix.uid_t,
    live: std.atomic.Value(usize) = .init(0),
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    _ = exe_path;

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => return Exit.usage.code(),
    };

    var env = try environ.createMap(arena);

    var threaded = std.Io.Threaded.init(gpa, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    const daemon_text = options.daemon orelse env.get(control.address_env) orelse text: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| {
            tty.print(.err, "chock serve: the state directory could not be found: {t}\n", .{err});
            return Exit.usage.code();
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
    };

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

    const socket_path = options.socket orelse path: {
        const state = chock_auth.paths.stateDir(arena, &env) catch |err| {
            tty.print(.err, "chock serve: the state directory could not be found: {t}\n", .{err});
            return Exit.usage.code();
        };
        makeDirAll(io, state) catch |err| {
            tty.print(.err, "chock serve: {s} could not be made: {t}\n", .{ state, err });
            return Exit.usage.code();
        };
        break :path std.fs.path.join(arena, &.{ state, socket_name }) catch
            return Exit.faulted.code();
    };

    const bind = bindAddress(socket_path, options);
    var listener = bind.listen(io) catch |err| {
        tty.print(.err, "chock serve: {f} could not be listened on: {t}\n", .{ bind, err });
        if (err == error.PathTooLong) tty.print(
            .err,
            "chock serve: a unix socket path is at most {d} bytes on this platform. " ++
                "Name a shorter one with --socket.\n",
            .{control.max_socket_path},
        );
        return Exit.usage.code();
    };
    defer listener.close(io);

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

        if (listener.unix_path != null and
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
    page,
    sessions,
    projects,
    prompt,
    events,
    /// The same events as `events`, read once and answered whole. A browser
    /// reads this: a page built on phantom's web backend gets one response per
    /// request and cannot hold a stream open.
    lines,
    answer,
    asset,
};

pub fn routeOf(target: []const u8) ?Route {
    const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
    if (std.mem.eql(u8, path, "/")) return .page;
    if (std.mem.eql(u8, path, "/api/sessions")) return .sessions;
    if (std.mem.eql(u8, path, "/api/projects")) return .projects;
    if (std.mem.eql(u8, path, "/api/events")) return .events;
    if (std.mem.eql(u8, path, "/api/lines")) return .lines;
    if (std.mem.eql(u8, path, "/api/answer")) return .answer;
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

    // A route that changes what a session does is a POST, so nothing that
    // prefetches a link can drive it.
    const wanted: std.http.Method = switch (route) {
        .answer, .prompt => .POST,
        .page, .asset, .sessions, .projects, .events, .lines => .GET,
    };
    if (request.head.method != wanted and !(wanted == .GET and request.head.method == .HEAD)) {
        try sendWhole(request, "that route does not take that method\n", .{ .status = .method_not_allowed });
        return;
    }

    switch (route) {
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
        .projects => try serveProjects(serve, arena, request),
        .events => try serveEvents(serve, arena, request),
        .lines => try serveLines(serve, arena, request),
        .answer => try serveAnswer(serve, arena, request),
        .prompt => try servePrompt(serve, arena, request),
    }
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
    return arena.dupe(u8, said) catch serve.project;
}

fn serveSessions(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    // `all=1` asks past the project this was started for. A browser is not
    // inside one project, and the rows then say which one each belongs to.
    const everything = queryValue(request.head.target, "all") != null;
    const project = if (everything) "" else serve.project;
    try sendRecords(serve, arena, request, .{ .list = .{ .project = project } });
}

fn serveProjects(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    try sendRecords(serve, arena, request, .{ .projects = {} });
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

    const json = try std.fmt.allocPrint(arena, "[{s}]", .{body.items});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

/// One session's events after a point, answered whole and then closed.
///
/// `serveEvents` holds a stream open, which a browser on phantom's web backend
/// cannot read: there, one request is one whole response. The daemon already
/// answers a bounded read, so this asks for that rather than asking the page to
/// do something it cannot.
fn serveLines(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "a session is required\n", .{ .status = .bad_request });
        return;
    };
    const after = parseAfter(queryValue(request.head.target, "after"));

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

    if (gather.failed) |text| {
        try respondDaemonRefusal(arena, request, text);
        return;
    }

    const json = try std.fmt.allocPrint(arena, "[{s}]", .{body.items});
    try sendWhole(request, json, .{ .extra_headers = &json_headers });
}

fn serveEvents(serve: *Serve, arena: std.mem.Allocator, request: *std.http.Server.Request) !void {
    const session = queryValue(request.head.target, "session") orelse {
        try sendWhole(request, "that needs a session\n", .{ .status = .bad_request });
        return;
    };
    const after = lastEventId(request) orelse parseAfter(queryValue(request.head.target, "after"));
    const project = projectOf(serve, arena, request.head.target);

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

        fn take(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |one| {
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
    var pump = Pump{ .out = &body };
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

    try askDaemon(serve, arena, request, asked, "{\"answered\":true}");
}

/// Put one request to the daemon and answer `good` when it says yes.
fn askDaemon(
    serve: *Serve,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    asked: control.Request,
    good: []const u8,
) !void {
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
        asked,
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
    try sendWhole(request, good, .{ .extra_headers = &json_headers });
}

/// The most one message may be. A prompt past this is not a person typing.
const max_message_bytes: usize = 128 * 1024;

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

    try askDaemon(serve, arena, request, .{ .prompt = .{
        .project = project,
        .session = asked,
        .message = message,
    } }, "{\"sent\":true}");
}

const json_headers = [_]std.http.Header{
    .{ .name = "content-type", .value = "application/json" },
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

        const takes_value = [_][]const u8{ "--daemon", "--project", "--socket", "--host", "--port" };
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
            if (std.mem.eql(u8, flag, "--host")) options.host = value;
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
    const id = "01JQ" ++ "A" ** 22;

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
    const id = "01JQ" ++ "A" ** 22;
    const asked = try answerFrom(
        "/api/answer?session=" ++ id ++ "&request=1&decision=yes&project=/etc",
        "/home/ross/chock",
    );
    try testing.expectEqualStrings("/home/ross/chock", asked.answer.project);
}

test "every route is one the dispatch has a case for, and a query does not make a new one" {
    try testing.expectEqual(Route.page, routeOf("/").?);
    // The page's own route, so a reload or a link lands back in the session.
    try testing.expectEqual(Route.page, routeOf("/s/01M2GPTA3SSYQ9X0KGRRNVY0MT").?);
    try testing.expectEqual(Route.page, routeOf("/s/01M2GPTA3SSYQ9X0KGRRNVY0MT?x=1").?);
    try testing.expectEqual(Route.sessions, routeOf("/api/sessions").?);
    try testing.expectEqual(Route.projects, routeOf("/api/projects").?);
    try testing.expectEqual(Route.events, routeOf("/api/events").?);
    try testing.expectEqual(Route.answer, routeOf("/api/answer").?);
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

    var reached = std.EnumSet(Route).initEmpty();
    for ([_][]const u8{
        "/",
        "/api/sessions",
        "/api/projects",
        "/api/events",
        "/api/lines",
        "/api/answer",
        "/api/prompt",
        "/boot.js",
    }) |target| {
        reached.insert(routeOf(target).?);
    }
    try testing.expectEqual(std.enums.values(Route).len, reached.count());
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

test "an event frame carries the log's own identifier and the log's own bytes" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    const line = "{\"id\":4096,\"session\":\"01JQ\",\"time_ms\":1,\"event\":{\"message\":{}}}";
    try writeFrame(&writer, .{ .id = 4096, .payload = line });

    try testing.expectEqualStrings("id: 4096\ndata: " ++ line ++ "\n\n", writer.buffered());
    try testing.expect(std.mem.endsWith(u8, writer.buffered(), "\n\n"));
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
    try testing.expect(plain.host == null);
    try testing.expectEqual(default_port, plain.port);
    try testing.expect(default_port != control.default_port);

    const named = try parseOptions(&.{
        "--daemon",  "10.0.0.4:7373",
        "--project", "/home/ross/chock",
        "--socket",  "/run/chock/other.sock",
        "--host",    "0.0.0.0",
        "--port",    "8080",
    });
    try testing.expectEqualStrings("10.0.0.4:7373", named.daemon.?);
    try testing.expectEqualStrings("/home/ross/chock", named.project.?);
    try testing.expectEqualStrings("/run/chock/other.sock", named.socket.?);
    try testing.expectEqualStrings("0.0.0.0", named.host.?);
    try testing.expectEqual(@as(u16, 8080), named.port);
    try testing.expectEqualStrings("", said.err());

    for ([_][]const u8{ "--daemon", "--project", "--socket", "--host", "--port" }) |flag| {
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

    try testing.expectEqual(
        @as(u16, 0),
        (try parseOptions(&.{ "--host", "127.0.0.1", "--port", "0" })).port,
    );

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--nonsense") != null);
    try testing.expectEqualStrings("", said.out());
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
