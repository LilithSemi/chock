//! The daemon's control protocol: a greeting, a request, then a reply of
//! lines until the connection closes. Additive verbs keep existing clients on
//! protocol version 1; changes that alter existing messages require a version
//! change.

const std = @import("std");
const builtin = @import("builtin");

const chain = @import("chain.zig");
const event = @import("event.zig");
const storage = @import("storage.zig");

pub const default_port: u16 = 7373;

pub const default_host = "127.0.0.1";

pub const socket_name = "daemon.sock";

pub const address_env = "CHOCK_DAEMON";

/// Never in a project, a path a tool call could name.
pub fn socketPathIn(gpa: std.mem.Allocator, state_dir: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fs.path.join(gpa, &.{ state_dir, socket_name });
}

pub const Address = union(enum) {
    unix: []const u8,
    ip: Ip,

    pub const Ip = struct {
        host: []const u8,
        port: u16,
    };

    pub const ParseError = error{
        EmptyPath,
        NoPort,
        EmptyHost,
    };

    pub fn parse(text: []const u8) ParseError!Address {
        if (std.mem.startsWith(u8, text, "unix:")) {
            const path = text["unix:".len..];
            if (path.len == 0) return error.EmptyPath;
            return .{ .unix = path };
        }

        // In a bracketed IPv6 host, the port colon follows the bracket, not the string's last colon.
        const separator = if (std.mem.startsWith(u8, text, "["))
            (std.mem.indexOfScalar(u8, text, ']') orelse return error.NoPort) + 1
        else
            std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.NoPort;
        if (separator >= text.len or text[separator] != ':') return error.NoPort;

        const host = text[0..separator];
        if (host.len == 0) return error.EmptyHost;
        const port = std.fmt.parseInt(u16, text[separator + 1 ..], 10) catch return error.NoPort;
        return .{ .ip = .{ .host = host, .port = port } };
    }

    pub const ConnectError = error{
        NotListening,
        BadAddress,
        PathTooLong,
        AccessDenied,
        Unreachable,
    };

    pub fn connect(self: Address, io: std.Io) ConnectError!std.Io.net.Stream {
        switch (self) {
            .unix => |path| {
                const address = try unixAddress(path);
                return address.connect(io) catch |err| return self.classify(err);
            },
            .ip => |ip| {
                const address = std.Io.net.IpAddress.parse(ip.host, ip.port) catch return error.BadAddress;
                return address.connect(io, .{ .mode = .stream }) catch |err| return self.classify(err);
            },
        }
    }

    /// A unix socket file left by a crash is removed, not refused.
    pub fn listen(self: Address, io: std.Io) ListenError!Listener {
        switch (self) {
            .unix => |path| {
                const address = try unixAddress(path);
                std.Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
                    error.FileNotFound => {},
                    else => return error.Unavailable,
                };
                const server = address.listen(io, .{}) catch |err| switch (err) {
                    error.AddressInUse => return error.AddressInUse,
                    error.AccessDenied, error.PermissionDenied => return error.AccessDenied,
                    else => return error.Unavailable,
                };
                return .{ .server = server, .unix_path = path };
            },
            .ip => |ip| {
                const address = std.Io.net.IpAddress.parse(ip.host, ip.port) catch return error.BadAddress;
                const server = address.listen(io, .{ .reuse_address = true }) catch |err| switch (err) {
                    error.AddressInUse => return error.AddressInUse,
                    else => return error.Unavailable,
                };
                return .{ .server = server, .unix_path = null };
            },
        }
    }

    pub const ListenError = error{
        AddressInUse,
        AccessDenied,
        BadAddress,
        PathTooLong,
        Unavailable,
    };

    pub fn format(self: Address, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .unix => |path| try writer.print("unix:{s}", .{path}),
            .ip => |ip| try writer.print("{s}:{d}", .{ ip.host, ip.port }),
        }
    }

    /// A stale socket gives `ECONNREFUSED`, which has no `ConnectError` member, so it arrives as `Unexpected`.
    pub fn classify(self: Address, err: anyerror) ConnectError {
        return switch (err) {
            error.FileNotFound, error.ConnectionRefused => error.NotListening,
            error.AccessDenied, error.PermissionDenied => error.AccessDenied,
            error.Unexpected => switch (self) {
                .unix => error.NotListening,
                .ip => error.Unreachable,
            },
            else => error.Unreachable,
        };
    }
};

pub const Listener = struct {
    server: std.Io.net.Server,
    unix_path: ?[]const u8,

    pub fn close(self: *Listener, io: std.Io) void {
        self.server.deinit(io);
        if (self.unix_path) |path| std.Io.Dir.deleteFileAbsolute(io, path) catch {};
        self.* = undefined;
    }
};

/// One byte below `sun_path`'s length, not `UnixAddress.max_len` (a flat, unchecked 108): `sun_path` is 104 on Darwin.
pub const max_socket_path: usize = sun_path_bytes - 1;

const sun_path_bytes: usize = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

pub fn unixAddress(path: []const u8) error{PathTooLong}!std.Io.net.UnixAddress {
    if (path.len > max_socket_path) return error.PathTooLong;
    return std.Io.net.UnixAddress.init(path) catch error.PathTooLong;
}

/// Null when the kernel won't say; a TCP peer has no identity.
pub fn peerUid(handle: std.posix.fd_t) ?std.posix.uid_t {
    switch (builtin.os.tag) {
        .linux => {
            const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };
            var credentials: Ucred = undefined;
            var length: std.posix.socklen_t = @sizeOf(Ucred);
            const rc = std.os.linux.getsockopt(
                handle,
                std.os.linux.SOL.SOCKET,
                std.os.linux.SO.PEERCRED,
                @ptrCast(&credentials),
                &length,
            );
            if (std.posix.errno(rc) != .SUCCESS) return null;
            if (length != @sizeOf(Ucred)) return null;
            // A TCP socket fills in pid 0 instead of refusing: no credential.
            if (credentials.pid == 0) return null;
            if (credentials.uid == std.math.maxInt(u32)) return null;
            return credentials.uid;
        },
        .macos => {
            // None of these three is in `std.c`, so all carry `<sys/ucred.h>` values.
            const Xucred = extern struct {
                version: u32,
                uid: u32,
                ngroups: i16,
                groups: [16]u32,
            };
            const sol_local: i32 = 0;
            const local_peercred: u32 = 1;
            const xucred_version: u32 = 0;
            var credentials: Xucred = undefined;
            var length: std.posix.socklen_t = @sizeOf(Xucred);
            // Darwin refuses this on a TCP socket. Read from the header, not tested.
            const rc = std.c.getsockopt(handle, sol_local, local_peercred, &credentials, &length);
            if (rc != 0) return null;
            if (credentials.version != xucred_version) return null;
            if (credentials.uid == std.math.maxInt(u32)) return null;
            return credentials.uid;
        },
        else => @compileError("chock-proto/control.zig: no peer credential call for this target"),
    }
}

/// The primary group of a local Unix peer, when the kernel exposes it.
/// Supplementary groups are deliberately not consulted.
pub fn peerGid(handle: std.posix.fd_t) ?std.posix.gid_t {
    switch (builtin.os.tag) {
        .linux => {
            const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };
            var credentials: Ucred = undefined;
            var length: std.posix.socklen_t = @sizeOf(Ucred);
            const rc = std.os.linux.getsockopt(
                handle,
                std.os.linux.SOL.SOCKET,
                std.os.linux.SO.PEERCRED,
                @ptrCast(&credentials),
                &length,
            );
            if (std.posix.errno(rc) != .SUCCESS or length != @sizeOf(Ucred)) return null;
            if (credentials.pid == 0 or credentials.gid == std.math.maxInt(u32)) return null;
            return credentials.gid;
        },
        else => return null,
    }
}

/// An unnamed peer is refused; absence is never permissive.
pub fn peerAllowed(uid: ?std.posix.uid_t, owner_uid: std.posix.uid_t) bool {
    const said = uid orelse return false;
    return said == owner_uid;
}

pub fn peerGroupAllowed(gid: ?std.posix.gid_t, allowed_gid: ?std.posix.gid_t) bool {
    const said = gid orelse return false;
    const allowed = allowed_gid orelse return false;
    return said == allowed;
}

test "local group authorization accepts only the configured primary group" {
    try std.testing.expect(peerGroupAllowed(42, 42));
    try std.testing.expect(!peerGroupAllowed(41, 42));
    try std.testing.expect(!peerGroupAllowed(null, 42));
    try std.testing.expect(!peerGroupAllowed(42, null));
}

pub fn refusalFor(writer: *std.Io.Writer, address: Address, err: Address.ConnectError) std.Io.Writer.Error!void {
    switch (err) {
        error.NotListening => switch (address) {
            .unix => try writer.print(
                "nothing is listening on {f}, so there is no daemon to talk to. " ++
                    "Start one with `chock daemon`, and then run this again.\n",
                .{address},
            ),
            .ip => try writer.print(
                "nothing is listening on {f}, so there is no daemon to talk to. " ++
                    "Start one there with `chock daemon --host <address>`, or name a " ++
                    "different one with --daemon.\n",
                .{address},
            ),
        },
        error.AccessDenied => try writer.print(
            "{f} refused this user. A daemon's socket belongs to the user that " ++
                "started it, and this is not that user.\n",
            .{address},
        ),
        // The number is read and never written out: 108 is false on Darwin.
        error.PathTooLong => try writer.print(
            "{f} is longer than a unix socket path may be on this platform, which is {d} " ++
                "bytes. Name a shorter one with --daemon.\n",
            .{ address, max_socket_path },
        ),
        error.BadAddress => try writer.print("{f} is not an address.\n", .{address}),
        error.Unreachable => try writer.print(
            "{f} could not be reached.\n",
            .{address},
        ),
    }
}

/// The wire's number, not the program's: moves only on a breaking change before a stable release.
pub const protocol_version: u32 = 1;

pub const protocol_name = "chock-control";

/// The client speaks first: closing with the request unread sends a reset, discarding what was written.
pub const Greeting = struct {
    version: u32 = protocol_version,

    pub const ask_prefix = "hello " ++ protocol_name ++ " ";

    pub const answer_prefix = ok_prefix ++ protocol_name ++ " ";

    pub const Side = enum {
        ask,
        answer,

        fn prefix(self: Side) []const u8 {
            return switch (self) {
                .ask => ask_prefix,
                .answer => answer_prefix,
            };
        }
    };

    pub const ParseError = error{
        NotAGreeting,
    };

    pub fn parse(side: Side, line: []const u8) ParseError!Greeting {
        const prefix = side.prefix();
        if (!std.mem.startsWith(u8, line, prefix)) return error.NotAGreeting;
        const number = std.mem.trim(u8, line[prefix.len..], " ");
        if (number.len == 0) return error.NotAGreeting;
        return .{
            .version = std.fmt.parseInt(u32, number, 10) catch return error.NotAGreeting,
        };
    }

    pub fn write(self: Greeting, side: Side, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}{d}\n", .{ side.prefix(), self.version });
    }
};

/// Equal, nothing else: a version window would promise untested compatibility.
pub fn accepts(ours: u32, theirs: u32) bool {
    return ours == theirs;
}

pub const Handshake = union(enum) {
    agreed: u32,
    mismatch: struct { ours: u32, theirs: u32 },
    refused: []const u8,
    unreadable: []const u8,

    pub fn ok(self: Handshake) bool {
        return self == .agreed;
    }
};

pub const HandshakeError = std.Io.Writer.Error || error{
    ReadFailed,
    StreamTooLong,
};

/// Checks `accepts`, never the reply's shape: a real `pcscd` answers a mismatch with a success code.
pub fn handshake(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    ours: u32,
) HandshakeError!Handshake {
    try (Greeting{ .version = ours }).write(.ask, writer);
    try writer.flush();

    const line = std.mem.trimEnd(u8, (try reader.takeDelimiter('\n')) orelse "", "\r");
    const said = Greeting.parse(.answer, line) catch {
        if (std.mem.startsWith(u8, line, error_prefix)) {
            return .{ .refused = line[error_prefix.len..] };
        }
        return .{ .unreadable = line };
    };
    if (!accepts(ours, said.version)) {
        return .{ .mismatch = .{ .ours = ours, .theirs = said.version } };
    }
    return .{ .agreed = said.version };
}

pub fn handshakeRefusal(
    writer: *std.Io.Writer,
    address: Address,
    said: Handshake,
) std.Io.Writer.Error!void {
    switch (said) {
        .agreed => |version| try writer.print(
            "{f} and this build both speak control protocol {d}.\n",
            .{ address, version },
        ),
        .mismatch => |both| try writer.print(
            "{f} speaks control protocol {d} and this build speaks {d}, so nothing was asked " ++
                "of it. The two have to be the same number. Update whichever end is older.\n",
            .{ address, both.theirs, both.ours },
        ),
        .refused => |text| try writer.print(
            "{f} refused the greeting of control protocol {d}. A daemon older than this " ++
                "greeting refuses here too, because `hello` is not a word it knows. It said: {s}\n",
            .{ address, protocol_version, text },
        ),
        .unreadable => |text| try writer.print(
            "{f} answered the greeting of control protocol {d} with a line this build cannot " ++
                "read: {s}\n",
            .{ address, protocol_version, text },
        ),
    }
}

pub const no_greeting_text = "this daemon reads a greeting first, and that line is not one. " ++
    "A client of it opens with `" ++ Greeting.ask_prefix ++ "<number>`, and a client built " ++
    "before that greeting existed cannot talk to this daemon. Update it.";

pub fn writeMismatch(writer: *std.Io.Writer, ours: u32, theirs: u32) std.Io.Writer.Error!void {
    try writer.print(
        error_prefix ++ "this daemon speaks control protocol {d} and that client speaks {d}, " ++
            "so nothing was done. The two have to be the same number. Update whichever end " ++
            "is older.\n",
        .{ ours, theirs },
    );
}

pub const Verb = enum {
    start,
    adopt,
    create,
    fork,
    review,
    select,
    undo_selection,
    prompt,
    cancel,
    read,
    list,
    projects,
    watch,
    answer,
    auth_status,
    auth_local_setup,
    auth_local_login,
    auth_oidc_setup,
    auth_oidc_begin,
    auth_oidc_exchange,
    auth_session,
    auth_logout,
    auth_authorize,
    auth_project_create,
    auth_project_list,
    auth_session_create,
    auth_session_register,
    auth_session_register_placed,
    auth_session_member,
    auth_session_people,
    auth_session_presence,
    auth_session_host,
    auth_worker_event,
    auth_worker_read,
    auth_worker_token,
    auth_people,
    auth_team,
    auth_acl,
    auth_provider,
    auth_prompt,
    auth_cancel,
    auth_answer,
    auth_agent_answer,
};

/// `read` is space separated, the rest tab separated; `src/detach.zig` already speaks them.
pub const Request = union(Verb) {
    start: Start,
    adopt: Adopt,
    create: Create,
    fork: Fork,
    review: Review,
    select: Select,
    undo_selection: UndoSelection,
    prompt: Prompt,
    cancel: Cancel,
    read: Read,
    list: List,
    /// Every project this daemon can see. Carries nothing: the answer is the
    /// whole set, and a caller that wanted one already knows its path.
    projects: void,
    watch: Watch,
    answer: Answer_,
    /// Authentication mode and first-run state, queried by the local gateway.
    auth_status: void,
    /// Initial local administrator credentials, JSON encoded then base64url encoded.
    auth_local_setup: AuthLocalCredentials,
    /// Local account credentials, JSON encoded then base64url encoded.
    auth_local_login: AuthLocalCredentials,
    /// First-run OIDC configuration, JSON encoded then base64url encoded.
    auth_oidc_setup: AuthOidcSetup,
    /// JSON encoded then base64url encoded; asks the daemon to create and
    /// retain the PKCE attempt before returning an authorization URL/state.
    auth_oidc_begin: AuthOidcBegin,
    /// A JSON payload encoded as base64url, containing the callback code and
    /// short-lived PKCE values. The daemon exchanges and verifies it.
    auth_oidc_exchange: AuthOidcExchange,
    auth_session: AuthSession,
    auth_logout: AuthLogout,
    /// Authorize one resource against a resolved daemon login session.
    auth_authorize: AuthAuthorize,
    auth_project_create: AuthProjectCreate,
    auth_project_list: AuthProjectList,
    auth_session_create: AuthSessionCreate,
    auth_session_register: AuthSessionRegister,
    auth_session_register_placed: AuthSessionRegisterPlaced,
    auth_session_member: AuthSessionMember,
    auth_session_people: AuthSessionPeople,
    auth_session_presence: AuthSessionPresence,
    auth_session_host: AuthSessionHost,
    auth_worker_event: AuthWorkerEvent,
    auth_worker_read: AuthWorkerRead,
    auth_worker_token: AuthWorkerToken,
    /// Request the administrator-only identity directory.
    auth_people: AuthPeople,
    auth_team: AuthTeam,
    auth_acl: AuthAcl,
    auth_provider: AuthProvider,
    auth_prompt: AuthPrompt,
    auth_cancel: AuthCancel,
    auth_answer: AuthAnswer,
    auth_agent_answer: AuthAgentAnswer,

    pub const Start = struct { project: []const u8, message: []const u8 };
    pub const Adopt = struct { project: []const u8, session: []const u8 };
    /// A session with a log and nothing running, named before there is anything to say.
    pub const Create = struct { project: []const u8 };
    /// Copy a completed prefix into a new session. Null means its latest turn.
    pub const Fork = struct { project: []const u8, session: []const u8, at: ?u64 };
    pub const Review = struct { project: []const u8, session: []const u8 };
    /// JSON keeps project-relative paths lossless while the outer protocol
    /// remains one line. JSON escapes tabs and newlines rather than turning
    /// them into field separators.
    pub const Select = struct { project: []const u8, session: []const u8, payload: []const u8 };
    pub const UndoSelection = struct { project: []const u8, session: []const u8 };
    /// Stops the running turn; a no-op if there is none.
    pub const Cancel = struct { project: []const u8, session: []const u8 };
    /// A message in a session that already exists; `start` both creates and speaks.
    pub const Prompt = struct {
        project: []const u8,
        session: []const u8,
        message: []const u8,
    };
    pub const Read = struct { session: []const u8, after: u64 };
    /// An empty `project` asks for every project this daemon can see.
    pub const List = struct { project: []const u8 };
    pub const Watch = struct { project: []const u8, session: []const u8, after: u64 };
    pub const Answer_ = struct {
        project: []const u8,
        session: []const u8,
        request_id: u64,
        decision: Answer,
    };
    pub const AuthOidcBegin = struct { input: []const u8 };
    pub const AuthOidcExchange = struct { exchange: []const u8 };
    pub const AuthOidcSetup = struct { configuration: []const u8 };
    pub const AuthLocalCredentials = struct { credentials: []const u8 };
    pub const AuthSession = struct { token: []const u8 };
    pub const AuthLogout = struct { token: []const u8 };
    pub const AuthAuthorize = struct {
        token: []const u8,
        resource_kind: []const u8,
        resource_id: []const u8,
        capability: []const u8,
    };
    pub const AuthProjectCreate = struct { token: []const u8, project_json: []const u8 };
    pub const AuthProjectList = struct { token: []const u8 };
    pub const AuthSessionCreate = struct { token: []const u8, project: []const u8, placement: []const u8 };
    pub const AuthSessionRegister = struct { token: []const u8, session: []const u8, project: []const u8 };
    pub const AuthSessionRegisterPlaced = struct { token: []const u8, session: []const u8, project: []const u8, placement: []const u8 };
    pub const AuthSessionMember = struct { token: []const u8, session: []const u8, identity: []const u8, role: []const u8 };
    pub const AuthSessionPeople = struct { token: []const u8, session: []const u8 };
    pub const AuthSessionPresence = struct { token: []const u8, action: []const u8, session: []const u8 };
    pub const AuthSessionHost = struct {
        token: []const u8,
        action: []const u8,
        session: []const u8,
        placement: []const u8,
        host_id: []const u8,
        generation: u64 = 0,
    };
    pub const AuthWorkerEvent = struct {
        token: []const u8,
        session: []const u8,
        host_id: []const u8,
        generation: u64,
        event_id: u64,
        event_json: []const u8,
    };
    pub const AuthWorkerRead = struct {
        token: []const u8,
        session: []const u8,
        host_id: []const u8,
        generation: u64,
        after: u64,
    };
    pub const AuthWorkerToken = struct { token: []const u8, session: []const u8 };
    pub const AuthPeople = struct { token: []const u8, action: []const u8 = "list", identity: []const u8 = "" };
    pub const AuthTeam = struct {
        token: []const u8,
        action: []const u8,
        team: []const u8 = "",
        identity: []const u8 = "",
        role: []const u8 = "",
        payload: []const u8 = "",
    };
    pub const AuthAcl = struct {
        token: []const u8,
        action: []const u8,
        resource_kind: []const u8 = "",
        resource_id: []const u8 = "",
        rule_id: []const u8 = "",
        payload: []const u8 = "",
    };
    pub const AuthProvider = struct {
        token: []const u8,
        action: []const u8,
        provider_id: []const u8 = "",
        payload: []const u8 = "",
    };
    /// Message is base64url-encoded so tabs/newlines remain data in v1 framing.
    pub const AuthPrompt = struct { token: []const u8, project: []const u8, session: []const u8, message: []const u8 };
    pub const AuthCancel = struct { token: []const u8, project: []const u8, session: []const u8 };
    pub const AuthAnswer = struct {
        token: []const u8,
        project: []const u8,
        session: []const u8,
        request_id: u64,
        decision: Answer,
    };
    /// The answer is base64url encoded so newlines remain data in v1 framing.
    pub const AuthAgentAnswer = struct {
        token: []const u8,
        project: []const u8,
        session: []const u8,
        request_id: u64,
        answer: []const u8,
    };

    pub const ParseError = error{
        NoVerb,
        BadArguments,
    };

    pub fn parse(line: []const u8) ParseError!Request {
        const asked = verbOf(line) orelse return error.NoVerb;
        return switch (asked.verb) {
            .start => .{ .start = .{
                .project = try field(asked.rest, 0, 2),
                .message = try field(asked.rest, 1, 2),
            } },
            .adopt => .{ .adopt = .{
                .project = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            .create => .{ .create = .{ .project = try field(asked.rest, 0, 1) } },
            .fork => fork: {
                const at = try field(asked.rest, 2, 3);
                break :fork .{ .fork = .{
                    .project = try field(asked.rest, 0, 3),
                    .session = try field(asked.rest, 1, 3),
                    .at = if (std.mem.eql(u8, at, "latest")) null else std.fmt.parseInt(u64, at, 10) catch return error.BadArguments,
                } };
            },
            .review => .{ .review = .{
                .project = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            .select => .{ .select = .{
                .project = try field(asked.rest, 0, 3),
                .session = try field(asked.rest, 1, 3),
                .payload = try field(asked.rest, 2, 3),
            } },
            .undo_selection => .{ .undo_selection = .{
                .project = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            .cancel => .{ .cancel = .{
                .project = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            .prompt => .{ .prompt = .{
                .project = try field(asked.rest, 0, 3),
                .session = try field(asked.rest, 1, 3),
                .message = try field(asked.rest, 2, 3),
            } },
            .read => read: {
                const space = std.mem.indexOfScalar(u8, asked.rest, ' ') orelse
                    return error.BadArguments;
                break :read .{ .read = .{
                    .session = asked.rest[0..space],
                    .after = std.fmt.parseInt(
                        u64,
                        std.mem.trim(u8, asked.rest[space + 1 ..], " "),
                        10,
                    ) catch return error.BadArguments,
                } };
            },
            .list => .{ .list = .{ .project = try field(asked.rest, 0, 1) } },
            .projects => .{ .projects = {} },
            .watch => .{ .watch = .{
                .project = try field(asked.rest, 0, 3),
                .session = try field(asked.rest, 1, 3),
                .after = std.fmt.parseInt(u64, try field(asked.rest, 2, 3), 10) catch
                    return error.BadArguments,
            } },
            .answer => .{
                .answer = .{
                    .project = try field(asked.rest, 0, 4),
                    .session = try field(asked.rest, 1, 4),
                    .request_id = std.fmt.parseInt(u64, try field(asked.rest, 2, 4), 10) catch
                        return error.BadArguments,
                    .decision = Answer.parse(try field(asked.rest, 3, 4)) orelse
                        return error.BadArguments,
                },
            },
            .auth_status => .{ .auth_status = {} },
            .auth_local_setup => .{ .auth_local_setup = .{ .credentials = try field(asked.rest, 0, 1) } },
            .auth_local_login => .{ .auth_local_login = .{ .credentials = try field(asked.rest, 0, 1) } },
            .auth_oidc_setup => .{ .auth_oidc_setup = .{ .configuration = try field(asked.rest, 0, 1) } },
            .auth_oidc_begin => .{ .auth_oidc_begin = .{ .input = try field(asked.rest, 0, 1) } },
            .auth_oidc_exchange => .{ .auth_oidc_exchange = .{ .exchange = try field(asked.rest, 0, 1) } },
            .auth_session => .{ .auth_session = .{ .token = try field(asked.rest, 0, 1) } },
            .auth_logout => .{ .auth_logout = .{ .token = try field(asked.rest, 0, 1) } },
            .auth_authorize => .{ .auth_authorize = .{
                .token = try field(asked.rest, 0, 4),
                .resource_kind = try field(asked.rest, 1, 4),
                .resource_id = try field(asked.rest, 2, 4),
                .capability = try field(asked.rest, 3, 4),
            } },
            .auth_project_create => .{ .auth_project_create = .{
                .token = try field(asked.rest, 0, 2),
                .project_json = try field(asked.rest, 1, 2),
            } },
            .auth_project_list => .{ .auth_project_list = .{ .token = try field(asked.rest, 0, 1) } },
            .auth_session_create => .{ .auth_session_create = .{
                .token = try field(asked.rest, 0, 3),
                .project = try field(asked.rest, 1, 3),
                .placement = try field(asked.rest, 2, 3),
            } },
            .auth_session_register => .{ .auth_session_register = .{
                .token = try field(asked.rest, 0, 3),
                .session = try field(asked.rest, 1, 3),
                .project = try field(asked.rest, 2, 3),
            } },
            .auth_session_register_placed => .{ .auth_session_register_placed = .{
                .token = try field(asked.rest, 0, 4),
                .session = try field(asked.rest, 1, 4),
                .project = try field(asked.rest, 2, 4),
                .placement = try field(asked.rest, 3, 4),
            } },
            .auth_session_member => .{ .auth_session_member = .{
                .token = try field(asked.rest, 0, 4),
                .session = try field(asked.rest, 1, 4),
                .identity = try field(asked.rest, 2, 4),
                .role = try field(asked.rest, 3, 4),
            } },
            .auth_session_people => .{ .auth_session_people = .{
                .token = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            .auth_session_presence => .{ .auth_session_presence = .{
                .token = try field(asked.rest, 0, 3),
                .action = try field(asked.rest, 1, 3),
                .session = try field(asked.rest, 2, 3),
            } },
            .auth_session_host => .{ .auth_session_host = .{
                .token = try field(asked.rest, 0, 6),
                .action = try field(asked.rest, 1, 6),
                .session = try field(asked.rest, 2, 6),
                .placement = try field(asked.rest, 3, 6),
                .host_id = try field(asked.rest, 4, 6),
                .generation = std.fmt.parseInt(u64, try field(asked.rest, 5, 6), 10) catch return error.BadArguments,
            } },
            .auth_worker_event => .{ .auth_worker_event = .{
                .token = try field(asked.rest, 0, 6),
                .session = try field(asked.rest, 1, 6),
                .host_id = try field(asked.rest, 2, 6),
                .generation = std.fmt.parseInt(u64, try field(asked.rest, 3, 6), 10) catch return error.BadArguments,
                .event_id = std.fmt.parseInt(u64, try field(asked.rest, 4, 6), 10) catch return error.BadArguments,
                .event_json = try field(asked.rest, 5, 6),
            } },
            .auth_worker_read => .{ .auth_worker_read = .{
                .token = try field(asked.rest, 0, 5),
                .session = try field(asked.rest, 1, 5),
                .host_id = try field(asked.rest, 2, 5),
                .generation = std.fmt.parseInt(u64, try field(asked.rest, 3, 5), 10) catch return error.BadArguments,
                .after = std.fmt.parseInt(u64, try field(asked.rest, 4, 5), 10) catch return error.BadArguments,
            } },
            .auth_worker_token => .{ .auth_worker_token = .{
                .token = try field(asked.rest, 0, 2),
                .session = try field(asked.rest, 1, 2),
            } },
            .auth_people => blk: {
                if (std.mem.indexOfScalar(u8, asked.rest, '\t') == null) break :blk .{ .auth_people = .{ .token = asked.rest } };
                break :blk .{ .auth_people = .{
                    .token = try field(asked.rest, 0, 3),
                    .action = try field(asked.rest, 1, 3),
                    .identity = try field(asked.rest, 2, 3),
                } };
            },
            .auth_team => .{ .auth_team = .{
                .token = try field(asked.rest, 0, 6),
                .action = try field(asked.rest, 1, 6),
                .team = try field(asked.rest, 2, 6),
                .identity = try field(asked.rest, 3, 6),
                .role = try field(asked.rest, 4, 6),
                .payload = try field(asked.rest, 5, 6),
            } },
            .auth_acl => .{ .auth_acl = .{
                .token = try field(asked.rest, 0, 6),
                .action = try field(asked.rest, 1, 6),
                .resource_kind = try field(asked.rest, 2, 6),
                .resource_id = try field(asked.rest, 3, 6),
                .rule_id = try field(asked.rest, 4, 6),
                .payload = try field(asked.rest, 5, 6),
            } },
            .auth_provider => .{ .auth_provider = .{
                .token = try field(asked.rest, 0, 4),
                .action = try field(asked.rest, 1, 4),
                .provider_id = try field(asked.rest, 2, 4),
                .payload = try field(asked.rest, 3, 4),
            } },
            .auth_prompt => .{ .auth_prompt = .{
                .token = try field(asked.rest, 0, 4),
                .project = try field(asked.rest, 1, 4),
                .session = try field(asked.rest, 2, 4),
                .message = try field(asked.rest, 3, 4),
            } },
            .auth_cancel => .{ .auth_cancel = .{
                .token = try field(asked.rest, 0, 3),
                .project = try field(asked.rest, 1, 3),
                .session = try field(asked.rest, 2, 3),
            } },
            .auth_answer => .{ .auth_answer = .{
                .token = try field(asked.rest, 0, 5),
                .project = try field(asked.rest, 1, 5),
                .session = try field(asked.rest, 2, 5),
                .request_id = std.fmt.parseInt(u64, try field(asked.rest, 3, 5), 10) catch return error.BadArguments,
                .decision = Answer.parse(try field(asked.rest, 4, 5)) orelse return error.BadArguments,
            } },
            .auth_agent_answer => .{ .auth_agent_answer = .{
                .token = try field(asked.rest, 0, 5),
                .project = try field(asked.rest, 1, 5),
                .session = try field(asked.rest, 2, 5),
                .request_id = std.fmt.parseInt(u64, try field(asked.rest, 3, 5), 10) catch return error.BadArguments,
                .answer = try field(asked.rest, 4, 5),
            } },
        };
    }

    pub fn write(self: Request, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .start => |one| try writer.print("start {s}\t{s}\n", .{ one.project, one.message }),
            .adopt => |one| try writer.print("adopt {s}\t{s}\n", .{ one.project, one.session }),
            .create => |one| try writer.print("create {s}\n", .{one.project}),
            .fork => |one| if (one.at) |at|
                try writer.print("fork {s}\t{s}\t{d}\n", .{ one.project, one.session, at })
            else
                try writer.print("fork {s}\t{s}\tlatest\n", .{ one.project, one.session }),
            .review => |one| try writer.print("review {s}\t{s}\n", .{ one.project, one.session }),
            .select => |one| try writer.print("select {s}\t{s}\t{s}\n", .{ one.project, one.session, one.payload }),
            .undo_selection => |one| try writer.print("undo_selection {s}\t{s}\n", .{ one.project, one.session }),
            .cancel => |one| try writer.print("cancel {s}\t{s}\n", .{ one.project, one.session }),
            .prompt => |one| try writer.print(
                "prompt {s}\t{s}\t{s}\n",
                .{ one.project, one.session, one.message },
            ),
            .read => |one| try writer.print("read {s} {d}\n", .{ one.session, one.after }),
            .list => |one| try writer.print("list {s}\n", .{one.project}),
            .projects => try writer.writeAll("projects\n"),
            .watch => |one| try writer.print(
                "watch {s}\t{s}\t{d}\n",
                .{ one.project, one.session, one.after },
            ),
            .answer => |one| try writer.print("answer {s}\t{s}\t{d}\t{s}\n", .{
                one.project,
                one.session,
                one.request_id,
                @tagName(one.decision),
            }),
            .auth_status => try writer.writeAll("auth_status\n"),
            .auth_local_setup => |one| try writer.print("auth_local_setup {s}\n", .{one.credentials}),
            .auth_local_login => |one| try writer.print("auth_local_login {s}\n", .{one.credentials}),
            .auth_oidc_setup => |one| try writer.print("auth_oidc_setup {s}\n", .{one.configuration}),
            .auth_oidc_begin => |one| try writer.print("auth_oidc_begin {s}\n", .{one.input}),
            .auth_oidc_exchange => |one| try writer.print("auth_oidc_exchange {s}\n", .{one.exchange}),
            .auth_session => |one| try writer.print("auth_session {s}\n", .{one.token}),
            .auth_logout => |one| try writer.print("auth_logout {s}\n", .{one.token}),
            .auth_authorize => |one| try writer.print("auth_authorize {s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.resource_kind, one.resource_id, one.capability,
            }),
            .auth_project_create => |one| try writer.print("auth_project_create {s}\t{s}\n", .{
                one.token, one.project_json,
            }),
            .auth_project_list => |one| try writer.print("auth_project_list {s}\n", .{one.token}),
            .auth_session_create => |one| try writer.print("auth_session_create {s}\t{s}\t{s}\n", .{
                one.token, one.project, one.placement,
            }),
            .auth_session_register => |one| try writer.print("auth_session_register {s}\t{s}\t{s}\n", .{
                one.token, one.session, one.project,
            }),
            .auth_session_register_placed => |one| try writer.print("auth_session_register_placed {s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.session, one.project, one.placement,
            }),
            .auth_session_member => |one| try writer.print("auth_session_member {s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.session, one.identity, one.role,
            }),
            .auth_session_people => |one| try writer.print("auth_session_people {s}\t{s}\n", .{
                one.token, one.session,
            }),
            .auth_session_presence => |one| try writer.print("auth_session_presence {s}\t{s}\t{s}\n", .{
                one.token, one.action, one.session,
            }),
            .auth_session_host => |one| try writer.print("auth_session_host {s}\t{s}\t{s}\t{s}\t{s}\t{d}\n", .{
                one.token, one.action, one.session, one.placement, one.host_id, one.generation,
            }),
            .auth_worker_event => |one| try writer.print("auth_worker_event {s}\t{s}\t{s}\t{d}\t{d}\t{s}\n", .{
                one.token, one.session, one.host_id, one.generation, one.event_id, one.event_json,
            }),
            .auth_worker_read => |one| try writer.print("auth_worker_read {s}\t{s}\t{s}\t{d}\t{d}\n", .{
                one.token, one.session, one.host_id, one.generation, one.after,
            }),
            .auth_worker_token => |one| try writer.print("auth_worker_token {s}\t{s}\n", .{ one.token, one.session }),
            .auth_people => |one| if (std.mem.eql(u8, one.action, "list"))
                try writer.print("auth_people {s}\n", .{one.token})
            else
                try writer.print("auth_people {s}\t{s}\t{s}\n", .{ one.token, one.action, one.identity }),
            .auth_team => |one| try writer.print("auth_team {s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.action, one.team, one.identity, one.role, one.payload,
            }),
            .auth_acl => |one| try writer.print("auth_acl {s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.action, one.resource_kind, one.resource_id, one.rule_id, one.payload,
            }),
            .auth_provider => |one| try writer.print("auth_provider {s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.action, one.provider_id, one.payload,
            }),
            .auth_prompt => |one| try writer.print("auth_prompt {s}\t{s}\t{s}\t{s}\n", .{
                one.token, one.project, one.session, one.message,
            }),
            .auth_cancel => |one| try writer.print("auth_cancel {s}\t{s}\t{s}\n", .{
                one.token, one.project, one.session,
            }),
            .auth_answer => |one| try writer.print("auth_answer {s}\t{s}\t{s}\t{d}\t{s}\n", .{
                one.token, one.project, one.session, one.request_id, @tagName(one.decision),
            }),
            .auth_agent_answer => |one| try writer.print("auth_agent_answer {s}\t{s}\t{s}\t{d}\t{s}\n", .{
                one.token, one.project, one.session, one.request_id, one.answer,
            }),
        }
    }
};

pub fn verbOf(request: []const u8) ?struct { verb: Verb, rest: []const u8 } {
    inline for (std.enums.values(Verb)) |verb| {
        const name = @tagName(verb);
        // Only a verb that takes nothing arrives on its own. Every other one
        // without its arguments is not a request.
        if (@FieldType(Request, name) == void and std.mem.eql(u8, request, name)) {
            return .{ .verb = verb, .rest = "" };
        }
        const prefix = name ++ " ";
        if (std.mem.startsWith(u8, request, prefix)) {
            return .{ .verb = verb, .rest = request[prefix.len..] };
        }
    }
    return null;
}

pub const no_verb_text = text: {
    @setEvalBranchQuota(2000);
    var built: []const u8 = "the request is none of";
    for (std.enums.values(Verb), 0..) |verb, index| {
        if (index != 0) built = built ++ (if (index + 1 == std.enums.values(Verb).len) " and" else ",");
        built = built ++ " `" ++ @tagName(verb) ++ "`";
    }
    break :text built;
};

/// Exactly `count` fields; an extra one is refused, not ignored.
fn field(rest: []const u8, want: usize, count: usize) Request.ParseError![]const u8 {
    var found: usize = 0;
    var start: usize = 0;
    var answer: ?[]const u8 = null;
    var index: usize = 0;
    while (index <= rest.len) : (index += 1) {
        if (index != rest.len and rest[index] != '\t') continue;
        if (found == want) answer = rest[start..index];
        found += 1;
        start = index + 1;
    }
    if (found != count) return error.BadArguments;
    return answer orelse error.BadArguments;
}

/// Two members, the protocol's whole trust boundary: naming `allowed_by_policy` would forge another's answer.
pub const Answer = enum {
    yes,
    no,

    pub fn parse(word: []const u8) ?Answer {
        inline for (std.enums.values(Answer)) |one| {
            if (std.mem.eql(u8, word, @tagName(one))) return one;
        }
        return null;
    }

    pub fn decision(self: Answer) event.ApprovalDecision {
        return switch (self) {
            .yes => .approved_by_user,
            .no => .refused_by_user,
        };
    }
};

/// Never alias a local struct, or a local field changes the wire; every field defaults, none a pass.
/// One project, as a picker shows it.
pub const ProjectRow = struct {
    /// Stable UUID of a daemon-registered project. Empty for a legacy
    /// filesystem-discovered row that has not been registered yet.
    id: []const u8 = "",
    /// The directory the project is in, or empty where nothing recorded it.
    root: []const u8 = "",
    /// Durable provisioning source, distinct from the current execution root.
    source_kind: []const u8 = "",
    source_locator: []const u8 = "",
    /// What to call it. Never empty.
    name: []const u8,
    sessions: usize = 0,
    status: []const u8 = "ready",
    /// Whether the authenticated identity may change project settings.
    can_manage: bool = false,

    pub fn toJson(self: ProjectRow, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(gpa, "{f}", .{std.json.fmt(self, .{})});
    }
};

pub const SessionRow = struct {
    id: []const u8,
    started_ms: u64 = 0,
    /// The direct parent and completed event this session branched from. Empty
    /// for a session that was not forked and for an older daemon.
    forked_from: []const u8 = "",
    forked_at: u64 = 0,
    model: []const u8 = "",
    model_count: usize = 0,
    model_alias: []const u8 = "",
    /// What the agent named the session, or empty when it named nothing. A
    /// person picks by this, because an id says nothing about the work.
    title: []const u8 = "",
    /// What to call the project this belongs to, for a listing that covers more
    /// than one. Empty when the caller asked for one project and already knows.
    project: []const u8 = "",
    /// That project's directory, which is what names it to the daemon. Empty
    /// where nothing recorded it, and such a session cannot be opened by a
    /// caller that is not already inside its project.
    project_root: []const u8 = "",
    /// A lock that could not be tested says `unknown`, never `idle`.
    live: []const u8 = "unknown",
    end: ?[]const u8 = null,
    turns: u64 = 0,
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    amount: f64 = 0,
    currency: []const u8 = "",
    /// False once a turn can't be priced; the number then isn't a total.
    spend_enforceable: bool = true,
    readable: bool = true,
    /// False if the log couldn't be read to its end; the numbers are then a floor.
    complete: bool = true,
    chain: []const u8 = "unreadable",
    chain_events: u64 = 0,
    chain_chained: u64 = 0,
    has_work: bool = false,
    has_root: bool = false,

    pub fn toJson(self: SessionRow, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(gpa, "{f}", .{std.json.fmt(self, .{})});
    }

    pub fn fromJson(gpa: std.mem.Allocator, text: []const u8) !std.json.Parsed(SessionRow) {
        return std.json.parseFromSlice(SessionRow, gpa, text, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
    }
};

pub const SessionPersonRow = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    email: []const u8 = "",
    role: ?[]const u8 = null,
};

pub const SessionPresenceRow = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    last_seen_ms: i64,
};

pub const TeamRow = struct {
    id: []const u8,
    name: []const u8,
    role: []const u8,
};

pub const TeamPersonRow = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    email: []const u8 = "",
    role: ?[]const u8 = null,
};

pub const PersonRow = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    email: []const u8 = "",
    instance_role: []const u8,
    local_account: bool = false,
    local_account_disabled: bool = false,
};

pub fn verdictName(verdict: chain.Verdict) []const u8 {
    return @tagName(verdict);
}

pub const ok_prefix = "ok ";
pub const error_prefix = "error ";

pub const Reply = union(enum) {
    ok: []const u8,
    failed: []const u8,
    record: Record,

    pub const Record = struct {
        id: u64,
        /// The log's own bytes: a re-encoding of the envelope reads as tampering.
        payload: []const u8,
    };

    pub const ParseError = error{Malformed};

    pub fn parse(line: []const u8) ParseError!Reply {
        if (std.mem.startsWith(u8, line, ok_prefix)) return .{ .ok = line[ok_prefix.len..] };
        if (std.mem.startsWith(u8, line, error_prefix)) return .{ .failed = line[error_prefix.len..] };
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return error.Malformed;
        const id = std.fmt.parseInt(u64, line[0..tab], 10) catch return error.Malformed;
        return .{ .record = .{ .id = id, .payload = line[tab + 1 ..] } };
    }

    pub fn write(self: Reply, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => |text| try writer.print(ok_prefix ++ "{s}\n", .{text}),
            .failed => |text| try writer.print(error_prefix ++ "{s}\n", .{text}),
            .record => |one| try writer.print("{d}\t{s}\n", .{ one.id, one.payload }),
        }
    }
};

pub const max_request_bytes: usize = 1024 * 1024;

pub const Feed = struct {
    /// Inclusive: the first event back is one the client has, so it's dropped.
    after: u64 = 0,
    /// Byte offset immediately after the last event written by `events`.
    /// Worker ingress uses this as its optimistic append cursor.
    end_offset: u64 = 0,
    ended: bool = false,
    sent: usize = 0,

    pub const Error = std.Io.Writer.Error || storage.ReplayError;

    /// Zero is the header's own byte offset, what a verifier wants.
    pub fn header(
        self: *Feed,
        io: std.Io,
        store: storage.Storage,
        writer: *std.Io.Writer,
    ) Error!void {
        _ = self;
        var buffer: [storage.max_header_bytes]u8 = undefined;
        const line = try store.headerLine(io, &buffer);
        try (Reply{ .record = .{ .id = 0, .payload = line } }).write(writer);
    }

    pub fn events(
        self: *Feed,
        gpa: std.mem.Allocator,
        io: std.Io,
        store: storage.Storage,
        writer: *std.Io.Writer,
        limit: usize,
    ) Error!bool {
        var replay = try store.replay(gpa, io, self.after);
        defer replay.deinit();
        self.end_offset = replay.at();

        var any = false;
        var first = true;
        var this_call: usize = 0;
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            self.end_offset = replay.at();

            if (first) {
                first = false;
                if (self.after != 0) continue;
            }

            try (Reply{ .record = .{
                .id = parsed.value.id,
                .payload = replay.line(),
            } }).write(writer);

            self.after = parsed.value.id;
            self.sent += 1;
            this_call += 1;
            any = true;
            switch (parsed.value.event) {
                .session_end => self.ended = true,
                .session_fork => self.ended = false,
                else => {},
            }
            if (limit != 0 and this_call >= limit) break;
        }
        return any;
    }
};

test "a bounded feed resumes after its last record and keeps append offset separate" {
    const gpa = testing.allocator;
    var memory = try storage.Memory.init(gpa, "01TESTSESSION");
    defer memory.deinit();
    const store = memory.storage();
    var locked = try store.lock(testing.io);
    const first_id = try locked.append(gpa, testing.io, .{ .unknown = .{ .kind = "test_one", .payload = .null } }, 1);
    const second_id = try locked.append(gpa, testing.io, .{ .unknown = .{ .kind = "test_two", .payload = .null } }, 2);
    const third_id = try locked.append(gpa, testing.io, .{ .unknown = .{ .kind = "test_three", .payload = .null } }, 3);
    try locked.unlock(testing.io);

    var feed: Feed = .{};
    var first_output: std.Io.Writer.Allocating = .init(gpa);
    defer first_output.deinit();
    try testing.expect(try feed.events(gpa, testing.io, store, &first_output.writer, 2));
    try testing.expectEqual(second_id, feed.after);
    try testing.expectEqual(third_id, feed.end_offset);
    try testing.expect(std.mem.indexOf(u8, first_output.written(), "test_one") != null);
    try testing.expect(std.mem.indexOf(u8, first_output.written(), "test_two") != null);
    try testing.expect(std.mem.indexOf(u8, first_output.written(), "test_three") == null);
    try testing.expect(first_id != second_id);

    var resumed: Feed = .{ .after = feed.after };
    var second_output: std.Io.Writer.Allocating = .init(gpa);
    defer second_output.deinit();
    try testing.expect(try resumed.events(gpa, testing.io, store, &second_output.writer, 2));
    try testing.expectEqual(third_id, resumed.after);
    try testing.expectEqual(memory.bytes.items.len, resumed.end_offset);
    try testing.expect(std.mem.indexOf(u8, second_output.written(), "test_three") != null);
}

/// The request waits for the greeting. `said` points into `reader`'s buffer; `each` returns false to stop.
pub fn exchange(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    request: Request,
    said: *Handshake,
    context: anytype,
    comptime each: fn (@TypeOf(context), Reply) anyerror!bool,
) anyerror!void {
    said.* = try handshake(reader, writer, protocol_version);
    if (!said.ok()) return error.HandshakeFailed;

    try request.write(writer);
    try writer.flush();

    while (true) {
        // Never `takeDelimiterExclusive`: it stops before the break, looping on an empty line.
        const line = (try reader.takeDelimiter('\n')) orelse return;
        const reply = Reply.parse(std.mem.trimEnd(u8, line, "\r")) catch continue;
        if (!try each(context, reply)) return;
    }
}

const testing = std.testing;

test "an address a person typed reads back as the address they typed" {
    const spellings = [_][]const u8{
        "unix:/run/user/1000/chock/daemon.sock",
        "127.0.0.1:7373",
        "0.0.0.0:8080",
        "[::1]:7373",
        "chock.example:443",
    };
    for (spellings) |text| {
        const address = try Address.parse(text);
        var buffer: [256]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try address.format(&writer);
        try testing.expectEqualStrings(text, writer.buffered());
    }

    const six = try Address.parse("[::1]:7373");
    try testing.expectEqualStrings("[::1]", six.ip.host);
    try testing.expectEqual(@as(u16, 7373), six.ip.port);

    const unix = try Address.parse("unix:/tmp/x.sock");
    try testing.expectEqualStrings("/tmp/x.sock", unix.unix);
}

test "an address that is not one is refused by name and never guessed at" {
    try testing.expectError(error.EmptyPath, Address.parse("unix:"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1:"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1:seventy"));
    try testing.expectError(error.NoPort, Address.parse("127.0.0.1:70000"));
    try testing.expectError(error.EmptyHost, Address.parse(":7373"));
    try testing.expectError(error.NoPort, Address.parse("/run/chock.sock"));
}

test "a client can decide exactly two things, and neither of them is the policy's" {
    try testing.expectEqual(@as(usize, 2), std.enums.values(Answer).len);

    var reached = std.EnumSet(std.meta.Tag(event.ApprovalDecision)).empty;
    for (std.enums.values(Answer)) |one| reached.insert(std.meta.activeTag(one.decision()));
    try testing.expect(reached.contains(.approved_by_user));
    try testing.expect(reached.contains(.refused_by_user));
    try testing.expect(!reached.contains(.allowed_by_policy));
    try testing.expect(!reached.contains(.approved_by_review));
    try testing.expect(!reached.contains(.unknown));
    try testing.expectEqual(@as(usize, 2), reached.count());

    inline for (@typeInfo(event.ApprovalDecision).@"union".field_names, @typeInfo(event.ApprovalDecision).@"union".field_types) |one_name, _| {
        const permitted = std.mem.eql(u8, one_name, "approved_by_user") or
            std.mem.eql(u8, one_name, "refused_by_user");
        if (!permitted) try testing.expect(Answer.parse(one_name) == null);
    }
}

test "the only words a client can put in an answer are yes and no" {
    try testing.expectEqual(Answer.yes, Answer.parse("yes").?);
    try testing.expectEqual(Answer.no, Answer.parse("no").?);
    for ([_][]const u8{
        "allowed_by_policy",
        "approved_by_policy",
        "approved_by_review",
        "approved_by_user",
        "refused_by_user",
        "YES",
        "y",
        "",
        "yes no",
    }) |word| try testing.expect(Answer.parse(word) == null);

    try testing.expectError(
        error.BadArguments,
        Request.parse("answer /p\t01JQ" ++ @as([22]u8, @splat('A')) ++ "\t128\tallowed_by_policy"),
    );
}

test "additive OIDC session verbs keep their v1 request spelling" {
    const examples = [_]Request{
        .{ .auth_oidc_setup = .{ .configuration = "eyJwcm92aWRlciI6ImthbmlkbSJ9" } },
        .{ .auth_oidc_begin = .{ .input = "eyJyZWRpcmVjdF91cmkiOiJodHRwcyJ9" } },
        .{ .auth_oidc_exchange = .{ .exchange = "eyJjb2RlIjoiY29kZSJ9" } },
        .{ .auth_session = .{ .token = "opaque-session-token" } },
        .{ .auth_logout = .{ .token = "opaque-session-token" } },
        .{ .auth_authorize = .{
            .token = "opaque-session-token",
            .resource_kind = "project",
            .resource_id = "project-uuid",
            .capability = "project_view",
        } },
        .{ .auth_project_create = .{
            .token = "opaque-session-token",
            .project_json = "eyJuYW1lIjoiRGVtbyJ9",
        } },
        .{ .auth_session_create = .{
            .token = "opaque-session-token",
            .project = "/work/project",
            .placement = "client",
        } },
        .{ .auth_session_register = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
            .project = "/work/project",
        } },
        .{ .auth_session_register_placed = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
            .project = "/work/project",
            .placement = "client",
        } },
        .{ .auth_session_member = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
            .identity = "00000000-0000-4000-8000-000000000001",
            .role = "editor",
        } },
        .{ .auth_session_people = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
        } },
        .{ .auth_session_presence = .{
            .token = "opaque-session-token",
            .action = "touch",
            .session = "01JQSESSION0000000000000000",
        } },
        .{ .auth_session_host = .{
            .token = "opaque-session-token",
            .action = "claim",
            .session = "01JQSESSION0000000000000000",
            .placement = "client",
            .host_id = "00000000-0000-4000-8000-000000000099",
        } },
        .{ .auth_worker_event = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
            .host_id = "00000000-0000-4000-8000-000000000099",
            .generation = 7,
            .event_id = 4096,
            .event_json = "eyJtZXNzYWdlIjp7fX0",
        } },
        .{ .auth_worker_read = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
            .host_id = "00000000-0000-4000-8000-000000000099",
            .generation = 7,
            .after = 4096,
        } },
        .{ .auth_worker_token = .{
            .token = "opaque-session-token",
            .session = "01JQSESSION0000000000000000",
        } },
        .{ .auth_people = .{ .token = "opaque-session-token" } },
        .{ .auth_team = .{
            .token = "opaque-session-token",
            .action = "create",
            .payload = "eyJuYW1lIjoiUmV2aWV3ZXJzIn0",
        } },
        .{ .auth_prompt = .{
            .token = "opaque-session-token",
            .project = "/work/project",
            .session = "01JQSESSION0000000000000000",
            .message = "dGFiIG5ldy1saW5lIGRhdGE",
        } },
        .{ .auth_cancel = .{
            .token = "opaque-session-token",
            .project = "/work/project",
            .session = "01JQSESSION0000000000000000",
        } },
        .{ .auth_answer = .{
            .token = "opaque-session-token",
            .project = "/work/project",
            .session = "01JQSESSION0000000000000000",
            .request_id = 17,
            .decision = .yes,
        } },
        .{ .auth_agent_answer = .{
            .token = "opaque-session-token",
            .project = "/work/project",
            .session = "01JQSESSION0000000000000000",
            .request_id = 4096,
            .answer = "dGFiIG5ldy1saW5lIGRhdGE",
        } },
    };
    const expected = [_][]const u8{
        "auth_oidc_setup eyJwcm92aWRlciI6ImthbmlkbSJ9\n",
        "auth_oidc_begin eyJyZWRpcmVjdF91cmkiOiJodHRwcyJ9\n",
        "auth_oidc_exchange eyJjb2RlIjoiY29kZSJ9\n",
        "auth_session opaque-session-token\n",
        "auth_logout opaque-session-token\n",
        "auth_authorize opaque-session-token\tproject\tproject-uuid\tproject_view\n",
        "auth_project_create opaque-session-token\teyJuYW1lIjoiRGVtbyJ9\n",
        "auth_session_create opaque-session-token\t/work/project\tclient\n",
        "auth_session_register opaque-session-token\t01JQSESSION0000000000000000\t/work/project\n",
        "auth_session_register_placed opaque-session-token\t01JQSESSION0000000000000000\t/work/project\tclient\n",
        "auth_session_member opaque-session-token\t01JQSESSION0000000000000000\t00000000-0000-4000-8000-000000000001\teditor\n",
        "auth_session_people opaque-session-token\t01JQSESSION0000000000000000\n",
        "auth_session_presence opaque-session-token\ttouch\t01JQSESSION0000000000000000\n",
        "auth_session_host opaque-session-token\tclaim\t01JQSESSION0000000000000000\tclient\t00000000-0000-4000-8000-000000000099\t0\n",
        "auth_worker_event opaque-session-token\t01JQSESSION0000000000000000\t00000000-0000-4000-8000-000000000099\t7\t4096\teyJtZXNzYWdlIjp7fX0\n",
        "auth_worker_read opaque-session-token\t01JQSESSION0000000000000000\t00000000-0000-4000-8000-000000000099\t7\t4096\n",
        "auth_worker_token opaque-session-token\t01JQSESSION0000000000000000\n",
        "auth_people opaque-session-token\n",
        "auth_team opaque-session-token\tcreate\t\t\t\teyJuYW1lIjoiUmV2aWV3ZXJzIn0\n",
        "auth_prompt opaque-session-token\t/work/project\t01JQSESSION0000000000000000\tdGFiIG5ldy1saW5lIGRhdGE\n",
        "auth_cancel opaque-session-token\t/work/project\t01JQSESSION0000000000000000\n",
        "auth_answer opaque-session-token\t/work/project\t01JQSESSION0000000000000000\t17\tyes\n",
        "auth_agent_answer opaque-session-token\t/work/project\t01JQSESSION0000000000000000\t4096\tdGFiIG5ldy1saW5lIGRhdGE\n",
    };
    for (examples, expected) |request, line| {
        var buffer: [256]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try request.write(&writer);
        try testing.expectEqualStrings(line, writer.buffered());
        const parsed = try Request.parse(std.mem.trimEnd(u8, line, "\n"));
        switch (request) {
            .auth_oidc_setup => |one| try testing.expectEqualStrings(one.configuration, parsed.auth_oidc_setup.configuration),
            .auth_oidc_begin => |one| try testing.expectEqualStrings(one.input, parsed.auth_oidc_begin.input),
            .auth_oidc_exchange => |one| try testing.expectEqualStrings(one.exchange, parsed.auth_oidc_exchange.exchange),
            .auth_session => |one| try testing.expectEqualStrings(one.token, parsed.auth_session.token),
            .auth_logout => |one| try testing.expectEqualStrings(one.token, parsed.auth_logout.token),
            .auth_authorize => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_authorize.token);
                try testing.expectEqualStrings(one.resource_kind, parsed.auth_authorize.resource_kind);
                try testing.expectEqualStrings(one.resource_id, parsed.auth_authorize.resource_id);
                try testing.expectEqualStrings(one.capability, parsed.auth_authorize.capability);
            },
            .auth_project_create => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_project_create.token);
                try testing.expectEqualStrings(one.project_json, parsed.auth_project_create.project_json);
            },
            .auth_session_create => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_create.token);
                try testing.expectEqualStrings(one.project, parsed.auth_session_create.project);
                try testing.expectEqualStrings(one.placement, parsed.auth_session_create.placement);
            },
            .auth_session_register => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_register.token);
                try testing.expectEqualStrings(one.session, parsed.auth_session_register.session);
                try testing.expectEqualStrings(one.project, parsed.auth_session_register.project);
            },
            .auth_session_register_placed => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_register_placed.token);
                try testing.expectEqualStrings(one.session, parsed.auth_session_register_placed.session);
                try testing.expectEqualStrings(one.project, parsed.auth_session_register_placed.project);
                try testing.expectEqualStrings(one.placement, parsed.auth_session_register_placed.placement);
            },
            .auth_session_member => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_member.token);
                try testing.expectEqualStrings(one.session, parsed.auth_session_member.session);
                try testing.expectEqualStrings(one.identity, parsed.auth_session_member.identity);
                try testing.expectEqualStrings(one.role, parsed.auth_session_member.role);
            },
            .auth_session_people => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_people.token);
                try testing.expectEqualStrings(one.session, parsed.auth_session_people.session);
            },
            .auth_session_presence => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_presence.token);
                try testing.expectEqualStrings(one.action, parsed.auth_session_presence.action);
                try testing.expectEqualStrings(one.session, parsed.auth_session_presence.session);
            },
            .auth_session_host => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_session_host.token);
                try testing.expectEqualStrings(one.action, parsed.auth_session_host.action);
                try testing.expectEqualStrings(one.session, parsed.auth_session_host.session);
                try testing.expectEqualStrings(one.placement, parsed.auth_session_host.placement);
                try testing.expectEqualStrings(one.host_id, parsed.auth_session_host.host_id);
                try testing.expectEqual(one.generation, parsed.auth_session_host.generation);
            },
            .auth_worker_event => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_worker_event.token);
                try testing.expectEqualStrings(one.session, parsed.auth_worker_event.session);
                try testing.expectEqualStrings(one.host_id, parsed.auth_worker_event.host_id);
                try testing.expectEqual(one.generation, parsed.auth_worker_event.generation);
                try testing.expectEqual(one.event_id, parsed.auth_worker_event.event_id);
                try testing.expectEqualStrings(one.event_json, parsed.auth_worker_event.event_json);
            },
            .auth_worker_read => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_worker_read.token);
                try testing.expectEqualStrings(one.session, parsed.auth_worker_read.session);
                try testing.expectEqualStrings(one.host_id, parsed.auth_worker_read.host_id);
                try testing.expectEqual(one.generation, parsed.auth_worker_read.generation);
                try testing.expectEqual(one.after, parsed.auth_worker_read.after);
            },
            .auth_worker_token => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_worker_token.token);
                try testing.expectEqualStrings(one.session, parsed.auth_worker_token.session);
            },
            .auth_people => |one| try testing.expectEqualStrings(one.token, parsed.auth_people.token),
            .auth_team => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_team.token);
                try testing.expectEqualStrings(one.action, parsed.auth_team.action);
                try testing.expectEqualStrings(one.team, parsed.auth_team.team);
                try testing.expectEqualStrings(one.identity, parsed.auth_team.identity);
                try testing.expectEqualStrings(one.role, parsed.auth_team.role);
                try testing.expectEqualStrings(one.payload, parsed.auth_team.payload);
            },
            .auth_prompt => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_prompt.token);
                try testing.expectEqualStrings(one.project, parsed.auth_prompt.project);
                try testing.expectEqualStrings(one.session, parsed.auth_prompt.session);
                try testing.expectEqualStrings(one.message, parsed.auth_prompt.message);
            },
            .auth_cancel => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_cancel.token);
                try testing.expectEqualStrings(one.project, parsed.auth_cancel.project);
                try testing.expectEqualStrings(one.session, parsed.auth_cancel.session);
            },
            .auth_answer => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_answer.token);
                try testing.expectEqualStrings(one.project, parsed.auth_answer.project);
                try testing.expectEqualStrings(one.session, parsed.auth_answer.session);
                try testing.expectEqual(one.request_id, parsed.auth_answer.request_id);
                try testing.expectEqual(one.decision, parsed.auth_answer.decision);
            },
            .auth_agent_answer => |one| {
                try testing.expectEqualStrings(one.token, parsed.auth_agent_answer.token);
                try testing.expectEqualStrings(one.project, parsed.auth_agent_answer.project);
                try testing.expectEqualStrings(one.session, parsed.auth_agent_answer.session);
                try testing.expectEqual(one.request_id, parsed.auth_agent_answer.request_id);
                try testing.expectEqualStrings(one.answer, parsed.auth_agent_answer.answer);
            },
            else => unreachable,
        }
    }
    try testing.expectEqual(@as(u32, 1), protocol_version);
}

test "ACL administration stays additive in control protocol v1" {
    const request: Request = .{ .auth_acl = .{
        .token = "opaque-session-token",
        .action = "list",
        .resource_kind = "project",
        .resource_id = "00000000-0000-4000-8000-000000000001",
    } };
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try request.write(&writer);
    const expected = "auth_acl opaque-session-token\tlist\tproject\t00000000-0000-4000-8000-000000000001\t\t\n";
    try testing.expectEqualStrings(expected, writer.buffered());
    const parsed = try Request.parse(std.mem.trimEnd(u8, expected, "\n"));
    try testing.expectEqualStrings("list", parsed.auth_acl.action);
    try testing.expectEqualStrings("project", parsed.auth_acl.resource_kind);
}

test "people credential revocation stays additive in control protocol v1" {
    const request: Request = .{ .auth_people = .{
        .token = "opaque-session-token",
        .action = "revoke-sessions",
        .identity = "00000000-0000-4000-8000-000000000001",
    } };
    var buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try request.write(&writer);
    const expected = "auth_people opaque-session-token\trevoke-sessions\t00000000-0000-4000-8000-000000000001\n";
    try testing.expectEqualStrings(expected, writer.buffered());
    const parsed = try Request.parse(std.mem.trimEnd(u8, expected, "\n"));
    try testing.expectEqualStrings("opaque-session-token", parsed.auth_people.token);
    try testing.expectEqualStrings("revoke-sessions", parsed.auth_people.action);
    try testing.expectEqualStrings("00000000-0000-4000-8000-000000000001", parsed.auth_people.identity);
    try testing.expectEqual(@as(u32, 1), protocol_version);
}

test "provider management stays additive in control protocol v1" {
    const request: Request = .{ .auth_provider = .{
        .token = "opaque-session-token",
        .action = "list",
    } };
    var buffer: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try request.write(&writer);
    const expected = "auth_provider opaque-session-token\tlist\t\t\n";
    try testing.expectEqualStrings(expected, writer.buffered());
    const parsed = try Request.parse(std.mem.trimEnd(u8, expected, "\n"));
    try testing.expectEqualStrings("list", parsed.auth_provider.action);
}

test "every verb round trips from a request to a line and back" {
    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    const requests = [_]Request{
        .{ .start = .{ .project = "/home/ross/chock", .message = "fix the parser please" } },
        .{ .adopt = .{ .project = "/home/ross/chock", .session = id } },
        .{ .create = .{ .project = "/home/ross/chock" } },
        .{ .fork = .{ .project = "/home/ross/chock", .session = id, .at = null } },
        .{ .fork = .{ .project = "/home/ross/chock", .session = id, .at = 4096 } },
        .{ .review = .{ .project = "/home/ross/chock", .session = id } },
        .{ .select = .{ .project = "/home/ross/chock", .session = id, .payload = "{\"paths\":[\"src/main.zig\"]}" } },
        .{ .undo_selection = .{ .project = "/home/ross/chock", .session = id } },
        .{ .cancel = .{ .project = "/home/ross/chock", .session = id } },
        .{ .prompt = .{
            .project = "/home/ross/chock",
            .session = id,
            .message = "and now the tests",
        } },
        .{ .read = .{ .session = id, .after = 0 } },
        .{ .read = .{ .session = id, .after = 4096 } },
        .{ .list = .{ .project = "/home/ross/chock" } },
        .{ .projects = {} },
        .{ .watch = .{ .project = "/home/ross/chock", .session = id, .after = 128 } },
        .{ .answer = .{ .project = "/home/ross/chock", .session = id, .request_id = 9, .decision = .yes } },
        .{ .answer = .{ .project = "/home/ross/chock", .session = id, .request_id = 9, .decision = .no } },
        .{ .auth_status = {} },
        .{ .auth_local_setup = .{ .credentials = "eyJ1c2VybmFtZSI6ImFkbWluIn0" } },
        .{ .auth_local_login = .{ .credentials = "eyJ1c2VybmFtZSI6ImFkbWluIn0" } },
        .{ .auth_oidc_setup = .{ .configuration = "eyJwcm92aWRlciI6ImthbmlkbSJ9" } },
        .{ .auth_oidc_begin = .{ .input = "eyJyZWRpcmVjdF91cmkiOiJodHRwcyJ9" } },
        .{ .auth_oidc_exchange = .{ .exchange = "eyJjb2RlIjoiY29kZSJ9" } },
        .{ .auth_session = .{ .token = "opaque-token" } },
        .{ .auth_logout = .{ .token = "opaque-token" } },
        .{ .auth_authorize = .{ .token = "opaque-token", .resource_kind = "project", .resource_id = "project-id", .capability = "project_view" } },
        .{ .auth_project_create = .{ .token = "opaque-token", .project_json = "{}" } },
        .{ .auth_project_list = .{ .token = "opaque-token" } },
        .{ .auth_session_create = .{ .token = "opaque-token", .project = "project-id", .placement = "daemon" } },
        .{ .auth_session_register = .{ .token = "opaque-token", .session = id, .project = "project-id" } },
        .{ .auth_session_register_placed = .{ .token = "opaque-token", .session = id, .project = "project-id", .placement = "client" } },
        .{ .auth_session_member = .{ .token = "opaque-token", .session = id, .identity = "identity-id", .role = "editor" } },
        .{ .auth_session_people = .{ .token = "opaque-token", .session = id } },
        .{ .auth_session_presence = .{ .token = "opaque-token", .action = "touch", .session = id } },
        .{ .auth_session_host = .{ .token = "opaque-token", .action = "claim", .session = id, .placement = "client", .host_id = "host-id", .generation = 7 } },
        .{ .auth_worker_event = .{ .token = "opaque-token", .session = id, .host_id = "host-id", .generation = 7, .event_id = 4096, .event_json = "{}" } },
        .{ .auth_worker_read = .{ .token = "opaque-token", .session = id, .host_id = "host-id", .generation = 7, .after = 9 } },
        .{ .auth_worker_token = .{ .token = "opaque-token", .session = id } },
        .{ .auth_people = .{ .token = "opaque-token" } },
        .{ .auth_team = .{ .token = "opaque-token", .action = "member", .team = "team-id", .identity = "identity-id", .role = "editor", .payload = "{}" } },
        .{ .auth_acl = .{ .token = "opaque-token", .action = "create", .resource_kind = "project", .resource_id = "project-id", .rule_id = "rule-id", .payload = "{}" } },
        .{ .auth_provider = .{ .token = "opaque-token", .action = "list", .provider_id = "provider-id", .payload = "{}" } },
        .{ .auth_prompt = .{ .token = "opaque-token", .project = "project-id", .session = id, .message = "hello" } },
        .{ .auth_cancel = .{ .token = "opaque-token", .project = "project-id", .session = id } },
        .{ .auth_answer = .{ .token = "opaque-token", .project = "project-id", .session = id, .request_id = 17, .decision = .yes } },
        .{ .auth_agent_answer = .{ .token = "opaque-token", .project = "project-id", .session = id, .request_id = 18, .answer = "approved" } },
    };

    var seen = std.EnumSet(Verb).empty;
    for (requests) |one| {
        seen.insert(std.meta.activeTag(one));

        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try one.write(&writer);
        const line = writer.buffered();
        try testing.expectEqual(@as(u8, '\n'), line[line.len - 1]);

        const back = try Request.parse(line[0 .. line.len - 1]);
        try testing.expectEqual(std.meta.activeTag(one), std.meta.activeTag(back));
        try testing.expectEqualDeep(one, back);
    }

    try testing.expectEqual(std.enums.values(Verb).len, seen.count());
}

test "a message with a tab in it cannot smuggle a field into a request" {
    try testing.expectError(
        error.BadArguments,
        Request.parse("start /p\thello\textra"),
    );
    try testing.expectError(error.BadArguments, Request.parse("list /p\textra"));
    try testing.expectError(
        error.BadArguments,
        Request.parse("answer /p\t01\t1\tyes\textra"),
    );
    try testing.expectError(error.BadArguments, Request.parse("watch /p\t01"));
    try testing.expectError(error.BadArguments, Request.parse("fork /p\t01\tnot-an-offset"));
    try testing.expectError(error.BadArguments, Request.parse("answer /p\t01\t1"));
}

test "a verb has to be a whole word, and every verb is one a client is told about" {
    inline for (std.enums.values(Verb)) |verb| {
        const asked = verbOf(@tagName(verb) ++ " the rest of it").?;
        try testing.expectEqual(verb, asked.verb);
        try testing.expectEqualStrings("the rest of it", asked.rest);
        try testing.expect(std.mem.indexOf(u8, no_verb_text, @tagName(verb)) != null);
    }

    try testing.expect(verbOf("started /p\tmessage") == null);
    try testing.expect(verbOf("listen /p") == null);
    try testing.expect(verbOf("watched /p") == null);
    try testing.expect(verbOf("answered /p") == null);
    try testing.expect(verbOf("") == null);
    try testing.expect(verbOf("list") == null);
    // `projects` takes nothing, so it is a whole request on its own.
    try testing.expectEqual(Verb.projects, verbOf("projects").?.verb);
    try testing.expectError(error.NoVerb, Request.parse("nonsense /p"));
}

test "a reply line reads back as what was written, records included" {
    const replies = [_]Reply{
        .{ .ok = "answered" },
        .{ .failed = "this daemon started no session with that identifier" },
        .{ .record = .{ .id = 0, .payload = "{\"chock\":1}" } },
        .{ .record = .{ .id = 4096, .payload = "{\"id\":4096}" } },
    };
    for (replies) |one| {
        var buffer: [512]u8 = undefined;
        var writer = std.Io.Writer.fixed(&buffer);
        try one.write(&writer);
        const line = writer.buffered();
        const back = try Reply.parse(line[0 .. line.len - 1]);
        try testing.expectEqualDeep(one, back);
    }

    const split = try Reply.parse("7\ta\tb");
    try testing.expectEqual(@as(u64, 7), split.record.id);
    try testing.expectEqualStrings("a\tb", split.record.payload);

    try testing.expectError(error.Malformed, Reply.parse("no tab here"));
    try testing.expectError(error.Malformed, Reply.parse("notanumber\tpayload"));
}

test "a listing row survives a daemon that grew a field and a client that has not" {
    const gpa = testing.allocator;

    const row = SessionRow{
        .id = "01JQ" ++ @as([22]u8, @splat('A')),
        .started_ms = 1_700_000_000_000,
        .forked_from = "01JQ" ++ @as([22]u8, @splat('P')),
        .forked_at = 42,
        .model = "claude-opus-5",
        .model_alias = "main",
        .live = "live",
        .turns = 3,
        .chain = "intact",
        .chain_events = 12,
        .chain_chained = 12,
    };
    const text = try row.toJson(gpa);
    defer gpa.free(text);

    var parsed = try SessionRow.fromJson(gpa, text);
    defer parsed.deinit();
    try testing.expectEqualStrings(row.id, parsed.value.id);
    try testing.expectEqualStrings(row.forked_from, parsed.value.forked_from);
    try testing.expectEqual(row.forked_at, parsed.value.forked_at);
    try testing.expectEqualStrings("live", parsed.value.live);
    try testing.expectEqualStrings("intact", parsed.value.chain);
    try testing.expectEqual(@as(u64, 3), parsed.value.turns);

    const newer =
        \\{"id":"01JQAAAAAAAAAAAAAAAAAAAAAA","live":"idle","something_new":{"a":1}}
    ;
    var older = try SessionRow.fromJson(gpa, newer);
    defer older.deinit();
    try testing.expectEqualStrings("idle", older.value.live);
    try testing.expectEqualStrings("unreadable", older.value.chain);
    try testing.expect(!older.value.readable == false);
}

test "a row's chain default is never a pass, and every verdict has a name" {
    const bare = SessionRow{ .id = "x" };
    try testing.expectEqualStrings(@tagName(chain.Verdict.unreadable), bare.chain);
    try testing.expect(!std.mem.eql(u8, bare.chain, @tagName(chain.Verdict.intact)));

    var names: [std.enums.values(chain.Verdict).len][]const u8 = undefined;
    for (std.enums.values(chain.Verdict), 0..) |verdict, index| {
        names[index] = verdictName(verdict);
        for (names[0..index]) |other| try testing.expect(!std.mem.eql(u8, other, names[index]));
    }
}

test "an exchange sends one line and reads every line back, and stops when told" {
    var out_buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    const greeting = std.fmt.comptimePrint(
        "{s}{d}\n",
        .{ Greeting.answer_prefix, protocol_version },
    );
    const script = greeting ++
        "0\t{\"chock\":1}\n" ++
        "128\t{\"id\":128}\n" ++
        "256\t{\"id\":256}\n";
    var reader = std.Io.Reader.fixed(script);

    const Collected = struct {
        ids: [8]u64 = @splat(0),
        count: usize = 0,
        stop_after: usize = 8,

        fn take(self: *@This(), reply: Reply) anyerror!bool {
            self.ids[self.count] = reply.record.id;
            self.count += 1;
            return self.count < self.stop_after;
        }
    };

    var all = Collected{};
    var said: Handshake = .{ .unreadable = "" };
    try exchange(&reader, &writer, .{ .watch = .{
        .project = "/p",
        .session = "01JQ" ++ @as([22]u8, @splat('A')),
        .after = 0,
    } }, &said, &all, Collected.take);

    try testing.expectEqualStrings(
        std.fmt.comptimePrint("{s}{d}\n", .{ Greeting.ask_prefix, protocol_version }) ++
            "watch /p\t01JQAAAAAAAAAAAAAAAAAAAAAA\t0\n",
        writer.buffered(),
    );
    try testing.expectEqual(protocol_version, said.agreed);
    try testing.expectEqual(@as(usize, 3), all.count);
    try testing.expectEqual(@as(u64, 0), all.ids[0]);
    try testing.expectEqual(@as(u64, 256), all.ids[2]);

    var early = Collected{ .stop_after = 2 };
    var again = std.Io.Reader.fixed(script);
    var second_out: [256]u8 = undefined;
    var second = std.Io.Writer.fixed(&second_out);
    try exchange(&again, &second, .{ .list = .{ .project = "/p" } }, &said, &early, Collected.take);
    try testing.expectEqual(@as(usize, 2), early.count);
}

test "an exchange asks nothing of a daemon whose number this build does not speak" {
    const Nothing = struct {
        fn take(_: *@This(), _: Reply) anyerror!bool {
            return true;
        }
    };
    var nothing = Nothing{};

    const older = std.fmt.comptimePrint("{s}{d}\n", .{ Greeting.answer_prefix, protocol_version + 1 });
    var reader = std.Io.Reader.fixed(older ++ "0\t{\"chock\":1}\n");
    var out_buffer: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&out_buffer);

    var said: Handshake = .{ .unreadable = "" };
    try testing.expectError(error.HandshakeFailed, exchange(
        &reader,
        &writer,
        .{ .list = .{ .project = "/p" } },
        &said,
        &nothing,
        Nothing.take,
    ));

    try testing.expect(!said.ok());
    try testing.expectEqual(protocol_version, said.mismatch.ours);
    try testing.expectEqual(protocol_version + 1, said.mismatch.theirs);

    try testing.expectEqualStrings(
        std.fmt.comptimePrint("{s}{d}\n", .{ Greeting.ask_prefix, protocol_version }),
        writer.buffered(),
    );

    var text_buffer: [512]u8 = undefined;
    var text = std.Io.Writer.fixed(&text_buffer);
    try handshakeRefusal(&text, .{ .unix = "/run/user/1000/chock/daemon.sock" }, said);
    const sentence = text.buffered();
    var ours_text: [16]u8 = undefined;
    var theirs_text: [16]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        sentence,
        try std.fmt.bufPrint(&ours_text, "{d}", .{protocol_version}),
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        sentence,
        try std.fmt.bufPrint(&theirs_text, "{d}", .{protocol_version + 1}),
    ) != null);
    try testing.expect(std.mem.indexOf(u8, sentence, "daemon.sock") != null);
}

test "a daemon older than the greeting is named as one, and so is anything else" {
    const Nothing = struct {
        fn take(_: *@This(), _: Reply) anyerror!bool {
            return true;
        }
    };
    var nothing = Nothing{};
    var out_buffer: [256]u8 = undefined;

    {
        var reader = std.Io.Reader.fixed(error_prefix ++ no_verb_text ++ "\n");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings(no_verb_text, said.refused);

        var text_buffer: [1024]u8 = undefined;
        var text = std.Io.Writer.fixed(&text_buffer);
        try handshakeRefusal(&text, .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } }, said);
        try testing.expect(std.mem.indexOf(u8, text.buffered(), no_verb_text) != null);
        try testing.expect(std.mem.indexOf(u8, text.buffered(), "10.0.0.4:7373") != null);
    }

    {
        var reader = std.Io.Reader.fixed(error_prefix ++ "this daemon serves the user that started it\n");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings("this daemon serves the user that started it", said.refused);
    }

    {
        var reader = std.Io.Reader.fixed("HTTP/1.1 400 Bad Request\n");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings("HTTP/1.1 400 Bad Request", said.unreadable);
    }

    {
        var reader = std.Io.Reader.fixed("");
        var writer = std.Io.Writer.fixed(&out_buffer);
        var said: Handshake = .{ .unreadable = "" };
        try testing.expectError(error.HandshakeFailed, exchange(
            &reader,
            &writer,
            .{ .list = .{ .project = "/p" } },
            &said,
            &nothing,
            Nothing.take,
        ));
        try testing.expectEqualStrings("", said.unreadable);
    }
}

test "a greeting round trips, each side has its own spelling, and only equal numbers agree" {
    var buffer: [128]u8 = undefined;

    inline for ([_]Greeting.Side{ .ask, .answer }) |side| {
        const other: Greeting.Side = if (side == .ask) .answer else .ask;
        for ([_]u32{ 0, 1, protocol_version, 4_294_967_295 }) |number| {
            var writer = std.Io.Writer.fixed(&buffer);
            try (Greeting{ .version = number }).write(side, &writer);
            const line = writer.buffered();
            try testing.expectEqual(@as(u8, '\n'), line[line.len - 1]);

            const bare = line[0 .. line.len - 1];
            try testing.expectEqual(number, (try Greeting.parse(side, bare)).version);
            try testing.expectError(error.NotAGreeting, Greeting.parse(other, bare));
        }
    }

    for ([_][]const u8{
        "",
        "hello",
        "hello chock-control",
        "hello chock-control ",
        "hello chock-control one",
        "hello chock-control -1",
        "hello chock-control 4294967296",
        "hello something-else 1",
        "start /p\tmessage",
        error_prefix ++ "no",
    }) |line| {
        try testing.expectError(error.NotAGreeting, Greeting.parse(.ask, line));
    }
    try testing.expectError(error.NotAGreeting, Greeting.parse(.answer, ok_prefix ++ "answered"));

    try testing.expect(accepts(protocol_version, protocol_version));
    try testing.expect(!accepts(protocol_version, protocol_version + 1));
    try testing.expect(!accepts(protocol_version + 1, protocol_version));
    try testing.expect(!accepts(1, 0));
    try testing.expect(!accepts(0, 1));
}

test "the version on the wire is the protocol's own number and not the program's" {
    try testing.expectEqual(u32, @TypeOf(protocol_version));
    try testing.expectEqual(@as(u32, 1), protocol_version);

    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try writeMismatch(&writer, 1, 7);
    const said = writer.buffered();
    try testing.expect(std.mem.startsWith(u8, said, error_prefix));
    try testing.expect(std.mem.indexOf(u8, said, " 1 ") != null);
    try testing.expect(std.mem.indexOf(u8, said, " 7") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said, "\n"));

    try testing.expect(std.mem.indexOf(u8, no_greeting_text, Greeting.ask_prefix) != null);
}

test "a daemon that is not running is a plain refusal that names what to do" {
    var buffer: [512]u8 = undefined;

    {
        var writer = std.Io.Writer.fixed(&buffer);
        try refusalFor(&writer, .{ .unix = "/run/user/1000/chock/daemon.sock" }, error.NotListening);
        const said = writer.buffered();
        try testing.expect(std.mem.indexOf(u8, said, "unix:/run/user/1000/chock/daemon.sock") != null);
        try testing.expect(std.mem.indexOf(u8, said, "chock daemon") != null);
    }
    {
        var writer = std.Io.Writer.fixed(&buffer);
        try refusalFor(&writer, .{ .ip = .{ .host = "10.0.0.4", .port = 7373 } }, error.NotListening);
        const said = writer.buffered();
        try testing.expect(std.mem.indexOf(u8, said, "10.0.0.4:7373") != null);
        try testing.expect(std.mem.indexOf(u8, said, "--host") != null);
    }

    inline for (@typeInfo(Address.ConnectError).error_set.error_names.?) |one| {
        var writer = std.Io.Writer.fixed(&buffer);
        const err = @field(Address.ConnectError, one);
        try refusalFor(&writer, .{ .ip = .{ .host = "127.0.0.1", .port = 7373 } }, err);
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), "127.0.0.1:7373") != null);
        try testing.expect(writer.buffered().len > 20);
    }
}

test "a daemon somebody stopped reads as one that is not listening" {
    // Driven through `classify`: a real refused unix connect prints a stack trace to stderr.
    const unix = Address{ .unix = "/run/user/1000/chock/daemon.sock" };
    const ip = Address{ .ip = .{ .host = "127.0.0.1", .port = 7373 } };

    try testing.expectEqual(Address.ConnectError.NotListening, unix.classify(error.Unexpected));
    try testing.expectEqual(Address.ConnectError.NotListening, unix.classify(error.FileNotFound));
    try testing.expectEqual(Address.ConnectError.NotListening, ip.classify(error.ConnectionRefused));

    try testing.expectEqual(Address.ConnectError.Unreachable, ip.classify(error.Unexpected));
    try testing.expectEqual(Address.ConnectError.Unreachable, ip.classify(error.NetworkDown));

    try testing.expectEqual(Address.ConnectError.AccessDenied, unix.classify(error.AccessDenied));
    try testing.expectEqual(Address.ConnectError.AccessDenied, unix.classify(error.PermissionDenied));
}

test "the socket path is under the state directory and nowhere near a project" {
    const gpa = testing.allocator;
    const path = try socketPathIn(gpa, "/home/ross/.local/state/chock");
    defer gpa.free(path);
    try testing.expectEqualStrings("/home/ross/.local/state/chock/" ++ socket_name, path);
}

/// Below `TMPDIR`: `std.testing.tmpDir`'s own path is already too long on macOS in a Nix build.
const BoundBench = struct {
    parent: std.Io.Dir,
    sub: [sub_len]u8,
    dir_path: [std.fs.max_path_bytes]u8,
    dir_len: usize,

    const random_bytes_count = 12;
    const sub_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

    fn open(io: std.Io) !BoundBench {
        const root = root: {
            const given = std.process.Environ.getPosix(testing.environ, "TMPDIR") orelse "/tmp";
            const trimmed = std.mem.trimEnd(u8, given, "/");
            break :root if (trimmed.len == 0) "/" else trimmed;
        };

        var self: BoundBench = undefined;
        var random_bytes: [random_bytes_count]u8 = undefined;
        io.random(&random_bytes);
        _ = std.base64.url_safe.Encoder.encode(&self.sub, &random_bytes);

        const written = try std.fmt.bufPrint(&self.dir_path, "{s}/{s}", .{ root, &self.sub });
        self.dir_len = written.len;
        if (self.dir_len + 2 > max_socket_path) return error.SkipZigTest;

        self.parent = try std.Io.Dir.cwd().openDir(io, root, .{});
        errdefer self.parent.close(io);
        var made = try self.parent.createDirPathOpen(io, &self.sub, .{});
        made.close(io);
        return self;
    }

    fn pathOfLength(self: *const BoundBench, buffer: []u8, want: usize) []const u8 {
        const path = buffer[0..want];
        @memcpy(path[0..self.dir_len], self.dir_path[0..self.dir_len]);
        path[self.dir_len] = '/';
        @memset(path[self.dir_len + 1 ..], 'n');
        return path;
    }

    fn cleanup(self: *BoundBench, io: std.Io) void {
        self.parent.deleteTree(io, &self.sub) catch {};
        self.parent.close(io);
        self.* = undefined;
    }
};

test "the daemon binds and is reached at exactly the bound, and refuses one byte more" {
    // Both ends: a wrong bound passes here on Linux and ends the test binary on Darwin.
    const io = testing.io;

    var bench = try BoundBench.open(io);
    defer bench.cleanup(io);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const at_bound = bench.pathOfLength(&buffer, max_socket_path);
    try testing.expectEqual(max_socket_path, at_bound.len);

    var listener = try (Address{ .unix = at_bound }).listen(io);
    defer listener.close(io);

    const stream = try (Address{ .unix = at_bound }).connect(io);
    stream.close(io);

    var over_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const over = bench.pathOfLength(&over_buffer, max_socket_path + 1);
    try testing.expectError(
        Address.ListenError.PathTooLong,
        (Address{ .unix = over }).listen(io),
    );
    try testing.expectError(
        Address.ConnectError.PathTooLong,
        (Address{ .unix = over }).connect(io),
    );
}

test "the refusal a person reads names this platform's own bound and not 108" {
    var buffer: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    try refusalFor(&writer, .{ .unix = "/tmp/x.sock" }, error.PathTooLong);

    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        writer.buffered(),
        try std.fmt.bufPrint(&number, "{d}", .{max_socket_path}),
    ) != null);
}

test "the bound always leaves room inside sun_path for the closing zero" {
    // Strict: a path that fills a 104 byte `sun_path` can be named only without a terminator.
    try testing.expect(max_socket_path < sun_path_bytes);
}
