//! The daemon's control protocol: one greeting line, one request line, and a reply
//! of lines that ends when the connection closes. A reader must tolerate unknown
//! fields; a changed verb, field order or separator must move `protocol_version`.

const std = @import("std");
const builtin = @import("builtin");

const chain = @import("chain.zig");
const event = @import("event.zig");
const storage = @import("storage.zig");

pub const default_port: u16 = 7373;

pub const default_host = "127.0.0.1";

pub const socket_name = "daemon.sock";

pub const address_env = "CHOCK_DAEMON";

/// Never in a project: that is a path a sandboxed tool call can name.
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

        // In a bracketed IPv6 host the port separator is the colon after the
        // closing bracket, never the last colon in the string.
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

    /// A unix connect to a stale socket file gives `ECONNREFUSED`, which
    /// `UnixAddress.ConnectError` has no member for, so it arrives as `Unexpected`.
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

/// One byte below `sun_path`, so the name has room for its closing zero. Never use
/// `UnixAddress.max_len`: it is a flat 108, unchecked, and `sun_path` is 104 on Darwin.
pub const max_socket_path: usize = sun_path_bytes - 1;

const sun_path_bytes: usize = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

pub fn unixAddress(path: []const u8) error{PathTooLong}!std.Io.net.UnixAddress {
    if (path.len > max_socket_path) return error.PathTooLong;
    return std.Io.net.UnixAddress.init(path) catch error.PathTooLong;
}

/// Null when the kernel will not say. A TCP peer carries no identity, so it is null.
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
            // A TCP socket does not refuse this call: `getsockopt` succeeds and
            // fills in a pid of zero and a uid of (uid_t)-1, meaning no credential.
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

/// A peer the kernel will not name is refused: an absent answer is never permissive.
pub fn peerAllowed(uid: ?std.posix.uid_t, owner_uid: std.posix.uid_t) bool {
    const said = uid orelse return false;
    return said == owner_uid;
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

/// The wire's own number, never the program's. It moves when a client built
/// against the old number would misread the new one, and at no other time.
pub const protocol_version: u32 = 1;

pub const protocol_name = "chock-control";

/// The client speaks first and waits. A daemon that closes a connection with a
/// request still unread sends a reset, and a reset discards what it already wrote.
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

/// Equal, and nothing else. A window of numbers promises this build was run
/// against every number in it, and it never was.
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

/// The check is `accepts` and never the shape of the reply: a real `pcscd` answers
/// a version mismatch with a success code, which a status check reads as agreement.
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
    read,
    list,
    watch,
    answer,
};

/// `read` is space separated and the rest are tab separated. Both spellings are
/// fixed: `src/detach.zig` already speaks them.
pub const Request = union(Verb) {
    start: Start,
    adopt: Adopt,
    read: Read,
    list: List,
    watch: Watch,
    answer: Answer_,

    pub const Start = struct { project: []const u8, message: []const u8 };
    pub const Adopt = struct { project: []const u8, session: []const u8 };
    pub const Read = struct { session: []const u8, after: u64 };
    pub const List = struct { project: []const u8 };
    pub const Watch = struct { project: []const u8, session: []const u8, after: u64 };
    pub const Answer_ = struct {
        project: []const u8,
        session: []const u8,
        request_id: u64,
        decision: Answer,
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
        };
    }

    pub fn write(self: Request, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .start => |one| try writer.print("start {s}\t{s}\n", .{ one.project, one.message }),
            .adopt => |one| try writer.print("adopt {s}\t{s}\n", .{ one.project, one.session }),
            .read => |one| try writer.print("read {s} {d}\n", .{ one.session, one.after }),
            .list => |one| try writer.print("list {s}\n", .{one.project}),
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
        }
    }
};

pub fn verbOf(request: []const u8) ?struct { verb: Verb, rest: []const u8 } {
    inline for (std.enums.values(Verb)) |verb| {
        const prefix = @tagName(verb) ++ " ";
        if (std.mem.startsWith(u8, request, prefix)) {
            return .{ .verb = verb, .rest = request[prefix.len..] };
        }
    }
    return null;
}

pub const no_verb_text = text: {
    var built: []const u8 = "the request is none of";
    for (std.enums.values(Verb), 0..) |verb, index| {
        if (index != 0) built = built ++ (if (index + 1 == std.enums.values(Verb).len) " and" else ",");
        built = built ++ " `" ++ @tagName(verb) ++ "`";
    }
    break :text built;
};

/// Exactly `count` fields: an extra field is refused, never quietly ignored.
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

/// Two members, which is the whole trust boundary of this protocol. A client that
/// could name `allowed_by_policy` would be forging somebody else's answer.
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

/// Never an alias of a local struct, or a field added locally would change the
/// wire. Every field has a default, and no default is a pass.
pub const SessionRow = struct {
    id: []const u8,
    started_ms: u64 = 0,
    model: []const u8 = "",
    model_count: usize = 0,
    model_alias: []const u8 = "",
    /// A lock that could not be tested says `unknown`, never `idle`.
    live: []const u8 = "unknown",
    end: ?[]const u8 = null,
    turns: u64 = 0,
    input_tokens: u64 = 0,
    output_tokens: u64 = 0,
    amount: f64 = 0,
    currency: []const u8 = "",
    /// False as soon as one turn could not be priced. The number is not a total.
    spend_enforceable: bool = true,
    readable: bool = true,
    /// False when the log could not be read to its end. The numbers are a floor.
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
    /// Inclusive: the first event read back is one the client has, and is dropped.
    after: u64 = 0,
    ended: bool = false,
    sent: usize = 0,

    pub const Error = std.Io.Writer.Error || storage.ReplayError;

    /// Zero is the header line's own byte offset, which is what a verifier wants.
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

        var any = false;
        var first = true;
        var this_call: usize = 0;
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();

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
            if (parsed.value.event == .session_end) self.ended = true;
            if (limit != 0 and this_call >= limit) break;
        }
        return any;
    }
};

/// The request is not written until the greeting agreed. `said` points into
/// `reader`'s own buffer. `each` answers false to stop reading.
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
        // `takeDelimiter` and never `takeDelimiterExclusive`: the exclusive one
        // stops before the line break, so a second call gives an empty line for ever.
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

    var reached = std.EnumSet(std.meta.Tag(event.ApprovalDecision)).initEmpty();
    for (std.enums.values(Answer)) |one| reached.insert(std.meta.activeTag(one.decision()));
    try testing.expect(reached.contains(.approved_by_user));
    try testing.expect(reached.contains(.refused_by_user));
    try testing.expect(!reached.contains(.allowed_by_policy));
    try testing.expect(!reached.contains(.approved_by_review));
    try testing.expect(!reached.contains(.unknown));
    try testing.expectEqual(@as(usize, 2), reached.count());

    inline for (@typeInfo(event.ApprovalDecision).@"union".fields) |one| {
        const permitted = std.mem.eql(u8, one.name, "approved_by_user") or
            std.mem.eql(u8, one.name, "refused_by_user");
        if (!permitted) try testing.expect(Answer.parse(one.name) == null);
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
        Request.parse("answer /p\t01JQ" ++ "A" ** 22 ++ "\t128\tallowed_by_policy"),
    );
}

test "every verb round trips from a request to a line and back" {
    const id = "01JQ" ++ "A" ** 22;
    const requests = [_]Request{
        .{ .start = .{ .project = "/home/ross/chock", .message = "fix the parser please" } },
        .{ .adopt = .{ .project = "/home/ross/chock", .session = id } },
        .{ .read = .{ .session = id, .after = 0 } },
        .{ .read = .{ .session = id, .after = 4096 } },
        .{ .list = .{ .project = "/home/ross/chock" } },
        .{ .watch = .{ .project = "/home/ross/chock", .session = id, .after = 128 } },
        .{ .answer = .{ .project = "/home/ross/chock", .session = id, .request_id = 9, .decision = .yes } },
        .{ .answer = .{ .project = "/home/ross/chock", .session = id, .request_id = 9, .decision = .no } },
    };

    var seen = std.EnumSet(Verb).initEmpty();
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
        .id = "01JQ" ++ "A" ** 22,
        .started_ms = 1_700_000_000_000,
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
        .session = "01JQ" ++ "A" ** 22,
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
    try testing.expect(protocol_version >= 1);

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

    inline for (@typeInfo(Address.ConnectError).error_set.?) |one| {
        var writer = std.Io.Writer.fixed(&buffer);
        const err = @field(Address.ConnectError, one.name);
        try refusalFor(&writer, .{ .ip = .{ .host = "127.0.0.1", .port = 7373 } }, err);
        try testing.expect(std.mem.indexOf(u8, writer.buffered(), "127.0.0.1:7373") != null);
        try testing.expect(writer.buffered().len > 20);
    }
}

test "a daemon somebody stopped reads as one that is not listening" {
    // Driven through `classify` and not a real refused connect: a refused unix
    // connect makes the standard library print a stack trace on standard error.
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

/// A directory below `TMPDIR`, because `std.testing.tmpDir` puts its directory
/// below the build directory, which on macos in a Nix build is already too long.
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
    // Both ends, because `std` copies the path into `sun_path` at both. A wrong
    // bound passes here on Linux and ends the test binary on Darwin.
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
    // Strict: `std` copies past the end of a 104 byte `sun_path` for a path of 105
    // to 108, and a path that fills the field can be named only without a terminator.
    try testing.expect(max_socket_path < sun_path_bytes);
}
