//! A real `git push`, driven by a real `git`, against a server in this file,
//! with the password answered off a real socket. Nothing here reaches a real
//! host or needs anybody's credential.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const askpass = chock_broker.askpass;
const table = chock_policy.table;
const testing = std.testing;

const chock_path = @import("chock_path").chock_path;
const git_path = @import("chock_path").git_path;

/// A run of characters no ordinary text holds, so finding it in a log proves a leak.
const the_password = "ghp_zzqqxx0123456789abcdefghijklmnopqrstuv";

/// In the remote URL on purpose, since `askpass.Asker` answers a password and never a user name.
const the_user = "ross";

/// The host labels are reversed, which is what `askpass.actionInto` builds.
const permit_loopback: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.password.127.0.0.1", .decision = .allow },
    \\        },
    \\    },
    \\}
;

const Pushed = struct {
    gpa: std.mem.Allocator,
    said: []u8,
    log: []u8,
    authorization: []u8,
    prompt: []u8,
    answered: usize,
    refused: usize,
    strangers: usize,
    requests: usize,

    fn deinit(self: *Pushed) void {
        self.gpa.free(self.said);
        self.gpa.free(self.log);
        self.gpa.free(self.authorization);
        self.gpa.free(self.prompt);
    }

    /// Every test here wants git to ask for the password and for nothing
    /// else. A bare `expect` on a count leaves nothing to read: which leg of
    /// the push stopped early is in these numbers and in what git printed.
    fn expectAsked(self: *const Pushed, answered: usize, refused: usize) !void {
        if (!std.mem.startsWith(u8, self.prompt, "Password for")) {
            return self.report("the helper was asked for something other than a password", answered, refused);
        }
        if (self.answered == answered and self.refused == refused) return;
        return self.report("the helper was asked for something else than this test expects", answered, refused);
    }

    fn expectCredential(self: *const Pushed) !void {
        if (self.authorization.len != 0) return;
        return self.report("no credential reached the server", self.answered, self.refused);
    }

    /// The evidence goes through the comparison the framework prints, since no
    /// source here may name standard error.
    fn report(self: *const Pushed, what: []const u8, answered: usize, refused: usize) !void {
        var wanted: std.Io.Writer.Allocating = .init(self.gpa);
        defer wanted.deinit();
        try wanted.writer.print(
            \\git_push: the push asks for the password and goes through
            \\  the prompt the helper sent: Password for
            \\  answered {d}, refused {d}
            \\
        , .{ answered, refused });

        var found: std.Io.Writer.Allocating = .init(self.gpa);
        defer found.deinit();
        try found.writer.print(
            \\git_push: {s}
            \\  the prompt the helper sent: {s}
            \\  answered {d}, refused {d}, strangers {d}, requests {d}
            \\  git said: {s}
            \\
        , .{ what, self.prompt, self.answered, self.refused, self.strangers, self.requests, self.said });
        if (std.mem.startsWith(u8, self.prompt, "Username for")) {
            try found.writer.writeAll(
                \\  This git asked for a user name, and the remote URL carries one.
                \\  git 2.56.0 against curl 8.23.0 does that, and against curl 8.22.0
                \\  it asks for the password. The helper refuses a user name on
                \\  purpose, so the push stops at the first question. A session
                \\  gives git `credential.<url>.username`, which stops the question.
                \\
            );
        }

        try testing.expectEqualStrings(wanted.written(), found.written());
        return error.PushDidNotAskForThePassword;
    }
};

/// Three requests, not two: `curl` answers the first challenge itself, with an empty password.
const Server = struct {
    net_server: std.Io.net.Server,
    io: std.Io,
    port: u16,
    authorization: [512]u8 = undefined,
    authorization_len: usize = 0,
    requests: usize = 0,

    fn open(io: std.Io) !Server {
        const wanted = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        const net_server = try wanted.listen(io, .{ .reuse_address = true });
        return .{
            .net_server = net_server,
            .io = io,
            .port = net_server.socket.address.getPort(),
        };
    }

    fn close(self: *Server) void {
        self.net_server.deinit(self.io);
    }

    /// Polled and not blocked on, since a block on `accept` would leave the askpass helper unread.
    fn serve(self: *Server, timeout_ms: i32) bool {
        if (!chock_broker.socket.readable(self.net_server.socket.handle, timeout_ms)) return false;

        var stream = self.net_server.accept(self.io) catch return false;
        defer stream.close(self.io);
        var buffer: [8192]u8 = undefined;
        var stream_reader = stream.reader(self.io, &buffer);
        const reader = &stream_reader.interface;
        const request = readHttpHead(reader, stream.socket.handle) catch return false;
        defer testing.allocator.free(request);
        self.requests += 1;

        if (headerIn(request, "authorization: ")) |value| {
            // The challenge stands until a password arrives, or `git` sends `ross:` and gives up.
            if (carriesPassword(value)) {
                const room = @min(value.len, self.authorization.len);
                @memcpy(self.authorization[0..room], value[0..room]);
                self.authorization_len = room;
            }
        }

        // A `401` with no challenge makes `git` give up without ever running the helper.
        const reply = if (self.authorization_len == 0)
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Basic realm=\"chock\"\r\n" ++
                "Content-Length: 0\r\n" ++
                "Connection: close\r\n\r\n"
        else
            "HTTP/1.1 403 Forbidden\r\n" ++
                "Content-Length: 0\r\n" ++
                "Connection: close\r\n\r\n";
        _ = chock_broker.socket.writeAll(stream.socket.handle, reply);
        return true;
    }

    fn readHttpHead(reader: *std.Io.Reader, handle: std.posix.fd_t) ![]u8 {
        var head: std.Io.Writer.Allocating = .init(testing.allocator);
        errdefer head.deinit();
        while (true) {
            // Every peek below needs bytes off the socket, so a peer that
            // connects and then says nothing cannot hold this test.
            if (!chock_broker.socket.readable(handle, 2000)) return error.NothingSaid;
            const buffered = reader.peekGreedy(4) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                else => return err,
            };
            if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |end| {
                try head.writer.writeAll(buffered[0 .. end + 4]);
                reader.toss(end + 4);
                return head.toOwnedSlice();
            }
            const consume = buffered.len -| 3;
            try head.writer.writeAll(buffered[0..consume]);
            reader.toss(consume);
        }
    }

    fn authorizationValue(self: *const Server) []const u8 {
        return self.authorization[0..self.authorization_len];
    }
};

fn headerIn(request: []const u8, name_lower: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, request, "\r\n");
    while (lines.next()) |line| {
        if (line.len < name_lower.len) continue;
        var folded: [64]u8 = undefined;
        if (name_lower.len > folded.len) return null;
        for (line[0..name_lower.len], folded[0..name_lower.len]) |byte, *slot| {
            slot.* = std.ascii.toLower(byte);
        }
        if (!std.mem.eql(u8, folded[0..name_lower.len], name_lower)) continue;
        return line[name_lower.len..];
    }
    return null;
}

fn carriesPassword(header: []const u8) bool {
    const lead = "Basic ";
    if (!std.mem.startsWith(u8, header, lead)) return false;
    const encoded = std.mem.trim(u8, header[lead.len..], " \t");
    var decoded: [512]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    const room = decoder.calcSizeForSlice(encoded) catch return false;
    if (room > decoded.len) return false;
    decoder.decode(decoded[0..room], encoded) catch return false;
    const colon = std.mem.indexOfScalar(u8, decoded[0..room], ':') orelse return false;
    return colon + 1 < room;
}

const Ask = struct {
    typed: []const u8 = the_password,
    policy: [:0]const u8 = permit_loopback,
};

fn push(gpa: std.mem.Allocator, io: std.Io, ask: Ask) !Pushed {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try absoluteDirPath(io, &path_buffer, tmp.dir);

    var server = try Server.open(io);
    defer server.close();

    const repo = try std.fmt.allocPrint(gpa, "{s}/repo", .{dir});
    defer gpa.free(repo);
    try std.Io.Dir.createDirAbsolute(io, repo, .fromMode(0o700));

    const remote = try std.fmt.allocPrint(
        gpa,
        "http://{s}@127.0.0.1:{d}/p.git",
        .{ the_user, server.port },
    );
    defer gpa.free(remote);

    const socket_path = try std.fmt.allocPrint(gpa, "{s}/cred/{s}", .{ dir, askpass.socket_name });
    defer gpa.free(socket_path);

    var endpoint = try askpass.Endpoint.open(io, socket_path, null);
    defer endpoint.close(io);

    const link_path = try std.fmt.allocPrint(gpa, "{s}/cred/{s}", .{ dir, askpass.link_name });
    defer gpa.free(link_path);
    const chock_absolute = try std.Io.Dir.realPathFileAlloc(.cwd(), io, chock_path, gpa);
    defer gpa.free(chock_absolute);
    try askpass.link(io, link_path, chock_absolute);

    var backing = try chock_proto.storage.Memory.init(gpa, "01GITPUSH");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const policy = try table.Table.parse(gpa, ask.policy, null);
    defer table.Table.destroy(gpa, policy);

    var grants: [1]askpass.Grant = .{.{ .host = "127.0.0.1", .secret = ask.typed }};
    const asker = askpass.Asker{
        .grants = .{ .entries = if (ask.typed.len == 0) &.{} else &grants },
        .table = policy,
        .chain = &.{"coder"},
        .agent_kind = "coder",
        .model = "main",
    };

    var env = try std.testing.environ.createMap(gpa);
    defer env.deinit();
    try env.put("LC_ALL", "C");
    try env.put("GIT_CONFIG_GLOBAL", "/dev/null");
    try env.put("GIT_CONFIG_SYSTEM", "/dev/null");
    try env.put("GIT_TERMINAL_PROMPT", "0");
    try env.put("GIT_ASKPASS", link_path);
    try env.put(askpass.env_socket, socket_path);
    try env.put("GIT_AUTHOR_NAME", "chock");
    try env.put("GIT_AUTHOR_EMAIL", "chock@example.com");
    try env.put("GIT_COMMITTER_NAME", "chock");
    try env.put("GIT_COMMITTER_EMAIL", "chock@example.com");

    try run(gpa, io, repo, &env, &.{ git_path, "init", "-q", "-b", "main" });
    try writeFileAbsolute(io, try joined(gpa, repo, "a"), "one\n");
    try run(gpa, io, repo, &env, &.{ git_path, "add", "a" });
    try run(gpa, io, repo, &env, &.{ git_path, "commit", "-q", "-m", "one" });

    const argv = [_][]const u8{ git_path, "push", remote, "HEAD:refs/heads/main" };
    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .cwd = .{ .path = repo },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });

    var said: std.Io.Writer.Allocating = .init(gpa);
    errdefer said.deinit();

    // A caller that blocked on `git` would deadlock, since `git` waits on the helper.
    //
    // **Both sockets are served until `git` is gone, and not for a fixed
    // number of turns.** A count is a budget in disguise: a loaded machine
    // spends longer on the first two requests than the turns allow, the helper
    // then waits on an endpoint nobody steps, and git gives up with no
    // password at all. `git` and the helper hold the only other ends of these
    // two pipes, so the end of both streams is the whole tree leaving. The
    // deadline ends a run that is wedged, and it says so instead of hanging.
    const deadline_ms = 120_000;
    const started = std.Io.Clock.Timestamp.now(io, .awake);
    var ended: usize = 0;
    var out_ended = false;
    var err_ended = false;
    while (ended < 2) {
        _ = server.serve(5);
        // Poll briefly when idle, but allow the helper time to send its frame
        // after connecting, especially when the test runner is under load.
        if (chock_broker.socket.readable(endpoint.server.socket.handle, 20)) {
            _ = try endpoint.step(gpa, io, &locked, asker, 1000);
        }
        if (!out_ended and try drain(child.stdout.?.handle, &said)) {
            out_ended = true;
            ended += 1;
        }
        if (!err_ended and try drain(child.stderr.?.handle, &said)) {
            err_ended = true;
            ended += 1;
        }
        if (ended < 2 and started.untilNow(io).raw.toMilliseconds() > deadline_ms) {
            child.kill(io);
            return error.GitNeverFinished;
        }
    }
    const term = child.wait(io) catch return error.GitNeverFinished;
    _ = term;

    return .{
        .gpa = gpa,
        .said = try said.toOwnedSlice(),
        .log = try gpa.dupe(u8, backing.bytes.items),
        .authorization = try gpa.dupe(u8, server.authorizationValue()),
        .prompt = try gpa.dupe(u8, firstPrompt(&endpoint)),
        .answered = endpoint.answered,
        .refused = endpoint.refused,
        .strangers = endpoint.strangers,
        .requests = server.requests,
    };
}

/// Takes what one of git's streams holds, and says whether that stream ended.
fn drain(handle: std.Io.File.Handle, into: *std.Io.Writer.Allocating) !bool {
    if (!chock_broker.socket.readable(handle, 0)) return false;
    var scratch: [4096]u8 = undefined;
    const read = std.posix.read(handle, &scratch) catch return true;
    if (read == 0) return true;
    try into.writer.writeAll(scratch[0..read]);
    return false;
}

/// What the helper asked for, which says whether it reached the socket at all.
fn firstPrompt(endpoint: *const askpass.Endpoint) []const u8 {
    if (endpoint.kept_count == 0) return "";
    return endpoint.kept[0][0..endpoint.kept_lens[0]];
}

fn joined(gpa: std.mem.Allocator, dir: []const u8, leaf: []const u8) ![]u8 {
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, leaf });
}

fn writeFileAbsolute(io: std.Io, path: []u8, bytes: []const u8) !void {
    defer testing.allocator.free(path);
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    var buffer: [64]u8 = undefined;
    var writer = file.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    cwd: []const u8,
    env: *std.process.Environ.Map,
    argv: []const []const u8,
) !void {
    _ = gpa;
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .environ_map = env,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.GitFailed,
        else => return error.GitFailed,
    }
}

fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) ![]const u8 {
    return chock_proto.log.absoluteDirPath(io, buffer, dir);
}

fn decodeBasic(gpa: std.mem.Allocator, header: []const u8) ![]u8 {
    const lead = "Basic ";
    if (!std.mem.startsWith(u8, header, lead)) return error.NotBasic;
    const encoded = std.mem.trim(u8, header[lead.len..], " \t");
    const decoder = std.base64.standard.Decoder;
    const room = try decoder.calcSizeForSlice(encoded);
    const out = try gpa.alloc(u8, room);
    errdefer gpa.free(out);
    try decoder.decode(out, encoded);
    return out;
}

test "an approved push prompts the person and the typed password reaches git" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var pushed = try push(gpa, io, .{});
    defer pushed.deinit();

    try pushed.expectAsked(1, 0);
    try pushed.expectCredential();
    const credential = try decodeBasic(gpa, pushed.authorization);
    defer gpa.free(credential);
    const expected = the_user ++ ":" ++ the_password;
    try testing.expectEqualStrings(expected, credential);
}

test "the password a person types is in neither the log nor anything git printed" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var pushed = try push(gpa, io, .{});
    defer pushed.deinit();

    try pushed.expectCredential();

    try testing.expect(std.mem.indexOf(u8, pushed.log, the_password) == null);
    try testing.expect(std.mem.indexOf(u8, pushed.said, the_password) == null);

    const encoded = std.mem.trim(u8, pushed.authorization["Basic ".len..], " \t");
    try testing.expect(encoded.len != 0);
    try testing.expect(std.mem.indexOf(u8, pushed.log, encoded) == null);
    try testing.expect(std.mem.indexOf(u8, pushed.said, encoded) == null);

    try testing.expect(std.mem.indexOf(u8, pushed.log, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, pushed.log, "127.0.0.1") != null);
}

test "a push nobody typed a password for sends no credential at all" {
    if (git_path.len == 0) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var pushed = try push(gpa, io, .{ .typed = "" });
    defer pushed.deinit();

    try pushed.expectAsked(0, 1);
    try testing.expectEqualStrings("", pushed.authorization);
    try testing.expect(std.mem.indexOf(u8, pushed.log, the_password) == null);
}
