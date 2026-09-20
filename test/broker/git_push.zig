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

/// A run of characters no ordinary text holds, so finding it in a log proves a
/// leak and not a coincidence.
const the_password = "ghp_zzqqxx0123456789abcdefghijklmnopqrstuv";

/// In the remote URL on purpose. `askpass.Asker` answers a password and never a
/// user name, and `git` puts a user name in the URL of every request.
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
    answered: usize,
    refused: usize,

    fn deinit(self: *Pushed) void {
        self.gpa.free(self.said);
        self.gpa.free(self.log);
        self.gpa.free(self.authorization);
    }
};

/// There are three requests and not two. `curl` answers the first challenge by
/// itself, out of the user name in the remote URL and an empty password, before
/// `git` writes a prompt.
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

    /// Polled and not blocked on. The same loop answers the askpass socket while
    /// `git` runs, and a block on `accept` would leave the helper unread.
    fn serve(self: *Server, timeout_ms: i32) bool {
        if (!chock_broker.socket.readable(self.net_server.socket.handle, timeout_ms)) return false;

        var stream = self.net_server.accept(self.io) catch return false;
        defer stream.close(self.io);
        const peer = stream.socket.handle;

        var buffer: [8192]u8 = undefined;
        const read = std.posix.read(peer, &buffer) catch return false;
        if (read == 0) return false;
        const request = buffer[0..read];
        self.requests += 1;

        if (headerIn(request, "authorization: ")) |value| {
            // The challenge stands until a password arrives. Without this,
            // `git` sends `ross:`, takes the refusal, and exits.
            if (carriesPassword(value)) {
                const room = @min(value.len, self.authorization.len);
                @memcpy(self.authorization[0..room], value[0..room]);
                self.authorization_len = room;
            }
        }

        // A `401` with no challenge makes `git` give up without ever running
        // the helper.
        const reply = if (self.authorization_len == 0)
            "HTTP/1.1 401 Unauthorized\r\n" ++
                "WWW-Authenticate: Basic realm=\"chock\"\r\n" ++
                "Content-Length: 0\r\n" ++
                "Connection: close\r\n\r\n"
        else
            "HTTP/1.1 403 Forbidden\r\n" ++
                "Content-Length: 0\r\n" ++
                "Connection: close\r\n\r\n";
        _ = chock_broker.socket.writeAll(peer, reply);
        return true;
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

    const out_path = try std.fmt.allocPrint(gpa, "{s}/said", .{dir});
    defer gpa.free(out_path);
    var said_file = try std.Io.Dir.createFileAbsolute(io, out_path, .{});

    const argv = [_][]const u8{ git_path, "push", remote, "HEAD:refs/heads/main" };
    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .cwd = .{ .path = repo },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .{ .file = said_file },
        .stderr = .{ .file = said_file },
    });

    // `git` waits on the helper and the helper waits on this socket, so a
    // caller that blocked on `git` would deadlock. `std.process.Child` has no
    // `tryWait` in Zig 0.16, so the blocking `wait` comes after the loop.
    var settled = false;
    var looks: usize = 0;
    while (looks < 400) : (looks += 1) {
        _ = server.serve(5);
        _ = endpoint.step(gpa, io, &locked, asker, 20) catch {};
        if (settled) continue;
        const asked = endpoint.answered + endpoint.refused;
        if (server.authorizationValue().len != 0 or (asked >= 1 and endpoint.answered == 0)) {
            settled = true;
            looks = 400 - 40;
        }
    }
    const term = child.wait(io) catch {
        said_file.close(io);
        return error.GitNeverFinished;
    };
    _ = term;
    said_file.close(io);

    return .{
        .gpa = gpa,
        .said = try std.Io.Dir.readFileAlloc(.cwd(), io, out_path, gpa, .limited(1 << 20)),
        .log = try gpa.dupe(u8, backing.bytes.items),
        .authorization = try gpa.dupe(u8, server.authorizationValue()),
        .answered = endpoint.answered,
        .refused = endpoint.refused,
    };
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

    try testing.expectEqual(@as(usize, 1), pushed.answered);
    try testing.expectEqual(@as(usize, 0), pushed.refused);

    try testing.expect(pushed.authorization.len != 0);
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

    try testing.expect(pushed.authorization.len != 0);

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

    try testing.expectEqual(@as(usize, 0), pushed.answered);
    try testing.expectEqual(@as(usize, 1), pushed.refused);
    try testing.expectEqualStrings("", pushed.authorization);
    try testing.expect(std.mem.indexOf(u8, pushed.log, the_password) == null);
}
