//! The approval socket: a `Broker.Waiter` for a session with nobody at its own
//! keyboard. The socket carries the question and the answer, never a log write:
//! the process that holds the session lock is still the only writer.

const std = @import("std");
const chock_proto = @import("chock-proto");

const Broker = @import("Broker.zig");
const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const event = chock_proto.event;

/// `chock_proto.storage.Locked` is not `pub`, so this reaches the same type
/// through the return type of `Storage.lock`, which is public.
const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

pub const max_peers: usize = 4;

pub const max_answer_bytes: usize = 4096;

/// The directory's mode is the gate. A unix socket's own file mode is not
/// honoured on every unix, and a directory nobody else may enter is.
pub const dir_suffix = ".ctl";

pub const socket_name = "s";

pub const max_socket_path: usize = chock_proto.control.max_socket_path;

pub fn addressFor(
    path: []const u8,
    diag: ?*?Diagnostic,
) error{PathTooLong}!std.Io.net.UnixAddress {
    return chock_proto.control.unixAddress(path) catch {
        _ = diagnostic.note(diag, .{ .socket_path_too_long = .{
            .path = path,
            .bound = max_socket_path,
        } });
        return error.PathTooLong;
    };
}

pub const dir_mode: std.posix.mode_t = 0o700;

/// Where the answer came from, and never a name a client chose.
pub const responder_prefix = "socket:";

pub const Paths = struct {
    gpa: std.mem.Allocator,
    dir: []u8,
    socket: []u8,

    pub fn deinit(self: *Paths) void {
        self.gpa.free(self.dir);
        self.gpa.free(self.socket);
        self.* = undefined;
    }
};

pub fn pathsFor(
    gpa: std.mem.Allocator,
    session_dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!Paths {
    const dir = try std.fmt.allocPrint(gpa, "{s}/{s}" ++ dir_suffix, .{ session_dir, id });
    errdefer gpa.free(dir);
    const socket = try std.fmt.allocPrint(gpa, "{s}/" ++ socket_name, .{dir});
    return .{ .gpa = gpa, .dir = dir, .socket = socket };
}

pub fn ensureDir(io: std.Io, dir_path: []const u8, diag: ?*?Diagnostic) Endpoint.OpenError!void {
    std.Io.Dir.createDirAbsolute(io, dir_path, .fromMode(dir_mode)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            _ = diagnostic.note(diag, .{ .socket_dir_not_made = .{ .path = dir_path, .err = err } });
            return error.SocketUnavailable;
        },
    };
    // The process umask narrows what `createDirAbsolute` asked for, so the mode
    // is set again after the fact. Without `iterate`, `setPermissions` reaches
    // the kernel as a bad descriptor.
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch |err| {
        _ = diagnostic.note(diag, .{ .socket_dir_not_opened = .{ .path = dir_path, .err = err } });
        return error.SocketUnavailable;
    };
    dir.setPermissions(io, .fromMode(dir_mode)) catch |err| {
        dir.close(io);
        _ = diagnostic.note(diag, .{ .socket_dir_not_private = .{ .path = dir_path, .err = err } });
        return error.SocketUnavailable;
    };
    dir.close(io);
}

pub fn readable(handle: std.posix.fd_t, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&fds, timeout_ms) catch return false;
    return ready != 0;
}

/// A short write is not a failure: a socket takes what fits in its buffer and
/// says how much, so a large question needs more than one write.
pub fn writeAll(handle: std.posix.fd_t, bytes: []const u8) bool {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = std.posix.system.write(handle, bytes.ptr + sent, bytes.len - sent);
        const written: isize = @bitCast(@as(usize, @bitCast(rc)));
        if (written > 0) {
            sent += @intCast(written);
            continue;
        }
        switch (std.posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return false,
            else => return false,
        }
    }
    return true;
}

const Peer = struct {
    handle: ?std.posix.fd_t = null,
    uid: std.posix.uid_t = 0,
    shown: ?u64 = null,
    filled: usize = 0,
    buffer: [max_answer_bytes]u8 = undefined,
};

/// Only the process that holds the session lock builds one.
pub const Endpoint = struct {
    server: std.Io.net.Server,
    socket_path: []const u8,
    owner_uid: std.posix.uid_t,
    peers: [max_peers]Peer = @splat(.{}),
    refused: usize = 0,
    refusal: ?Diagnostic = null,

    pub const OpenError = error{
        /// The bound is not the same number on both platforms.
        PathTooLong,
        SocketUnavailable,
    };

    /// A stale socket is removed rather than refused, or one crash would wedge
    /// that session id forever.
    pub fn open(io: std.Io, paths: Paths, diag: ?*?Diagnostic) OpenError!Endpoint {
        const address = try addressFor(paths.socket, diag);

        try ensureDir(io, paths.dir, diag);

        std.Io.Dir.deleteFileAbsolute(io, paths.socket) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                _ = diagnostic.note(diag, .{ .socket_not_removed = .{ .path = paths.socket, .err = err } });
                return error.SocketUnavailable;
            },
        };

        // Twice `max_peers`, because at exactly `max_peers` the kernel refuses
        // the fifth client itself, which reads to that client as a session that
        // is not listening. On Darwin the queue refuses rather than waits.
        const server = address.listen(io, .{ .kernel_backlog = max_peers * 2 }) catch |err| {
            _ = diagnostic.note(diag, .{ .socket_not_opened = .{ .path = paths.socket, .err = err } });
            return error.SocketUnavailable;
        };

        return .{
            .server = server,
            .socket_path = paths.socket,
            .owner_uid = std.posix.system.getuid(),
        };
    }

    pub fn close(self: *Endpoint, io: std.Io) void {
        for (&self.peers) |*peer| self.dropPeer(io, peer);
        self.server.deinit(io);
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
    }

    pub fn attached(self: *const Endpoint) usize {
        var count: usize = 0;
        for (self.peers) |peer| {
            if (peer.handle != null) count += 1;
        }
        return count;
    }

    pub fn acceptPending(self: *Endpoint, io: std.Io) void {
        for (0..max_peers * 2) |_| {
            if (!readable(self.server.socket.handle, 0)) return;
            const stream = self.server.accept(io) catch return;

            const uid = peerUid(stream.socket.handle) orelse {
                self.refused += 1;
                stream.close(io);
                continue;
            };
            if (uid != self.owner_uid) {
                self.refused += 1;
                _ = diagnostic.note(&self.refusal, .{ .client_uid_refused = .{
                    .uid = uid,
                    .owner_uid = self.owner_uid,
                } });
                stream.close(io);
                continue;
            }

            const slot = self.freeSlot() orelse {
                self.refused += 1;
                stream.close(io);
                continue;
            };
            slot.* = .{ .handle = stream.socket.handle, .uid = uid };
        }
    }

    fn freeSlot(self: *Endpoint) ?*Peer {
        for (&self.peers) |*peer| {
            if (peer.handle == null) return peer;
        }
        return null;
    }

    fn dropPeer(self: *Endpoint, io: std.Io, peer: *Peer) void {
        _ = self;
        const handle = peer.handle orelse return;
        const stream = std.Io.net.Stream{ .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } } };
        stream.close(io);
        peer.* = .{};
    }
};

/// The answer is appended through `locked`, the same handle the broker writes
/// the question with, so no lock changes.
pub const Waiter = struct {
    gpa: std.mem.Allocator,
    storage: chock_proto.storage.Storage,
    locked: *Locked,
    endpoint: *Endpoint,
    stop: *const fn () bool = neverStopped,
    nap: *const fn (budget_ms: u64) void = pollNap,
    failed: ?anyerror = null,
    diagnostic: ?Diagnostic = null,

    pub fn waiter(self: *Waiter) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = ptr;
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *Waiter = @ptrCast(@alignCast(ptr));
        return self.step(io, budget_ms);
    }

    pub fn step(self: *Waiter, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        // A session that is stopping must not show a question it cannot finish.
        if (self.stop()) return .canceled;

        self.endpoint.acceptPending(io);

        const open = Broker.openRequest(self.gpa, io, self.storage) catch |err| {
            self.report(err, "the session log could not be read, so nobody could be asked");
            return .canceled;
        } orelse {
            self.idle(budget_ms);
            return .slept;
        };

        self.show(io, open);
        return self.readAnswers(io, open, budget_ms);
    }

    fn show(self: *Waiter, io: std.Io, request_id: u64) void {
        var line: ?[]u8 = null;
        defer if (line) |owned| self.gpa.free(owned);

        for (&self.endpoint.peers) |*peer| {
            if (peer.handle == null) continue;
            if (peer.shown != null and peer.shown.? == request_id) continue;

            if (line == null) {
                line = self.questionLine(io, request_id) catch |err| {
                    self.report(err, "the approval could not be read back out of the session log");
                    return;
                };
            }
            if (writeAll(peer.handle.?, line.?)) {
                peer.shown = request_id;
            } else {
                self.endpoint.dropPeer(io, peer);
            }
        }
    }

    fn questionLine(self: *Waiter, io: std.Io, request_id: u64) ![]u8 {
        var replay = try self.storage.replay(self.gpa, io, request_id);
        defer replay.deinit();

        const parsed = try replay.next(io) orelse return error.RequestNotInTheLog;
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) return error.RequestNotInTheLog;

        const text = try event.toJson(self.gpa, parsed.value);
        defer self.gpa.free(text);
        return std.fmt.allocPrint(self.gpa, "{s}\n", .{text});
    }

    fn readAnswers(
        self: *Waiter,
        io: std.Io,
        request_id: u64,
        budget_ms: u64,
    ) Broker.Waiter.Wake {
        var fds: [max_peers]std.posix.pollfd = undefined;
        var slots: [max_peers]usize = undefined;
        var count: usize = 0;
        for (&self.endpoint.peers, 0..) |*peer, index| {
            const handle = peer.handle orelse continue;
            // Checked here and not after the poll. A peer that filled the
            // buffer then stops sending, so the poll never names it again.
            if (peer.filled == peer.buffer.len) {
                self.endpoint.dropPeer(io, peer);
                continue;
            }
            fds[count] = .{ .fd = handle, .events = std.posix.POLL.IN, .revents = 0 };
            slots[count] = index;
            count += 1;
        }
        if (count == 0) {
            self.idle(budget_ms);
            return .slept;
        }

        const timeout: i32 = if (budget_ms > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(budget_ms);
        const ready = std.posix.poll(fds[0..count], timeout) catch return .slept;
        if (ready == 0) return .slept;

        for (fds[0..count], slots[0..count]) |entry, index| {
            if (entry.revents == 0) continue;
            const peer = &self.endpoint.peers[index];
            if (self.readOne(io, peer, request_id)) |decision| {
                return self.record(io, request_id, decision, peer.uid);
            }
        }
        return .slept;
    }

    fn readOne(
        self: *Waiter,
        io: std.Io,
        peer: *Peer,
        request_id: u64,
    ) ?event.ApprovalDecision {
        const handle = peer.handle orelse return null;
        const room = peer.buffer[peer.filled..];
        std.debug.assert(room.len > 0);

        const read = std.posix.read(handle, room) catch |err| switch (err) {
            // `poll` can say there is something to read when there is not.
            error.WouldBlock => return null,
            else => {
                self.endpoint.dropPeer(io, peer);
                return null;
            },
        };
        if (read == 0) {
            self.endpoint.dropPeer(io, peer);
            return null;
        }
        peer.filled += read;

        const line = peer.buffer[0..peer.filled];
        const end = std.mem.indexOfScalar(u8, line, '\n') orelse return null;
        const said = line[0..end];
        peer.filled = 0;

        return self.decisionFrom(said, request_id);
    }

    /// A client may say only what a person may say. A plain yes is the only
    /// thing that permits: a client that could write `allowed_by_policy` would
    /// be claiming the project's own table had permitted the act.
    fn decisionFrom(
        self: *Waiter,
        said: []const u8,
        request_id: u64,
    ) ?event.ApprovalDecision {
        var parsed = event.fromJson(self.gpa, said) catch return null;
        defer parsed.deinit();

        if (parsed.value.event != .approval_response) return null;
        const answer = parsed.value.event.approval_response;
        if (answer.request_id != request_id) return null;

        return switch (answer.decision) {
            .approved_by_user => .approved_by_user,
            else => .refused_by_user,
        };
    }

    fn record(
        self: *Waiter,
        io: std.Io,
        request_id: u64,
        decision: event.ApprovalDecision,
        uid: std.posix.uid_t,
    ) Broker.Waiter.Wake {
        const responder = std.fmt.allocPrint(
            self.gpa,
            responder_prefix ++ "{d}",
            .{uid},
        ) catch |err| {
            self.report(err, "the answer could not be recorded");
            return .canceled;
        };
        defer self.gpa.free(responder);

        const action = (Broker.requestAction(self.gpa, io, self.storage, request_id) catch |err| {
            self.report(err, "the answer could not be recorded");
            return .canceled;
        }) orelse {
            self.report(error.RequestNotInTheLog, "the answer could not be recorded");
            return .canceled;
        };
        defer self.gpa.free(action);

        _ = self.locked.append(self.gpa, io, .{ .approval_response = .{
            .request_id = request_id,
            .decision = decision,
            .responder = responder,
            .action = action,
        } }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| {
            self.report(err, "the answer could not be written to the session log");
            return .canceled;
        };
        return .slept;
    }

    /// A `wait` that comes back at once with nothing waited for turns
    /// `Broker.request` into a busy loop for the whole deadline.
    fn idle(self: *Waiter, budget_ms: u64) void {
        self.nap(budget_ms);
    }

    fn report(self: *Waiter, err: anyerror, what: []const u8) void {
        _ = diagnostic.note(&self.diagnostic, .{ .waiter_step_failed = .{ .path = what, .err = err } });
        if (self.failed == null) self.failed = err;
    }
};

pub const Pair = struct {
    first: Broker.Waiter,
    second: Broker.Waiter,

    pub fn waiter(self: *Pair) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        const self: *Pair = @ptrCast(@alignCast(ptr));
        return self.first.nowMs(io);
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *Pair = @ptrCast(@alignCast(ptr));
        // A stop that only one half noticed is a session that keeps the lock.
        if (self.first.wait(io, 0) == .canceled) return .canceled;
        return self.second.wait(io, budget_ms);
    }
};

/// Zero when there is nobody to ask, and that is a refusal: a question nobody
/// can answer must not hold the session lock for five minutes first. Somebody
/// means a person at this terminal, or a client attached when the question is
/// asked, never one that might attach later.
pub fn timeoutMs(at_terminal: bool, attached: usize) i64 {
    if (at_terminal or attached > 0) return Broker.default_timeout_ms;
    return 0;
}

/// `SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on Darwin. The body sits in
/// `chock-proto` because `src/serve.zig` needs the same check and its own test
/// fails the build if it imports `chock-broker`.
pub const peerUid = chock_proto.control.peerUid;

fn neverStopped() bool {
    return false;
}

/// A `poll` over no descriptors, which signals still reach.
fn pollNap(budget_ms: u64) void {
    if (budget_ms == 0) return;
    var nothing: [0]std.posix.pollfd = .{};
    const timeout: i32 = if (budget_ms > std.math.maxInt(i32))
        std.math.maxInt(i32)
    else
        @intCast(budget_ms);
    _ = std.posix.poll(&nothing, timeout) catch {};
}

const testing = std.testing;

/// A directory below `TMPDIR`. `std.testing.tmpDir` makes its directory below
/// the build directory, and on macos inside a Nix build that is already 112
/// bytes, so a bench built on it cannot reach `max_socket_path` at all.
pub const BoundBench = struct {
    gpa: std.mem.Allocator,
    parent: std.Io.Dir,
    sub: [sub_len]u8,
    dir_path: []u8,

    const random_bytes_count = 12;
    const sub_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

    pub fn open(gpa: std.mem.Allocator, io: std.Io) !BoundBench {
        const root = root: {
            const given = std.process.Environ.getPosix(testing.environ, "TMPDIR") orelse "/tmp";
            const trimmed = std.mem.trimEnd(u8, given, "/");
            break :root if (trimmed.len == 0) "/" else trimmed;
        };

        var self: BoundBench = undefined;
        self.gpa = gpa;
        var random_bytes: [random_bytes_count]u8 = undefined;
        io.random(&random_bytes);
        _ = std.base64.url_safe.Encoder.encode(&self.sub, &random_bytes);

        self.dir_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ root, &self.sub });
        errdefer gpa.free(self.dir_path);
        if (self.dir_path.len + 2 > max_socket_path) return error.SkipZigTest;

        self.parent = try std.Io.Dir.cwd().openDir(io, root, .{});
        errdefer self.parent.close(io);
        var made = try self.parent.createDirPathOpen(io, &self.sub, .{});
        made.close(io);
        return self;
    }

    pub fn pathsOfLength(self: *const BoundBench, want: usize) !Paths {
        const dir = try self.gpa.dupe(u8, self.dir_path);
        errdefer self.gpa.free(dir);
        const socket_path = try self.gpa.alloc(u8, want);
        @memcpy(socket_path[0..dir.len], dir);
        socket_path[dir.len] = '/';
        @memset(socket_path[dir.len + 1 ..], 'n');
        return .{ .gpa = self.gpa, .dir = dir, .socket = socket_path };
    }

    pub fn cleanup(self: *BoundBench, io: std.Io) void {
        self.parent.deleteTree(io, &self.sub) catch {};
        self.parent.close(io);
        self.gpa.free(self.dir_path);
        self.* = undefined;
    }
};

/// A test reads the log back after the replay that parsed it has ended, and a
/// tag outlives that parse where a borrowed string does not.
const Decision = std.meta.Tag(event.ApprovalDecision);

const Bench = struct {
    gpa: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    paths: Paths,
    endpoint: Endpoint,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Bench {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);

        var paths = try pathsFor(gpa, dir, "01SOCKET");
        errdefer paths.deinit();

        const endpoint = try Endpoint.open(io, paths, null);
        return .{ .gpa = gpa, .tmp = tmp, .paths = paths, .endpoint = endpoint };
    }

    fn deinit(self: *Bench, io: std.Io) void {
        self.endpoint.close(io);
        self.paths.deinit();
        self.tmp.cleanup();
    }

    fn attach(self: *Bench, io: std.Io) !std.Io.net.Stream {
        const address = try addressFor(self.paths.socket, null);
        return address.connect(io);
    }
};

const ask_everything: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

fn testRequest() Broker.Request {
    return .{
        .action = "workspace.apply",
        .summary = "move 3 objects and set refs/chock/01SOCKET",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "call1",
        .timeout_ms = Broker.default_timeout_ms,
    };
}

fn sendAnswer(
    gpa: std.mem.Allocator,
    stream: std.Io.net.Stream,
    request_id: u64,
    decision: event.ApprovalDecision,
) !void {
    const text = try event.toJson(gpa, .{
        .id = 0,
        .session = "01SOCKET",
        .time_ms = 0,
        .event = .{
            .approval_response = .{
                .request_id = request_id,
                .decision = decision,
                .responder = "somebody",
            },
        },
    });
    defer gpa.free(text);
    try testing.expect(writeAll(stream.socket.handle, text));
    try testing.expect(writeAll(stream.socket.handle, "\n"));
}

fn readLine(stream: std.Io.net.Stream, buffer: []u8) ![]u8 {
    var filled: usize = 0;
    while (filled < buffer.len) {
        if (!readable(stream.socket.handle, 1000)) return error.NothingArrived;
        const read = try std.posix.read(stream.socket.handle, buffer[filled..]);
        if (read == 0) return error.PeerClosed;
        filled += read;
        if (std.mem.indexOfScalar(u8, buffer[0..filled], '\n')) |end| return buffer[0..end];
    }
    return error.LineTooLong;
}

const Drive = struct {
    outcome: ?Broker.Outcome,
    failure: ?anyerror,
    answers: []Decision,
    questions: usize,
    gpa: std.mem.Allocator,

    fn deinit(self: *Drive) void {
        self.gpa.free(self.answers);
    }
};

fn readBack(gpa: std.mem.Allocator, io: std.Io, store: chock_proto.storage.Storage) !Drive {
    var answers: std.ArrayList(Decision) = .empty;
    errdefer answers.deinit(gpa);
    var questions: usize = 0;
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => questions += 1,
            .approval_response => |response| try answers.append(gpa, std.meta.activeTag(response.decision)),
            else => {},
        }
    }
    return .{
        .outcome = null,
        .failure = null,
        .answers = try answers.toOwnedSlice(gpa),
        .questions = questions,
        .gpa = gpa,
    };
}

test "a client that attaches is shown the open question and its answer reaches the log" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    const request_id = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 0));
    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());

    var line_buffer: [8192]u8 = undefined;
    const shown = try readLine(client, &line_buffer);
    try testing.expect(std.mem.indexOf(u8, shown, "approval.request") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "workspace.apply") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "a1b2c3 fix the parser") != null);
    var parsed = try event.fromJson(gpa, shown);
    defer parsed.deinit();
    try testing.expectEqual(request_id, parsed.value.id);

    try sendAnswer(gpa, client, request_id, .approved_by_user);
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 1000));

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.approved_by_user, result.answers[0]);

    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var responder_seen: bool = false;
    while (try replay.next(io)) |line| {
        defer line.deinit();
        if (line.value.event != .approval_response) continue;
        try testing.expect(std.mem.startsWith(u8, line.value.event.approval_response.responder, responder_prefix));
        try testing.expect(!std.mem.eql(u8, line.value.event.approval_response.responder, "somebody"));
        responder_seen = true;
    }
    try testing.expect(responder_seen);
}

test "a whole broker request is answered over the socket, and the outcome permits" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    // No thread here: the tool path forks, and a forked process carries only
    // the calling thread. The client answers from inside the broker's wait.
    const Answerer = struct {
        gpa: std.mem.Allocator,
        io: std.Io,
        store: chock_proto.storage.Storage,
        client: std.Io.net.Stream,
        inner: *Waiter,
        line_buffer: [8192]u8 = undefined,
        failed: ?anyerror = null,

        fn waiter(self: *@This()) Broker.Waiter {
            return .{ .ptr = self, .vtable = &.{ .nowMs = nowMs, .wait = wait } };
        }

        fn nowMs(ptr: *anyopaque, io_inner: std.Io) i64 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.inner.waiter().nowMs(io_inner);
        }

        fn wait(ptr: *anyopaque, io_inner: std.Io, budget_ms: u64) Broker.Waiter.Wake {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const first = self.inner.step(io_inner, 0);
            if (first == .canceled) return first;
            const shown = readLine(self.client, &self.line_buffer) catch |err| {
                if (self.failed == null) self.failed = err;
                return .canceled;
            };
            var parsed = event.fromJson(self.gpa, shown) catch |err| {
                if (self.failed == null) self.failed = err;
                return .canceled;
            };
            defer parsed.deinit();
            sendAnswer(self.gpa, self.client, parsed.value.id, .approved_by_user) catch |err| {
                if (self.failed == null) self.failed = err;
                return .canceled;
            };
            return self.inner.step(io_inner, budget_ms);
        }
    };

    var answerer = Answerer{
        .gpa = gpa,
        .io = io,
        .store = store,
        .client = client,
        .inner = &socket_waiter,
    };

    const policy = try @import("chock-policy").table.Table.parse(gpa, ask_everything, null);
    defer @import("chock-policy").table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = answerer.waiter() };
    const outcome = try broker.request(gpa, io, store, &locked, testRequest(), null);
    if (answerer.failed) |err| return err;

    try testing.expectEqual(Broker.Outcome.approved_by_user, outcome);
    try testing.expect(outcome.permits());

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 1), result.answers.len);
    try testing.expectEqual(Decision.approved_by_user, result.answers[0]);
}

test "a client cannot claim the policy allowed it, and cannot claim a review did" {
    const gpa = testing.allocator;
    const io = testing.io;

    const claimed = [_]event.ApprovalDecision{
        .allowed_by_policy,
        .approved_by_review,
        .{ .unknown = "approved_by_everyone" },
        .approved_by_user_for_session,
    };

    for (claimed) |decision| {
        var bench = try Bench.init(gpa, io);
        defer bench.deinit(io);

        var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const client = try bench.attach(io);
        defer client.close(io);

        var socket_waiter = Waiter{
            .gpa = gpa,
            .storage = store,
            .locked = &locked,
            .endpoint = &bench.endpoint,
        };

        const request_id = try locked.append(gpa, io, .{ .approval_request = .{
            .action = "workspace.apply",
            .summary = "move 3 objects",
            .detail = "",
            .reason = "the session made a commit",
            .agent_kind = "coder",
            .spawn_chain = &.{},
            .timeout_at_ms = 0,
            .tool_call_id = "call1",
        } }, 1);

        _ = socket_waiter.step(io, 0);
        var line_buffer: [8192]u8 = undefined;
        _ = try readLine(client, &line_buffer);
        try sendAnswer(gpa, client, request_id, decision);
        _ = socket_waiter.step(io, 1000);

        var result = try readBack(gpa, io, store);
        defer result.deinit();
        try testing.expectEqual(@as(usize, 1), result.answers.len);
        try testing.expectEqual(Decision.refused_by_user, result.answers[0]);
    }
}

test "an answer to another question is not an answer to this one" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    const request_id = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3",
        .detail = "",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    _ = socket_waiter.step(io, 0);
    var line_buffer: [8192]u8 = undefined;
    _ = try readLine(client, &line_buffer);

    try sendAnswer(gpa, client, request_id + 4096, .approved_by_user);
    _ = socket_waiter.step(io, 1000);

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 0), result.answers.len);
    try testing.expectEqual(@as(usize, 1), result.questions);
}

test "a client that dies mid question leaves a log a fold can still read" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    {
        const client = try bench.attach(io);
        _ = socket_waiter.step(io, 0);
        try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());
        var line_buffer: [8192]u8 = undefined;
        _ = try readLine(client, &line_buffer);
        client.close(io);
    }

    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 10));
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());
    try testing.expect(socket_waiter.failed == null);

    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 0));
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 0));

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 0), result.answers.len);
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |line| line.deinit();
    try testing.expect(!replay.truncated());
}

test "a client that goes away before it is shown anything does not end the session" {
    // `std.Io.Threaded.init` installs the handler for `SIGPIPE`, so a write to
    // a dead peer reports `EPIPE`. Do not set a signal disposition here.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    {
        const client = try bench.attach(io);
        _ = socket_waiter.step(io, 0);
        try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());
        client.close(io);
    }

    _ = try locked.append(gpa, io, .{
        .approval_request = .{
            .action = "workspace.apply",
            .summary = "move 3 objects",
            .detail = "x" ** 4096,
            .reason = "the session made a commit",
            .agent_kind = "coder",
            .spawn_chain = &.{},
            .timeout_at_ms = 0,
            .tool_call_id = "call1",
        },
    }, 1);

    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 10));
    try testing.expect(socket_waiter.failed == null);
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());
}

test "a session that dies does not leave a client waiting forever" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer {
        bench.paths.deinit();
        bench.tmp.cleanup();
    }

    const client = try bench.attach(io);
    defer client.close(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };
    _ = socket_waiter.step(io, 0);
    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());

    bench.endpoint.close(io);

    var line_buffer: [64]u8 = undefined;
    try testing.expectError(error.PeerClosed, readLine(client, &line_buffer));

    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.accessAbsolute(io, bench.paths.socket, .{}),
    );
}

test "a stale socket left by a crash does not wedge the path" {
    // `bind` refuses a path that already exists.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var abandoned = try Endpoint.open(io, bench.paths, null);
    abandoned.server.deinit(io);

    var second = try Endpoint.open(io, bench.paths, null);
    defer second.close(io);
    const client = try std.Io.net.UnixAddress.connect(
        &(try addressFor(bench.paths.socket, null)),
        io,
    );
    defer client.close(io);
    second.acceptPending(io);
    try testing.expectEqual(@as(usize, 1), second.attached());
}

test "the fifth client is refused rather than left hanging" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var streams: [max_peers + 1]std.Io.net.Stream = undefined;
    for (streams[0..max_peers]) |*stream| stream.* = try bench.attach(io);
    defer for (streams) |stream| stream.close(io);

    bench.endpoint.acceptPending(io);
    try testing.expectEqual(max_peers, bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 0), bench.endpoint.refused);

    streams[max_peers] = try bench.attach(io);
    bench.endpoint.acceptPending(io);
    try testing.expectEqual(max_peers, bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 1), bench.endpoint.refused);

    var line_buffer: [64]u8 = undefined;
    try testing.expectError(error.PeerClosed, readLine(streams[max_peers], &line_buffer));
}

test "the socket sits in a directory this user alone can enter" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var dir = try std.Io.Dir.openDirAbsolute(io, bench.paths.dir, .{});
    defer dir.close(io);
    const stat = try dir.stat(io);
    try testing.expectEqual(dir_mode, stat.permissions.toMode() & 0o7777);
    try testing.expect(std.mem.startsWith(u8, bench.paths.socket, bench.paths.dir));
}

test "the peer credential call answers with this user's own uid" {
    // Two answers, because either alone is easy to fake: always null refuses
    // everybody, always this uid accepts everybody.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const client = try bench.attach(io);
    defer client.close(io);
    bench.endpoint.acceptPending(io);

    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 0), bench.endpoint.refused);
    for (bench.endpoint.peers) |peer| {
        if (peer.handle == null) continue;
        try testing.expectEqual(std.posix.system.getuid(), peer.uid);
    }
    try testing.expectEqual(
        @as(?std.posix.uid_t, std.posix.system.getuid()),
        peerUid(client.socket.handle),
    );

    const plain = try bench.tmp.dir.createFile(io, "not-a-socket", .{});
    defer plain.close(io);
    try testing.expectEqual(@as(?std.posix.uid_t, null), peerUid(plain.handle));
}

test "a peer that is not this user is closed before it is read" {
    // The endpoint's own owner uid is what moves, not the connecting process,
    // because a test cannot become another user. The comparison is the same.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    bench.endpoint.owner_uid = std.posix.system.getuid() +% 1;

    const client = try bench.attach(io);
    defer client.close(io);
    bench.endpoint.acceptPending(io);

    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());
    try testing.expectEqual(@as(usize, 1), bench.endpoint.refused);

    var line_buffer: [64]u8 = undefined;
    try testing.expectError(error.PeerClosed, readLine(client, &line_buffer));
}

test "a session with nobody attached and no terminal waits for nothing at all" {
    try testing.expectEqual(@as(i64, 0), timeoutMs(false, 0));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(true, 0));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(false, 1));
    try testing.expectEqual(Broker.default_timeout_ms, timeoutMs(true, 1));
}

/// File scope because a `*const fn (u64) void` cannot capture.
var naps: usize = 0;
var last_nap_budget_ms: u64 = 0;

fn countingNap(budget_ms: u64) void {
    naps += 1;
    last_nap_budget_ms = budget_ms;
}

test "a look with nobody attached waits for the whole budget rather than spinning" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    naps = 0;
    last_nap_budget_ms = 0;
    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
        .nap = countingNap,
    };

    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 50));
    try testing.expectEqual(@as(usize, 1), naps);
    try testing.expectEqual(@as(u64, 50), last_nap_budget_ms);

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3",
        .detail = "",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);
    try testing.expectEqual(Broker.Waiter.Wake.slept, socket_waiter.step(io, 25));
    try testing.expectEqual(@as(usize, 2), naps);
    try testing.expectEqual(@as(u64, 25), last_nap_budget_ms);

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 0), result.answers.len);
}

test "a peer that fills the buffer with no line break in it is dropped" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3",
        .detail = "",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    _ = socket_waiter.step(io, 0);
    var line_buffer: [8192]u8 = undefined;
    _ = try readLine(client, &line_buffer);
    try testing.expectEqual(@as(usize, 1), bench.endpoint.attached());

    const filler: [max_answer_bytes]u8 = @splat('x');
    try testing.expect(writeAll(client.socket.handle, &filler));

    for (0..4) |_| _ = socket_waiter.step(io, 50);
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 0), result.answers.len);
}

test "a stop ends the wait before anything is shown, and leaves the question open" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
        .stop = alwaysStopped,
    };

    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "workspace.apply",
        .summary = "move 3 objects",
        .detail = "",
        .reason = "the session made a commit",
        .agent_kind = "coder",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "call1",
    } }, 1);

    try testing.expectEqual(Broker.Waiter.Wake.canceled, socket_waiter.step(io, 1000));
    try testing.expectEqual(@as(usize, 0), bench.endpoint.attached());

    var result = try readBack(gpa, io, store);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.questions);
    try testing.expectEqual(@as(usize, 0), result.answers.len);
}

fn alwaysStopped() bool {
    return true;
}

test "a pair answers from either half, and a stop in either half ends the wait" {
    const io = testing.io;

    const Counting = struct {
        waits: usize = 0,
        answer: Broker.Waiter.Wake = .slept,
        last_budget_ms: u64 = 0,

        fn waiter(self: *@This()) Broker.Waiter {
            return .{ .ptr = self, .vtable = &.{ .nowMs = nowMs, .wait = wait } };
        }
        fn nowMs(ptr: *anyopaque, io_inner: std.Io) i64 {
            _ = ptr;
            _ = io_inner;
            return 1_700_000_000_000;
        }
        fn wait(ptr: *anyopaque, io_inner: std.Io, budget_ms: u64) Broker.Waiter.Wake {
            _ = io_inner;
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.waits += 1;
            self.last_budget_ms = budget_ms;
            return self.answer;
        }
    };

    var first = Counting{};
    var second = Counting{};
    var pair = Pair{ .first = first.waiter(), .second = second.waiter() };

    try testing.expectEqual(Broker.Waiter.Wake.slept, pair.waiter().wait(io, 50));
    try testing.expectEqual(@as(u64, 0), first.last_budget_ms);
    try testing.expectEqual(@as(u64, 50), second.last_budget_ms);

    first.answer = .canceled;
    try testing.expectEqual(Broker.Waiter.Wake.canceled, pair.waiter().wait(io, 50));
    try testing.expectEqual(@as(usize, 1), second.waits);

    first.answer = .slept;
    second.answer = .canceled;
    try testing.expectEqual(Broker.Waiter.Wake.canceled, pair.waiter().wait(io, 50));
}

test "a socket path longer than a unix socket path may be is refused and says so" {
    const gpa = testing.allocator;
    const io = testing.io;

    const long: [200]u8 = @splat('d');
    var paths = try pathsFor(gpa, "/tmp/" ++ ("x" ** 0), &long);
    defer paths.deinit();

    try testing.expectError(error.PathTooLong, Endpoint.open(io, paths, null));
}

test "the approval socket binds at exactly the bound and refuses one byte more" {
    // The bound is not `std.Io.net.UnixAddress.max_len`. That is a flat 108 on
    // every platform but Windows, which is past the end of Darwin's `sun_path`.
    // On Linux a path of 108 still binds.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try BoundBench.open(gpa, io);
    defer bench.cleanup(io);

    var at_bound = try bench.pathsOfLength(max_socket_path);
    defer at_bound.deinit();
    try testing.expectEqual(max_socket_path, at_bound.socket.len);
    var endpoint = try Endpoint.open(io, at_bound, null);
    endpoint.close(io);

    var over = try bench.pathsOfLength(max_socket_path + 1);
    defer over.deinit();
    var diag: ?Diagnostic = null;
    try testing.expectError(error.PathTooLong, Endpoint.open(io, over, &diag));

    var said_buffer: [512]u8 = undefined;
    const said = try std.fmt.bufPrint(&said_buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, said, over.socket) != null);
    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{max_socket_path}),
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{over.socket.len}),
    ) != null);
}

test "the question a client is shown is the log's own envelope and no second format" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01SOCKET");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const client = try bench.attach(io);
    defer client.close(io);

    var socket_waiter = Waiter{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .endpoint = &bench.endpoint,
    };

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "the task named a build" },
    };
    _ = try locked.append(gpa, io, .{ .approval_request = .{
        .action = "git.push",
        .summary = "push a1b2c3 to origin",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .spawn_chain = &chain,
        .timeout_at_ms = 1_700_000_000_000,
        .tool_call_id = "call1",
        .review = .approved,
        .review_note = "the diff is the fix the task asked for",
    } }, 1);

    _ = socket_waiter.step(io, 0);
    var line_buffer: [8192]u8 = undefined;
    const shown = try readLine(client, &line_buffer);

    var parsed = try event.fromJson(gpa, shown);
    defer parsed.deinit();
    const question = parsed.value.event.approval_request;
    try testing.expectEqualStrings("git.push", question.action);
    try testing.expectEqual(@as(usize, 1), question.spawn_chain.len);
    try testing.expectEqualStrings("main", question.spawn_chain[0].agent_kind);
    try testing.expectEqualStrings("approved", question.review.wireName());
    try testing.expectEqualStrings("the diff is the fix the task asked for", question.review_note);
    try testing.expectEqual(@as(i64, 1_700_000_000_000), question.timeout_at_ms);
    try testing.expectEqual(@as(usize, 0), std.mem.count(u8, shown, "\n"));
}
