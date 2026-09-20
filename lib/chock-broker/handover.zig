//! The handover socket. One process asks a running session to stop at a turn
//! boundary, so another process can take the session log's exclusive lock.
//! This socket carries a question and an answer, and never a log write.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const socket = @import("socket.zig");

/// A unix socket path is bounded at 107 bytes on Linux and 103 on Darwin.
pub const socket_name = "h";

pub const max_frame_bytes: usize = 4096;

pub const ask_frame = "ask";
pub const take_frame = "take";
pub const ready_frame = "ready";
pub const handing_over_frame = "handing over";
pub const busy_prefix = "busy ";
/// Sent once per exchange and never repeated.
pub const waiting_prefix = "waiting ";

pub const default_confirm_budget_ms: u64 = 5_000;

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
    const dir = try std.fmt.allocPrint(gpa, "{s}/{s}" ++ socket.dir_suffix, .{ session_dir, id });
    errdefer gpa.free(dir);
    const path = try std.fmt.allocPrint(gpa, "{s}/" ++ socket_name, .{dir});
    return .{ .gpa = gpa, .dir = dir, .socket = path };
}

pub const InFlight = struct {
    tasks: usize = 0,
    children: usize = 0,

    pub fn empty(self: InFlight) bool {
        return self.tasks == 0 and self.children == 0;
    }
};

pub const Decision = enum {
    carry_on,
    hand_over,
};

pub const Endpoint = struct {
    server: std.Io.net.Server,
    socket_path: []const u8,
    owner_uid: std.posix.uid_t,
    peer: ?std.posix.fd_t = null,
    /// Two cursors, because one read brings more than one frame. A client can
    /// send `take` together with its `ask`.
    start: usize = 0,
    filled: usize = 0,
    buffer: [max_frame_bytes]u8 = undefined,
    offered: bool = false,
    waiting: bool = false,
    refused: usize = 0,
    refusal: ?Diagnostic = null,

    pub const OpenError = socket.Endpoint.OpenError;

    pub fn open(io: std.Io, paths: Paths, diag: ?*?Diagnostic) OpenError!Endpoint {
        const address = try socket.addressFor(paths.socket, diag);

        try socket.ensureDir(io, paths.dir, diag);

        std.Io.Dir.deleteFileAbsolute(io, paths.socket) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                _ = diagnostic.note(diag, .{ .socket_not_removed = .{ .path = paths.socket, .err = err } });
                return error.SocketUnavailable;
            },
        };

        // Darwin refuses a connection when the queue is full instead of making
        // it wait, and a refused client cannot tell that from no listener.
        const server = address.listen(io, .{ .kernel_backlog = 4 }) catch |err| {
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
        // The file goes first and the peer second. A dropped peer can start the
        // next owner, and a later remove would unlink that owner's new socket.
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
        self.server.deinit(io);
        self.dropPeer(io);
    }

    pub fn look(
        self: *Endpoint,
        io: std.Io,
        in_flight: InFlight,
        confirm_budget_ms: u64,
    ) Decision {
        self.acceptPending(io);

        const handle = self.peer orelse return .carry_on;

        if (self.waiting) {
            self.noticeGoneWhileWaiting(io, handle);
            if (self.peer == null) return .carry_on;
            if (!in_flight.empty()) return .carry_on;
            if (!self.offer(io, handle)) return .carry_on;
        } else if (!self.offered) {
            const line = self.readFrame(io, handle, 0) orelse return .carry_on;

            if (!std.mem.eql(u8, line, ask_frame)) {
                self.refuse(io, handle, "that is not a frame this session understands");
                return .carry_on;
            }

            if (!in_flight.empty()) {
                var line_buffer: [max_frame_bytes]u8 = undefined;
                const said = std.fmt.bufPrint(
                    &line_buffer,
                    waiting_prefix ++ "this session still holds {d} background command(s) and " ++
                        "{d} running subagent(s). Neither one moves to another process, so this " ++
                        "hands over at the first turn boundary after they finish.\n",
                    .{ in_flight.tasks, in_flight.children },
                ) catch waiting_prefix ++ "this session still holds work that does not move to " ++
                    "another process, so this hands over once it is done\n";
                if (!socket.writeAll(handle, said)) {
                    self.dropPeer(io);
                    return .carry_on;
                }
                self.waiting = true;
                return .carry_on;
            }

            if (!self.offer(io, handle)) return .carry_on;
        }

        const confirm = self.readFrame(io, handle, confirm_budget_ms) orelse return .carry_on;
        if (!std.mem.eql(u8, confirm, take_frame)) {
            self.refuse(io, handle, "that is not an answer to a ready this session sent");
            return .carry_on;
        }

        _ = socket.writeAll(handle, handing_over_frame ++ "\n");
        return .hand_over;
    }

    pub fn asking(self: *const Endpoint) bool {
        return self.peer != null;
    }

    fn acceptPending(self: *Endpoint, io: std.Io) void {
        for (0..4) |_| {
            if (!socket.readable(self.server.socket.handle, 0)) return;
            const stream = self.server.accept(io) catch return;

            const uid = socket.peerUid(stream.socket.handle) orelse {
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
            if (self.peer != null) {
                self.refused += 1;
                _ = socket.writeAll(
                    stream.socket.handle,
                    busy_prefix ++ "another process is already asking for this session\n",
                );
                stream.close(io);
                continue;
            }
            self.peer = stream.socket.handle;
            self.start = 0;
            self.filled = 0;
            self.offered = false;
            self.waiting = false;
        }
    }

    fn readFrame(self: *Endpoint, io: std.Io, handle: std.posix.fd_t, timeout_ms: u64) ?[]const u8 {
        while (true) {
            if (std.mem.indexOfScalar(u8, self.buffer[self.start..self.filled], '\n')) |offset| {
                const line = self.buffer[self.start .. self.start + offset];
                self.start += offset + 1;
                return std.mem.trimEnd(u8, line, "\r");
            }
            if (self.start != 0) {
                const rest = self.buffer[self.start..self.filled];
                std.mem.copyForwards(u8, self.buffer[0..rest.len], rest);
                self.filled = rest.len;
                self.start = 0;
            }
            // Checked before the poll. Once a peer that filled the buffer stops
            // sending, a poll never names it again.
            if (self.filled == self.buffer.len) {
                self.dropPeer(io);
                return null;
            }

            const bounded: i32 = if (timeout_ms > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(timeout_ms);
            if (!socket.readable(handle, bounded)) return null;

            const read = std.posix.read(handle, self.buffer[self.filled..]) catch |err| switch (err) {
                error.WouldBlock => return null,
                else => {
                    self.dropPeer(io);
                    return null;
                },
            };
            if (read == 0) {
                self.dropPeer(io);
                return null;
            }
            self.filled += read;
        }
    }

    fn offer(self: *Endpoint, io: std.Io, handle: std.posix.fd_t) bool {
        if (!socket.writeAll(handle, ready_frame ++ "\n")) {
            self.dropPeer(io);
            return false;
        }
        self.waiting = false;
        self.offered = true;
        return true;
    }

    /// A held ask is the one state where nothing is read for many turns, so a
    /// client that died would shut every other asker out.
    fn noticeGoneWhileWaiting(self: *Endpoint, io: std.Io, handle: std.posix.fd_t) void {
        while (socket.readable(handle, 0)) {
            if (self.start != 0) {
                const rest = self.buffer[self.start..self.filled];
                std.mem.copyForwards(u8, self.buffer[0..rest.len], rest);
                self.filled = rest.len;
                self.start = 0;
            }
            if (self.filled == self.buffer.len) {
                self.dropPeer(io);
                return;
            }
            const read = std.posix.read(handle, self.buffer[self.filled..]) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    self.dropPeer(io);
                    return;
                },
            };
            if (read == 0) {
                self.dropPeer(io);
                return;
            }
            self.filled += read;
        }
    }

    fn refuse(self: *Endpoint, io: std.Io, handle: std.posix.fd_t, reason: []const u8) void {
        var frame: [max_frame_bytes]u8 = undefined;
        const said = std.fmt.bufPrint(&frame, busy_prefix ++ "{s}\n", .{reason}) catch
            busy_prefix ++ "this session will not hand over now\n";
        _ = socket.writeAll(handle, said);
        self.dropPeer(io);
    }

    fn dropPeer(self: *Endpoint, io: std.Io) void {
        const handle = self.peer orelse return;
        const stream = std.Io.net.Stream{
            .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } },
        };
        stream.close(io);
        self.peer = null;
        self.start = 0;
        self.filled = 0;
        self.offered = false;
        self.waiting = false;
    }
};

pub const Answer = union(enum) {
    handed_over,
    busy: []const u8,
    not_listening,
    silent,
    unreadable: []const u8,
};

pub const Offer = union(enum) {
    offered,
    waiting: []const u8,
    busy: []const u8,
    silent,
    /// Never fold this into `silent`. A live session reported that way told a
    /// person to wait for a session that had already stopped.
    ended,
    unreadable: []const u8,
};

pub const Client = struct {
    handle: std.posix.fd_t,
    frames: Frames,

    /// Every borrowed string in a result points into `buffer`, so it must live
    /// as long as the results do.
    pub fn over(handle: std.posix.fd_t, buffer: []u8) Client {
        return .{ .handle = handle, .frames = .{ .buffer = buffer } };
    }

    pub fn sendAsk(self: *Client) bool {
        return socket.writeAll(self.handle, ask_frame ++ "\n");
    }

    pub fn readOffer(self: *Client, patience_ms: u64) Offer {
        const said = self.frames.next(self.handle, patience_ms) orelse
            return if (readEnded(self.handle)) .ended else .silent;
        if (std.mem.startsWith(u8, said, waiting_prefix)) {
            return .{ .waiting = said[waiting_prefix.len..] };
        }
        if (std.mem.startsWith(u8, said, busy_prefix)) return .{ .busy = said[busy_prefix.len..] };
        if (!std.mem.eql(u8, said, ready_frame)) return .{ .unreadable = said };
        return .offered;
    }

    pub fn sendTake(self: *Client) bool {
        return socket.writeAll(self.handle, take_frame ++ "\n");
    }

    /// Never assume this answer. A client that believes it owns a session which
    /// is still running is the worst answer this file can give.
    pub fn readFinal(self: *Client, patience_ms: u64) Answer {
        const said = self.frames.next(self.handle, patience_ms) orelse return .silent;
        if (std.mem.startsWith(u8, said, busy_prefix)) return .{ .busy = said[busy_prefix.len..] };
        if (!std.mem.eql(u8, said, handing_over_frame)) return .{ .unreadable = said };
        return .handed_over;
    }

    /// The loop releases the log's exclusive lock before the run closes this
    /// socket, so the end of this stream happens strictly after the unlock.
    pub fn waitForEnd(self: *Client, patience_ms: u64) bool {
        while (self.frames.next(self.handle, patience_ms)) |_| {}
        return readEnded(self.handle);
    }
};

/// A closed peer leaves a socket permanently readable with a read of zero
/// bytes, which is how it differs from a peer that has said nothing yet.
fn readEnded(handle: std.posix.fd_t) bool {
    if (!socket.readable(handle, 0)) return false;
    var scratch: [1]u8 = undefined;
    const read = std.posix.read(handle, &scratch) catch |err| switch (err) {
        // A poll can say readable when nothing is there. True here would tell a
        // client the log lock is free while the first owner still holds it.
        error.WouldBlock => return false,
        else => return true,
    };
    return read == 0;
}

/// `std.Io` copies the path into `sun_path` on the connect side too, and a path
/// longer than that field ends a safety checked build on Darwin.
pub fn ask(io: std.Io, socket_path: []const u8, patience_ms: u64, buffer: []u8) Answer {
    const address = socket.addressFor(socket_path, null) catch return .not_listening;
    const stream = address.connect(io) catch return .not_listening;
    defer stream.close(io);

    var client = Client.over(stream.socket.handle, buffer);
    if (!client.sendAsk()) return .not_listening;
    for (0..2) |attempt| {
        switch (client.readOffer(patience_ms)) {
            .offered => break,
            .waiting => |said| if (attempt == 0) continue else return .{ .unreadable = said },
            .busy => |said| return .{ .busy = said },
            .silent => return .silent,
            .ended => return .not_listening,
            .unreadable => |said| return .{ .unreadable = said },
        }
    }
    if (!client.sendTake()) return .silent;
    return client.readFinal(patience_ms);
}

pub const Frames = struct {
    buffer: []u8,
    start: usize = 0,
    filled: usize = 0,

    /// The slice points into `buffer` and is valid until the next call.
    fn next(self: *Frames, handle: std.posix.fd_t, timeout_ms: u64) ?[]const u8 {
        while (true) {
            if (std.mem.indexOfScalar(u8, self.buffer[self.start..self.filled], '\n')) |offset| {
                const line = self.buffer[self.start .. self.start + offset];
                self.start += offset + 1;
                return std.mem.trimEnd(u8, line, "\r");
            }
            if (self.start != 0) {
                const rest = self.buffer[self.start..self.filled];
                std.mem.copyForwards(u8, self.buffer[0..rest.len], rest);
                self.filled = rest.len;
                self.start = 0;
            }
            if (self.filled == self.buffer.len) return null;

            const bounded: i32 = if (timeout_ms > std.math.maxInt(i32))
                std.math.maxInt(i32)
            else
                @intCast(timeout_ms);
            if (!socket.readable(handle, bounded)) return null;
            const read = std.posix.read(handle, self.buffer[self.filled..]) catch return null;
            if (read == 0) return null;
            self.filled += read;
        }
    }
};

const testing = std.testing;

const Bench = struct {
    gpa: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    paths: Paths,
    endpoint: Endpoint,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Bench {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &buffer);

        var paths = try pathsFor(gpa, buffer[0..len], "01HANDOVER");
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
        const address = try socket.addressFor(self.paths.socket, null);
        return address.connect(io);
    }
};

fn readClientLine(stream: std.Io.net.Stream, buffer: []u8) ![]const u8 {
    var frames = Frames{ .buffer = buffer };
    return frames.next(stream.socket.handle, 1000) orelse error.NothingArrived;
}

fn sendFrame(stream: std.Io.net.Stream, frame: []const u8) !void {
    try testing.expect(socket.writeAll(stream.socket.handle, frame));
    try testing.expect(socket.writeAll(stream.socket.handle, "\n"));
}

test "the handover socket binds at exactly the bound and refuses one byte more" {
    // `std.Io.net.UnixAddress.max_len` is 108 and wrong on Darwin. On Linux
    // both halves below still pass, because `std` binds an unterminated 108.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try socket.BoundBench.open(gpa, io);
    defer bench.cleanup(io);

    var at_bound = try bench.pathsOfLength(socket.max_socket_path);
    defer at_bound.deinit();
    var endpoint = try Endpoint.open(io, .{
        .gpa = gpa,
        .dir = at_bound.dir,
        .socket = at_bound.socket,
    }, null);
    endpoint.close(io);

    var over = try bench.pathsOfLength(socket.max_socket_path + 1);
    defer over.deinit();
    var diag: ?Diagnostic = null;
    try testing.expectError(error.PathTooLong, Endpoint.open(io, .{
        .gpa = gpa,
        .dir = over.dir,
        .socket = over.socket,
    }, &diag));

    var said_buffer: [512]u8 = undefined;
    const said = try std.fmt.bufPrint(&said_buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, said, over.socket) != null);
    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{socket.max_socket_path}),
    ) != null);

    var frames: [max_frame_bytes]u8 = undefined;
    try testing.expect(ask(io, over.socket, 0, &frames) == .not_listening);
}

test "the socket path is built from the session directory and the identifier alone" {
    const gpa = testing.allocator;
    var paths = try pathsFor(gpa, "/state/p", "01ABC");
    defer paths.deinit();
    try testing.expectEqualStrings("/state/p/01ABC.ctl", paths.dir);
    try testing.expectEqualStrings("/state/p/01ABC.ctl/h", paths.socket);

    var approval = try socket.pathsFor(gpa, "/state/p", "01ABC");
    defer approval.deinit();
    try testing.expectEqualStrings(approval.dir, paths.dir);
    try testing.expect(!std.mem.eql(u8, approval.socket, paths.socket));
}

test "a session with nothing in flight hands over only after the client confirms" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(bench.endpoint.asking());

    try testing.expect(client.sendAsk());
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));

    try testing.expect(bench.endpoint.asking());
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));

    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Answer.handed_over, client.readFinal(0));
}

test "work that does not move to another process holds the handover open by name" {
    const gpa = testing.allocator;
    const io = testing.io;

    const held = [_]InFlight{
        .{ .tasks = 1 },
        .{ .children = 1 },
        .{ .tasks = 2, .children = 3 },
    };
    for (held) |in_flight| {
        var bench = try Bench.init(gpa, io);
        defer bench.deinit(io);

        const stream = try bench.attach(io);
        defer stream.close(io);
        var answers: [max_frame_bytes]u8 = undefined;
        var client = Client.over(stream.socket.handle, &answers);

        try testing.expect(client.sendAsk());
        try testing.expect(client.sendTake());
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, in_flight, 0));

        const offer = client.readOffer(0);
        try testing.expect(offer == .waiting);
        try testing.expect(std.mem.indexOf(u8, offer.waiting, "background command") != null);
        try testing.expect(std.mem.indexOf(u8, offer.waiting, "subagent") != null);

        try testing.expect(bench.endpoint.asking());

        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, in_flight, 0));
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, in_flight, 0));
        try testing.expectEqual(Offer.silent, client.readOffer(0));

        try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
        try testing.expectEqual(Offer.offered, client.readOffer(0));
        try testing.expectEqual(Answer.handed_over, client.readFinal(0));
    }

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);
    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);
    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));
}

test "a client that goes away while its ask is held lets the next one in" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    {
        const gone = try bench.attach(io);
        defer gone.close(io);
        var answers: [max_frame_bytes]u8 = undefined;
        var client = Client.over(gone.socket.handle, &answers);
        try testing.expect(client.sendAsk());
        try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{ .tasks = 1 }, 0));
        try testing.expect(client.readOffer(0) == .waiting);
        try testing.expect(bench.endpoint.asking());
    }

    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{ .tasks = 1 }, 0));
    try testing.expect(!bench.endpoint.asking());

    const next = try bench.attach(io);
    defer next.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(next.socket.handle, &answers);
    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));
}

test "a client that goes away after asking leaves the session running" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    {
        const stream = try bench.attach(io);
        var answers: [max_frame_bytes]u8 = undefined;
        var client = Client.over(stream.socket.handle, &answers);
        try testing.expect(client.sendAsk());
        stream.close(io);
    }

    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(!bench.endpoint.asking());

    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
}

test "a second asker is told it was turned away, and the first exchange is untouched" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const first = try bench.attach(io);
    defer first.close(io);
    var first_answers: [max_frame_bytes]u8 = undefined;
    var first_client = Client.over(first.socket.handle, &first_answers);

    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(bench.endpoint.asking());

    const second = try bench.attach(io);
    defer second.close(io);
    var second_answers: [max_frame_bytes]u8 = undefined;
    var second_client = Client.over(second.socket.handle, &second_answers);
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(@as(usize, 1), bench.endpoint.refused);

    const turned_away = second_client.readOffer(0);
    try testing.expect(turned_away == .busy);
    try testing.expect(std.mem.indexOf(u8, turned_away.busy, "already asking") != null);

    try testing.expect(first_client.sendAsk());
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, first_client.readOffer(0));
}

test "nothing listening is its own answer, and never a silence" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buffer);
    var paths = try pathsFor(gpa, path_buffer[0..len], "01NOBODY");
    defer paths.deinit();

    var buffer: [max_frame_bytes]u8 = undefined;
    try testing.expectEqual(Answer.not_listening, ask(io, paths.socket, 0, &buffer));
}

test "a session that answers nothing is reported as silent, and not as a handover" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());
    try testing.expectEqual(Offer.silent, client.readOffer(0));

    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
}

test "a session that ended while a client waited is not a session that is thinking" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.tmp.cleanup();
    defer bench.paths.deinit();

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());

    try testing.expectEqual(Offer.silent, client.readOffer(0));

    bench.endpoint.close(io);
    try testing.expectEqual(Offer.ended, client.readOffer(0));
}

test "a frame this build cannot read ends the exchange rather than the session" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stranger = try bench.attach(io);
    defer stranger.close(io);
    var stranger_answers: [max_frame_bytes]u8 = undefined;
    var stranger_frames = Frames{ .buffer = &stranger_answers };

    try testing.expect(socket.writeAll(stranger.socket.handle, "take\n"));
    try testing.expectEqual(Decision.carry_on, bench.endpoint.look(io, .{}, 0));
    try testing.expect(!bench.endpoint.asking());

    const said = stranger_frames.next(stranger.socket.handle, 0) orelse
        return error.NothingArrived;
    try testing.expect(std.mem.startsWith(u8, said, busy_prefix));

    const real = try bench.attach(io);
    defer real.close(io);
    var real_answers: [max_frame_bytes]u8 = undefined;
    var real_client = Client.over(real.socket.handle, &real_answers);
    try testing.expect(real_client.sendAsk());
    try testing.expect(real_client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, real_client.readOffer(0));
    try testing.expectEqual(Answer.handed_over, real_client.readFinal(0));
}

test "two frames that arrive in one read are two frames" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    const stream = try bench.attach(io);
    defer stream.close(io);

    try testing.expect(socket.writeAll(
        stream.socket.handle,
        ask_frame ++ "\n" ++ take_frame ++ "\n",
    ));
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));

    var answers: [max_frame_bytes]u8 = undefined;
    var frames = Frames{ .buffer = &answers };
    try testing.expectEqualStrings(ready_frame, frames.next(stream.socket.handle, 0).?);
    try testing.expectEqualStrings(handing_over_frame, frames.next(stream.socket.handle, 0).?);
}

test "the end of the stream is what tells the next owner the session has let go" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.tmp.cleanup();
    defer bench.paths.deinit();

    const stream = try bench.attach(io);
    defer stream.close(io);
    var answers: [max_frame_bytes]u8 = undefined;
    var client = Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());
    try testing.expect(client.sendTake());
    try testing.expectEqual(Decision.hand_over, bench.endpoint.look(io, .{}, 0));
    try testing.expectEqual(Offer.offered, client.readOffer(0));
    try testing.expectEqual(Answer.handed_over, client.readFinal(0));

    try testing.expect(!client.waitForEnd(0));

    bench.endpoint.close(io);
    try testing.expect(client.waitForEnd(0));
}

test "a closed endpoint leaves no socket file, so a client learns nobody is there" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    const socket_path = try gpa.dupe(u8, bench.paths.socket);
    defer gpa.free(socket_path);

    const stream = try bench.attach(io);
    defer stream.close(io);

    bench.endpoint.close(io);

    var answers: [max_frame_bytes]u8 = undefined;
    var frames = Frames{ .buffer = &answers };
    try testing.expect(frames.next(stream.socket.handle, 0) == null);

    try testing.expectEqual(Answer.not_listening, ask(io, socket_path, 0, &answers));

    bench.paths.deinit();
    bench.tmp.cleanup();
}
