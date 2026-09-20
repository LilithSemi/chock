//! The daemon's control protocol over a real socket, carrying a real session
//! log. The far end here sends with `chock_proto.control.Feed`, the same code
//! `src/daemon.zig` sends with, so there is no stand-in. Nothing reaches a
//! network: the port is one the kernel gave on `127.0.0.1`.

const std = @import("std");
const chock_proto = @import("chock-proto");

const chain = chock_proto.chain;
const control = chock_proto.control;
const event = chock_proto.event;
const log = chock_proto.log;
const storage = chock_proto.storage;

const testing = std.testing;

const session_id = "01CONTROLTEST";

const Greeting = struct {
    speaks: u32 = control.protocol_version,
    /// `pcscd`'s own behaviour, in `lib/chock-pcsc/linux/wire.zig`: offering
    /// `9:5` gets success back carrying the daemon's own `4:5`.
    lenient: bool = false,
};

/// One listener, one connection, one request, answered with `control.Feed`.
const Far = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    listener: control.Listener,
    log_path: [:0]const u8,
    /// A field, so a test can be a daemon of another build.
    greeting: Greeting = .{},
    thread: std.Thread = undefined,
    /// A thread cannot fail a test from inside itself, so this is read after the join.
    failed: ?anyerror = null,
    /// Tells "the client got nothing" from "the far end was never reached".
    served: usize = 0,

    fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        address: control.Address,
        log_path: [:0]const u8,
        rounds: usize,
        greeting: Greeting,
    ) !*Far {
        const self = try gpa.create(Far);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .listener = try address.listen(io),
            .log_path = log_path,
            .greeting = greeting,
        };
        self.thread = try std.Thread.spawn(.{}, serve, .{ self, rounds });
        return self;
    }

    /// The address this really ended up on. For a port of zero the kernel picks one.
    fn reachable(self: *const Far, address: control.Address) control.Address {
        return switch (address) {
            .unix => address,
            .ip => |ip| .{ .ip = .{
                .host = ip.host,
                .port = self.listener.server.socket.address.getPort(),
            } },
        };
    }

    fn serve(self: *Far, rounds: usize) void {
        for (0..rounds) |_| {
            var stream = self.listener.server.accept(self.io) catch |err| {
                if (self.failed == null) self.failed = err;
                return;
            };
            defer stream.close(self.io);
            self.serveOne(&stream) catch |err| {
                if (self.failed == null) self.failed = err;
                return;
            };
            self.served += 1;
        }
    }

    fn serveOne(self: *Far, stream: *std.Io.net.Stream) !void {
        var read_buffer: [8 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        var write_buffer: [64 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);
        const writer = &stream_writer.interface;

        const reader = &stream_reader.interface;

        const greeting = (try reader.takeDelimiter('\n')) orelse return;
        const asked = control.Greeting.parse(.ask, greeting) catch {
            try (control.Reply{ .failed = control.no_greeting_text }).write(writer);
            try writer.flush();
            return;
        };
        if (!self.greeting.lenient and !control.accepts(self.greeting.speaks, asked.version)) {
            try control.writeMismatch(writer, self.greeting.speaks, asked.version);
            try writer.flush();
            return;
        }
        try (control.Greeting{ .version = self.greeting.speaks }).write(.answer, writer);
        try writer.flush();

        const line = (try reader.takeDelimiter('\n')) orelse return;
        const request = control.Request.parse(line) catch {
            try (control.Reply{ .failed = control.no_verb_text }).write(writer);
            try writer.flush();
            return;
        };

        const watch = switch (request) {
            .watch => |one| one,
            else => {
                try (control.Reply{ .failed = "this far end only answers watch" }).write(writer);
                try writer.flush();
                return;
            },
        };
        if (!std.mem.eql(u8, watch.session, session_id)) {
            try (control.Reply{
                .failed = "this machine holds no session with that identifier under that project",
            }).write(writer);
            try writer.flush();
            return;
        }

        var opened = try log.Log.open(self.io, self.log_path, session_id);
        defer opened.close(self.io);
        var backing = storage.JsonLines{ .log = opened };
        const store = backing.storage();

        var feed = control.Feed{ .after = watch.after };
        if (watch.after == 0) try feed.header(self.io, store, writer);
        _ = try feed.events(self.gpa, self.io, store, writer, 0);
        try writer.flush();
    }

    fn finish(self: *Far) !void {
        self.thread.join();
        if (self.failed) |err| return err;
    }

    fn deinit(self: *Far) void {
        self.listener.close(self.io);
        self.gpa.destroy(self);
    }
};

const Collected = struct {
    arena: std.heap.ArenaAllocator,
    ids: std.ArrayList(u64) = .empty,
    lines: std.ArrayList([]const u8) = .empty,
    refusal: ?[]const u8 = null,
    /// Points into the reader's buffer, so a caller that keeps it copies it first.
    said: control.Handshake = .{ .unreadable = "" },

    fn deinit(self: *Collected) void {
        self.arena.deinit();
    }
};

/// One request against a daemon at `address`. It never knows which transport.
fn collect(
    gpa: std.mem.Allocator,
    io: std.Io,
    address: control.Address,
    request: control.Request,
) !Collected {
    var got = Collected{ .arena = std.heap.ArenaAllocator.init(gpa) };
    errdefer got.deinit();
    const arena = got.arena.allocator();

    const stream = try address.connect(io);
    defer stream.close(io);

    var read_buffer: [256 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    var write_buffer: [8 * 1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);

    const Take = struct {
        arena: std.mem.Allocator,
        got: *Collected,

        fn one(self: *@This(), reply: control.Reply) anyerror!bool {
            switch (reply) {
                .record => |record| {
                    try self.got.ids.append(self.arena, record.id);
                    try self.got.lines.append(self.arena, try self.arena.dupe(u8, record.payload));
                },
                .failed => |text| self.got.refusal = try self.arena.dupe(u8, text),
                .ok => {},
            }
            return true;
        }
    };
    var take = Take{ .arena = arena, .got = &got };

    control.exchange(
        &stream_reader.interface,
        &stream_writer.interface,
        request,
        &got.said,
        &take,
        Take.one,
    ) catch |err| {
        if (err != error.HandshakeFailed) return err;
        got.said = switch (got.said) {
            .agreed, .mismatch => got.said,
            .refused => |text| .{ .refused = try arena.dupe(u8, text) },
            .unreadable => |text| .{ .unreadable = try arena.dupe(u8, text) },
        };
        return got;
    };
    return got;
}

/// Greet and stop there, offering `speaks`. `control.exchange` offers only
/// `control.protocol_version`, which leaves the refusal path out of reach.
fn greetOnly(
    io: std.Io,
    address: control.Address,
    speaks: u32,
    out: []u8,
) !control.Handshake {
    const stream = try address.connect(io);
    defer stream.close(io);

    var read_buffer: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    var write_buffer: [8 * 1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);

    const said = try control.handshake(
        &stream_reader.interface,
        &stream_writer.interface,
        speaks,
    );
    return switch (said) {
        .agreed, .mismatch => said,
        .refused => |text| .{ .refused = copyInto(out, text) },
        .unreadable => |text| .{ .unreadable = copyInto(out, text) },
    };
}

fn copyInto(out: []u8, text: []const u8) []const u8 {
    const room = @min(out.len, text.len);
    @memcpy(out[0..room], text[0..room]);
    return out[0..room];
}

const Bench = struct {
    tmp: std.testing.TmpDir,
    gpa: std.mem.Allocator,
    log_path: [:0]u8,
    ids: [4]u64 = @splat(0),

    fn init(gpa: std.mem.Allocator, io: std.Io) !Bench {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try log.absoluteDirPath(io, &buffer, tmp.dir);
        const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/s.jsonl", .{dir}, 0);
        errdefer gpa.free(log_path);

        var self = Bench{ .tmp = tmp, .gpa = gpa, .log_path = log_path };

        const opened = try log.Log.open(io, log_path, session_id);
        var backing = storage.JsonLines{ .log = opened };
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        const said = [_]event.ContentPart{.{ .text = "make the parser stop crashing" }};
        self.ids[0] = try locked.append(gpa, io, .{
            .message = .{ .role = .user, .content = &said },
        }, 1);
        self.ids[1] = try locked.append(gpa, io, .{
            .tool_call = .{ .call_id = "call1", .tool = "read_file", .arguments = "{}" },
        }, 2);
        self.ids[2] = try locked.append(gpa, io, .{
            .tool_result = .{
                .call_id = "call1",
                .output = "fn main() void {}",
                .is_error = false,
                .truncated = false,
            },
        }, 3);
        self.ids[3] = try locked.append(gpa, io, .{
            .session_end = .{ .reason = .finished, .detail = "" },
        }, 4);
        try locked.unlock(io);

        return self;
    }

    fn deinit(self: *Bench, io: std.Io) void {
        _ = io;
        self.gpa.free(self.log_path);
        self.tmp.cleanup();
    }

    /// Short: a unix socket path is bounded at `control.max_socket_path`.
    fn socketPath(self: *Bench, io: std.Io, buffer: []u8) ![]const u8 {
        var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try log.absoluteDirPath(io, &dir_buffer, self.tmp.dir);
        return std.fmt.bufPrint(buffer, "{s}/c", .{dir});
    }
};

/// The log's own lines, so the wire copy is compared against something else.
fn localLines(gpa: std.mem.Allocator, io: std.Io, log_path: [:0]const u8) !Collected {
    var got = Collected{ .arena = std.heap.ArenaAllocator.init(gpa) };
    errdefer got.deinit();
    const arena = got.arena.allocator();

    const opened = try log.Log.open(io, log_path, session_id);
    var backing = storage.JsonLines{ .log = opened };
    const store = backing.storage();
    defer store.close(io);

    var header_buffer: [storage.max_header_bytes]u8 = undefined;
    const header = try store.headerLine(io, &header_buffer);
    try got.ids.append(arena, 0);
    try got.lines.append(arena, try arena.dupe(u8, header));

    var replay = try store.replay(arena, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try got.ids.append(arena, parsed.value.id);
        try got.lines.append(arena, try arena.dupe(u8, replay.line()));
    }
    return got;
}

/// Read a chain out of what arrived, with nothing local consulted. The
/// verifier is seeded from the header record, which is why `watch` sends one.
fn verifyArrived(gpa: std.mem.Allocator, got: *const Collected) !chain.Report {
    try testing.expect(got.lines.items.len >= 1);
    try testing.expectEqual(@as(u64, 0), got.ids.items[0]);

    var verifier = chain.Verifier.init(chain.of(got.lines.items[0]));
    for (got.ids.items[1..], got.lines.items[1..]) |id, line| {
        var parsed = try event.fromJson(gpa, line);
        defer parsed.deinit();
        verifier.take(id, line, parsed.value.prev);
    }
    return verifier.finish(.complete, 0);
}

test "a session on the far end streams to a client, and its chain verifies there" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);
    const address = control.Address{ .unix = socket };

    const far = try Far.start(gpa, io, address, bench.log_path, 1, .{});
    defer far.deinit();

    var got = try collect(gpa, io, far.reachable(address), .{ .watch = .{
        .project = "/some/project",
        .session = session_id,
        .after = 0,
    } });
    defer got.deinit();
    try far.finish();

    try testing.expect(got.refusal == null);
    try testing.expectEqual(@as(usize, 5), got.lines.items.len);

    var local = try localLines(gpa, io, bench.log_path);
    defer local.deinit();
    try testing.expectEqual(local.lines.items.len, got.lines.items.len);
    for (local.lines.items, got.lines.items, local.ids.items, got.ids.items) |mine, theirs, my_id, their_id| {
        try testing.expectEqualStrings(mine, theirs);
        try testing.expectEqual(my_id, their_id);
    }

    const report = try verifyArrived(gpa, &got);
    try testing.expectEqual(chain.Verdict.intact, report.verdict);
    try testing.expectEqual(@as(u64, 4), report.events);
    try testing.expectEqual(@as(u64, 4), report.chained);
}

test "a daemon of another protocol number is refused over both transports, and asked nothing" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);

    const request = control.Request{ .watch = .{
        .project = "/some/project",
        .session = session_id,
        .after = 0,
    } };

    const other = control.protocol_version + 1;
    const addresses = [_]control.Address{
        .{ .unix = socket },
        .{ .ip = .{ .host = "127.0.0.1", .port = 0 } },
    };

    for (addresses) |address| {
        const far = try Far.start(gpa, io, address, bench.log_path, 1, .{
            .speaks = other,
            .lenient = true,
        });
        defer far.deinit();

        var got = try collect(gpa, io, far.reachable(address), request);
        defer got.deinit();
        try far.finish();

        try testing.expect(!got.said.ok());
        try testing.expectEqual(control.protocol_version, got.said.mismatch.ours);
        try testing.expectEqual(other, got.said.mismatch.theirs);
        try testing.expectEqual(@as(usize, 0), got.lines.items.len);
        try testing.expect(got.refusal == null);

        var text: std.Io.Writer.Allocating = .init(gpa);
        defer text.deinit();
        try control.handshakeRefusal(&text.writer, far.reachable(address), got.said);
        var ours: [16]u8 = undefined;
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            text.written(),
            try std.fmt.bufPrint(&ours, "{d}", .{control.protocol_version}),
        ) != null);
        try testing.expect(std.mem.indexOf(
            u8,
            text.written(),
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
    }

    {
        const address = control.Address{ .unix = socket };
        const far = try Far.start(gpa, io, address, bench.log_path, 1, .{ .speaks = other });
        defer far.deinit();

        var got = try collect(gpa, io, far.reachable(address), request);
        defer got.deinit();
        try far.finish();

        try testing.expect(!got.said.ok());
        try testing.expectEqual(@as(usize, 0), got.lines.items.len);
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            got.said.refused,
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
    }
}

test "a client of another protocol number is refused by the daemon, in words that name both" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);
    const address = control.Address{ .unix = socket };

    const far = try Far.start(gpa, io, address, bench.log_path, 1, .{ .lenient = false });
    defer far.deinit();

    var words: [512]u8 = undefined;
    const said = try greetOnly(io, far.reachable(address), control.protocol_version + 1, &words);
    try far.finish();

    try testing.expect(!said.ok());
    var ours: [16]u8 = undefined;
    var theirs: [16]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        said.refused,
        try std.fmt.bufPrint(&ours, "{d}", .{control.protocol_version}),
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        said.refused,
        try std.fmt.bufPrint(&theirs, "{d}", .{control.protocol_version + 1}),
    ) != null);
}

test "the same client reaches a daemon on a socket and a daemon on a port" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);

    const request = control.Request{ .watch = .{
        .project = "/some/project",
        .session = session_id,
        .after = 0,
    } };

    var over_socket = through: {
        const address = control.Address{ .unix = socket };
        const far = try Far.start(gpa, io, address, bench.log_path, 1, .{});
        defer far.deinit();
        var answer = try collect(gpa, io, far.reachable(address), request);
        errdefer answer.deinit();
        try far.finish();
        try testing.expectEqual(@as(usize, 1), far.served);
        break :through answer;
    };
    defer over_socket.deinit();

    var over_port = through: {
        const address = control.Address{ .ip = .{ .host = "127.0.0.1", .port = 0 } };
        const far = try Far.start(gpa, io, address, bench.log_path, 1, .{});
        defer far.deinit();
        var answer = try collect(gpa, io, far.reachable(address), request);
        errdefer answer.deinit();
        try far.finish();
        try testing.expectEqual(@as(usize, 1), far.served);
        break :through answer;
    };
    defer over_port.deinit();

    try testing.expectEqual(over_socket.lines.items.len, over_port.lines.items.len);
    try testing.expect(over_socket.lines.items.len > 1);
    for (over_socket.lines.items, over_port.lines.items) |a, b| {
        try testing.expectEqualStrings(a, b);
    }
    for (over_socket.ids.items, over_port.ids.items) |a, b| {
        try testing.expectEqual(a, b);
    }
}

test "a client that resumes gets no gap and no repeat" {
    // An event identifier is its own byte offset, so a client names the last it saw.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);
    const address = control.Address{ .unix = socket };

    const far = try Far.start(gpa, io, address, bench.log_path, 1, .{});
    defer far.deinit();

    var got = try collect(gpa, io, far.reachable(address), .{ .watch = .{
        .project = "/some/project",
        .session = session_id,
        .after = bench.ids[1],
    } });
    defer got.deinit();
    try far.finish();

    try testing.expect(got.refusal == null);
    // No header: sending it again would put a record with the identifier zero
    // in the middle of a stream.
    try testing.expectEqual(@as(usize, 2), got.ids.items.len);
    try testing.expectEqual(bench.ids[2], got.ids.items[0]);
    try testing.expectEqual(bench.ids[3], got.ids.items[1]);
    for (got.ids.items) |id| try testing.expect(id != bench.ids[1]);
}

test "a far end that will not serve says why, and never an empty stream" {
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);
    const address = control.Address{ .unix = socket };

    const far = try Far.start(gpa, io, address, bench.log_path, 1, .{});
    defer far.deinit();

    var got = try collect(gpa, io, far.reachable(address), .{ .watch = .{
        .project = "/some/project",
        .session = "01NOSUCHSESSION",
        .after = 0,
    } });
    defer got.deinit();
    try far.finish();

    try testing.expectEqual(@as(usize, 0), got.lines.items.len);
    try testing.expect(got.refusal != null);
    try testing.expect(std.mem.indexOf(u8, got.refusal.?, "holds no session") != null);
}

test "a daemon that is not listening is a refusal a client can name" {
    // Nothing is started here. This is the case where there is no far end.
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try log.absoluteDirPath(io, &dir_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const missing = try std.fmt.bufPrint(&path_buffer, "{s}/nothing", .{dir});

    try testing.expectError(
        error.NotListening,
        (control.Address{ .unix = missing }).connect(io),
    );

    // Port 1 is reserved and unused, and a connect to it on the loopback
    // interface is refused by this machine's own kernel with no packet sent.
    try testing.expectError(
        error.NotListening,
        (control.Address{ .ip = .{ .host = "127.0.0.1", .port = 1 } }).connect(io),
    );
}

test "a unix peer is named by the kernel and a TCP peer carries no identity at all" {
    // Loopback TCP tells a listener nothing about who opened it, so peer identity
    // only works where the kernel writes it. Both transports, because it is a contrast.
    const io = testing.io;
    const mine = std.posix.system.getuid();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try log.absoluteDirPath(io, &dir_buffer, tmp.dir);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try std.fmt.bufPrint(&path_buffer, "{s}/p.sock", .{dir});

    {
        var listener = try (control.Address{ .unix = socket }).listen(io);
        defer listener.close(io);
        // `unix_path` is what an accept loop reads to tell the transports apart.
        try testing.expect(listener.unix_path != null);

        const client = try (control.Address{ .unix = socket }).connect(io);
        defer client.close(io);
        var served = try listener.server.accept(io);
        defer served.close(io);

        const said = control.peerUid(served.socket.handle);
        try testing.expectEqual(@as(?std.posix.uid_t, mine), said);
        try testing.expect(control.peerAllowed(said, mine));
        try testing.expect(!control.peerAllowed(said, mine +% 1));
    }

    {
        var listener = try (control.Address{ .ip = .{ .host = "127.0.0.1", .port = 0 } }).listen(io);
        defer listener.close(io);
        try testing.expect(listener.unix_path == null);

        const port = listener.server.socket.address.getPort();
        const client = try (control.Address{ .ip = .{ .host = "127.0.0.1", .port = port } }).connect(io);
        defer client.close(io);
        var served = try listener.server.accept(io);
        defer served.close(io);

        // Null rather than a guess. An absent answer is never a permissive one.
        try testing.expectEqual(@as(?std.posix.uid_t, null), control.peerUid(served.socket.handle));
        try testing.expect(!control.peerAllowed(control.peerUid(served.socket.handle), mine));
    }
}
