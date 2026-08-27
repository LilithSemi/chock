//! The daemon's control protocol over a real socket, carrying a real session
//! log.
//!
//! ## Why this is its own test target and not a test inside `control.zig`
//!
//! The tests beside the protocol drive its grammar over buffers, which is
//! right: they pin what a request means and what a reply means, and they need
//! no socket to do it. **What they cannot pin is that the two halves compose
//! over a real transport**, and that is the whole claim a frontend rests on: a
//! browser reads a session it can never open, over a connection to a process it
//! is not.
//!
//! ## There is no stand-in here
//!
//! The far end below sends with `chock_proto.control.Feed`, which is the very
//! code `src/daemon.zig` sends with. A protocol proved against a fake server
//! that accepts more than the real one does has already been caught in this
//! project once, and a second copy of the sending logic here would be exactly
//! that fault again. What this file writes is the request handling around
//! `Feed`, which is a dozen lines, and never the sending itself.
//!
//! ## Both addresses, one client
//!
//! `collect` is one function and it is what every test below uses. It is given
//! a `control.Address`, and it does not know whether that address is a unix
//! socket on this machine or a port. **That is the design rule**: a unix
//! socket is one value of that parameter and a TCP host is another, so that
//! the daemon can move to another machine without a frontend changing. The
//! test that drives the same session over both is what says the rule holds
//! rather than being written down.
//!
//! No test here reaches a network: a unix socket lives in a temporary
//! directory, and the port is one the kernel gave on `127.0.0.1`, which is the
//! same thing `test/core/fake_provider.zig` already does.

const std = @import("std");
const chock_proto = @import("chock-proto");

const chain = chock_proto.chain;
const control = chock_proto.control;
const event = chock_proto.event;
const log = chock_proto.log;
const storage = chock_proto.storage;

const testing = std.testing;

/// The session identifier every test below uses. Not one `newId` wrote: no
/// test here builds a path from it, so nothing needs it to be well formed
/// beyond being a name a log can carry.
const session_id = "01CONTROLTEST";

/// How a far end greets, and what it does about a number it does not speak.
const Greeting = struct {
    /// The control protocol number it answers with.
    speaks: u32 = control.protocol_version,
    /// Whether it greets back whatever the client offered.
    ///
    /// **This is `pcscd`'s own behaviour and it is measured, not invented.**
    /// `lib/chock-pcsc/linux/wire.zig` records that offering `9:5` gets
    /// `SCARD_S_SUCCESS` back carrying the daemon's own `4:5`. A far end like
    /// that is the only thing that reaches a client's own number check, and it
    /// is exactly the far end a client must not talk over.
    lenient: bool = false,
};

/// A daemon's worth of the protocol: one listener, one connection, one
/// request, answered with `control.Feed`.
///
/// **It is the request handling and never the sending.** See this file's own
/// top comment.
const Far = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    listener: control.Listener,
    /// The log this serves. Borrowed.
    log_path: [:0]const u8,
    /// How this far end greets. **Fields so a test can be a daemon of another
    /// build**, which is the only way to reach either refusal against a far end
    /// that is not itself broken. The same reason
    /// `lib/chock-pcsc/linux/driver.zig` makes its `offered` a field.
    greeting: Greeting = .{},
    thread: std.Thread = undefined,
    /// The first fault the serving thread met, for the test to report after
    /// the join. A thread cannot fail a test from inside itself.
    failed: ?anyerror = null,
    /// How many connections were served. A test reads it to tell "the client
    /// got nothing" from "the far end was never reached".
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

    /// The address this really ended up on. **For a port of zero the kernel
    /// picks one**, and a client given the zero would have nothing to connect
    /// to.
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

        // **The greeting, answered exactly as `src/daemon.zig` answers it.** A
        // far end that skipped it would be a stand-in that accepts more than
        // the real daemon does, which is the fault this file exists to avoid.
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
            // The refusal a client gets for a session this end does not hold.
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

/// Everything one exchange brought back, copied out of the reader's buffer.
const Collected = struct {
    arena: std.heap.ArenaAllocator,
    ids: std.ArrayList(u64) = .empty,
    lines: std.ArrayList([]const u8) = .empty,
    refusal: ?[]const u8 = null,
    /// What the greeting ended in. Its text points into the reader's own
    /// buffer, so a test that keeps it past `collect` copies it first.
    said: control.Handshake = .{ .unreadable = "" },

    fn deinit(self: *Collected) void {
        self.arena.deinit();
    }
};

/// Run one request against a daemon at `address` and keep every line it sent.
///
/// **The one client in this file, and it takes an address.** Nothing in it
/// knows which transport it got: see this file's own top comment for why that
/// is the point rather than a detail.
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
                    // Copied: a reply points into the reader's own buffer,
                    // which the next line overwrites.
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
        // **Copied out of the reader's buffer**, which goes when this function
        // does. A caller then reads what the far end really said rather than
        // whatever the next connection left in that memory.
        got.said = switch (got.said) {
            .agreed, .mismatch => got.said,
            .refused => |text| .{ .refused = try arena.dupe(u8, text) },
            .unreadable => |text| .{ .unreadable = try arena.dupe(u8, text) },
        };
        return got;
    };
    return got;
}

/// Greet a daemon and stop there, offering `speaks` rather than what this build
/// speaks.
///
/// **The only way to be an older client against a far end that is not itself
/// broken.** `control.exchange` offers `control.protocol_version` and nothing
/// else, which is right for every real client and leaves the daemon's own
/// refusal path unreachable from a test. `lib/chock-pcsc/linux/driver.zig` makes
/// its `offered` a field for the same reason.
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

/// The head of `text` that fits in `out`. The reader's buffer goes with the
/// connection, so a caller that keeps the words keeps its own copy.
fn copyInto(out: []u8, text: []const u8) []const u8 {
    const room = @min(out.len, text.len);
    @memcpy(out[0..room], text[0..room]);
    return out[0..room];
}

/// A temporary directory with one session log in it.
const Bench = struct {
    tmp: std.testing.TmpDir,
    gpa: std.mem.Allocator,
    log_path: [:0]u8,
    /// The identifiers of the events written, in order.
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

    /// The path of a unix socket inside this bench's own directory.
    ///
    /// **Short on purpose.** A unix socket path is bounded at
    /// `control.max_socket_path`, and a temporary directory has already spent
    /// some of it.
    fn socketPath(self: *Bench, io: std.Io, buffer: []u8) ![]const u8 {
        var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try log.absoluteDirPath(io, &dir_buffer, self.tmp.dir);
        return std.fmt.bufPrint(buffer, "{s}/c", .{dir});
    }
};

/// Read the log's own lines back locally, so the wire copy has something to be
/// compared against that is not itself.
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

/// Read a chain out of what arrived, with nothing local consulted.
///
/// **This is the fact the whole export argument rests on.** A client that only
/// ever saw a socket has to be able to say whether the log it was shown agrees
/// with itself, and it can only do that if the bytes it got are the bytes on
/// disk. The verifier is seeded from the header record, which is why `watch`
/// sends one.
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
    // **The claim a frontend rests on.** A browser can never open a session
    // log: it reads what a daemon sent it over a connection. So the bytes that
    // arrive have to be the bytes on disk, or a reader at the far end cannot
    // say whether the record it is looking at agrees with itself.
    //
    // Mutation check: re-encode the parsed envelope in `control.Feed.events`
    // instead of sending `Replay.line`, and the verdict below becomes `broken`
    // for a log nobody touched. That is the fault `lib/chock-proto/ship.zig`
    // warns about, reached from the other direction.
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
    // The header line and four events.
    try testing.expectEqual(@as(usize, 5), got.lines.items.len);

    // Byte for byte what the log holds, in the log's own order.
    var local = try localLines(gpa, io, bench.log_path);
    defer local.deinit();
    try testing.expectEqual(local.lines.items.len, got.lines.items.len);
    for (local.lines.items, got.lines.items, local.ids.items, got.ids.items) |mine, theirs, my_id, their_id| {
        try testing.expectEqualStrings(mine, theirs);
        try testing.expectEqual(my_id, their_id);
    }

    // And the chain holds when it is read out of what arrived alone.
    const report = try verifyArrived(gpa, &got);
    try testing.expectEqual(chain.Verdict.intact, report.verdict);
    try testing.expectEqual(@as(u64, 4), report.events);
    try testing.expectEqual(@as(u64, 4), report.chained);
}

test "a daemon of another protocol number is refused over both transports, and asked nothing" {
    // **The fault the greeting exists for, over a real socket and a real
    // port.** Two installs mean two versions, and a client that spoke on
    // regardless would either fail to parse or, worse, send a line the far end
    // reads as something else.
    //
    // Mutation check: make `control.handshake` check only that the answer
    // starts with `Greeting.answer_prefix` and drop the `accepts` call. That is
    // exactly what `lib/chock-pcsc/linux/driver.zig` measured a real `pcscd`
    // let through, and both blocks below fail: the exchange succeeds and the
    // far end serves a `watch` to a client of a number it does not speak.
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
        // **The `pcscd` far end**: it takes whatever the client offered and
        // answers success carrying its own number. A client that read the
        // status alone would go straight on.
        const far = try Far.start(gpa, io, address, bench.log_path, 1, .{
            .speaks = other,
            .lenient = true,
        });
        defer far.deinit();

        var got = try collect(gpa, io, far.reachable(address), request);
        defer got.deinit();
        try far.finish();

        // **Nothing of the session arrived.** Not a line, not a refusal about
        // the session: the client never asked.
        try testing.expect(!got.said.ok());
        try testing.expectEqual(control.protocol_version, got.said.mismatch.ours);
        try testing.expectEqual(other, got.said.mismatch.theirs);
        try testing.expectEqual(@as(usize, 0), got.lines.items.len);
        try testing.expect(got.refusal == null);

        // And the sentence a person reads names both numbers and the address.
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

    // A far end that refuses rather than being lenient is the other half, and
    // its own words reach the client whole.
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
    // The other direction, and it is the one a person meets first: a client
    // built before a wire change, reaching a daemon that moved. **The daemon
    // refuses before it reads a request at all**, so no verb of it runs for a
    // grammar the client may not have.
    //
    // Mutation check: drop the `accepts` call from the far end's greeting and
    // this passes nothing: the daemon greets back and goes on to serve.
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

    // A refusal in the daemon's own words, and both numbers are in them, so a
    // client too old to check anything still tells its person what to update.
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
    // **The design rule, driven rather than written down.**
    // `chock serve` must not branch on whether the daemon is here, because in a
    // hosted world it is not, and every shortcut for a local one is work
    // somebody has to unpick. `collect` is one function, it takes an address,
    // and it is given two of them.
    //
    // Mutation check: give `Address.connect` a fast path that opens the log
    // when the address is a unix socket, and the two answers stop being
    // produced by the same code even while they still match.
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

    // Over a unix socket.
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

    // And over a port the kernel chose on the loopback interface. **Not a
    // network**: nothing leaves this machine, which is the same thing
    // `test/core/fake_provider.zig` already does.
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
    // **`after` means "I already have this one".** An event identifier is its
    // own byte offset, so a client that reconnects names the last one it saw
    // and the far end carries on from exactly there. That is what makes a
    // browser's own `Last-Event-ID` a resume point rather than a hint.
    //
    // Mutation check: drop the "skip the first" rule in `control.Feed.events`
    // and the event a client already has arrives a second time, which a page
    // would draw twice.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try Bench.init(gpa, io);
    defer bench.deinit(io);

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const socket = try bench.socketPath(io, &path_buffer);
    const address = control.Address{ .unix = socket };

    const far = try Far.start(gpa, io, address, bench.log_path, 1, .{});
    defer far.deinit();

    // Resume from the second event.
    var got = try collect(gpa, io, far.reachable(address), .{ .watch = .{
        .project = "/some/project",
        .session = session_id,
        .after = bench.ids[1],
    } });
    defer got.deinit();
    try far.finish();

    try testing.expect(got.refusal == null);
    // The two events after it, and no header: a client resuming already has
    // the header, and sending it again would put a record with the identifier
    // zero in the middle of a stream.
    try testing.expectEqual(@as(usize, 2), got.ids.items.len);
    try testing.expectEqual(bench.ids[2], got.ids.items[0]);
    try testing.expectEqual(bench.ids[3], got.ids.items[1]);
    for (got.ids.items) |id| try testing.expect(id != bench.ids[1]);
}

test "a far end that will not serve says why, and never an empty stream" {
    // **An empty answer and a refusal are different facts**, and a client that
    // could not tell them apart would show "no events yet" for a session this
    // machine has never heard of. The reason travels as a line of its own, so a
    // client that reads a whole connection always gets either events or a
    // sentence.
    //
    // Mutation check: close the connection instead of writing the refusal and
    // this fails, because `refusal` stays null while the stream is empty either
    // way.
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
    // The first thing anybody meets. A connect to an address nothing is on has
    // to come back as one error a caller can act on, over either transport, so
    // that `chock serve` can print the same sentence for both.
    //
    // Nothing is started here on purpose: this is the case where there is no
    // far end at all.
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

    // A port nothing listens on. Port 1 is reserved and unused, and a connect
    // to it on the loopback interface is refused by this machine's own kernel
    // without a packet leaving it.
    try testing.expectError(
        error.NotListening,
        (control.Address{ .ip = .{ .host = "127.0.0.1", .port = 1 } }).connect(io),
    );
}

test "a unix peer is named by the kernel and a TCP peer carries no identity at all" {
    // **The reason the default listener of `chock daemon` and `chock serve` is
    // a socket.** The identity is on the connection and there is no token,
    // and that only works where the kernel writes one. On a
    // machine with more than one account, loopback TCP tells a listener
    // nothing about who opened it, so a listener that trusted a local peer
    // would be trusting every account on the machine.
    //
    // **Both transports in one test, because the fact is a contrast.** A test
    // of the unix arm alone would still pass if the TCP arm answered a
    // plausible uid, and that answer is the one that would let a wrong check
    // look right.
    //
    // Mutation check: answer `getuid()` when `getsockopt` refuses, and the TCP
    // assertion below fails while the unix one still passes.
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
        // `unix_path` is what an accept loop reads to tell the two transports
        // apart, so it has to be set here and clear below.
        try testing.expect(listener.unix_path != null);

        const client = try (control.Address{ .unix = socket }).connect(io);
        defer client.close(io);
        var served = try listener.server.accept(io);
        defer served.close(io);

        const said = control.peerUid(served.socket.handle);
        try testing.expectEqual(@as(?std.posix.uid_t, mine), said);
        try testing.expect(control.peerAllowed(said, mine));
        // Another account is refused, which is the whole use of the answer.
        try testing.expect(!control.peerAllowed(said, mine +% 1));
    }

    {
        // A port the kernel chose on the loopback interface. **Nothing leaves
        // this machine**, the same thing the tests above already do.
        var listener = try (control.Address{ .ip = .{ .host = "127.0.0.1", .port = 0 } }).listen(io);
        defer listener.close(io);
        try testing.expect(listener.unix_path == null);

        const port = listener.server.socket.address.getPort();
        const client = try (control.Address{ .ip = .{ .host = "127.0.0.1", .port = port } }).connect(io);
        defer client.close(io);
        var served = try listener.server.accept(io);
        defer served.close(io);

        // **No identity, and null rather than a guess.** A caller cannot tell
        // who this is, and `peerAllowed` therefore refuses it: an absent
        // answer is never a permissive answer.
        try testing.expectEqual(@as(?std.posix.uid_t, null), control.peerUid(served.socket.handle));
        try testing.expect(!control.peerAllowed(control.peerUid(served.socket.handle), mine));
    }
}
