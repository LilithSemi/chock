//! Shipping a session log off the machine it was written on. Nothing here
//! writes to a log, locks one, or appends an event. Not named `export`, which
//! is a keyword in Zig.

const std = @import("std");
const chain = @import("chain.zig");
const storage = @import("storage.zig");

/// A record the sink will not carry is never retried. A retry sends the same
/// bytes to the same sink, so the shipper would stop for ever on one line.
pub const Delivery = union(enum) {
    delivered,
    refused: []const u8,
};

pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery,
        flush: *const fn (ptr: *anyopaque, io: std.Io) anyerror!void,
        /// Null for a sink that cannot say, so the shipper sends from the start.
        resumeAt: *const fn (ptr: *anyopaque, io: std.Io) anyerror!?u64,
        /// Nothing is sent, so a probe leaves no record in an audit trail.
        reach: *const fn (ptr: *anyopaque, io: std.Io) anyerror!void,
    };

    pub fn send(self: Sink, io: std.Io, record: Record) anyerror!Delivery {
        return self.vtable.send(self.ptr, io, record);
    }

    pub fn flush(self: Sink, io: std.Io) anyerror!void {
        return self.vtable.flush(self.ptr, io);
    }

    pub fn resumeAt(self: Sink, io: std.Io) anyerror!?u64 {
        return self.vtable.resumeAt(self.ptr, io);
    }

    pub fn reach(self: Sink, io: std.Io) anyerror!void {
        return self.vtable.reach(self.ptr, io);
    }
};

pub const Record = struct {
    session: []const u8,
    id: u64,
    /// The bytes exactly as they sit on disk, without the newline. A
    /// re-encoding makes a sound log read as tampered at the far end.
    line: []const u8,
    kind: Kind,

    pub const Kind = enum { header, event };
};

pub const Health = struct {
    delivered: u64 = 0,
    refused: u64 = 0,
    first_refusal: ?[]const u8 = null,
    faults: u64 = 0,
    first_fault: ?anyerror = null,
    stalled_at: ?u64 = null,
    recovered: bool = false,
    /// A duplicate is found at the far end by identifier; a gap is found by
    /// nobody.
    resent_from_start: bool = false,

    pub fn wantsSaying(self: Health) bool {
        return self.faults != 0 or self.refused != 0 or self.stalled_at != null or
            self.recovered or self.resent_from_start;
    }

    pub fn format(self: *const Health, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d} lines of the session log reached the sink", .{self.delivered});
        if (self.refused != 0) {
            try writer.print(", {d} could not travel it ({s})", .{
                self.refused,
                self.first_refusal orelse "no reason given",
            });
        }
        if (self.faults != 0) {
            try writer.print(", and the sink could not be reached {d} {s} (first: {s})", .{
                self.faults,
                if (self.faults == 1) "time" else "times",
                @errorName(self.first_fault orelse error.Unexpected),
            });
        }
        if (self.stalled_at) |offset| {
            try writer.print(
                ". Nothing has been shipped from byte {d} of the log onward, so that tail is on this machine and nowhere else",
                .{offset},
            );
        } else if (self.recovered) {
            try writer.print(
                ". The sink came back and was given everything it missed, so there is no gap",
                .{},
            );
        }
        if (self.resent_from_start) {
            try writer.print(
                ". This sink cannot say what it already holds, so the whole log was sent again rather than risking a gap",
                .{},
            );
        }
        try writer.print(".", .{});
    }
};

pub const Shipper = struct {
    sink: Sink,
    session: []const u8,
    cursor: u64 = 0,
    /// No replay yields the header. Without it the far end cannot anchor.
    sent_header: bool = false,
    continued: bool = false,
    started: bool = false,
    health: Health = .{},

    pub fn start(self: *Shipper, io: std.Io) void {
        if (self.started) return;
        self.started = true;
        const held = self.sink.resumeAt(io) catch |err| {
            // An absent answer must never read as "the sink has it all
            // already", which is the reading that makes a silent gap.
            self.note(err, 0);
            self.health.resent_from_start = self.continued;
            return;
        } orelse {
            self.health.resent_from_start = self.continued;
            return;
        };
        if (held == 0) return;
        self.sent_header = true;
        self.cursor = held;
    }

    /// It can fail at nothing: an audit sink must not stop a session.
    pub fn push(self: *Shipper, gpa: std.mem.Allocator, io: std.Io, store: storage.Storage) void {
        self.start(io);

        if (!self.sent_header) {
            var buffer: [storage.max_header_bytes]u8 = undefined;
            const header = store.headerLine(io, &buffer) catch |err| {
                self.note(err, 0);
                return;
            };
            switch (self.deliver(io, .{
                .session = self.session,
                .id = 0,
                .line = header,
                .kind = .header,
            }, 0)) {
                .stop => return,
                .carry_on => self.sent_header = true,
            }
        }

        var replay = store.replay(gpa, io, self.cursor) catch |err| switch (err) {
            // The cursor sits at the end of the file, which is not a fault.
            error.OffsetOutOfRange => return,
            else => {
                self.note(err, self.cursor);
                return;
            },
        };
        defer replay.deinit();

        while (true) {
            // Read the position before the call, never after. A `next` that
            // could not parse has already stepped past the line it choked on,
            // and one that found a torn fragment goes back to that start.
            const at = replay.at();
            const parsed = replay.next(io) catch |err| {
                self.note(err, at);
                return;
            } orelse {
                self.health.stalled_at = null;
                return;
            };
            defer parsed.deinit();

            switch (self.deliver(io, .{
                .session = self.session,
                .id = parsed.value.id,
                .line = replay.line(),
                .kind = .event,
            }, at)) {
                .stop => return,
                .carry_on => self.cursor = replay.at(),
            }
        }
    }

    /// The last line is the `session.end`, which is how a far end tells a whole
    /// record from one that stopped.
    pub fn finish(self: *Shipper, gpa: std.mem.Allocator, io: std.Io, store: storage.Storage) void {
        self.push(gpa, io, store);
        self.sink.flush(io) catch |err| self.note(err, self.cursor);
    }

    const Step = enum { carry_on, stop };

    fn deliver(self: *Shipper, io: std.Io, record: Record, at: u64) Step {
        const answer = self.sink.send(io, record) catch |err| {
            self.note(err, at);
            return .stop;
        };
        switch (answer) {
            .delivered => {
                self.health.delivered += 1;
                if (self.health.faults != 0) self.health.recovered = true;
            },
            .refused => |why| {
                self.health.refused += 1;
                if (self.health.first_refusal == null) self.health.first_refusal = why;
            },
        }
        self.health.stalled_at = null;
        return .carry_on;
    }

    fn note(self: *Shipper, err: anyerror, at: u64) void {
        self.health.faults += 1;
        if (self.health.first_fault == null) self.health.first_fault = err;
        self.health.stalled_at = at;
    }
};

/// The file is byte for byte the log. Write positionally, from the length this
/// sink keeps: an appending write puts a part write and then the whole line one
/// after the other, and the far end then reads a broken chain.
pub const FileDrop = struct {
    path: []const u8,
    file: ?std.Io.File = null,
    written: u64 = 0,

    pub fn sink(self: *FileDrop) Sink {
        return .{ .ptr = self, .vtable = &file_drop_vtable };
    }

    pub fn close(self: *FileDrop, io: std.Io) void {
        const file = self.file orelse return;
        self.file = null;
        file.close(io);
    }

    fn openIfNeeded(self: *FileDrop, io: std.Io) !std.Io.File {
        if (self.file) |file| return file;
        const file = try std.Io.Dir.cwd().createFile(io, self.path, .{ .truncate = false });
        errdefer file.close(io);
        self.written = try file.length(io);
        self.file = file;
        return file;
    }

    fn sendFn(ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        const file = try self.openIfNeeded(io);
        try file.writePositionalAll(io, record.line, self.written);
        try file.writePositionalAll(io, "\n", self.written + record.line.len);
        self.written += record.line.len + 1;
        return .delivered;
    }

    fn flushFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        const file = self.file orelse return;
        try file.sync(io);
    }

    fn resumeAtFn(ptr: *anyopaque, io: std.Io) anyerror!?u64 {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        _ = try self.openIfNeeded(io);
        // The file is byte for byte the log, so its own length is a log offset.
        return self.written;
    }

    fn reachFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        const self: *FileDrop = @ptrCast(@alignCast(ptr));
        _ = try self.openIfNeeded(io);
    }
};

const file_drop_vtable = Sink.VTable{
    .send = FileDrop.sendFn,
    .flush = FileDrop.flushFn,
    .resumeAt = FileDrop.resumeAtFn,
    .reach = FileDrop.reachFn,
};

pub const syslog_facility: u8 = 10;

pub const syslog_severity: u8 = 5;

pub const syslog_priority: u8 = syslog_facility * 8 + syslog_severity;

/// RFC 5424 bounds the application name at 48 characters.
pub const syslog_app_name = "chock";

/// One RFC 5424 message per log line. A collector cannot verify the chain from
/// these alone: a daemon may rewrite, reorder, or drop a datagram. `MSGID` is
/// the session identifier, which RFC 5424 bounds at 32 characters and a session
/// identifier is a 26 character ULID. The time is `NILVALUE`, so the receiver
/// stamps its own.
pub const Syslog = struct {
    path: []const u8,
    handle: ?std.posix.fd_t = null,

    pub const linux_path = "/dev/log";
    pub const darwin_path = "/var/run/syslog";

    pub fn defaultPath() []const u8 {
        return switch (@import("builtin").os.tag) {
            .macos, .ios, .tvos, .watchos, .visionos => darwin_path,
            else => linux_path,
        };
    }

    pub const Error = error{
        SyslogSocketRefused,
        SyslogPathTooLong,
        SyslogUnreachable,
        SyslogWriteFailed,
    };

    pub fn sink(self: *Syslog) Sink {
        return .{ .ptr = self, .vtable = &syslog_vtable };
    }

    pub fn close(self: *Syslog) void {
        const handle = self.handle orelse return;
        self.handle = null;
        _ = std.posix.system.close(handle);
    }

    fn connectIfNeeded(self: *Syslog) Error!std.posix.fd_t {
        if (self.handle) |handle| return handle;

        var address: std.posix.sockaddr.un = .{ .path = @splat(0) };
        if (self.path.len >= address.path.len) return error.SyslogPathTooLong;
        @memcpy(address.path[0..self.path.len], self.path);

        // These are datagram sockets, and `std.Io.net.UnixAddress` connects a
        // stream with no datagram mode, so this steps down to `std.posix`.
        const made = std.posix.system.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
        if (std.posix.errno(made) != .SUCCESS) return error.SyslogSocketRefused;
        const handle: std.posix.fd_t = @intCast(made);
        errdefer _ = std.posix.system.close(handle);

        const joined = std.posix.system.connect(
            handle,
            @ptrCast(&address),
            @intCast(@sizeOf(std.posix.sockaddr.un)),
        );
        if (std.posix.errno(joined) != .SUCCESS) return error.SyslogUnreachable;

        self.handle = handle;
        return handle;
    }

    pub fn frame(
        gpa: std.mem.Allocator,
        record: Record,
    ) std.mem.Allocator.Error![]u8 {
        return std.fmt.allocPrint(gpa, "<{d}>1 - - {s} - {s} - {s}", .{
            syslog_priority,
            syslog_app_name,
            if (record.session.len == 0) "-" else record.session,
            record.line,
        });
    }

    fn sendFn(ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery {
        _ = io;
        const self: *Syslog = @ptrCast(@alignCast(ptr));
        const handle = try self.connectIfNeeded();

        var stack: [2048]u8 = undefined;
        var fixed: std.heap.FixedBufferAllocator = .init(&stack);
        var heap: ?[]u8 = null;
        defer if (heap) |bytes| std.heap.page_allocator.free(bytes);

        const message = frame(fixed.allocator(), record) catch built: {
            const bytes = try frame(std.heap.page_allocator, record);
            heap = bytes;
            break :built bytes;
        };

        const rc = std.posix.system.write(handle, message.ptr, message.len);
        const written: isize = @bitCast(@as(usize, @bitCast(rc)));
        if (written >= 0 and @as(usize, @intCast(written)) == message.len) return .delivered;
        return switch (std.posix.errno(rc)) {
            // The kernel refuses a line larger than one datagram whole and
            // does not cut it. A truncated line reads as a tampered line.
            .MSGSIZE => .{ .refused = "the line is larger than one syslog datagram" },
            // A datagram goes whole or not at all, so a short write is a fault.
            .SUCCESS => error.SyslogWriteFailed,
            else => error.SyslogWriteFailed,
        };
    }

    fn flushFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = ptr;
        _ = io;
    }

    fn resumeAtFn(ptr: *anyopaque, io: std.Io) anyerror!?u64 {
        _ = ptr;
        _ = io;
        // A syslog daemon holds nothing this process can read back.
        return null;
    }

    /// A connect on a unix datagram socket answers: `ENOENT` for a path with
    /// nothing at it, `EACCES` for a socket this process may not reach.
    fn reachFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = io;
        const self: *Syslog = @ptrCast(@alignCast(ptr));
        _ = try self.connectIfNeeded();
    }
};

const syslog_vtable = Sink.VTable{
    .send = Syslog.sendFn,
    .flush = Syslog.flushFn,
    .resumeAt = Syslog.resumeAtFn,
    .reach = Syslog.reachFn,
};

const testing = std.testing;
const event = @import("event.zig");

const FakeSink = struct {
    gpa: std.mem.Allocator,
    lines: std.ArrayList([]u8) = .empty,
    ids: std.ArrayList(u64) = .empty,
    flushes: usize = 0,
    answer: Answer = .deliver,
    holds: ?u64 = 0,
    attempts: usize = 0,
    reachable: ?anyerror = null,
    reaches: usize = 0,

    const Answer = union(enum) {
        deliver,
        refuse: []const u8,
        fail: anyerror,
    };

    fn deinit(self: *FakeSink) void {
        for (self.lines.items) |one| self.gpa.free(one);
        self.lines.deinit(self.gpa);
        self.ids.deinit(self.gpa);
    }

    fn sink(self: *FakeSink) Sink {
        return .{ .ptr = self, .vtable = &fake_vtable };
    }

    fn joined(self: *FakeSink) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.gpa);
        for (self.lines.items) |one| {
            try out.appendSlice(self.gpa, one);
            try out.append(self.gpa, '\n');
        }
        return out.toOwnedSlice(self.gpa);
    }

    fn sendFn(ptr: *anyopaque, io: std.Io, record: Record) anyerror!Delivery {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        self.attempts += 1;
        switch (self.answer) {
            .fail => |err| return err,
            .refuse => |why| return .{ .refused = why },
            .deliver => {},
        }
        try self.lines.append(self.gpa, try self.gpa.dupe(u8, record.line));
        try self.ids.append(self.gpa, record.id);
        return .delivered;
    }

    fn flushFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        self.flushes += 1;
    }

    fn resumeAtFn(ptr: *anyopaque, io: std.Io) anyerror!?u64 {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        return self.holds;
    }

    fn reachFn(ptr: *anyopaque, io: std.Io) anyerror!void {
        _ = io;
        const self: *FakeSink = @ptrCast(@alignCast(ptr));
        self.reaches += 1;
        if (self.reachable) |err| return err;
    }

    const fake_vtable = Sink.VTable{
        .send = FakeSink.sendFn,
        .flush = FakeSink.flushFn,
        .resumeAt = FakeSink.resumeAtFn,
        .reach = FakeSink.reachFn,
    };
};

/// `text` must be comptime. A runtime slice makes `&.{ .{ .text = text } }` a
/// pointer into this function's frame, which is gone when a caller appends it.
fn say(comptime text: []const u8) event.Event {
    return .{ .message = .{ .role = .assistant, .content = &.{.{ .text = text }} } };
}

const TestLog = struct {
    tmp: std.testing.TmpDir,
    backing: *storage.JsonLines,
    store: storage.Storage,
    path: [:0]u8,
    gpa: std.mem.Allocator,

    fn open(gpa: std.mem.Allocator, io: std.Io, name: []const u8) !TestLog {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);
        const path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dir_path, name }, 0);
        errdefer gpa.free(path);

        const backing = try gpa.create(storage.JsonLines);
        errdefer gpa.destroy(backing);
        backing.* = .{ .log = try @import("log.zig").Log.open(io, path, "01TESTSESSION") };

        return .{
            .tmp = tmp,
            .backing = backing,
            .store = backing.storage(),
            .path = path,
            .gpa = gpa,
        };
    }

    fn deinit(self: *TestLog, io: std.Io) void {
        self.store.close(io);
        self.gpa.destroy(self.backing);
        self.gpa.free(self.path);
        self.tmp.cleanup();
    }

    fn append(self: *TestLog, io: std.Io, ev: event.Event, time_ms: i64) !u64 {
        var locked = try self.store.lock(io);
        defer locked.unlock(io) catch {};
        return locked.append(self.gpa, io, ev, time_ms);
    }
};

test "a log that was shipped verifies at the far end, with its chain intact" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "shipped-source");
    defer source.deinit(io);

    _ = try source.append(io, say("first"), 1000);
    _ = try source.append(io, say("second"), 2000);
    _ = try source.append(io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 3000);

    var far = std.testing.tmpDir(.{});
    defer far.cleanup();
    var far_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const far_dir = try @import("log.zig").absoluteDirPath(io, &far_buffer, far.dir);
    const drop_path = try std.fmt.allocPrintSentinel(gpa, "{s}/copy.jsonl", .{far_dir}, 0);
    defer gpa.free(drop_path);

    var drop = FileDrop{ .path = drop_path };
    defer drop.close(io);
    var shipper = Shipper{ .sink = drop.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 0), shipper.health.faults);
    try testing.expectEqual(@as(u64, 0), shipper.health.refused);
    try testing.expectEqual(@as(u64, 4), shipper.health.delivered);
    try testing.expectEqual(@as(?u64, null), shipper.health.stalled_at);

    const original = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(copy);
    try testing.expectEqualStrings(original, copy);

    var arrived = storage.JsonLines{ .log = try @import("log.zig").Log.open(io, drop_path, "01TESTSESSION") };
    const arrived_store = arrived.storage();
    defer arrived_store.close(io);

    const report = try storage.verify(arrived_store, gpa, io);
    try testing.expectEqual(chain.Verdict.intact, report.verdict);
    try testing.expectEqual(@as(u64, 3), report.events);
    try testing.expectEqual(@as(u64, 3), report.chained);
    try testing.expect(!report.edited());
}

test "an edit made after a log was shipped disagrees with the copy that left" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "shipped-then-edited");
    defer source.deinit(io);
    _ = try source.append(io, say("what really happened"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    const shipped = try sink.joined();
    defer gpa.free(shipped);
    try testing.expect(std.mem.indexOf(u8, shipped, "what really happened") != null);

    const original = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const header_end = std.mem.indexOfScalar(u8, original, '\n').? + 1;
    const header = original[0 .. header_end - 1];

    var rewritten: std.ArrayList(u8) = .empty;
    defer rewritten.deinit(gpa);
    try rewritten.appendSlice(gpa, original[0..header_end]);
    try rewritten.print(
        gpa,
        "{{\"id\":0,\"time_ms\":1000,\"session\":\"01TESTSESSION\",\"prev\":\"{s}\"," ++
            "\"event\":{{\"message\":{{\"role\":\"assistant\",\"content\":[]}}}}}}\n",
        .{&chain.of(header)},
    );
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = source.path, .data = rewritten.items });

    var rewritten_log = storage.JsonLines{
        .log = try @import("log.zig").Log.open(io, source.path, "01TESTSESSION"),
    };
    const rewritten_store = rewritten_log.storage();
    defer rewritten_store.close(io);
    const report = try storage.verify(rewritten_store, gpa, io);
    try testing.expectEqual(chain.Verdict.intact, report.verdict);

    const now = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(now);
    try testing.expect(std.mem.indexOf(u8, now, "what really happened") == null);
    try testing.expect(!std.mem.eql(u8, shipped, now));
}

test "a sink that is down fails nothing, keeps the cursor, and backfills when it returns" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "sink-that-is-down");
    defer source.deinit(io);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };

    _ = try source.append(io, say("before the outage"), 1000);
    shipper.push(gpa, io, source.store);
    try testing.expectEqual(@as(u64, 2), shipper.health.delivered);
    try testing.expect(!shipper.health.wantsSaying());

    sink.answer = .{ .fail = error.ConnectionRefused };
    _ = try source.append(io, say("during the outage"), 2000);
    shipper.push(gpa, io, source.store);
    _ = try source.append(io, say("still during"), 3000);
    shipper.push(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 2), shipper.health.delivered);
    try testing.expect(shipper.health.faults >= 2);
    try testing.expectEqual(@as(?anyerror, error.ConnectionRefused), shipper.health.first_fault);
    try testing.expect(shipper.health.stalled_at != null);
    try testing.expect(shipper.health.wantsSaying());
    const said = try std.fmt.allocPrint(gpa, "{f}", .{&shipper.health});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "could not be reached") != null);
    try testing.expect(std.mem.indexOf(u8, said, "on this machine and nowhere else") != null);

    sink.answer = .deliver;
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 4), shipper.health.delivered);
    try testing.expectEqual(@as(?u64, null), shipper.health.stalled_at);
    try testing.expect(shipper.health.recovered);

    const shipped = try sink.joined();
    defer gpa.free(shipped);
    try testing.expect(std.mem.indexOf(u8, shipped, "before the outage") != null);
    try testing.expect(std.mem.indexOf(u8, shipped, "during the outage") != null);
    try testing.expect(std.mem.indexOf(u8, shipped, "still during") != null);

    const after = try std.fmt.allocPrint(gpa, "{f}", .{&shipper.health});
    defer gpa.free(after);
    try testing.expect(std.mem.indexOf(u8, after, "there is no gap") != null);
    try testing.expect(std.mem.indexOf(u8, after, "on this machine and nowhere else") == null);
}

test "a record the sink will not carry is counted and stepped over, never retried for ever" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "refused-record");
    defer source.deinit(io);
    _ = try source.append(io, say("one"), 1000);
    _ = try source.append(io, say("two"), 2000);

    var sink = FakeSink{ .gpa = gpa, .answer = .{ .refuse = "too large for one datagram" } };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.push(gpa, io, source.store);

    try testing.expectEqual(@as(usize, 3), sink.attempts);
    try testing.expectEqual(@as(u64, 3), shipper.health.refused);
    try testing.expectEqual(@as(u64, 0), shipper.health.faults);
    try testing.expectEqualStrings("too large for one datagram", shipper.health.first_refusal.?);
    try testing.expect(shipper.health.wantsSaying());

    sink.answer = .deliver;
    _ = try source.append(io, say("three"), 3000);
    shipper.push(gpa, io, source.store);
    try testing.expectEqual(@as(u64, 1), shipper.health.delivered);
    const shipped = try sink.joined();
    defer gpa.free(shipped);
    try testing.expect(std.mem.indexOf(u8, shipped, "three") != null);
}

test "the header line goes first, and it hashes to the digest the chain is anchored to" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "header-first");
    defer source.deinit(io);
    _ = try source.append(io, say("an event"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.push(gpa, io, source.store);

    try testing.expectEqual(@as(usize, 2), sink.lines.items.len);
    try testing.expectEqual(@as(u64, 0), sink.ids.items[0]);
    try testing.expect(sink.ids.items[1] != 0);

    var buffer: [storage.max_header_bytes]u8 = undefined;
    const header = try source.store.headerLine(io, &buffer);
    try testing.expectEqualStrings(header, sink.lines.items[0]);
    const anchored = try source.store.verifier(io);
    try testing.expectEqualStrings(&chain.of(header), &anchored.expected);
}

test "a sink that already holds part of the log is not sent it again" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "continued-session");
    defer source.deinit(io);
    _ = try source.append(io, say("first run"), 1000);

    var far = std.testing.tmpDir(.{});
    defer far.cleanup();
    var far_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const far_dir = try @import("log.zig").absoluteDirPath(io, &far_buffer, far.dir);
    const drop_path = try std.fmt.allocPrintSentinel(gpa, "{s}/continued.jsonl", .{far_dir}, 0);
    defer gpa.free(drop_path);

    {
        var drop = FileDrop{ .path = drop_path };
        defer drop.close(io);
        var first = Shipper{ .sink = drop.sink(), .session = "01TESTSESSION" };
        first.finish(gpa, io, source.store);
        try testing.expectEqual(@as(u64, 2), first.health.delivered);
        try testing.expect(!first.health.resent_from_start);
    }

    _ = try source.append(io, say("second run"), 2000);

    {
        var drop = FileDrop{ .path = drop_path };
        defer drop.close(io);
        var second = Shipper{ .sink = drop.sink(), .session = "01TESTSESSION" };
        second.finish(gpa, io, source.store);
        try testing.expectEqual(@as(u64, 1), second.health.delivered);
    }

    const original = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(copy);
    try testing.expectEqualStrings(original, copy);
}

test "a continued session is sent to a forgetful sink again, and a fresh one is not" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "sink-with-no-memory");
    defer source.deinit(io);
    _ = try source.append(io, say("one"), 1000);
    _ = try source.append(io, say("two"), 2000);

    var sink = FakeSink{ .gpa = gpa, .holds = null };
    defer sink.deinit();
    var shipper = Shipper{
        .sink = sink.sink(),
        .session = "01TESTSESSION",
        .continued = true,
    };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 3), shipper.health.delivered);
    try testing.expect(shipper.health.resent_from_start);
    try testing.expect(shipper.health.wantsSaying());
    const said = try std.fmt.allocPrint(gpa, "{f}", .{&shipper.health});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "sent again") != null);

    var fresh = try TestLog.open(gpa, io, "fresh-session");
    defer fresh.deinit(io);
    _ = try fresh.append(io, say("the first turn"), 1000);
    var forgetful = FakeSink{ .gpa = gpa, .holds = null };
    defer forgetful.deinit();
    var first_run = Shipper{ .sink = forgetful.sink(), .session = "01TESTSESSION" };
    first_run.finish(gpa, io, fresh.store);

    try testing.expect(!first_run.health.resent_from_start);
    try testing.expect(!first_run.health.wantsSaying());
    try testing.expectEqual(@as(u64, 2), first_run.health.delivered);
}

test "a shipper that has nothing new does not send and does not report a fault" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "nothing-new");
    defer source.deinit(io);
    _ = try source.append(io, say("only one"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.push(gpa, io, source.store);
    const after_first = sink.attempts;

    shipper.push(gpa, io, source.store);
    shipper.push(gpa, io, source.store);

    try testing.expectEqual(after_first, sink.attempts);
    try testing.expectEqual(@as(u64, 0), shipper.health.faults);
    try testing.expect(!shipper.health.wantsSaying());
}

test "an empty log ships its header and nothing else" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "empty-log");
    defer source.deinit(io);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 1), shipper.health.delivered);
    try testing.expectEqual(@as(usize, 1), sink.flushes);
    try testing.expect(!shipper.health.wantsSaying());
}

test "the shipper writes nothing to the log it reads" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "read-only-shipper");
    defer source.deinit(io);
    _ = try source.append(io, say("the only event"), 1000);

    var sink = FakeSink{ .gpa = gpa };
    defer sink.deinit();
    var shipper = Shipper{ .sink = sink.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);
    sink.answer = .{ .fail = error.ConnectionRefused };
    _ = try source.append(io, say("a second event"), 2000);
    const after_append = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(after_append);
    shipper.finish(gpa, io, source.store);

    const after = try std.Io.Dir.cwd().readFileAlloc(io, source.path, gpa, .limited(1 << 20));
    defer gpa.free(after);
    try testing.expectEqualStrings(after_append, after);
    var locked = try source.store.lock(io);
    try locked.unlock(io);
}

test "a syslog message is RFC 5424, carries the whole line, and stamps no time of its own" {
    const gpa = testing.allocator;

    const message = try Syslog.frame(gpa, .{
        .session = "01JQAAAAAAAAAAAAAAAAAAAAAA",
        .id = 16,
        .line = "{\"id\":16,\"time_ms\":1000,\"event\":{}}",
        .kind = .event,
    });
    defer gpa.free(message);

    try testing.expectEqualStrings(
        "<85>1 - - chock - 01JQAAAAAAAAAAAAAAAAAAAAAA - {\"id\":16,\"time_ms\":1000,\"event\":{}}",
        message,
    );
    try testing.expectEqual(@as(u8, 85), syslog_priority);
    try testing.expect(std.mem.endsWith(u8, message, "{\"id\":16,\"time_ms\":1000,\"event\":{}}"));

    const anonymous = try Syslog.frame(gpa, .{ .session = "", .id = 0, .line = "{}", .kind = .header });
    defer gpa.free(anonymous);
    try testing.expectEqualStrings("<85>1 - - chock - - - {}", anonymous);
}

test "the syslog sink writes to a real unix datagram socket and reads back what it sent" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/s", .{dir_path});
    defer gpa.free(socket_path);

    const listener = bindDatagram(socket_path) orelse return error.SkipZigTest;
    defer _ = std.posix.system.close(listener);

    var syslog = Syslog{ .path = socket_path };
    defer syslog.close();
    const sink = syslog.sink();

    const answer = try sink.send(io, .{
        .session = "01JQAAAAAAAAAAAAAAAAAAAAAA",
        .id = 16,
        .line = "{\"id\":16}",
        .kind = .event,
    });
    try testing.expectEqual(Delivery.delivered, answer);
    try sink.flush(io);
    try testing.expectEqual(@as(?u64, null), try sink.resumeAt(io));

    var arrived: [512]u8 = undefined;
    const count = readDatagram(listener, &arrived) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(
        "<85>1 - - chock - 01JQAAAAAAAAAAAAAAAAAAAAAA - {\"id\":16}",
        arrived[0..count],
    );
}

test "a syslog socket nothing is listening on is a fault the shipper survives" {
    const gpa = testing.allocator;
    const io = testing.io;

    var source = try TestLog.open(gpa, io, "syslog-not-there");
    defer source.deinit(io);
    _ = try source.append(io, say("an event"), 1000);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);
    const missing = try std.fmt.allocPrint(gpa, "{s}/nothing-here", .{dir_path});
    defer gpa.free(missing);

    var syslog = Syslog{ .path = missing };
    defer syslog.close();
    var shipper = Shipper{ .sink = syslog.sink(), .session = "01TESTSESSION" };
    shipper.finish(gpa, io, source.store);

    try testing.expectEqual(@as(u64, 0), shipper.health.delivered);
    try testing.expect(shipper.health.faults != 0);
    try testing.expect(shipper.health.wantsSaying());
    try testing.expectEqual(@as(?u64, 0), shipper.health.stalled_at);

    const long = try gpa.alloc(u8, 512);
    defer gpa.free(long);
    @memset(long, 'x');
    var far_too_long = Syslog{ .path = long };
    defer far_too_long.close();
    try testing.expectError(
        error.SyslogPathTooLong,
        far_too_long.sink().send(io, .{ .session = "s", .id = 0, .line = "{}", .kind = .header }),
    );
}

test "a sink is reached for with nothing sent, and a sink that is down says so" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try @import("log.zig").absoluteDirPath(io, &buffer, tmp.dir);

    const drop_path = try std.fmt.allocPrintSentinel(gpa, "{s}/reached.jsonl", .{dir_path}, 0);
    defer gpa.free(drop_path);
    var drop = FileDrop{ .path = drop_path };
    defer drop.close(io);
    try drop.sink().reach(io);

    const after = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(after);
    try testing.expectEqualStrings("", after);

    const missing_drop = try std.fmt.allocPrintSentinel(gpa, "{s}/no-such-dir/copy.jsonl", .{dir_path}, 0);
    defer gpa.free(missing_drop);
    var lost = FileDrop{ .path = missing_drop };
    defer lost.close(io);
    try testing.expectError(error.FileNotFound, lost.sink().reach(io));

    const socket_path = try std.fmt.allocPrint(gpa, "{s}/s", .{dir_path});
    defer gpa.free(socket_path);
    const listener = bindDatagram(socket_path) orelse return error.SkipZigTest;
    defer _ = std.posix.system.close(listener);

    var syslog = Syslog{ .path = socket_path };
    defer syslog.close();
    try syslog.sink().reach(io);
    try testing.expectEqual(Delivery.delivered, try syslog.sink().send(io, .{
        .session = "01TESTSESSION",
        .id = 16,
        .line = "{\"id\":16}",
        .kind = .event,
    }));

    var arrived: [512]u8 = undefined;
    const count = readDatagram(listener, &arrived) orelse return error.SkipZigTest;
    try testing.expectEqualStrings(
        "<85>1 - - chock - 01TESTSESSION - {\"id\":16}",
        arrived[0..count],
    );

    const nothing = try std.fmt.allocPrint(gpa, "{s}/not-a-socket", .{dir_path});
    defer gpa.free(nothing);
    var down = Syslog{ .path = nothing };
    defer down.close();
    try testing.expectError(error.SyslogUnreachable, down.sink().reach(io));
}

fn bindDatagram(path: []const u8) ?std.posix.fd_t {
    var address: std.posix.sockaddr.un = .{ .path = @splat(0) };
    if (path.len >= address.path.len) return null;
    @memcpy(address.path[0..path.len], path);

    const made = std.posix.system.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM, 0);
    if (std.posix.errno(made) != .SUCCESS) return null;
    const handle: std.posix.fd_t = @intCast(made);

    const bound = std.posix.system.bind(
        handle,
        @ptrCast(&address),
        @intCast(@sizeOf(std.posix.sockaddr.un)),
    );
    if (std.posix.errno(bound) != .SUCCESS) {
        _ = std.posix.system.close(handle);
        return null;
    }
    return handle;
}

fn readDatagram(handle: std.posix.fd_t, buffer: []u8) ?usize {
    const rc = std.posix.system.read(handle, buffer.ptr, buffer.len);
    const count: isize = @bitCast(@as(usize, @bitCast(rc)));
    if (count <= 0) return null;
    return @intCast(count);
}
