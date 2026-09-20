//! A tiny HTTP/1.1 server on `127.0.0.1` that gives a real socket to drive a
//! client against. It interprets no HTTP framing, so a `Script` must carry its
//! own headers and framing. Imported by path, not through `build.zig`.

const std = @import("std");

pub const Chunk = struct {
    bytes: []const u8,
    delay: std.Io.Duration = .zero,
};

/// Plain atomics because `std.Io.Mutex` needs an `Io` and this waits on a
/// thread of the server's own.
pub const Gate = struct {
    allowed: std.atomic.Value(usize) = .init(0),
    open: std.atomic.Value(bool) = .init(false),

    /// A release valve, not an assertion. Counted in operations, not seconds.
    pub const give_up_yields: usize = 10_000_000;

    pub fn release(self: *Gate) void {
        _ = self.allowed.fetchAdd(1, .release);
    }

    /// A test must call this before it joins the server. A client that has all
    /// it needs stops asking, and the pieces left would wait for ever.
    pub fn openAll(self: *Gate) void {
        self.open.store(true, .release);
    }

    fn wait(self: *Gate) void {
        var yields: usize = 0;
        while (yields < give_up_yields) : (yields += 1) {
            if (self.open.load(.acquire)) return;
            const have = self.allowed.load(.acquire);
            if (have != 0 and self.allowed.cmpxchgWeak(have, have - 1, .acq_rel, .monotonic) == null) {
                return;
            }
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }
};

pub const Script = struct {
    head: []const u8,
    body: []const Chunk = &.{},
    gate: ?*Gate = null,
};

pub fn httpChunk(comptime bytes: []const u8) []const u8 {
    return std.fmt.comptimePrint("{x}\r\n{s}\r\n", .{ bytes.len, bytes });
}

pub const last_chunk = "0\r\n\r\n";

/// `captured` is only valid to read after `join` returns.
pub const FakeProvider = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    net_server: std.Io.net.Server,
    port: u16,
    script: Script,
    thread: std.Thread,
    captured: Captured = .{},

    pub const Captured = struct {
        head: []u8 = &.{},
        body: []u8 = &.{},

        fn deinit(self: *Captured, allocator: std.mem.Allocator) void {
            allocator.free(self.head);
            allocator.free(self.body);
        }
    };

    /// `script` must outlive the returned server. Nothing here copies it.
    pub fn start(allocator: std.mem.Allocator, io: std.Io, script: Script) !*FakeProvider {
        const self = try allocator.create(FakeProvider);
        errdefer allocator.destroy(self);

        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        const net_server = try address.listen(io, .{ .reuse_address = true });

        self.* = .{
            .allocator = allocator,
            .io = io,
            .net_server = net_server,
            .port = net_server.socket.address.getPort(),
            .script = script,
            .thread = undefined,
        };
        self.thread = try std.Thread.spawn(.{}, serveOne, .{self});
        return self;
    }

    pub fn join(self: *FakeProvider) void {
        self.thread.join();
    }

    pub fn deinit(self: *FakeProvider) void {
        self.net_server.deinit(self.io);
        self.captured.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn baseUrl(self: *const FakeProvider, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}", .{self.port}) catch unreachable;
    }

    fn serveOne(self: *FakeProvider) void {
        var stream = self.net_server.accept(self.io) catch return;
        defer stream.close(self.io);

        var read_buf: [8 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buf);
        const reader = &stream_reader.interface;

        const head = readHead(self.allocator, reader) catch return;
        self.captured.head = head;

        if (contentLength(head)) |len| {
            const body = self.allocator.alloc(u8, len) catch return;
            reader.readSliceAll(body) catch {
                self.allocator.free(body);
                return;
            };
            self.captured.body = body;
        }

        var write_buf: [8 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buf);
        const writer = &stream_writer.interface;

        writer.writeAll(self.script.head) catch return;
        writer.flush() catch return;
        for (self.script.body) |piece| {
            if (self.script.gate) |gate| gate.wait();
            if (piece.delay.toNanoseconds() != 0) std.Io.sleep(self.io, piece.delay, .real) catch return;
            writer.writeAll(piece.bytes) catch return;
            writer.flush() catch return;
        }
        // Falling off the end closes the stream. A script that stopped short of
        // its declared length ends exactly the way a dropped connection does.
    }
};

fn readHead(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]u8 {
    var head: std.ArrayList(u8) = .empty;
    errdefer head.deinit(allocator);
    while (true) {
        const line = try reader.takeDelimiterInclusive('\n');
        try head.appendSlice(allocator, line);
        if (std.mem.trimEnd(u8, line, "\r\n").len == 0) break;
    }
    return head.toOwnedSlice(allocator);
}

fn contentLength(head: []const u8) ?usize {
    var lines = std.mem.splitSequence(u8, head, "\n");
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        const prefix = "content-length:";
        if (!std.ascii.startsWithIgnoreCase(line, prefix)) continue;
        const value = std.mem.trim(u8, line[prefix.len..], " ");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}
