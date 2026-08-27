//! A tiny HTTP/1.1 server that a test starts on `127.0.0.1`, used only to
//! give `Client.HttpClient` a real socket to drive against. It is not a
//! general purpose server: it understands exactly enough of the protocol to
//! read one request head and reply with whatever bytes a `Script` names,
//! however slowly or however brokenly the test wants those bytes delivered.
//!
//! A model provider is a peer Chock does not control, so this double must
//! reply slowly, in small pieces, and fail in the middle, because those are
//! the cases that break a client.
//! This file plays back exactly the bytes a `Script` gives it, with an
//! optional pause before each piece, and simply closes the connection when
//! it runs out of pieces: a truncated chunked body and a clean one look
//! identical up to the point where the truncated one stops, which is the
//! same shape a real dropped connection takes.
//!
//! `lib/chock-provider/Client.zig`'s own tests import this file directly by
//! its path in `test/`, not through `build.zig`: it needs no privilege and
//! no separate process, only a real socket a real `std.http.Client` can
//! connect to, so it needs none of the helper-binary machinery that
//! `test/sandbox/probe.zig` and `test/workspace/overlay_helper.zig` need.

const std = @import("std");

/// One piece of the response body, written and flushed on its own, with an
/// optional pause before it.
pub const Chunk = struct {
    bytes: []const u8,
    /// How long to wait before writing `bytes`. Zero for no pause. Simulates
    /// a provider that answers slowly.
    delay: std.Io.Duration = .zero,
};

/// Holds every body piece back until something lets it through, so a test
/// drives the order two threads run in instead of guessing it from a clock.
///
/// **This is what makes a test of the gap bound deterministic.** The client
/// asks `chock_provider.Client.Wire` whether the provider is still sending, and
/// a test whose `Wire` opens this gate one piece at a time makes each piece
/// arrive **because** the client asked. So the test pins the order of the two
/// acts, which is the fact, rather than pinning that one pause was shorter than
/// one bound, which is the machine.
///
/// A `Script` with no gate sends every piece as fast as it can, which is what
/// every other test wants.
/// Plain atomics and a yield, the same shape `chock_core.tasks`'s own `Lock`
/// takes, because `std.Io.Mutex` and `std.Io.Semaphore` both need an `Io` and
/// this waits on a thread of the server's own. The wait is measured in
/// instructions in a healthy run: the client answers the question and lets the
/// piece out before the server thread has yielded many times.
pub const Gate = struct {
    /// How many more pieces may go out. Ignored once `open` is set.
    allowed: std.atomic.Value(usize) = .init(0),
    /// Set by `openAll`: every piece from here on goes out at once.
    open: std.atomic.Value(bool) = .init(false),

    /// How many times one piece gives the processor away before it goes out
    /// anyway.
    ///
    /// **A release valve and never an assertion.** A healthy run yields a
    /// handful of times, because the test opens the gate for each piece as the
    /// client asks for it and opens it fully before it joins the server thread.
    /// A build that broke the gap check so that it never asks would otherwise
    /// hold this thread for ever, and a test that hangs says less than a test
    /// that fails. **Counted in operations and not in seconds**, so a busier
    /// machine does not change what this reaches.
    pub const give_up_yields: usize = 10_000_000;

    /// Let one more piece out.
    pub fn release(self: *Gate) void {
        _ = self.allowed.fetchAdd(1, .release);
    }

    /// Let every piece still waiting, and every piece after it, out at once.
    /// **A test calls this before it joins the server**, because a client that
    /// has all it needs stops asking and the pieces left would wait for ever.
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
            // Give the other thread the processor rather than spinning on it.
            // A yield this platform refuses leaves the spin, which is correct
            // and only slower.
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }
};

/// What one connection is answered with. This server does not interpret
/// HTTP framing at all: `head` must already carry whatever
/// `Content-Length`, `Transfer-Encoding`, or neither, the test wants the
/// client to see, and `body` must already be shaped to match, for example
/// pre-framed as chunked encoding's `<hex length>\r\n<bytes>\r\n` pieces.
/// See `httpChunk`.
pub const Script = struct {
    /// The status line and every header, ending with the blank line that
    /// ends the head. Sent first, verbatim.
    head: []const u8,
    /// The body, in pieces, each written and flushed before the next one is
    /// considered. Leaving the last chunked-encoding piece off, or ending
    /// the whole body before whatever `Content-Length` promised, is how a
    /// test simulates a connection that drops mid reply.
    body: []const Chunk = &.{},
    /// Holds each piece back until the test lets it out. Null sends every
    /// piece as fast as the script says. See `Gate`.
    gate: ?*Gate = null,
};

/// Frame `bytes` as one chunk of an HTTP/1.1 `Transfer-Encoding: chunked`
/// body: the hex length, `bytes` itself, then the trailing CRLF the chunked
/// encoding requires. `bytes` must be known at compile time because the hex
/// length is computed and joined into the result at compile time.
pub fn httpChunk(comptime bytes: []const u8) []const u8 {
    return std.fmt.comptimePrint("{x}\r\n{s}\r\n", .{ bytes.len, bytes });
}

/// The zero length chunk that ends a well formed chunked body.
pub const last_chunk = "0\r\n\r\n";

/// A running server. `start` spawns a thread that accepts exactly one
/// connection, reads its request head (and, when the head names a
/// `Content-Length`, its body), plays back `script`, then closes the
/// connection. `join` waits for that thread. `captured` is only valid to
/// read after `join` returns.
pub const FakeProvider = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    net_server: std.Io.net.Server,
    port: u16,
    script: Script,
    thread: std.Thread,
    captured: Captured = .{},

    /// What the one connection this server handled sent. Both fields are
    /// empty slices if the connection never sent a readable head, for
    /// example because the test never made a request at all.
    pub const Captured = struct {
        /// The raw request head, exactly as read off the wire, `\r\n` line
        /// endings included.
        head: []u8 = &.{},
        /// The request body, read according to the head's own
        /// `Content-Length`. Empty when the head named none.
        body: []u8 = &.{},

        fn deinit(self: *Captured, allocator: std.mem.Allocator) void {
            allocator.free(self.head);
            allocator.free(self.body);
        }
    };

    /// Start listening on an OS assigned port of `127.0.0.1` and spawn the
    /// thread that serves one connection according to `script`. `script`
    /// must outlive the returned server: nothing here copies it.
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

    /// Wait for the serving thread to finish. `captured` is safe to read
    /// only after this returns, once the thread that filled it in has
    /// joined.
    pub fn join(self: *FakeProvider) void {
        self.thread.join();
    }

    /// Release everything, including `captured`'s owned memory. Call after
    /// `join`.
    pub fn deinit(self: *FakeProvider) void {
        self.net_server.deinit(self.io);
        self.captured.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// "http://127.0.0.1:<port>", the base URL a `Client.HttpClient` in a
    /// test points at. `buf` must be at least 32 bytes.
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
        // Falling off the end here, taking `defer stream.close` with it, is
        // deliberate: a script that never wrote a final chunked-encoding
        // piece, or never reached a `Content-Length` body's declared
        // length, ends exactly the way a dropped connection would. A script
        // that finished normally closes the same way, because a real server
        // does that too once it is done: the two are told apart only by
        // whether `script.body` was actually complete, which is the test's
        // job to shape, not this file's to judge.
    }
};

/// Read lines until a blank one ends the request head, and return every
/// byte read, `\r\n` line endings and all. A malformed or endless head
/// simply propagates whatever `Reader` error stopped it. A test that wants
/// to see a truncated head never gets far enough to need one played back.
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

/// Find a `Content-Length` header's value in a raw request head. Case
/// insensitive, because HTTP header names are.
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
