//! The fetch tool against a real HTTP server.
//!
//! **The unit tests beside the code cannot prove the things that matter here.**
//! `lib/chock-broker/fetch.zig` pins the shape of a policy key, what a
//! `robots.txt` says, and what the table answers for a host. None of that
//! touches a socket, so none of it proves that a redirect is really followed
//! one hop at a time, that a denied hop is never opened, or that a `Disallow`
//! really stops a request before it is made.
//!
//! This project has been caught by a fake that was too kind once already: the
//! language server client had never worked against a real server, because both
//! in-house stand-ins accepted what no real one would. So every test below
//! drives `std.http.Client` through the whole of `Session.fetch` against a real
//! listening socket on the loopback interface, speaking real HTTP/1.1 bytes,
//! and asserts on **what the server was asked for** rather than on what this
//! process believes it sent.
//!
//! ## Two hosts, both on the loopback interface
//!
//! A redirect that has to be refused needs a second host, or there is nothing
//! for the policy to tell apart. `127.0.0.1` and `127.0.0.2` are two different
//! names, so they are two different policy keys, `net.fetch.1.0.0.127` and
//! `net.fetch.2.0.0.127`, and each answers itself. The whole of `127.0.0.0/8`
//! is on `lo` on Linux, which is why `build.zig` registers this suite there.
//!
//! ## Proving that nothing reached the denied host
//!
//! The second server counts the requests it served. A refusal that opened the
//! connection and then threw the answer away would pass a test that only looked
//! at the result, so the test looks at the server: it must have served nothing
//! at all. `TestServer.stop` is what releases the thread that is still waiting
//! for the connection that never came.
//!
//! ## The address guard refuses the very interface these tests run on
//!
//! `actions.perform` checks the address a name answers with before it opens
//! anything, and `127.0.0.0/8` is exactly what that check refuses. So the two
//! things this file needs are in tension, and they are separated rather than
//! traded off:
//!
//! * A test about **policy, redirects or `robots.txt`** builds its session with
//!   `Harness.initWithNames`, and says in its own call that `127.0.0.1` answers
//!   an address on the internet. Only the lookup is faked. The socket, the
//!   bytes and the server are as real as they ever were.
//! * A test about **the address guard itself** builds its session with
//!   `Harness.init`, which fakes no lookup at all, so `127.0.0.1` answers
//!   itself and the production check is the thing under test.
//!
//! A name the fake table does not hold answers itself, so a fake entry is one
//! deliberate act per name and never a blanket permission.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");

const actions = chock_broker.actions;
const fetch = chock_broker.fetch;
const table = chock_policy.table;
const testing = std.testing;

/// One thing the server answers, and the bytes it answers with. The reply is
/// the whole response, head and body, exactly as it goes on the wire: a test
/// that wants a redirect writes a redirect, and nothing here interprets HTTP
/// on the way out.
const Route = struct {
    path: []const u8,
    raw: []const u8,
};

/// A real HTTP/1.1 server on one loopback address, serving a fixed route table
/// until it is stopped, and recording every path it was asked for.
///
/// It understands exactly enough of the protocol to read one request head per
/// connection and write one reply. Each hop of a fetch is its own connection,
/// because the broker builds a fresh client per request and asks for no keep
/// alive.
const TestServer = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    net_server: std.Io.net.Server,
    address: std.Io.net.IpAddress,
    host: []const u8,
    port: u16,
    routes: []const Route,
    thread: std.Thread,
    stopping: std.atomic.Value(bool) = .init(false),

    /// Every request path, in the order they arrived.
    ///
    /// **Written only by the serving thread, and read only after `stop`.** That
    /// join is what makes it safe with no lock at all: nothing here reads a
    /// count while the thread is still running, and a test that did would be
    /// asserting on a race rather than on the server.
    seen: std.ArrayList([]u8) = .empty,

    /// The whole request head of every request, in the same order as `seen`.
    /// **What the server was really asked for**, down to the headers: a test
    /// about compression has to prove Chock offered gzip, because a client that
    /// is never offered it is never sent it.
    heads: std.ArrayList([]u8) = .empty,

    fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        routes: []const Route,
    ) !*TestServer {
        return startOnPort(gpa, io, host, 0, routes);
    }

    /// The same, on a port the caller names. **Two servers on one port and two
    /// addresses** is what the rebinding tests need: the port comes out of the
    /// URL, so the only thing that can tell the two apart is the address the
    /// connection really went to.
    fn startOnPort(
        gpa: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        wanted_port: u16,
        routes: []const Route,
    ) !*TestServer {
        const self = try gpa.create(TestServer);
        errdefer gpa.destroy(self);

        const address = try std.Io.net.IpAddress.parse(host, wanted_port);
        const net_server = try address.listen(io, .{ .reuse_address = true });
        const port = net_server.socket.address.getPort();

        self.* = .{
            .gpa = gpa,
            .io = io,
            .net_server = net_server,
            .address = try std.Io.net.IpAddress.parse(host, port),
            .host = host,
            .port = port,
            .routes = routes,
            .thread = undefined,
        };
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
        return self;
    }

    /// `http://<host>:<port>`, the prefix every URL in a test is built from.
    fn base(self: *const TestServer, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(buffer, "http://{s}:{d}", .{ self.host, self.port }) catch unreachable;
    }

    /// End the serving thread and wait for it.
    ///
    /// **The connection is what releases it.** The thread is blocked in
    /// `accept`, and a test that proved a host was never reached is exactly the
    /// test where no request will ever arrive to release it.
    fn stop(self: *TestServer) void {
        self.stopping.store(true, .release);
        if (self.address.connect(self.io, .{ .mode = .stream })) |stream| {
            var poke = stream;
            poke.close(self.io);
        } else |_| {}
        self.thread.join();
    }

    fn deinit(self: *TestServer) void {
        self.net_server.deinit(self.io);
        for (self.seen.items) |path| self.gpa.free(path);
        self.seen.deinit(self.gpa);
        for (self.heads.items) |head| self.gpa.free(head);
        self.heads.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    /// How many requests this server really answered. Read after `stop`.
    fn served(self: *TestServer) usize {
        return self.seen.items.len;
    }

    fn sawPath(self: *TestServer, path: []const u8) bool {
        for (self.seen.items) |one| {
            if (std.mem.eql(u8, one, path)) return true;
        }
        return false;
    }

    fn serve(self: *TestServer) void {
        while (true) {
            var stream = self.net_server.accept(self.io) catch break;
            defer stream.close(self.io);
            if (self.stopping.load(.acquire)) break;
            self.answerOne(&stream) catch break;
        }
    }

    fn answerOne(self: *TestServer, stream: *std.Io.net.Stream) !void {
        var read_buffer: [8 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        const reader = &stream_reader.interface;

        const head = try readHead(self.gpa, reader);
        defer self.gpa.free(head);

        const path = try self.gpa.dupe(u8, requestPath(head));
        self.seen.append(self.gpa, path) catch {
            self.gpa.free(path);
            return error.OutOfMemory;
        };

        const kept = try self.gpa.dupe(u8, head);
        self.heads.append(self.gpa, kept) catch {
            self.gpa.free(kept);
            return error.OutOfMemory;
        };

        var write_buffer: [8 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);
        const writer = &stream_writer.interface;

        for (self.routes) |route| {
            if (!std.mem.eql(u8, route.path, path)) continue;
            try writer.writeAll(route.raw);
            try writer.flush();
            return;
        }
        try writer.writeAll(not_found);
        try writer.flush();
    }
};

const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Read lines until a blank one ends the request head, and give back every
/// byte read.
fn readHead(gpa: std.mem.Allocator, reader: *std.Io.Reader) ![]u8 {
    var head: std.ArrayList(u8) = .empty;
    errdefer head.deinit(gpa);
    while (true) {
        const line = try reader.takeDelimiterInclusive('\n');
        try head.appendSlice(gpa, line);
        if (std.mem.trimEnd(u8, line, "\r\n").len == 0) break;
    }
    return head.toOwnedSlice(gpa);
}

/// The path out of a request line, or the empty string for a head this cannot
/// read. A request this server cannot parse is a test that has already gone
/// wrong, and an empty path matches no route.
fn requestPath(head: []const u8) []const u8 {
    const line_end = std.mem.indexOfScalar(u8, head, '\n') orelse return "";
    const line = std.mem.trimEnd(u8, head[0..line_end], "\r");
    var parts = std.mem.splitScalar(u8, line, ' ');
    _ = parts.next() orelse return "";
    return parts.next() orelse "";
}

/// A 200 with `body`, framed so a real client reads it.
fn okReply(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
}

/// `body`, deflated inside a gzip container, the way a real site answers a
/// client that offered gzip. The caller owns the bytes.
///
/// **A test server that never compresses is a fake that is too kind.** Every
/// other server in this file answers in plain text, which no site of any size
/// does, and that is why a fetch tool that could not decode a page passed all
/// of them.
fn gzipped(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, 1024);
    errdefer out.deinit();

    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);

    var compress = try std.compress.flate.Compress.init(&out.writer, window, .gzip, .default);
    try compress.writer.writeAll(body);
    try compress.finish();
    return out.toOwnedSlice();
}

/// A 200 whose body is gzip, framed and labelled as a real site labels it.
fn gzipReply(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    const packed_body = try gzipped(gpa, body);
    defer gpa.free(packed_body);

    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ packed_body.len, packed_body },
    );
}

/// A 200 whose body is gzip, sent in two chunks with no length in front of it.
///
/// **This is the shape ziglang.org really answers in**, measured: nginx gzips
/// on the fly, so it cannot know the length and it chunks instead. Std reads a
/// chunked body through a different path from a counted one, so a test of the
/// counted path alone leaves the real case unproven.
fn gzipChunkedReply(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    const packed_body = try gzipped(gpa, body);
    defer gpa.free(packed_body);

    const half = packed_body.len / 2;
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n" ++
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" ++
            "{x}\r\n{s}\r\n{x}\r\n{s}\r\n0\r\n\r\n",
        .{ half, packed_body[0..half], packed_body.len - half, packed_body[half..] },
    );
}

/// A 200 that claims an encoding Chock never offered.
fn encodedReply(gpa: std.mem.Allocator, encoding: []const u8, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: {s}\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ encoding, body.len, body },
    );
}

/// A 302 pointing at `location`.
fn redirectReply(gpa: std.mem.Allocator, location: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{location},
    );
}

/// A policy that permits `127.0.0.1` and nothing else.
const allows_first_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.fetch.1.0.0.127", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// A policy that permits both loopback hosts.
const allows_both_hosts: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.fetch.1.0.0.127", .decision = .allow },
    \\            .{ .action = "net.fetch.2.0.0.127", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// A resolver that answers a few names from a table, and lets every other name
/// answer itself.
///
/// **It exists for one reason**: `actions.perform` refuses the loopback
/// interface, and every server in this file listens on it. A test that needs a
/// real hop out therefore says, in its own call, which loopback host is to look
/// like a host on the internet. Nothing else about the fetch is faked: the
/// socket, the bytes and the server stay real.
///
/// **A test about the guard itself uses none of this.** It leaves the session
/// on `actions.Resolver.system`, so `127.0.0.1` answers `127.0.0.1` and the
/// refusal is the production check working.
const NamedAddresses = struct {
    entries: []const Entry,
    lookups: usize = 0,

    /// `host` answers `address`, both written out. An address rather than an
    /// `IpAddress` value, so a table reads as the DNS answer it stands for.
    const Entry = struct {
        host: []const u8,
        address: []const u8,
    };

    fn resolver(self: *NamedAddresses) actions.Resolver {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = actions.Resolver.VTable{ .lookup = lookupFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        into: []actions.Resolver.Address,
    ) actions.Resolver.LookupError!usize {
        _ = io;
        const self: *NamedAddresses = @ptrCast(@alignCast(ptr));
        self.lookups += 1;
        if (into.len == 0) return error.TooManyAddresses;
        for (self.entries) |entry| {
            if (!std.mem.eql(u8, entry.host, host)) continue;
            into[0] = std.Io.net.IpAddress.parse(entry.address, 0) catch return error.NotResolved;
            return 1;
        }
        // Not in the table, so the truth: a name that is a written out address
        // answers itself, the same as the real resolver, and anything else does
        // not resolve at all.
        into[0] = std.Io.net.IpAddress.parse(host, 0) catch return error.NotResolved;
        return 1;
    }
};

/// The claim the redirect, policy and `robots.txt` tests make about the two
/// loopback hosts they run their servers on. `93.184.216.34` is a real address
/// on the internet and nothing here connects to it.
const loopback_on_the_internet = [_]NamedAddresses.Entry{
    .{ .host = "127.0.0.1", .address = "93.184.216.34" },
    .{ .host = "127.0.0.2", .address = "93.184.216.35" },
};

/// A reachability check that counts the loopback interface as reachable, and
/// answers exactly like the production one about everything else.
///
/// **It exists for one reason**, and it is not the reason `NamedAddresses`
/// exists. A test that has to prove **where** a connection really went needs
/// the address the guard checks and the address the socket goes to to be one
/// and the same, and every server in this file listens on the interface the
/// production check refuses. Faking the lookup cannot help there: the whole
/// claim under test is that the lookup's answer is what gets dialled.
///
/// **The tests about the guard itself use none of this.** They leave
/// `Session.reachable` alone, so `network.addressIsReachable` is what refuses.
fn loopbackCounts(address: actions.Resolver.Address) bool {
    switch (address) {
        .ip4 => |ip4| if (ip4.bytes[0] == 127) return true,
        .ip6 => {},
    }
    return chock_broker.network.addressIsReachable(address);
}

/// Everything one test needs to drive a real fetch, in one value.
const Harness = struct {
    gpa: std.mem.Allocator,
    policy: *const table.Table,
    env: std.process.Environ.Map,
    addresses: NamedAddresses,
    session: fetch.Session,

    /// A session with the production resolver, untouched. **Every loopback
    /// address really answers itself here**, so the address guard applies as it
    /// does in a real run.
    fn init(gpa: std.mem.Allocator, source: [:0]const u8) !*Harness {
        return build(gpa, source, null, null);
    }

    /// A session whose lookups answer from `entries`. See `NamedAddresses` for
    /// why a test would want that and what it does not fake.
    fn initWithNames(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        entries: []const NamedAddresses.Entry,
    ) !*Harness {
        return build(gpa, source, entries, null);
    }

    /// A session whose lookups answer from `entries` and which counts the
    /// loopback interface as reachable. See `loopbackCounts`.
    fn initReachingLoopback(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        entries: []const NamedAddresses.Entry,
    ) !*Harness {
        return build(gpa, source, entries, loopbackCounts);
    }

    fn build(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        entries: ?[]const NamedAddresses.Entry,
        reachable: ?*const fn (address: actions.Resolver.Address) bool,
    ) !*Harness {
        const self = try gpa.create(Harness);
        errdefer gpa.destroy(self);

        const policy = try table.Table.parse(gpa, source, null);
        errdefer table.Table.destroy(gpa, policy);

        self.* = .{
            .gpa = gpa,
            .policy = policy,
            .env = std.process.Environ.Map.init(gpa),
            .addresses = .{ .entries = entries orelse &.{} },
            .session = undefined,
        };
        self.session = .{
            .gpa = gpa,
            .table = policy,
            .chain = &.{"main"},
            .agent_kind = "main",
            .model = "test",
            .tool = "fetch_url",
            .env = &self.env,
        };
        // Each field is left at its own default when the test gave nothing for
        // it, so a test that fakes nothing really drives what a session drives.
        if (entries != null) self.session.resolver = self.addresses.resolver();
        if (reachable) |one| self.session.reachable = one;
        return self;
    }

    fn deinit(self: *Harness) void {
        self.session.deinit();
        self.env.deinit();
        table.Table.destroy(self.gpa, self.policy);
        self.gpa.destroy(self);
    }

    fn read(self: *Harness, io: std.Io, url: []const u8) !fetch.Outcome {
        return self.session.fetch(io, .{ .url = url }, null);
    }
};

test "a page on a permitted host comes back, and the request really went out" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "the agent read this\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqual(@as(u16, 200), outcome.fetched.status);
    try testing.expectEqualStrings("the agent read this\n", outcome.fetched.body);
    try testing.expectEqual(@as(usize, 0), outcome.fetched.hops);
    try testing.expectEqualStrings(url, outcome.fetched.url);

    // The bytes came off a socket, and the server was asked for exactly two
    // things: the site's own rules, then the page.
    try testing.expectEqual(@as(usize, 2), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
    try testing.expectEqualStrings("/manual", server.seen.items[1]);
}

test "a gzip page is decoded, and the request really offered gzip" {
    // The fault this pins: `performNetFetch` used `Response.reader`, which
    // hands back the compressed bytes, while `std.http.Client` offers gzip on
    // every request. A real site took the offer, and the agent was given a page
    // of bytes nothing could read. Every other server in this file answers in
    // plain text, so not one of them could catch it.
    //
    // Mutation check: put `response.reader(&transfer_buffer)` back in
    // `lib/chock-broker/actions.zig` and this test fails on the body.
    const gpa = testing.allocator;
    const io = testing.io;

    const written = "The Zig Software Foundation is a non-profit corporation.\n" ++
        "This sentence exists so the deflate stream is worth having.\n";
    const page = try gzipReply(gpa, written);
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/download", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/download", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqual(@as(u16, 200), outcome.fetched.status);
    // The assertion is the text itself. A byte count or a status code would
    // have passed while the body was still compressed.
    try testing.expectEqualStrings(written, outcome.fetched.body);

    // **What the server was asked for.** The offer is why it compressed at
    // all, so a client that stops making it must stop this test as well.
    try testing.expectEqual(@as(usize, 2), server.served());
    try testing.expect(std.mem.indexOf(u8, server.heads.items[1], "accept-encoding: gzip") != null);
}

test "a chunked gzip page is decoded, which is the shape a real site answers in" {
    const gpa = testing.allocator;
    const io = testing.io;

    const written = "<!DOCTYPE html>\n<html lang=\"en-US\">\n  <head id=\"head\">\n" ++
        "    <title>Home</title>\n  </head>\n</html>\n";
    const page = try gzipChunkedReply(gpa, written);
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nAllow: /\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings(written, outcome.fetched.body);
}

test "a gzip robots.txt is decoded before its rules are read" {
    // The convention fails open, so a `robots.txt` nothing could decode reads
    // as a site that stated no rules, and the page a site disallows comes back
    // with no fault anywhere. That is the quiet half of the same fault.
    const gpa = testing.allocator;
    const io = testing.io;

    const robots = try gzipReply(gpa, "User-agent: chock\nDisallow: /private\n");
    defer gpa.free(robots);
    const secret = try okReply(gpa, "this page must not be requested\n");
    defer gpa.free(secret);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/private/notes", .raw = secret },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/private/notes", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.robots_disallow, outcome.refused.kind);

    // The rules were the only thing asked for. The page was never requested.
    try testing.expectEqual(@as(usize, 1), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
}

test "a small body that decodes past the bound is refused" {
    // The bound now measures what a reader gets rather than what arrived, so a
    // few kilobytes that grow into megabytes are stopped by the same rule that
    // stops a large page.
    const gpa = testing.allocator;
    const io = testing.io;

    const huge = try gpa.alloc(u8, 2 * fetch.max_body_bytes);
    defer gpa.free(huge);
    @memset(huge, 'a');

    const page = try gzipReply(gpa, huge);
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nAllow: /\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/bomb", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/bomb", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    // What arrived on the wire is a small fraction of the bound, so this is
    // the decoded size being measured and nothing else.
    try testing.expect(page.len < fetch.max_body_bytes);
    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.response_too_large, outcome.refused.kind);
}

test "an encoding Chock never offered reads nothing, and says so" {
    // The honest answer to a body nothing decoded. A page of undecoded bytes
    // under a header that calls it the page is the one thing this must never
    // do.
    //
    // `zstd` is a name `std.http` knows and Chock does not offer, so the head
    // is refused for the encoding and for nothing else. An encoding std cannot
    // name at all is the test below.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try encodedReply(gpa, "zstd", "\x28\xb5\x2f\xfdthis is not text\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nAllow: /\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.encoding_not_readable, outcome.refused.kind);
    // The agent is told which encodings this reads, so it can act on the
    // refusal rather than ask again for the same bytes.
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "gzip and deflate") != null);
    // Nothing of the body reached the answer.
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "not text") == null);
}

test "an encoding std cannot name at all still reads nothing" {
    // `brotli` is not in `std.http.ContentEncoding`, so `Head.parse` refuses
    // the whole head and the reason it refused is lost on the way out: the
    // refusal is the general one. **Measured, and stated here rather than
    // claimed as the named refusal above**, because the two really are
    // different answers and only the second names the cause.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try encodedReply(gpa, "br", "\x1b\x0e\x00\x00this is not text\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nAllow: /\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.fetch_failed, outcome.refused.kind);
    // Whatever the refusal says, it is not the body.
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "not text") == null);
}

test "a host the policy does not name reads nothing, and the server is never asked" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "this must not be read\n");
    defer gpa.free(page);

    const routes = [_]Route{.{ .path = "/manual", .raw = page }};
    // The server is on the second loopback host, and the policy names only the
    // first one.
    const server = try TestServer.start(gpa, io, "127.0.0.2", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.host_not_permitted, outcome.refused.kind);
    // The refusal names the row that would permit it, so a person reading the
    // agent's turn knows what to write.
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "net.fetch.2.0.0.127") != null);

    // **Nothing at all went out.** Not the page, and not even the robots.txt:
    // the policy is read before anything touches the network.
    try testing.expectEqual(@as(usize, 0), server.served());
}

test "a redirect is followed only when the host it names is permitted in its own right" {
    const gpa = testing.allocator;
    const io = testing.io;

    // The second host serves a page it must never be asked for.
    const secret = try okReply(gpa, "the denied host answered\n");
    defer gpa.free(secret);
    const denied_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/moved", .raw = secret },
    };
    const denied = try TestServer.start(gpa, io, "127.0.0.2", &denied_routes);
    defer denied.deinit();

    var denied_base: [64]u8 = undefined;
    const away = try std.fmt.allocPrint(gpa, "{s}/moved", .{denied.base(&denied_base)});
    defer gpa.free(away);
    const redirect = try redirectReply(gpa, away);
    defer gpa.free(redirect);

    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);
    const allowed_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/old", .raw = redirect },
    };
    const allowed = try TestServer.start(gpa, io, "127.0.0.1", &allowed_routes);
    defer allowed.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var allowed_base: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/old", .{allowed.base(&allowed_base)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    allowed.stop();
    denied.stop();

    // The first host was permitted and really answered a 302. The second was
    // not, so the chain stops there.
    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.host_not_permitted, outcome.refused.kind);
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "net.fetch.2.0.0.127") != null);

    try testing.expectEqual(@as(usize, 2), allowed.served());
    try testing.expect(allowed.sawPath("/old"));
    // **This is the assertion the whole design exists for.** An HTTP client
    // that followed the redirect for us would have asked the denied host for
    // the page, and every check above would still have passed.
    try testing.expectEqual(@as(usize, 0), denied.served());
}

test "a redirect to a permitted host is followed, and the answer says where it landed" {
    const gpa = testing.allocator;
    const io = testing.io;

    const landing = try okReply(gpa, "the page moved here\n");
    defer gpa.free(landing);
    const second_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/new", .raw = landing },
    };
    const second = try TestServer.start(gpa, io, "127.0.0.2", &second_routes);
    defer second.deinit();

    var second_base: [64]u8 = undefined;
    const away = try std.fmt.allocPrint(gpa, "{s}/new", .{second.base(&second_base)});
    defer gpa.free(away);
    const redirect = try redirectReply(gpa, away);
    defer gpa.free(redirect);

    const first_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/old", .raw = redirect },
    };
    const first = try TestServer.start(gpa, io, "127.0.0.1", &first_routes);
    defer first.deinit();

    var harness = try Harness.initWithNames(gpa, allows_both_hosts, &loopback_on_the_internet);
    defer harness.deinit();

    var first_base: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/old", .{first.base(&first_base)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    first.stop();
    second.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings("the page moved here\n", outcome.fetched.body);
    try testing.expectEqual(@as(usize, 1), outcome.fetched.hops);
    // The URL the bytes really came from, and not the one the agent asked for.
    try testing.expectEqualStrings(away, outcome.fetched.url);

    // The second host was asked for its own rules before its own page: a hop
    // is a whole fetch and not half of one.
    try testing.expectEqual(@as(usize, 2), second.served());
    try testing.expectEqualStrings("/robots.txt", second.seen.items[0]);
    try testing.expectEqualStrings("/new", second.seen.items[1]);
}

test "a relative redirect on the same host is resolved and followed" {
    const gpa = testing.allocator;
    const io = testing.io;

    const landing = try okReply(gpa, "the same host answered\n");
    defer gpa.free(landing);
    // A real server writes a bare path far more often than a whole URL.
    const redirect = try redirectReply(gpa, "/docs/here");
    defer gpa.free(redirect);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/docs/old", .raw = redirect },
        .{ .path = "/docs/here", .raw = landing },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/docs/old", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings("the same host answered\n", outcome.fetched.body);
    try testing.expect(std.mem.endsWith(u8, outcome.fetched.url, "/docs/here"));
    // One robots.txt for the site, not one per hop.
    try testing.expectEqual(@as(usize, 3), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
}

test "a robots.txt Disallow stops the page before the request is made" {
    const gpa = testing.allocator;
    const io = testing.io;

    const secret = try okReply(gpa, "this page must not be requested\n");
    defer gpa.free(secret);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /secret\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/secret/plan", .raw = secret },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/secret/plan", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.robots_disallow, outcome.refused.kind);

    // The rules were read, and the page never was.
    try testing.expectEqual(@as(usize, 1), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
    try testing.expect(!server.sawPath("/secret/plan"));
}

test "a robots.txt group naming chock beats the wildcard group on a real server" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "chock may read this\n");
    defer gpa.free(page);
    // Everybody else is shut out. A client that read the wildcard group would
    // refuse this page.
    const robots = try okReply(gpa,
        \\User-agent: *
        \\Disallow: /
        \\
        \\User-agent: chock
        \\Disallow: /private
        \\
    );
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings("chock may read this\n", outcome.fetched.body);
}

test "the robots.txt of one site is read once for the whole session" {
    const gpa = testing.allocator;
    const io = testing.io;

    const one = try okReply(gpa, "first page\n");
    defer gpa.free(one);
    const two = try okReply(gpa, "second page\n");
    defer gpa.free(two);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/one", .raw = one },
        .{ .path = "/two", .raw = two },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const base = server.base(&base_buffer);
    const first_url = try std.fmt.allocPrint(gpa, "{s}/one", .{base});
    defer gpa.free(first_url);
    const second_url = try std.fmt.allocPrint(gpa, "{s}/two", .{base});
    defer gpa.free(second_url);

    var first = try harness.read(io, first_url);
    defer first.deinit(gpa);
    var second = try harness.read(io, second_url);
    defer second.deinit(gpa);
    server.stop();

    try testing.expect(first == .fetched);
    try testing.expect(second == .fetched);

    // Three requests for two pages, and not four. One page fetch must not
    // become two requests every time.
    try testing.expectEqual(@as(usize, 3), server.served());
    var robots_reads: usize = 0;
    for (server.seen.items) |path| {
        if (std.mem.eql(u8, path, "/robots.txt")) robots_reads += 1;
    }
    try testing.expectEqual(@as(usize, 1), robots_reads);
}

test "a promise the session made stops a host the project allows" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "this must not be read\n");
    defer gpa.free(page);
    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    // The promise `restrict_self` offers word for word in its own description.
    const promised = [_]chock_policy.ratchet.Restriction{.{
        .action = "net.fetch",
        .ceiling = .deny,
        .reason = "this task reads local files",
    }};
    var outcome = try harness.session.fetch(io, .{
        .url = url,
        .self_policy = &promised,
    }, null);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.host_not_permitted, outcome.refused.kind);
    // A promise costs no request at all, the same as a policy refusal.
    try testing.expectEqual(@as(usize, 0), server.served());
}

test "a URL that carries a password reads nothing, and no request goes out" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "this must not be read\n");
    defer gpa.free(page);
    const routes = [_]Route{.{ .path = "/manual", .raw = page }};
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    // `std.http.Client` turns this into an Authorization header, so this is
    // the one shape of URL that could carry a secret to a site.
    const url = try std.fmt.allocPrint(
        gpa,
        "http://user:secret@127.0.0.1:{d}/manual",
        .{server.port},
    );
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.url_carries_user_information, outcome.refused.kind);
    try testing.expectEqual(@as(usize, 0), server.served());
}

test "a redirect chain longer than the bound stops, and stops at the bound" {
    const gpa = testing.allocator;
    const io = testing.io;

    // Every hop points back at itself, so the only thing that ends this is the
    // hop bound.
    const loop = try redirectReply(gpa, "/loop");
    defer gpa.free(loop);
    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/loop", .raw = loop },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.initWithNames(gpa, allows_first_host, &loopback_on_the_internet);
    defer harness.deinit();

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/loop", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.too_many_hops, outcome.refused.kind);

    // The rules, then one request per hop the bound allows, and not one more.
    try testing.expectEqual(@as(usize, fetch.max_hops + 2), server.served());
}

test "a permitted name that answers this machine reads nothing, and no socket opens" {
    // Mutation check: delete the `addressIsReachable` loop in
    // `performNetFetch` and this test fails, because the page comes back.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "this must not be read\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    // The policy really does permit this host, so the policy is not what
    // refuses below. Without that row the refusal would be the ordinary one and
    // this test would prove nothing.
    var harness = try Harness.init(gpa, allows_first_host);
    defer harness.deinit();
    try testing.expectEqual(table.Decision.allow, harness.session.decide("127.0.0.1", &.{}));

    var base_buffer: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/manual", .{server.base(&base_buffer)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);

    // **Nothing at all went out.** Not the page, and not even the robots.txt:
    // the address is checked after the lookup and before anything opens.
    try testing.expectEqual(@as(usize, 0), server.served());
}

test "the address check applies to a redirect hop, not only to the first request" {
    // A redirect is precisely how a name that looked fine reaches the metadata
    // address, so the check has to run again for the host a `Location` names.
    //
    // The first host is said to answer an address on the internet, so hop zero
    // really goes out over a socket. The second is not in that table, so it
    // answers itself, which is the loopback interface.
    //
    // Mutation check: delete the `addressIsReachable` loop in
    // `performNetFetch` and this test fails, because the denied host serves the
    // page.
    const gpa = testing.allocator;
    const io = testing.io;

    const secret = try okReply(gpa, "the address the guard exists for\n");
    defer gpa.free(secret);
    const denied_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/moved", .raw = secret },
    };
    const denied = try TestServer.start(gpa, io, "127.0.0.2", &denied_routes);
    defer denied.deinit();

    var denied_base: [64]u8 = undefined;
    const away = try std.fmt.allocPrint(gpa, "{s}/moved", .{denied.base(&denied_base)});
    defer gpa.free(away);
    const redirect = try redirectReply(gpa, away);
    defer gpa.free(redirect);

    const allowed_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/old", .raw = redirect },
    };
    const allowed = try TestServer.start(gpa, io, "127.0.0.1", &allowed_routes);
    defer allowed.deinit();

    // Only the first host is claimed to be on the internet.
    const first_host_only = [_]NamedAddresses.Entry{
        .{ .host = "127.0.0.1", .address = "93.184.216.34" },
    };
    // **Both hosts are permitted by the policy**, so the policy is not what
    // stops the second hop. That is the whole point of this test: the row is
    // there, and the address is what refuses.
    var harness = try Harness.initWithNames(gpa, allows_both_hosts, &first_host_only);
    defer harness.deinit();
    try testing.expectEqual(table.Decision.allow, harness.session.decide("127.0.0.2", &.{}));

    var allowed_base: [64]u8 = undefined;
    const url = try std.fmt.allocPrint(gpa, "{s}/old", .{allowed.base(&allowed_base)});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    allowed.stop();
    denied.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);

    // Hop zero really happened: the first host was asked for its own rules and
    // then for the page that redirects. Without this the test could pass with a
    // guard that refused everything at hop zero.
    try testing.expectEqual(@as(usize, 2), allowed.served());
    try testing.expect(allowed.sawPath("/old"));

    // And hop one never opened at all.
    try testing.expectEqual(@as(usize, 0), denied.served());
}

// `actions.perform` checked the address a name answered with, and then handed
// the URL to `std.http.Client`, which resolved the same name a second time for
// itself. A zone that answered differently between the two got past the guard,
// which is classic DNS rebinding and reaches `169.254.169.254` on every large
// cloud. `actions.pinnedConnection` closes that: the socket is opened to an
// address that was checked, and the client is handed a connection.
//
// **The two tests below are the only ones in this file that can tell the
// difference.** Every other test names a host that is already written out as
// an address, where both lookups are the same pure parse of the same bytes and
// there is no second answer for anybody to change.
//
// The two lookups are played by two real resolvers. `NamedAddresses` is the
// first answer, and the machine's own resolver is the second: `localhost` is a
// name, not a written out address, and RFC 6761 makes every resolver answer it
// with `127.0.0.1`. So a client that resolved the name again would land on
// `127.0.0.1`, and the address that was checked is `127.0.0.2`. Two servers on
// one port, one on each, and the one that answers says which lookup won.

/// `localhost` is claimed to answer `127.0.0.2`. The machine's own resolver
/// answers `127.0.0.1` for it, whatever this says, which is the disagreement
/// these tests are about.
const localhost_answers_the_second_host = [_]NamedAddresses.Entry{
    .{ .host = "localhost", .address = "127.0.0.2" },
};

/// A policy that permits the name `localhost`.
const allows_localhost: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.fetch.localhost", .decision = .allow },
    \\        },
    \\    },
    \\}
;

test "the request goes to the address that was checked, and not to the one a second lookup gives" {
    // Mutation check: make `actions.pinnedConnection` give back null for every
    // host and this test fails, because `rebound` serves the page instead of
    // `checked`.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "the checked address answered\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);
    const checked_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const checked = try TestServer.start(gpa, io, "127.0.0.2", &checked_routes);
    defer checked.deinit();

    // The same port on the other loopback address, which is where the second
    // lookup points. It must serve nothing at all.
    const secret = try okReply(gpa, "the rebound address answered\n");
    defer gpa.free(secret);
    const rebound_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/manual", .raw = secret },
    };
    const rebound = try TestServer.startOnPort(gpa, io, "127.0.0.1", checked.port, &rebound_routes);
    defer rebound.deinit();

    var harness = try Harness.initReachingLoopback(gpa, allows_localhost, &localhost_answers_the_second_host);
    defer harness.deinit();

    const url = try std.fmt.allocPrint(gpa, "http://localhost:{d}/manual", .{checked.port});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    checked.stop();
    rebound.stop();

    try testing.expect(outcome == .fetched);
    // The bytes say which server answered, so this cannot pass on a fetch that
    // merely succeeded.
    try testing.expectEqualStrings("the checked address answered\n", outcome.fetched.body);

    try testing.expectEqual(@as(usize, 2), checked.served());
    try testing.expectEqualStrings("/robots.txt", checked.seen.items[0]);
    try testing.expectEqualStrings("/manual", checked.seen.items[1]);

    // **The assertion the fix exists for.** The second lookup answers this
    // host, so a client that made one would have asked it for both requests.
    try testing.expectEqual(@as(usize, 0), rebound.served());
}

test "a redirect hop is dialled at the address that was checked as well" {
    // A redirect is how a name that looked fine reaches an address nobody
    // wanted, so the hop after one has to be held to a checked address too.
    //
    // Mutation check: make `actions.pinnedConnection` give back null for every
    // host and this test fails, because `rebound` serves both hops.
    const gpa = testing.allocator;
    const io = testing.io;

    const landing = try okReply(gpa, "the checked address answered the hop\n");
    defer gpa.free(landing);
    var checked_port: u16 = 0;

    // The `Location` is built before the server, so the port is chosen first
    // by binding the second host and reusing that number.
    const rebound_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/old", .raw = not_found },
        .{ .path = "/new", .raw = not_found },
    };
    const rebound = try TestServer.start(gpa, io, "127.0.0.1", &rebound_routes);
    defer rebound.deinit();
    checked_port = rebound.port;

    const away = try std.fmt.allocPrint(gpa, "http://localhost:{d}/new", .{checked_port});
    defer gpa.free(away);
    const redirect = try redirectReply(gpa, away);
    defer gpa.free(redirect);

    const checked_routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/old", .raw = redirect },
        .{ .path = "/new", .raw = landing },
    };
    const checked = try TestServer.startOnPort(gpa, io, "127.0.0.2", checked_port, &checked_routes);
    defer checked.deinit();

    var harness = try Harness.initReachingLoopback(gpa, allows_localhost, &localhost_answers_the_second_host);
    defer harness.deinit();

    const url = try std.fmt.allocPrint(gpa, "http://localhost:{d}/old", .{checked_port});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    checked.stop();
    rebound.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings("the checked address answered the hop\n", outcome.fetched.body);
    try testing.expectEqual(@as(usize, 1), outcome.fetched.hops);

    // The rules, the page that redirects, and the page it named. All three on
    // the address the guard checked.
    try testing.expectEqual(@as(usize, 3), checked.served());
    try testing.expect(checked.sawPath("/old"));
    try testing.expect(checked.sawPath("/new"));
    try testing.expectEqual(@as(usize, 0), rebound.served());
}

/// A policy that permits one name, which is not written out as an address.
const allows_the_docs_name: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.fetch.test.example.docs", .decision = .allow },
    \\        },
    \\    },
    \\}
;

test "a name that answers IPv6 addresses only is read rather than refused" {
    // Mutation check: give back `error.AddressNotPinnable` from
    // `actions.pinnedConnection` when `firstIp4` finds nothing, and this test
    // fails, because the fetch is refused instead of answered.
    //
    // The URL names `localhost`, so the client's own second lookup lands on
    // this machine and the server really answers. That second lookup is the
    // open window itself, written down: the first answer here is an IPv6
    // address on the internet, and the request goes somewhere else.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "the ordinary path answered\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);
    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    // A real address on the internet, so `addressIsReachable` permits it and
    // nothing but the missing IPv4 address decides what happens.
    const only_ip6 = [_]NamedAddresses.Entry{
        .{ .host = "localhost", .address = "2606:4700:10::6814:179a" },
    };
    var harness = try Harness.initWithNames(gpa, allows_localhost, &only_ip6);
    defer harness.deinit();

    const url = try std.fmt.allocPrint(gpa, "http://localhost:{d}/manual", .{server.port});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings("the ordinary path answered\n", outcome.fetched.body);
    // The rules and the page. The name was looked up and checked first, and
    // then read by the ordinary path.
    try testing.expectEqual(@as(usize, 2), server.served());
    try testing.expect(server.sawPath("/manual"));
    // One checked lookup per request, the rules and the page, so the guard ran
    // over the IPv6 answer both times.
    try testing.expectEqual(@as(usize, 2), harness.addresses.lookups);
}

test "an IPv6 address the guard refuses stops the fetch, pinned or not" {
    // **The check that must survive the fallback.** An IPv6 answer is no longer
    // held to an address, so the address guard is the only thing left between a
    // permitted name and whatever it answers with. Both addresses below are
    // IPv6 and neither is written as an IPv4 address, so nothing but the IPv6
    // arm of `network.addressIsReachable` can refuse them.
    //
    // Mutation check: skip an `.ip6` address in the check loop of
    // `actions.performNetFetch`, or make the `.ip6` arm of
    // `network.addressIsReachable` answer true, and this test fails, because
    // the fetch is no longer refused.
    const gpa = testing.allocator;
    const io = testing.io;

    // `::1` is this machine, and `fe80::1` is link local, which is where the
    // cloud metadata service lives on the IPv4 side.
    const refused_addresses = [_][]const u8{ "::1", "fe80::1" };

    for (refused_addresses) |address| {
        const page = try okReply(gpa, "this must not be read\n");
        defer gpa.free(page);
        const routes = [_]Route{
            .{ .path = "/robots.txt", .raw = not_found },
            .{ .path = "/manual", .raw = page },
        };
        const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
        defer server.deinit();

        const answers = [_]NamedAddresses.Entry{
            .{ .host = "docs.example.test", .address = address },
        };
        var harness = try Harness.initWithNames(gpa, allows_the_docs_name, &answers);
        defer harness.deinit();
        // The policy really does permit the host, so the policy is not what
        // refuses below.
        try testing.expectEqual(
            table.Decision.allow,
            harness.session.decide("docs.example.test", &.{}),
        );

        const url = try std.fmt.allocPrint(gpa, "http://docs.example.test:{d}/manual", .{server.port});
        defer gpa.free(url);

        var outcome = try harness.read(io, url);
        defer outcome.deinit(gpa);
        server.stop();

        try testing.expect(outcome == .refused);
        try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);
        // Nothing opened. The first request of the hop is the site's own
        // robots.txt, and it never went out either.
        try testing.expectEqual(@as(usize, 0), server.served());
    }
}

// The IPv6 fallback exists to keep an IPv6-only or a NAT64 network working, so
// the guard has to read a NAT64 address for what it is. `64:ff9b::/96` is the
// well-known prefix of RFC 6052, and a translator turns `64:ff9b::a9fe:a9fe`
// into `169.254.169.254`, the cloud metadata service. `Ip4Address.fromIp6`
// knows `::ffff:/96` and no other prefix, so the unwrap is
// `network.addressIsReachable`'s own.
//
// **The three tests below name a host of `localhost` on purpose.** The address
// is IPv6, so no connection is held to it, and the client's own second lookup
// lands on this machine where the server really is listening. A guard that
// permitted the address would therefore serve the page, and the count says so.
// A host name that resolves nowhere would have hidden that.

test "an IPv4 address behind the NAT64 prefix is refused, and nothing opens" {
    // Mutation check: delete the `nat64_well_known_prefix` arm of
    // `network.addressIsReachable` and this test fails, because the page comes
    // back and the server serves two requests.
    //
    // The second address is `127.0.0.1` behind the same prefix, which proves
    // the unwrap runs the whole of `ip4BytesAreReachable` and is not a rule
    // about the metadata address alone.
    const gpa = testing.allocator;
    const io = testing.io;

    const refused_addresses = [_][]const u8{ "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1" };

    for (refused_addresses) |address| {
        const page = try okReply(gpa, "this must not be read\n");
        defer gpa.free(page);
        const routes = [_]Route{
            .{ .path = "/robots.txt", .raw = not_found },
            .{ .path = "/manual", .raw = page },
        };
        const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
        defer server.deinit();

        const answers = [_]NamedAddresses.Entry{.{ .host = "localhost", .address = address }};
        var harness = try Harness.initWithNames(gpa, allows_localhost, &answers);
        defer harness.deinit();

        const url = try std.fmt.allocPrint(gpa, "http://localhost:{d}/manual", .{server.port});
        defer gpa.free(url);

        var outcome = try harness.read(io, url);
        defer outcome.deinit(gpa);
        server.stop();

        try testing.expect(outcome == .refused);
        try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);
        try testing.expectEqual(@as(usize, 0), server.served());
    }
}

test "the EC2 metadata address over IPv6 is refused, and nothing opens" {
    // Mutation check: delete the `ec2_metadata_ip6` arm of
    // `network.addressIsReachable` and this test fails, because the page comes
    // back.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "this must not be read\n");
    defer gpa.free(page);
    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = not_found },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    const answers = [_]NamedAddresses.Entry{.{ .host = "localhost", .address = "fd00:ec2::254" }};
    var harness = try Harness.initWithNames(gpa, allows_localhost, &answers);
    defer harness.deinit();

    const url = try std.fmt.allocPrint(gpa, "http://localhost:{d}/manual", .{server.port});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);
    try testing.expectEqual(@as(usize, 0), server.served());
}

test "an ordinary unique local address is still read" {
    // **This is what stops the rule above widening into `fc00::/7`.** Unique
    // local addressing is the IPv6 form of `10.0.0.0/8`, and a company's own
    // API on its own network is the main reason anybody permits a host at all.
    // Refusing the range would break the IPv6 half of the case the IPv4 half is
    // allowed for.
    //
    // Mutation check: refuse the whole of `fc00::/7` in
    // `network.addressIsReachable` and this test fails, because the page is
    // refused instead of read.
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "the internal API answered\n");
    defer gpa.free(page);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /private\n");
    defer gpa.free(robots);
    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/manual", .raw = page },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    const answers = [_]NamedAddresses.Entry{.{ .host = "localhost", .address = "fd12:3456:789a::1" }};
    var harness = try Harness.initWithNames(gpa, allows_localhost, &answers);
    defer harness.deinit();

    const url = try std.fmt.allocPrint(gpa, "http://localhost:{d}/manual", .{server.port});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    try testing.expect(outcome == .fetched);
    try testing.expectEqualStrings("the internal API answered\n", outcome.fetched.body);
    try testing.expectEqual(@as(usize, 2), server.served());
}

/// A resolver that answers this machine for the first lookup of a session, and
/// an address on the internet for every lookup after it.
///
/// **It is what tells the two readings of a refused `robots.txt` apart.** The
/// first request of a hop is the site's own rules, so this one meets the
/// address guard, and everything after it is permitted.
const RefusesTheFirstLookup = struct {
    lookups: usize = 0,

    fn resolver(self: *RefusesTheFirstLookup) actions.Resolver {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = actions.Resolver.VTable{ .lookup = lookupFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        into: []actions.Resolver.Address,
    ) actions.Resolver.LookupError!usize {
        _ = io;
        _ = host;
        const self: *RefusesTheFirstLookup = @ptrCast(@alignCast(ptr));
        if (into.len == 0) return error.TooManyAddresses;
        self.lookups += 1;
        const answer = if (self.lookups == 1) "127.0.0.1" else "93.184.216.34";
        into[0] = std.Io.net.IpAddress.parse(answer, 0) catch return error.NotResolved;
        return 1;
    }
};

test "a robots.txt the address guard refused is not read as a site with no rules" {
    // `robotsFor` used to read every fault as "this site stated no rules",
    // which is right for a 404 and wrong for the guard: nothing opened, the
    // emptiness was kept for the whole session, and the page the rules
    // disallow was then fetched.
    //
    // The host is written out as an address, so no connection is held to
    // anything and the page request really does reach the server.
    //
    // Mutation check: read `error.AddressNotPermitted` as "no rules" in
    // `robotsFor` again and this test fails, because the disallowed page comes
    // back.
    const gpa = testing.allocator;
    const io = testing.io;

    const secret = try okReply(gpa, "this page must not be requested\n");
    defer gpa.free(secret);
    const robots = try okReply(gpa, "User-agent: *\nDisallow: /secret\n");
    defer gpa.free(robots);

    const routes = [_]Route{
        .{ .path = "/robots.txt", .raw = robots },
        .{ .path = "/secret/plan", .raw = secret },
    };
    const server = try TestServer.start(gpa, io, "127.0.0.1", &routes);
    defer server.deinit();

    var harness = try Harness.init(gpa, allows_first_host);
    defer harness.deinit();
    var answers: RefusesTheFirstLookup = .{};
    harness.session.resolver = answers.resolver();

    const url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/secret/plan", .{server.port});
    defer gpa.free(url);

    var outcome = try harness.read(io, url);
    defer outcome.deinit(gpa);
    server.stop();

    // The refusal names the guard, which is what really stopped the call.
    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);

    // One lookup and no requests. The page was never asked for, and neither
    // was the second copy of the rules.
    try testing.expectEqual(@as(usize, 1), answers.lookups);
    try testing.expectEqual(@as(usize, 0), server.served());
}
