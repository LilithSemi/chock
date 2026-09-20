//! The fetch tool against a real HTTP server on the loopback interface. Every
//! test drives `Session.fetch` through `std.http.Client` against a real socket
//! and asserts on what the server was asked for.
//!
//! `127.0.0.1` and `127.0.0.2` are two policy keys, which is what a refused
//! redirect needs. All of `127.0.0.0/8` is on `lo` on Linux, so build.zig
//! registers this suite there. `actions.perform` refuses that range before it
//! opens anything, so a test about policy, redirects or `robots.txt` uses
//! `Harness.initWithNames` to say a loopback host answers an internet address,
//! while a test about the guard itself uses `Harness.init` and fakes no lookup.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");

const actions = chock_broker.actions;
const fetch = chock_broker.fetch;
const table = chock_policy.table;
const testing = std.testing;

const Route = struct {
    path: []const u8,
    raw: []const u8,
};

/// A real HTTP/1.1 server on one loopback address. Each hop of a fetch is its
/// own connection, because the broker builds a fresh client per request.
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

    /// Written only by the serving thread and read only after `stop`, which is
    /// what makes it safe with no lock at all.
    seen: std.ArrayList([]u8) = .empty,

    heads: std.ArrayList([]u8) = .empty,

    fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        routes: []const Route,
    ) !*TestServer {
        return startOnPort(gpa, io, host, 0, routes);
    }

    /// Two servers on one port and two addresses is what the rebinding tests
    /// need: only the address can tell the two apart.
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

    fn base(self: *const TestServer, buffer: []u8) []const u8 {
        return std.fmt.bufPrint(buffer, "http://{s}:{d}", .{ self.host, self.port }) catch unreachable;
    }

    /// End the serving thread and wait for it. The thread is blocked in
    /// `accept`, so a test where no request arrives must send the connection.
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

fn requestPath(head: []const u8) []const u8 {
    const line_end = std.mem.indexOfScalar(u8, head, '\n') orelse return "";
    const line = std.mem.trimEnd(u8, head[0..line_end], "\r");
    var parts = std.mem.splitScalar(u8, line, ' ');
    _ = parts.next() orelse return "";
    return parts.next() orelse "";
}

fn okReply(gpa: std.mem.Allocator, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ body.len, body },
    );
}

/// `body`, deflated inside a gzip container, the way a real site answers a
/// client that offered gzip. Every other server here answers in plain text.
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

/// A 200 whose body is gzip, sent in two chunks with no length. nginx gzips on
/// the fly, so it cannot know the length and chunks instead, and std reads a
/// chunked body through a different path from a counted one.
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

fn encodedReply(gpa: std.mem.Allocator, encoding: []const u8, body: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: {s}\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ encoding, body.len, body },
    );
}

fn redirectReply(gpa: std.mem.Allocator, location: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{location},
    );
}

const allows_first_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.fetch.1.0.0.127", .decision = .allow },
    \\        },
    \\    },
    \\}
;

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
/// answer itself. It exists because `actions.perform` refuses the loopback
/// interface, and every server in this file listens on it.
const NamedAddresses = struct {
    entries: []const Entry,
    lookups: usize = 0,

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
        into[0] = std.Io.net.IpAddress.parse(host, 0) catch return error.NotResolved;
        return 1;
    }
};

const loopback_on_the_internet = [_]NamedAddresses.Entry{
    .{ .host = "127.0.0.1", .address = "93.184.216.34" },
    .{ .host = "127.0.0.2", .address = "93.184.216.35" },
};

/// A reachability check that counts the loopback interface as reachable. A
/// test that must prove where a connection went needs the checked address and
/// the dialled address to be the same one.
fn loopbackCounts(address: actions.Resolver.Address) bool {
    switch (address) {
        .ip4 => |ip4| if (ip4.bytes[0] == 127) return true,
        .ip6 => {},
    }
    return chock_broker.network.addressIsReachable(address);
}

const Harness = struct {
    gpa: std.mem.Allocator,
    policy: *const table.Table,
    env: std.process.Environ.Map,
    addresses: NamedAddresses,
    session: fetch.Session,

    fn init(gpa: std.mem.Allocator, source: [:0]const u8) !*Harness {
        return build(gpa, source, null, null);
    }

    fn initWithNames(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        entries: []const NamedAddresses.Entry,
    ) !*Harness {
        return build(gpa, source, entries, null);
    }

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

    try testing.expectEqual(@as(usize, 2), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
    try testing.expectEqualStrings("/manual", server.seen.items[1]);
}

test "a gzip page is decoded, and the request really offered gzip" {
    // `std.http.Client` offers gzip on every request, and a real site takes it.
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
    try testing.expectEqualStrings(written, outcome.fetched.body);

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
    // The convention fails open, so rules nothing could decode read as no rules.
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

    try testing.expectEqual(@as(usize, 1), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
}

test "a small body that decodes past the bound is refused" {
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

    try testing.expect(page.len < fetch.max_body_bytes);
    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.response_too_large, outcome.refused.kind);
}

test "an encoding Chock never offered reads nothing, and says so" {
    // `zstd` is a name `std.http` knows and Chock does not offer.
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
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "gzip and deflate") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "not text") == null);
}

test "an encoding std cannot name at all still reads nothing" {
    // `brotli` is not in `std.http.ContentEncoding`, so `Head.parse` refuses the
    // whole head and the cause is lost. This refusal is the general one.
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
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "not text") == null);
}

test "a host the policy does not name reads nothing, and the server is never asked" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "this must not be read\n");
    defer gpa.free(page);

    const routes = [_]Route{.{ .path = "/manual", .raw = page }};
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
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "net.fetch.2.0.0.127") != null);

    try testing.expectEqual(@as(usize, 0), server.served());
}

test "a redirect is followed only when the host it names is permitted in its own right" {
    const gpa = testing.allocator;
    const io = testing.io;

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

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.host_not_permitted, outcome.refused.kind);
    try testing.expect(std.mem.indexOf(u8, outcome.refused.text, "net.fetch.2.0.0.127") != null);

    try testing.expectEqual(@as(usize, 2), allowed.served());
    try testing.expect(allowed.sawPath("/old"));
    // An HTTP client that followed the redirect for us would have asked the
    // denied host for the page, and every check above would still have passed.
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
    try testing.expectEqualStrings(away, outcome.fetched.url);

    try testing.expectEqual(@as(usize, 2), second.served());
    try testing.expectEqualStrings("/robots.txt", second.seen.items[0]);
    try testing.expectEqualStrings("/new", second.seen.items[1]);
}

test "a relative redirect on the same host is resolved and followed" {
    const gpa = testing.allocator;
    const io = testing.io;

    const landing = try okReply(gpa, "the same host answered\n");
    defer gpa.free(landing);
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

    try testing.expectEqual(@as(usize, 1), server.served());
    try testing.expectEqualStrings("/robots.txt", server.seen.items[0]);
    try testing.expect(!server.sawPath("/secret/plan"));
}

test "a robots.txt group naming chock beats the wildcard group on a real server" {
    const gpa = testing.allocator;
    const io = testing.io;

    const page = try okReply(gpa, "chock may read this\n");
    defer gpa.free(page);
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

    // `std.http.Client` turns this into an Authorization header.
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

    try testing.expectEqual(@as(usize, fetch.max_hops + 2), server.served());
}

test "a permitted name that answers this machine reads nothing, and no socket opens" {
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

    try testing.expectEqual(@as(usize, 0), server.served());
}

test "the address check applies to a redirect hop, not only to the first request" {
    // A redirect is how a name that looked fine reaches the metadata address.
    // The first host is said to answer an internet address, and the second is
    // not in that table, so it answers itself.
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

    const first_host_only = [_]NamedAddresses.Entry{
        .{ .host = "127.0.0.1", .address = "93.184.216.34" },
    };
    // Both hosts are permitted by the policy, so the address is what refuses.
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

    try testing.expectEqual(@as(usize, 2), allowed.served());
    try testing.expect(allowed.sawPath("/old"));

    try testing.expectEqual(@as(usize, 0), denied.served());
}

// `actions.perform` checked the address a name answered with, and then handed
// the URL to `std.http.Client`, which resolved the same name a second time.
// `localhost` is a name, and RFC 6761 makes every resolver answer it with
// `127.0.0.1`, so a client that resolved again lands there while the checked
// address is `127.0.0.2`. Two servers on one port say which lookup won.

/// The machine's own resolver answers `127.0.0.1` for `localhost` whatever
/// this says, which is the disagreement these tests are about.
const localhost_answers_the_second_host = [_]NamedAddresses.Entry{
    .{ .host = "localhost", .address = "127.0.0.2" },
};

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
    try testing.expectEqualStrings("the checked address answered\n", outcome.fetched.body);

    try testing.expectEqual(@as(usize, 2), checked.served());
    try testing.expectEqualStrings("/robots.txt", checked.seen.items[0]);
    try testing.expectEqualStrings("/manual", checked.seen.items[1]);

    try testing.expectEqual(@as(usize, 0), rebound.served());
}

test "a redirect hop is dialled at the address that was checked as well" {
    const gpa = testing.allocator;
    const io = testing.io;

    const landing = try okReply(gpa, "the checked address answered the hop\n");
    defer gpa.free(landing);
    var checked_port: u16 = 0;

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

    try testing.expectEqual(@as(usize, 3), checked.served());
    try testing.expect(checked.sawPath("/old"));
    try testing.expect(checked.sawPath("/new"));
    try testing.expectEqual(@as(usize, 0), rebound.served());
}

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
    // The URL names `localhost`, so the client's own second lookup lands on
    // this machine and the server really answers. The first answer here is an
    // IPv6 address on the internet.
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
    try testing.expectEqual(@as(usize, 2), server.served());
    try testing.expect(server.sawPath("/manual"));
    try testing.expectEqual(@as(usize, 2), harness.addresses.lookups);
}

test "an IPv6 address the guard refuses stops the fetch, pinned or not" {
    // An IPv6 answer is no longer held to an address, so the address guard is
    // the only thing left. Both addresses below are IPv6.
    const gpa = testing.allocator;
    const io = testing.io;

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
        // Nothing opened. The first request of a hop is the site's own rules.
        try testing.expectEqual(@as(usize, 0), server.served());
    }
}

// `64:ff9b::/96` is the well-known prefix of RFC 6052, and a translator turns
// `64:ff9b::a9fe:a9fe` into `169.254.169.254`. `Ip4Address.fromIp6` knows
// `::ffff:/96` and no other prefix. The three tests below name `localhost` on
// purpose: the address is IPv6, so no connection is held to it and the second
// lookup lands on this machine, where a permitted address would serve the page.

test "an IPv4 address behind the NAT64 prefix is refused, and nothing opens" {
    // The second address is `127.0.0.1` behind the same prefix, so the unwrap
    // runs the whole of `ip4BytesAreReachable`.
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
    // Unique local addressing is the IPv6 form of `10.0.0.0/8`, and a company's
    // own API on its own network is the main reason anybody permits a host.
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
/// an internet address after it. The first request of a hop is the site's own
/// rules, so that one meets the address guard.
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
    // which is right for a 404 and wrong for the guard. The host is written out
    // as an address, so the page request really reaches the server.
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

    try testing.expect(outcome == .refused);
    try testing.expectEqual(fetch.Refusal.Kind.address_not_permitted, outcome.refused.kind);

    try testing.expectEqual(@as(usize, 1), answers.lookups);
    try testing.expectEqual(@as(usize, 0), server.served());
}
