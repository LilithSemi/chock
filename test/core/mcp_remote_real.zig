//! A real MCP server over the streamable HTTP transport, driven by the
//! production transport. The server is the reference `mcp` package's own, so
//! the framing under test is not one Chock wrote.
//!
//! The server runs on loopback over plain http, which is what the destination
//! reader refuses in a project file. So this covers the protocol, the socket
//! and the reply reading, and it does not cover TLS. The address check and the
//! pinning have their own tests in `lib/chock-broker/mcp_remote.zig`, where a
//! loopback answer is refused by the real `network.addressIsReachable`.

const std = @import("std");

const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");

const mcp = chock_core.mcp;
const mcp_http = chock_core.mcp_http;
const mcp_remote = chock_broker.mcp_remote;
const actions = chock_broker.actions;

/// Found on the dev shell's `PATH` at build time. Null is a skip, not a
/// failure: `pkgs/chock/default.nix` names it, and the package build has it
/// not.
const server_path: ?[]const u8 = @import("mcp_probe_path").mcp_probe_http_path;

const testing = std.testing;

const budget_ns: u64 = 30 * std.time.ns_per_s;

/// Loopback is refused by the shared check, which is the point of it. A test
/// that drives a server on this machine says so here and nowhere else.
fn loopbackIsReachable(address: actions.Resolver.Address) bool {
    _ = address;
    return true;
}

const Answers = struct {
    port: u16,

    fn resolver(self: *Answers) actions.Resolver {
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
        const self: *Answers = @ptrCast(@alignCast(ptr));
        if (into.len == 0) return error.TooManyAddresses;
        into[0] = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = self.port } };
        return 1;
    }
};

const Probe = struct {
    child: std.process.Child,
    port: u16,
    url: []u8,

    /// The port comes from a listener this closes again, so two runs of the
    /// suite do not land on one port.
    fn freePort(io: std.Io) !u16 {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        var server = try address.listen(io, .{ .reuse_address = true });
        const port = server.socket.address.getPort();
        server.socket.close(io);
        return port;
    }

    fn start(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !Probe {
        const port = try freePort(io);
        const text = try std.fmt.allocPrint(gpa, "{d}", .{port});
        defer gpa.free(text);

        var child = try std.process.spawn(io, .{
            .argv = &.{ path, text },
            .stdin = .ignore,
            .stdout = .ignore,
            // An undrained pipe would fill up and wedge the server.
            .stderr = .ignore,
        });
        errdefer child.kill(io);

        const url = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/mcp", .{port});
        errdefer gpa.free(url);

        var probe = Probe{ .child = child, .port = port, .url = url };
        try probe.waitUntilUp(gpa, io);
        return probe;
    }

    /// A server that never answers fails the test rather than hanging it.
    fn waitUntilUp(self: *Probe, gpa: std.mem.Allocator, io: std.Io) !void {
        var tries: usize = 0;
        while (tries < 60) : (tries += 1) {
            var arena_state = std.heap.ArenaAllocator.init(gpa);
            defer arena_state.deinit();

            var answers = Answers{ .port = self.port };
            var session = self.sessionWith(gpa, &answers);
            var driver = mcp_http.Driver.init(gpa, bridgeFor(&session).exchange());
            defer driver.deinit();

            if (driver.host().list(arena_state.allocator(), io, std.time.ns_per_s)) |_| {
                return;
            } else |_| {}

            std.Io.Clock.Duration.sleep(.{
                .raw = .fromNanoseconds(200 * std.time.ns_per_ms),
                .clock = .awake,
            }, io) catch {};
        }
        return error.ProbeNeverAnswered;
    }

    fn sessionWith(self: *Probe, gpa: std.mem.Allocator, answers: *Answers) mcp_remote.Session {
        return .{
            .gpa = gpa,
            .server = "probe",
            .host = "127.0.0.1",
            .url = self.url,
            .port = self.port,
            .resolver = answers.resolver(),
            .reachable = loopbackIsReachable,
        };
    }

    /// `kill` closes every pipe and reaps the process.
    fn stop(self: *Probe, gpa: std.mem.Allocator, io: std.Io) void {
        self.child.kill(io);
        gpa.free(self.url);
    }
};

/// The same bridge `src/run.zig` builds, kept here because a test module is
/// not the binary. It writes no record: that half belongs to `src/run.zig`
/// and its own tests cover it.
const Bridge = struct {
    session: *mcp_remote.Session,

    fn exchange(self: *Bridge) mcp_http.Exchange {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = mcp_http.Exchange.VTable{ .post = postFn };

    fn postFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        one: mcp_http.Post,
    ) mcp_http.Error!mcp_http.Reply {
        const self: *Bridge = @ptrCast(@alignCast(ptr));
        const posted = self.session.post(
            arena,
            io,
            one.body,
            one.session_id,
            one.protocol_version,
        ) catch |err| {
            return if (err == error.OutOfMemory) error.OutOfMemory else error.Gone;
        };
        return .{
            .status = posted.status,
            .kind = switch (posted.kind) {
                .json => .json,
                .event_stream => .event_stream,
                .other => .other,
            },
            .session_id = posted.session_id,
            .body = if (posted.live) |live| bodyOf(live) else null,
        };
    }

    fn bodyOf(live: *mcp_remote.Live) mcp_http.Body {
        return .{ .ptr = live, .vtable = &body_vtable };
    }

    const body_vtable = mcp_http.Body.VTable{ .read = readFn, .close = closeFn };

    fn readFn(
        ptr: *anyopaque,
        io: std.Io,
        into: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) mcp_http.ReadError!usize {
        const live: *mcp_remote.Live = @ptrCast(@alignCast(ptr));
        return live.read(io, into, deadline);
    }

    fn closeFn(ptr: *anyopaque, io: std.Io) void {
        _ = io;
        const live: *mcp_remote.Live = @ptrCast(@alignCast(ptr));
        live.close();
    }
};

var bridge_storage: Bridge = undefined;

fn bridgeFor(session: *mcp_remote.Session) *Bridge {
    bridge_storage = .{ .session = session };
    return &bridge_storage;
}

test "a real server answers the handshake, lists its tool, and runs it" {
    const path = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var probe = try Probe.start(gpa, io, path);
    defer probe.stop(gpa, io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var answers = Answers{ .port = probe.port };
    var session = probe.sessionWith(gpa, &answers);
    var driver = mcp_http.Driver.init(gpa, bridgeFor(&session).exchange());
    defer driver.deinit();

    const declared = try driver.host().list(arena, io, budget_ns);
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqualStrings("echo", declared[0].name);
    try testing.expect(declared[0].schema == .object);

    // The server named a session, and it travelled on the later requests.
    try testing.expect(driver.session_id.len != 0);
    try testing.expectEqualStrings("2025-06-18", driver.negotiated);

    const said = try driver.host().call(arena, io, "echo", "{\"text\":\"hei\"}", budget_ns);
    try testing.expect(!said.is_error);
    try testing.expectEqualStrings("hei", said.text);

    // A tool that failed is an answer the model reads, and not a dead server.
    const failed = try driver.host().call(arena, io, "echo", "{}", budget_ns);
    try testing.expect(failed.is_error);
    try testing.expect(failed.text.len != 0);

    // A method no server knows is a JSON-RPC error, which `tools/call` of an
    // unknown tool answers with.
    const unknown = try driver.host().call(arena, io, "nope", "{}", budget_ns);
    try testing.expect(unknown.is_error);
}

test "a session the server dropped is opened again, and the call still answers" {
    const path = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var probe = try Probe.start(gpa, io, path);
    defer probe.stop(gpa, io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var answers = Answers{ .port = probe.port };
    var session = probe.sessionWith(gpa, &answers);
    var driver = mcp_http.Driver.init(gpa, bridgeFor(&session).exchange());
    defer driver.deinit();

    _ = try driver.host().list(arena, io, budget_ns);

    // A session id this server never issued, which it answers 404 to.
    gpa.free(driver.session_id);
    driver.session_id = try gpa.dupe(u8, "00000000000000000000000000000000");

    const declared = try driver.host().list(arena, io, budget_ns);
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqual(@as(usize, 1), driver.reinitialised);
}

test "a host the policy did not approve is refused against a server that is there" {
    const path = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var probe = try Probe.start(gpa, io, path);
    defer probe.stop(gpa, io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var answers = Answers{ .port = probe.port };
    var session = probe.sessionWith(gpa, &answers);
    // The destination the policy approved, against the URL this would dial.
    session.host = "elsewhere.example.com";

    var driver = mcp_http.Driver.init(gpa, bridgeFor(&session).exchange());
    defer driver.deinit();

    try testing.expectError(
        error.Gone,
        driver.host().list(arena_state.allocator(), io, budget_ns),
    );
}

comptime {
    _ = mcp;
}
