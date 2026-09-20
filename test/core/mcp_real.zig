//! A real third party MCP server, `mcp-server-time`, driven by the production
//! protocol into the offers a model would be given.
//!
//! Not real here: the sandbox. The server is an ordinary child process, so the
//! mount tree and the seccomp filter go untested.
//!
//! An MCP server frames a message with a newline, not a `Content-Length` header.

const std = @import("std");
const chock_core = @import("chock-core");

const helper = chock_core.helper;
const mcp = chock_core.mcp;
const mcp_driver = chock_core.mcp_driver;

const chock_proto = @import("chock-proto");

/// Found on the dev shell's `PATH` at build time. Null is a skip, not a failure.
const server_path: ?[]const u8 = @import("mcp_real_path").mcp_server_time_path;

const testing = std.testing;

/// A session with no arbiter runs no MCP tool at all, so this file names one.
const PermitAll = struct {
    var anchor: u8 = 0;

    fn arbiter() chock_core.arbiter.Arbiter {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = chock_core.arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.arbiter.Locked,
        ask: chock_core.arbiter.Ask,
    ) chock_core.arbiter.Answer {
        _ = ptr;
        _ = gpa;
        _ = io;
        _ = locked;
        _ = ask;
        return .{ .permitted = true, .outcome = "allowed_by_policy" };
    }
};

const LockedLog = struct {
    backing: chock_proto.storage.Memory,
    store: chock_proto.storage.Storage = undefined,
    locked: chock_core.arbiter.Locked = undefined,

    fn init(gpa: std.mem.Allocator) !LockedLog {
        return .{ .backing = try chock_proto.storage.Memory.init(gpa, "01MCPREAL") };
    }

    /// Separate from `init` because the handle points at the storage beside it,
    /// and a struct returned by value moves.
    fn arm(self: *LockedLog, io: std.Io) !void {
        self.store = self.backing.storage();
        self.locked = try self.store.lock(io);
    }

    fn deinit(self: *LockedLog, io: std.Io) void {
        self.locked.unlock(io) catch {};
        self.store.close(io);
    }
};

const RealServer = struct {
    child: std.process.Child,
    channel: helper.Channel,
    protocol: mcp_driver.Protocol,

    fn start(gpa: std.mem.Allocator, io: std.Io, program: []const u8) !RealServer {
        var child = try std.process.spawn(io, .{
            .argv = &.{program},
            .stdin = .pipe,
            .stdout = .pipe,
            // The server writes validation warnings there, and a pipe nobody
            // drains fills up and wedges it mid sentence.
            .stderr = .ignore,
        });
        errdefer child.kill(io);

        return .{
            .child = child,
            .channel = .{
                .to_helper = child.stdin.?,
                .from_helper = child.stdout.?,
            },
            .protocol = .{ .gpa = gpa },
        };
    }

    /// `kill` closes every pipe and reaps the process.
    fn deinit(self: *RealServer, io: std.Io) void {
        self.protocol.deinit();
        self.child.kill(io);
    }

    fn deadline(io: std.Io) std.Io.Clock.Timestamp {
        return helper.Channel.deadlineIn(io, mcp.discovery_budget_ns);
    }
};

test "a real MCP server lists its real tools through the production protocol" {
    const program = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var server = try RealServer.start(gpa, io, program);
    defer server.deinit(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    const declared = try server.protocol.list(
        arena_state.allocator(),
        io,
        &server.channel,
        RealServer.deadline(io),
    );

    // The count this server really declares.
    try testing.expectEqual(@as(usize, 2), declared.len);
    var found_time = false;
    for (declared) |one| {
        if (std.mem.eql(u8, one.name, "get_current_time")) found_time = true;
        try testing.expect(mcp.nameIsUsable(one.name));
        try testing.expect(one.description.len != 0);
        try testing.expect(one.schema == .object);
    }
    try testing.expect(found_time);
}

test "a real tool runs, and its answer reaches the context through the flattening" {
    const program = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var server = try RealServer.start(gpa, io, program);
    defer server.deinit(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    var driver = ProtocolHost{ .server = &server };
    var session = mcp.Session.init(gpa);
    defer session.deinit();
    var one = mcp.Server{ .name = "time", .host = driver.host() };
    session.servers = @as(*[1]mcp.Server, &one);

    var policy = AllowAll{};
    const declared = try driver.host().list(
        arena_state.allocator(),
        io,
        mcp.discovery_budget_ns,
    );
    try session.admit(&one, declared, policy.decider());

    var log = try LockedLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);
    session.asker = .{ .arbiter = PermitAll.arbiter(), .locked = &log.locked };

    try testing.expect(one.failure == null);
    try testing.expect(!session.isEmpty());

    const outcome = (try session.dispatch(gpa, io, .{
        .call_id = "call1",
        .tool = "get_current_time",
        .arguments =
        \\{"timezone":"UTC"}
        ,
    })).?;
    defer gpa.free(outcome.text);

    try testing.expect(!outcome.is_error);
    // The exact time is a clock, so nothing here asserts one.
    try testing.expect(std.mem.indexOf(u8, outcome.text, "\"timezone\": \"UTC\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "datetime") != null);
    // A real server answers pretty printed JSON, so the newline must survive.
    try testing.expect(std.mem.indexOfScalar(u8, outcome.text, '\n') != null);
    for (outcome.text) |byte| {
        if (byte == '\n' or byte == '\t') continue;
        try testing.expect(byte >= 0x20 and byte != 0x7F);
    }
}

test "a real tool that fails is a result, and the server still answers the next call" {
    // This server answers a bad time zone with a text result and `isError` true,
    // and not with a JSON-RPC error.
    const program = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var server = try RealServer.start(gpa, io, program);
    defer server.deinit(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const failed = try server.protocol.call(arena, io, &server.channel, RealServer.deadline(io), "get_current_time",
        \\{"timezone":"Not/AZone"}
    );
    try testing.expect(failed.is_error);
    try testing.expect(std.mem.indexOf(u8, failed.text, "Invalid timezone") != null);

    // A method the server does not know comes back as a JSON-RPC error.
    const unknown = try server.protocol.call(
        arena,
        io,
        &server.channel,
        RealServer.deadline(io),
        "no_such_tool",
        "{}",
    );
    try testing.expect(unknown.is_error);

    const good = try server.protocol.call(arena, io, &server.channel, RealServer.deadline(io), "get_current_time",
        \\{"timezone":"UTC"}
    );
    try testing.expect(!good.is_error);
    try testing.expect(std.mem.indexOf(u8, good.text, "datetime") != null);
}

test "a real server is asked to initialize one time, however many calls follow" {
    // A second `initialize` is a protocol error.
    const program = server_path orelse return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var server = try RealServer.start(gpa, io, program);
    defer server.deinit(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try server.protocol.list(arena, io, &server.channel, RealServer.deadline(io));
    try testing.expect(server.protocol.ready);
    const before = server.protocol.last_id;

    _ = try server.protocol.list(arena, io, &server.channel, RealServer.deadline(io));
    const answer = try server.protocol.call(arena, io, &server.channel, RealServer.deadline(io), "get_current_time",
        \\{"timezone":"UTC"}
    );
    try testing.expect(!answer.is_error);
    try testing.expectEqual(before + 2, server.protocol.last_id);
}

const ProtocolHost = struct {
    server: *RealServer,

    fn host(self: *ProtocolHost) mcp.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = mcp.Host.VTable{ .list = listFn, .call = callFn };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) mcp.Error![]const mcp.Declared {
        const self: *ProtocolHost = @ptrCast(@alignCast(ptr));
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.server.protocol.list(arena, io, &self.server.channel, deadline);
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) mcp.Error!mcp.Outcome {
        const self: *ProtocolHost = @ptrCast(@alignCast(ptr));
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.server.protocol.call(arena, io, &self.server.channel, deadline, name, arguments);
    }
};

const AllowAll = struct {
    fn decider(self: *AllowAll) mcp.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = mcp.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) @import("chock-policy").table.Decision {
        _ = ptr;
        _ = tool;
        _ = action;
        return .allow;
    }
};
