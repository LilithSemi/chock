//! A **real MCP server**, driven by the production protocol, into the offers a
//! model would be given.
//!
//! `lib/chock-core/mcp_driver.zig` has tests of its own, and it says out loud
//! what they leave out: a server written by the same hand as the driver agrees
//! with every assumption the driver makes, including the wrong ones. That is
//! the trap of a fake that is too kind, and this project has already shipped a
//! whole LSP feature that had never worked against a real server for exactly
//! that reason.
//!
//! So this file runs `mcp-server-time`, which is a real third party MCP server
//! built on the reference Python `mcp` package. **It reaches no network and
//! keeps no state**: it answers the current time and converts one time zone to
//! another, which is why it is safe in a test suite.
//!
//! ## What is real here, and what is not
//!
//! Real: the process, the framing, the JSON, the handshake, the tool list, a
//! tool call that works, a tool call that fails, and the whole of
//! `chock_core.mcp.Session` on top of them.
//!
//! **Not real: the sandbox.** The server runs as an ordinary child process of
//! this test and not through `Sandbox.spawn`. `chock_core.helper.Channel` is
//! two ordinary pipes and nothing else, so the production protocol reaches a
//! real server over the production channel either way, and this test then runs
//! on Darwin as well, where `Sandbox.spawn` refuses outright. What the missing
//! half would add is the mount tree and the seccomp filter, and
//! `test/core/lsp.zig` already proves a real long lived helper comes up inside
//! a real sandbox. This file proves the other thing, which is that Chock and a
//! server nobody here wrote agree about the protocol.
//!
//! ## What this found that no written server did
//!
//! **An MCP server frames a message with a newline and not with a
//! `Content-Length` header.** The obvious way to build this driver is to copy
//! `lib/chock-core/lsp_driver.zig`, which frames with headers, and a test
//! server written from the same file would have read them happily. Measured
//! against `mcp-server-time` 2026.7.10 on 2026-08-23 before a line of the
//! driver was written.
//!
//! Two more facts came from the same run, and both are in the driver now:
//!
//! * A call that goes wrong comes back as a **result** with `isError` true and
//!   a text part, and not as a JSON-RPC error. An `Invalid timezone` is
//!   something the model reads and acts on.
//! * A **method the server does not know** does come back as a JSON-RPC error,
//!   with `code` -32602, while the server writes a wall of validation text on
//!   its own standard error. That standard error is `/dev/null` for a real
//!   helper, which is `chock_core.helper.Helper`'s own decision.

const std = @import("std");
const chock_core = @import("chock-core");

const helper = chock_core.helper;
const mcp = chock_core.mcp;
const mcp_driver = chock_core.mcp_driver;

/// The server this suite runs, found on the dev shell's own `PATH` when the
/// project was built. **Null is an ordinary answer**: a machine whose shell has
/// no MCP server skips these tests rather than failing them, and a test that
/// fetched one would be a build. `pkgs/chock/default.nix` names it.
const server_path: ?[]const u8 = @import("mcp_real_path").mcp_server_time_path;

const testing = std.testing;

/// A real server on two real pipes, and the production channel over them.
const RealServer = struct {
    child: std.process.Child,
    channel: helper.Channel,
    protocol: mcp_driver.Protocol,

    fn start(gpa: std.mem.Allocator, io: std.Io, program: []const u8) !RealServer {
        var child = try std.process.spawn(io, .{
            .argv = &.{program},
            .stdin = .pipe,
            .stdout = .pipe,
            // **Ignored, and not a pipe.** The server writes validation
            // warnings there, and a pipe nobody drains fills up and wedges it
            // mid sentence. That is the same decision
            // `chock_core.helper.Helper.start` makes for a real helper, and
            // this test would be a poor place to find out it was wrong.
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

    /// `kill` closes every pipe and reaps the process, so nothing here closes
    /// a descriptor of its own.
    fn deinit(self: *RealServer, io: std.Io) void {
        self.protocol.deinit();
        self.child.kill(io);
    }

    fn deadline(io: std.Io) std.Io.Clock.Timestamp {
        return helper.Channel.deadlineIn(io, mcp.discovery_budget_ns);
    }
};

test "a real MCP server lists its real tools through the production protocol" {
    // The floor, and the whole point of this file: the framing, the handshake
    // and the list are the production ones, and the far end is a program
    // nobody here wrote.
    //
    // Mutation check: frame a message with a `Content-Length` header in
    // `mcp_driver.Protocol.send` and this test hangs until its budget ends,
    // while every written server in that file still passes.
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

    // The two tools this server really has, measured on 2026-08-23.
    try testing.expectEqual(@as(usize, 2), declared.len);
    var found_time = false;
    for (declared) |one| {
        if (std.mem.eql(u8, one.name, "get_current_time")) found_time = true;
        // Every real name passes the shape rule, so the rule is not one that
        // refuses every real server.
        try testing.expect(mcp.nameIsUsable(one.name));
        try testing.expect(one.description.len != 0);
        // A real schema is an object, which is what the provider requires.
        try testing.expect(one.schema == .object);
    }
    try testing.expect(found_time);
}

test "a real tool runs, and its answer reaches the context through the flattening" {
    // A call that works, end to end, through `mcp.Session`: the policy, the
    // name rules, the dispatch and the text cleaning are all the production
    // ones, and the answer is one a real program computed.
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

    // Not one real tool name shadows a built-in, so the server loads.
    try testing.expect(one.failure == null);
    try testing.expect(!session.isEmpty());

    const outcome = (try session.dispatch(gpa, io, "get_current_time",
        \\{"timezone":"UTC"}
    )).?;
    defer gpa.free(outcome.text);

    try testing.expect(!outcome.is_error);
    // The server answers a JSON object as text. The exact time is a clock, so
    // nothing here asserts one: what is pinned is that the answer is the
    // server's own and came back whole.
    try testing.expect(std.mem.indexOf(u8, outcome.text, "\"timezone\": \"UTC\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "datetime") != null);
    // **The newline survived**, which is the one thing that separates this
    // cleaning from `chock_core.lsp.flattenMessage`. A real server answers
    // pretty printed JSON, and a result folded onto one line is a result
    // nothing can read.
    try testing.expect(std.mem.indexOfScalar(u8, outcome.text, '\n') != null);
    // And nothing that could move a terminal cursor came back.
    for (outcome.text) |byte| {
        if (byte == '\n' or byte == '\t') continue;
        try testing.expect(byte >= 0x20 and byte != 0x7F);
    }
}

test "a real tool that fails is a result, and the server still answers the next call" {
    // Measured: this server answers a bad time zone with a text result and
    // `isError` true, and not with a JSON-RPC error. A driver that read that
    // as a fault would end a server that is working perfectly.
    //
    // The second call is what pins that nothing wedged.
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

    // A method the server does not know comes back as a JSON-RPC error, and
    // that is a result too.
    const unknown = try server.protocol.call(
        arena,
        io,
        &server.channel,
        RealServer.deadline(io),
        "no_such_tool",
        "{}",
    );
    try testing.expect(unknown.is_error);

    // And the server is still there, so neither of the two wedged anything.
    const good = try server.protocol.call(arena, io, &server.channel, RealServer.deadline(io), "get_current_time",
        \\{"timezone":"UTC"}
    );
    try testing.expect(!good.is_error);
    try testing.expect(std.mem.indexOf(u8, good.text, "datetime") != null);
}

test "a real server is asked to initialize one time, however many calls follow" {
    // A second `initialize` is a protocol error, and a real server is what
    // proves this client does not send one. Three exchanges on one server, and
    // the third answers as well as the first.
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
    // Two more requests went out and no more, so no second handshake was
    // among them.
    try testing.expectEqual(before + 2, server.protocol.last_id);
}

/// An `mcp.Host` over a `RealServer`, so `mcp.Session` can drive one with no
/// `helper.Helper` and therefore no sandbox. `chock_core.mcp_driver.Driver` is
/// the production shape and it only adds the process.
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

/// A policy that says yes to everything, so this file measures the protocol
/// and not the table. `lib/chock-core/mcp.zig` is where the policy itself is
/// tested, against every decision.
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
