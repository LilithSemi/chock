//! Somebody else's word, and the one thing the agent loop is allowed to do about it.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");

var listening: ?*chock_broker.handover.Endpoint = null;

var confirm_budget_ms: u64 = chock_broker.handover.default_confirm_budget_ms;

pub fn arm(endpoint: *chock_broker.handover.Endpoint) void {
    listening = endpoint;
}

pub fn disarm() void {
    listening = null;
}

pub fn requested(io: std.Io, in_flight: chock_core.Loop.InFlight) bool {
    const endpoint = listening orelse return false;
    const decision = endpoint.look(io, .{
        .tasks = in_flight.tasks,
        .children = in_flight.children,
    }, confirm_budget_ms);
    return decision == .hand_over;
}

pub fn setConfirmBudgetForTest(budget_ms: u64) void {
    confirm_budget_ms = budget_ms;
}

const testing = std.testing;

test "a session that armed nothing refuses every ask, and one that armed a socket does not" {
    const gpa = testing.allocator;
    const io = testing.io;

    disarm();
    try testing.expect(!requested(io, .{}));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buffer);

    var paths = try chock_broker.handover.pathsFor(gpa, path_buffer[0..len], "01ARMED");
    defer paths.deinit();
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);
    defer endpoint.close(io);

    arm(&endpoint);
    defer disarm();

    try testing.expect(!requested(io, .{}));

    setConfirmBudgetForTest(1000);
    defer setConfirmBudgetForTest(chock_broker.handover.default_confirm_budget_ms);

    const address = try chock_broker.socket.addressFor(paths.socket, null);
    const client = try address.connect(io);
    defer client.close(io);
    try testing.expect(chock_broker.socket.writeAll(
        client.socket.handle,
        chock_broker.handover.ask_frame ++ "\n",
    ));
    try testing.expect(chock_broker.socket.writeAll(
        client.socket.handle,
        chock_broker.handover.take_frame ++ "\n",
    ));
    try testing.expect(requested(io, .{}));
}

test "what the loop counts reaches the socket, so the wait is for the right work" {
    const gpa = testing.allocator;
    const io = testing.io;

    setConfirmBudgetForTest(1000);
    defer setConfirmBudgetForTest(chock_broker.handover.default_confirm_budget_ms);

    const held = [_]chock_core.Loop.InFlight{ .{ .tasks = 1 }, .{ .children = 1 } };
    for (held, 0..) |in_flight, index| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &path_buffer);

        var id: [8]u8 = "01COUNT0".*;
        id[7] = '0' + @as(u8, @intCast(index));
        var paths = try chock_broker.handover.pathsFor(gpa, path_buffer[0..len], &id);
        defer paths.deinit();
        var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);
        defer endpoint.close(io);

        arm(&endpoint);
        defer disarm();

        const address = try chock_broker.socket.addressFor(paths.socket, null);
        const client = try address.connect(io);
        defer client.close(io);
        try testing.expect(chock_broker.socket.writeAll(
            client.socket.handle,
            chock_broker.handover.ask_frame ++ "\n",
        ));
        try testing.expect(chock_broker.socket.writeAll(
            client.socket.handle,
            chock_broker.handover.take_frame ++ "\n",
        ));

        try testing.expect(!requested(io, in_flight));
        try testing.expect(!requested(io, in_flight));

        try testing.expect(requested(io, .{}));
    }
}
