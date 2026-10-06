//! How the agent gives its own work back to the project it is working on.

const std = @import("std");
const chock_proto = @import("chock-proto");

pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

pub const apply_action = "workspace.apply";

pub const Ask = struct {
    reason: []const u8,
    tool_call_id: []const u8,
};

pub const Result = struct {
    carried: bool,
    output: []u8,
};

pub const Handback = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        apply: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            locked: *Locked,
            ask: Ask,
        ) std.mem.Allocator.Error!Result,
    };

    pub fn apply(
        self: Handback,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *Locked,
        ask: Ask,
    ) std.mem.Allocator.Error!Result {
        return self.vtable.apply(self.ptr, gpa, io, locked, ask);
    }
};

pub const not_offered = "this session cannot carry work back at all, so nothing was asked and " ++
    "nothing was carried. That is not a decision against you.";

const testing = std.testing;

test "an ask carries an argument and never an answer" {
    inline for (@typeInfo(Ask).@"struct".fields) |field| {
        if (field.type != []const u8) @compileError(
            "Ask gained the member \"" ++ field.name ++ "\", which is not text. Everything in " ++
                "an Ask is written by the agent, and a member that was not plain text would be " ++
                "the route a decision travels in along. The agent asks; it never decides",
        );
    }
    try testing.expect(@typeInfo(Ask).@"struct".fields.len == 2);
}

test "one action is named, and it is the policy key a project writes a rule for" {
    try testing.expectEqualStrings("workspace.apply", apply_action);
    try testing.expect(std.mem.indexOfScalar(u8, apply_action, '.') != null);
}

test "a session with no handback says so, and does not imply a decision" {
    try testing.expect(not_offered.len > 0);
    try testing.expect(std.mem.indexOf(u8, not_offered, "not a decision") != null);
}
