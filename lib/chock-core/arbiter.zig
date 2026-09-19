//! How the loop asks somebody else whether an act may happen. `chock-core`
//! imports no `chock-broker`, so the policy table stays in a process the agent
//! cannot reach.

const std = @import("std");
const chock_proto = @import("chock-proto");

/// `chock_proto.storage.Locked` is not `pub`. This reaches it anyway.
pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

pub const Ask = struct {
    action: []const u8,
    summary: []const u8,
    /// The whole effect, never a command string.
    detail: []const u8,
    reason: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    source: []const u8 = "",
};

/// Every string here is static and comes from an outcome, so a reviewer's own
/// words have no route back to the agent that asked.
pub const Answer = struct {
    permitted: bool,
    outcome: []const u8,
    review_text: []const u8 = "",
};

pub const Arbiter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// This never fails. Every way of not reaching a decision is already
        /// an `Answer` that does not permit.
        decide: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            locked: *Locked,
            ask: Ask,
        ) Answer,
    };

    pub fn decide(
        self: Arbiter,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *Locked,
        ask: Ask,
    ) Answer {
        return self.vtable.decide(self.ptr, gpa, io, locked, ask);
    }
};

pub const Asker = struct {
    arbiter: Arbiter,
    /// The pointer is the loop's own, so whoever stores it never unlocks it.
    locked: ?*Locked = null,

    pub fn decide(self: ?Asker, gpa: std.mem.Allocator, io: std.Io, ask: Ask) Answer {
        const one = self orelse return not_asked;
        const locked = one.locked orelse return not_asked;
        return one.arbiter.decide(gpa, io, locked, ask);
    }
};

pub fn refusalText(
    gpa: std.mem.Allocator,
    subject: []const u8,
    answer: Answer,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "nothing ran: \"{s}\" needs approval to run and the answer was \"{s}\". {s}{s}Do the part " ++
            "of the task that does not need it, or stop and say what is left and why.",
        .{
            subject,
            answer.outcome,
            answer.review_text,
            if (answer.review_text.len == 0) "" else " ",
        },
    );
}

/// "Nobody could be asked" and "somebody said no" stay apart. A message that
/// implied the request had been weighed makes a model argue with it.
pub const not_asked = Answer{
    .permitted = false,
    .outcome = "this session can ask nobody",
};

const testing = std.testing;

test "an answer carries only static text, so nothing a reviewer wrote can travel in one" {
    inline for (@typeInfo(Answer).@"struct".fields) |field| {
        const ok = field.type == bool or field.type == []const u8;
        if (!ok) @compileError(
            "Answer gained the member \"" ++ field.name ++ "\", which is neither a flag nor " ++
                "borrowed text. The arbitrator gets the reasoning and the calling " ++
                "agent only the outcome, and a member that owned memory is the route that " ++
                "reasoning would travel back along",
        );
    }
    try testing.expect(@typeInfo(Answer).@"struct".fields.len == 3);
}

test "an asker that is not there, and one whose handle has not arrived, both refuse and say nobody was asked" {
    const question = Ask{
        .action = "mcp.time.tool.get_current_time",
        .summary = "run a tool",
        .detail = "mcp.time.tool.get_current_time",
        .reason = "",
        .tool = "get_current_time",
        .tool_call_id = "call1",
    };

    const none = Asker.decide(null, testing.allocator, testing.io, question);
    try testing.expect(!none.permitted);
    try testing.expectEqualStrings(not_asked.outcome, none.outcome);

    var counted = CountingArbiter{};
    const unarmed = Asker.decide(
        .{ .arbiter = counted.arbiter() },
        testing.allocator,
        testing.io,
        question,
    );
    try testing.expect(!unarmed.permitted);
    try testing.expectEqualStrings(not_asked.outcome, unarmed.outcome);
    try testing.expectEqual(@as(usize, 0), counted.asks);
}

test "the refusal an agent reads names the outcome, and carries a reviewer's sentence only when there was one" {
    const gpa = testing.allocator;

    const bare = try refusalText(gpa, "get_current_time", .{
        .permitted = false,
        .outcome = "refused_by_user",
    });
    defer gpa.free(bare);
    try testing.expect(std.mem.indexOf(u8, bare, "get_current_time") != null);
    try testing.expect(std.mem.indexOf(u8, bare, "refused_by_user") != null);
    try testing.expect(std.mem.indexOf(u8, bare, "\".  ") == null);

    const reviewed = try refusalText(gpa, "fs.write", .{
        .permitted = false,
        .outcome = "denied_by_review",
        .review_text = "A reviewer weighed this and declined.",
    });
    defer gpa.free(reviewed);
    try testing.expect(std.mem.indexOf(u8, reviewed, "fs.write") != null);
    try testing.expect(std.mem.indexOf(u8, reviewed, "A reviewer weighed this and declined.") != null);
    try testing.expect(std.mem.indexOf(u8, reviewed, "declined. Do the part") != null);
}

const CountingArbiter = struct {
    asks: usize = 0,

    fn arbiter(self: *CountingArbiter) Arbiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *Locked,
        ask: Ask,
    ) Answer {
        _ = gpa;
        _ = io;
        _ = locked;
        _ = ask;
        const self: *CountingArbiter = @ptrCast(@alignCast(ptr));
        self.asks += 1;
        return .{ .permitted = true, .outcome = "allowed_by_policy" };
    }
};

test "a session with no arbiter says so, and does not permit" {
    try testing.expect(!not_asked.permitted);
    try testing.expect(not_asked.outcome.len > 0);
    try testing.expectEqual(@as(usize, 0), not_asked.review_text.len);
}
