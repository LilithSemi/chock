//! How the loop asks somebody else whether an act may happen. `chock-core`
//! imports no `chock-broker`, so the policy table stays in a process the agent
//! cannot reach.

const std = @import("std");
const chock_proto = @import("chock-proto");

pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

pub const Ask = struct {
    action: []const u8,
    summary: []const u8,
    detail: []const u8,
    reason: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    source: []const u8 = "",
};

pub const Answer = struct {
    permitted: bool,
    outcome: []const u8,
    review_text: []const u8 = "",
};

pub const Arbiter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
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
    locked: ?*Locked = null,

    pub fn decide(self: ?Asker, gpa: std.mem.Allocator, io: std.Io, ask: Ask) Answer {
        const one = self orelse return not_asked;
        const locked = one.locked orelse return not_asked;
        return one.arbiter.decide(gpa, io, locked, ask);
    }
};

pub const denied_by_policy = "denied_by_policy";

pub fn refusalText(
    gpa: std.mem.Allocator,
    subject: []const u8,
    answer: Answer,
) std.mem.Allocator.Error![]u8 {
    if (std.mem.eql(u8, answer.outcome, denied_by_policy)) return denialText(gpa, subject);
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

/// What the agent reads when policy denied `subject`. A tool name or an
/// action name both fit. It names no way to change policy, because the agent has none.
pub fn denialText(gpa: std.mem.Allocator, subject: []const u8) std.mem.Allocator.Error![]u8 {
    if (std.mem.startsWith(u8, subject, "git.push")) return std.fmt.allocPrint(
        gpa,
        "nothing ran: policy denied \"{s}\" and nobody was asked, so asking again will not change " ++
            "the answer. Your work is committed in the workspace and travels back through " ++
            "workspace.apply. Do not look for another way to push. Say plainly in your answer " ++
            "that the push was refused by policy.",
        .{subject},
    );
    return std.fmt.allocPrint(
        gpa,
        "nothing ran: policy denied \"{s}\" and nobody was asked, so asking again will not change " ++
            "the answer. Do not look for another way to do it. Do the part of the task that does " ++
            "not need it, and say plainly in your answer that policy refused it.",
        .{subject},
    );
}

/// What a person reads about a policy deny of `action`. The agent never sees this text.
pub fn denialAdvice(gpa: std.mem.Allocator, action: []const u8) std.mem.Allocator.Error![]u8 {
    const force_note = if (std.mem.eql(u8, action, "git.push"))
        " A forced push is the action git.push.force and needs a rule of its own."
    else
        "";
    return std.fmt.allocPrint(
        gpa,
        "Policy denied \"{[a]s}\" and nobody was asked. Nothing is wrong with your setup: " ++
            "Chock denies this action unless a rule allows it. To allow it, add " ++
            ".{{ .action = \"{[a]s}\", .decision = .ask }} to the policy rules in chock.zon, " ++
            "or start the session with --policy-rule {[a]s}=ask. Write .allow in place of .ask " ++
            "to skip the question. Chock reads chock.zon once when a session starts, so start a " ++
            "new session after you edit it.{[f]s} An org bundle that denies it cannot be widened by " ++
            "a project rule or by --policy-rule, so the owner of the bundle has to change it.",
        .{ .a = action, .f = force_note },
    );
}

pub const not_asked = Answer{
    .permitted = false,
    .outcome = "this session can ask nobody",
};

const testing = std.testing;

test "an answer carries only static text, so nothing a reviewer wrote can travel in one" {
    inline for (@typeInfo(Answer).@"struct".field_names, @typeInfo(Answer).@"struct".field_types) |field_name, field_type| {
        const ok = field_type == bool or field_type == []const u8;
        if (!ok) @compileError(
            "Answer gained the member \"" ++ field_name ++ "\", which is neither a flag nor " ++
                "borrowed text. The arbitrator gets the reasoning and the calling " ++
                "agent only the outcome, and a member that owned memory is the route that " ++
                "reasoning would travel back along",
        );
    }
    try testing.expect(@typeInfo(Answer).@"struct".field_names.len == 3);
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

test "a policy deny says nobody was asked, and an answered question does not" {
    const gpa = testing.allocator;

    const denied = try refusalText(gpa, "git.push", .{ .permitted = false, .outcome = denied_by_policy });
    defer gpa.free(denied);
    try testing.expect(std.mem.indexOf(u8, denied, "nobody was asked") != null);
    try testing.expect(std.mem.indexOf(u8, denied, "workspace.apply") != null);
    try testing.expect(std.mem.indexOf(u8, denied, "refused by policy") != null);
    try testing.expect(std.mem.indexOf(u8, denied, "needs approval") == null);
    try testing.expect(std.mem.indexOf(u8, denied, "--policy-rule") == null);

    const other = try denialText(gpa, "git.gc");
    defer gpa.free(other);
    try testing.expect(std.mem.indexOf(u8, other, "workspace.apply") == null);

    const asked = try refusalText(gpa, "git.push", .{ .permitted = false, .outcome = "refused_by_user" });
    defer gpa.free(asked);
    try testing.expect(std.mem.indexOf(u8, asked, "needs approval") != null);
}

test "the advice a person reads names the rule in the syntax chock.zon and the flag take" {
    const gpa = testing.allocator;
    const text = try denialAdvice(gpa, "git.push");
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "--policy-rule git.push=ask") != null);
    try testing.expect(std.mem.indexOf(u8, text, ".{ .action = \"git.push\", .decision = .ask }") != null);
    try testing.expect(std.mem.indexOf(u8, text, "new session") != null);
    try testing.expect(std.mem.indexOf(u8, text, "org bundle") != null);
    try testing.expect(std.mem.indexOf(u8, text, "git.push.force") != null);
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
