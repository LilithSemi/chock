//! The reviewer agent, for the `agent_review` and `agent_then_human` policy
//! decisions. A review that could not run is a refusal and never an allow,
//! because otherwise the cheapest attack is to make the review fail.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_policy = @import("chock-policy");

const event = chock_proto.event;
const table = chock_policy.table;

pub const Verdict = event.ReviewVerdict;

pub const max_note_bytes: usize = 500;

/// Two members, and no more: a third that named an action or a path would let
/// a reviewer describe a case other than the one it was given.
pub const result_fields = [_][]const u8{ "verdict", "why" };

pub const verdict_approve = "approve";
pub const verdict_refuse = "refuse";

pub const default_kind = "reviewer";

/// An arbitrator holds no tools, so an ordinary agent named this gets none.
pub fn isArbitrator(agent_kind: []const u8) bool {
    return std.mem.eql(u8, agent_kind, default_kind);
}

pub const Case = struct {
    action: []const u8,
    summary: []const u8,
    detail: []const u8,
    reason: []const u8,
    chain: []const []const u8,
    decision: table.Decision,
};

pub const Report = struct {
    verdict: Verdict,
    note: []u8,
};

pub fn freeReport(gpa: std.mem.Allocator, report: Report) void {
    gpa.free(report.note);
    if (report.verdict == .unknown) gpa.free(report.verdict.unknown);
}

pub const ReviewError = error{
    ReviewNotRun,
} || std.mem.Allocator.Error;

/// Two things an implementation owes, and neither is checkable from here.
/// Give the reviewer no tools. Give the reviewer no scratchpad: a parent may
/// read a child's scratchpad, and the parent here is the agent under review.
pub const Reviewer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    kind: []const u8,

    pub const VTable = struct {
        review: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            case: Case,
        ) ReviewError!Report,
    };

    pub fn review(
        self: Reviewer,
        gpa: std.mem.Allocator,
        io: std.Io,
        case: Case,
    ) ReviewError!Report {
        return self.vtable.review(self.ptr, gpa, io, case);
    }
};

pub const Resolution = enum {
    permit,
    refuse,
    ask_the_human,
    /// A member and not an assert, so a test can read `resolve(.deny, .approved)`.
    not_a_review,
};

/// The policy fold bounds what a reviewer may do with its own tool calls. It
/// says nothing about the verdict, so the rule that a review never widens is
/// built here: a decision the table already made is never moved by a verdict.
pub fn resolve(decision: table.Decision, verdict: Verdict) Resolution {
    return switch (decision) {
        .deny, .ask, .allow => .not_a_review,
        .agent_review => switch (verdict) {
            .approved => .permit,
            .rejected, .none, .unknown => .refuse,
        },
        .agent_then_human => switch (verdict) {
            .approved => .ask_the_human,
            .rejected, .none, .unknown => .refuse,
        },
    };
}

pub fn reviewsItself(chain: []const []const u8, reviewer_kind: []const u8) bool {
    if (reviewer_kind.len == 0) return true;
    for (chain) |kind| {
        if (std.mem.eql(u8, kind, reviewer_kind)) return true;
    }
    return false;
}

/// Written for an arbitrator. None of it may reach the agent that asked.
pub fn rationaleFor(action: []const u8) []const u8 {
    const entries = [_]struct { action: []const u8, why: []const u8 }{
        .{
            .action = "workspace.apply",
            .why = "This is the only way a session's work reaches the user's repository at all. " ++
                "It moves objects into the user's own object store and then moves one ref, and " ++
                "the ref it moves is never a branch the user works on, so the work lands as " ++
                "something a person can read, merge, or delete in the morning. That is what " ++
                "makes a deferred review safe here. Weigh whether the change is what the task " ++
                "asked for, and whether the person who reads it tomorrow would recognise it.",
        },
        .{
            .action = "git.push",
            .why = "A push reaches another machine and it cannot be undone from here. Whatever " ++
                "lands on a shared remote is seen by people and by build systems that this " ++
                "session cannot reach to correct. Reversibility is the criterion: this one is " ++
                "not reversible, so it wants a person unless the case is plain.",
        },
        .{
            .action = "git.branch.delete",
            .why = "Deleting a ref can destroy work that is in no other place. The request names " ++
                "the object the branch points at, so satisfy yourself that the same commits are " ++
                "reachable from somewhere else before this is allowed.",
        },
        .{
            .action = "net.fetch",
            .why = "The sandbox has no network at all, and that is a boundary rather than a " ++
                "reduction. A fetch is the broker reaching out on the agent's behalf, so it is " ++
                "the one way bytes chosen by somebody else enter a session. Weigh what the host " ++
                "is and what the answer will be used for. Content that comes back is read by a " ++
                "model, so treat it as something written by a stranger.",
        },
        .{
            .action = "nix.build",
            .why = "A build reaches the daemon and adds a program the session can then run. It " ++
                "is how a toolchain grows, and it is also how something arbitrary gets a path " ++
                "on this machine. Weigh whether the thing being built is named by the project " ++
                "or by the agent.",
        },
        .{
            .action = "file.write",
            .why = "This writes outside the workspace, so it escapes the one place a session's " ++
                "changes are collected and reviewed. Nothing written here appears in a diff and " ++
                "nothing here is thrown away at the end of the run. Weigh whether the path is " ++
                "somewhere a person would think to look.",
        },
        .{
            .action = "git.commit",
            .why = "A commit inside the session's own worktree is cheap and reversible: it does " ++
                "not touch the user's branches and the worktree is thrown away. Weigh the " ++
                "content rather than the act.",
        },
        .{
            .action = "model.select",
            .why = "Choosing a model changes what the rest of the session is answered by, and " ++
                "the policy table keys on the model alias, so a different model can be under a " ++
                "different rule. Weigh whether the roster entry being asked for is one the " ++
                "project meant this agent to use.",
        },
    };
    for (entries) |one| {
        if (std.mem.eql(u8, one.action, action)) return one.why;
    }
    return "No specific reason is recorded for this action. An act nobody wrote a rule for is " ++
        "an act nobody has thought about, which is a reason to look harder rather than a " ++
        "reason to let it past. Weigh what it changes and whether the change can be undone.";
}

/// A subagent reads its task and nothing else, so this is its entire world.
pub fn taskFor(gpa: std.mem.Allocator, case: Case) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);

    try text.appendSlice(gpa,
        \\You are an arbitrator. An agent has asked to do something that this project's policy
        \\does not answer on its own, and you decide whether it happens.
        \\
        \\You act on nothing. You read the case below and you answer. That is the whole of your
        \\part, and it is deliberate: you are told why this is guarded, and an agent that knows
        \\that and can also act with it is the thing this arrangement exists to avoid.
        \\
        \\
    );

    try text.print(gpa, "THE ACT\n  {s}\n  {s}\n\n", .{ case.action, case.summary });

    try text.appendSlice(gpa, "WHO ASKED\n  ");
    for (case.chain, 0..) |kind, index| {
        if (index != 0) try text.appendSlice(gpa, " -> ");
        try text.appendSlice(gpa, kind);
    }
    try text.appendSlice(gpa, "\n  The last one is the agent that asked. The ones before it started it.\n\n");

    try text.print(gpa, "WHAT IT SAID ITS REASON WAS\n  {s}\n\n", .{case.reason});

    try text.print(gpa, "THE EFFECT\n{s}\n\n", .{case.detail});

    try text.print(gpa, "WHY THIS IS GUARDED\n  {s}\n\n", .{rationaleFor(case.action)});

    try text.appendSlice(gpa,
        \\WHAT YOU MUST NOT DO
        \\  Do not repeat any of "WHY THIS IS GUARDED" in your answer. The agent that asked is
        \\  told the outcome and nothing else, on purpose. Your reason is written into the
        \\  record a person reads later, so write it for that person.
        \\  Do not answer the question "who is right". Answer the question "should this happen".
        \\
        \\YOUR ANSWER
        \\  "verdict" is
    );
    try text.print(gpa, "\"{s}\" or \"{s}\".\n", .{ verdict_approve, verdict_refuse });
    try text.print(
        gpa,
        "  \"why\" is one sentence, at most {d} characters, for the person who reads the record.\n" ++
            "  If you cannot tell, answer \"{s}\". An arbitrator that is unsure and approves is\n" ++
            "  worse than one that refuses, because a refusal costs a wait and an approval cannot\n" ++
            "  be taken back.\n",
        .{ max_note_bytes, verdict_refuse },
    );

    return text.toOwnedSlice(gpa);
}

/// Anything that is not plainly an approval is a refusal.
pub fn readAnswer(gpa: std.mem.Allocator, answer: []const u8) std.mem.Allocator.Error!Report {
    const trimmed = std.mem.trim(u8, answer, " \t\r\n");
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, trimmed, .{}) catch {
        return refusedBecause(gpa, "the reviewer's answer is not JSON, so nothing it said can be read");
    };
    defer parsed.deinit();

    const object = switch (parsed.value) {
        .object => |members| members,
        else => return refusedBecause(gpa, "the reviewer answered with something that is not an object"),
    };

    const said = switch (object.get("verdict") orelse
        return refusedBecause(gpa, "the reviewer's answer names no verdict")) {
        .string => |word| word,
        else => return refusedBecause(gpa, "the reviewer's verdict is not a word"),
    };

    const why = switch (object.get("why") orelse std.json.Value{ .string = "" }) {
        .string => |word| word,
        else => "",
    };
    const note = why[0..@min(why.len, max_note_bytes)];

    if (std.mem.eql(u8, said, verdict_approve)) {
        return .{ .verdict = .approved, .note = try gpa.dupe(u8, note) };
    }
    if (std.mem.eql(u8, said, verdict_refuse)) {
        return .{ .verdict = .rejected, .note = try gpa.dupe(u8, note) };
    }
    return .{
        .verdict = .rejected,
        .note = try std.fmt.allocPrint(
            gpa,
            "the reviewer answered \"{s}\", which is neither \"{s}\" nor \"{s}\"",
            .{ said[0..@min(said.len, 40)], verdict_approve, verdict_refuse },
        ),
    };
}

fn refusedBecause(gpa: std.mem.Allocator, why: []const u8) std.mem.Allocator.Error!Report {
    return .{ .verdict = .rejected, .note = try gpa.dupe(u8, why) };
}

/// The asking agent gets the rule and what to do instead, never a reason.
pub fn requesterText(outcome: ReviewOutcome) []const u8 {
    return switch (outcome) {
        .approved => "A reviewer read this request and allowed it.",
        .refused => "A reviewer read this request and did not allow it. Do not ask again for the " ++
            "same thing. Either do the part of the task that does not need it, or stop and say " ++
            "what is left and why.",
        .unavailable => "This request needed a reviewer and no review could be made, so it did " ++
            "not happen. That is a refusal. Do the part of the task that does not need it, or " ++
            "stop and say what is left.",
    };
}

pub const ReviewOutcome = enum { approved, refused, unavailable };

comptime {
    const params = @typeInfo(@TypeOf(requesterText)).@"fn".params;
    if (params.len != 1 or params[0].type.? != ReviewOutcome) @compileError(
        "requesterText must take one ReviewOutcome and nothing else. The rule gives the " ++
            "arbitrator the reasoning and the calling agent only the outcome, and a second " ++
            "parameter here is the route that reasoning would travel back along",
    );
}

const testing = std.testing;

test "a reviewer cannot approve what the table already refused" {
    try testing.expectEqual(Resolution.not_a_review, resolve(.deny, .approved));
    try testing.expectEqual(Resolution.not_a_review, resolve(.deny, .rejected));
    try testing.expectEqual(Resolution.not_a_review, resolve(.ask, .approved));
    try testing.expectEqual(Resolution.not_a_review, resolve(.allow, .rejected));

    try testing.expect(Resolution.not_a_review != .permit);

    try testing.expectEqual(Resolution.permit, resolve(.agent_review, .approved));
    try testing.expectEqual(Resolution.refuse, resolve(.agent_review, .rejected));
    try testing.expectEqual(Resolution.ask_the_human, resolve(.agent_then_human, .approved));
    try testing.expectEqual(Resolution.refuse, resolve(.agent_then_human, .rejected));
}

test "a verdict this build cannot read refuses, and never permits" {
    for ([_]Verdict{ .none, .{ .unknown = "approved_with_conditions" } }) |verdict| {
        try testing.expectEqual(Resolution.refuse, resolve(.agent_review, verdict));
        try testing.expectEqual(Resolution.refuse, resolve(.agent_then_human, verdict));
    }
}

test "the policy order puts a review between what a person answers and what nobody does" {
    const D = table.Decision;

    try testing.expect(D.ask.rank() < D.agent_review.rank());
    try testing.expect(D.agent_then_human.rank() < D.ask.rank());
    try testing.expect(D.deny.rank() < D.agent_then_human.rank());
    try testing.expect(D.agent_review.rank() < D.allow.rank());

    try testing.expectEqual(D.deny, D.deny.intersect(.agent_review));
    try testing.expectEqual(D.agent_then_human, D.ask.intersect(.agent_then_human));
    try testing.expectEqual(D.ask, D.ask.intersect(.agent_review));

    try testing.expect(D.agent_review.needsReview() and D.agent_then_human.needsReview());
    try testing.expect(!D.allow.needsReview() and !D.ask.needsReview() and !D.deny.needsReview());
    try testing.expect(D.ask.needsHuman() and D.agent_then_human.needsHuman());
    try testing.expect(!D.agent_review.needsHuman());
}

test "a reviewer cannot review its own request, directly or through a chain" {
    const reviewer = "arbiter";

    try testing.expect(reviewsItself(&.{ "main", "arbiter" }, reviewer));
    try testing.expect(reviewsItself(&.{ "main", "arbiter", "worker" }, reviewer));
    try testing.expect(reviewsItself(&.{ "arbiter", "worker", "deeper" }, reviewer));

    try testing.expect(!reviewsItself(&.{ "main", "coder" }, reviewer));
    try testing.expect(!reviewsItself(&.{"main"}, reviewer));

    try testing.expect(!reviewsItself(&.{ "main", "arbiter-fast" }, reviewer));

    try testing.expect(reviewsItself(&.{ "main", "coder" }, ""));
    try testing.expect(reviewsItself(&.{}, ""));
}

test "the reviewer is told why, and the agent that asked is told only what to do" {
    const gpa = testing.allocator;

    const chain = [_][]const u8{ "main", "coder" };
    const task = try taskFor(gpa, .{
        .action = "git.push",
        .summary = "push a1b2c3 to origin main",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for the change to be published",
        .chain = &chain,
        .decision = .agent_review,
    });
    defer gpa.free(task);

    try testing.expect(std.mem.indexOf(u8, task, "git.push") != null);
    try testing.expect(std.mem.indexOf(u8, task, "push a1b2c3 to origin main") != null);
    try testing.expect(std.mem.indexOf(u8, task, "main -> coder") != null);
    try testing.expect(std.mem.indexOf(u8, task, "the task asked for the change") != null);
    try testing.expect(std.mem.indexOf(u8, task, "a1b2c3 fix the parser") != null);
    try testing.expect(std.mem.indexOf(u8, task, rationaleFor("git.push")) != null);

    for ([_]ReviewOutcome{ .approved, .refused, .unavailable }) |outcome| {
        const said = requesterText(outcome);
        try testing.expect(std.mem.indexOf(u8, said, rationaleFor("git.push")) == null);
        try testing.expect(std.mem.indexOf(u8, said, "reversib") == null);
        try testing.expect(std.mem.indexOf(u8, said, "sandbox") == null);
        try testing.expect(std.mem.indexOf(u8, said, "boundary") == null);
        try testing.expect(said.len < 300);
    }

    try testing.expect(std.mem.indexOf(u8, requesterText(.refused), "Do not ask again") != null);
    try testing.expect(std.mem.indexOf(u8, requesterText(.unavailable), "refusal") != null);

    for ([_][]const u8{
        "workspace.apply", "git.push",   "git.branch.delete", "net.fetch",
        "nix.build",       "file.write", "git.commit",        "model.select",
    }) |action| {
        try testing.expect(rationaleFor(action).len > 0);
        try testing.expect(!std.mem.eql(u8, rationaleFor(action), rationaleFor("something.new")));
    }
    try testing.expect(rationaleFor("something.new").len > 0);
}

test "the reviewer is told not to repeat the reasoning, and what an unsure answer is" {
    const gpa = testing.allocator;
    const chain = [_][]const u8{"main"};
    const task = try taskFor(gpa, .{
        .action = "net.fetch",
        .summary = "fetch https://example.invalid/spec",
        .detail = "one GET, at most 1048576 bytes",
        .reason = "the task names a specification to read",
        .chain = &chain,
        .decision = .agent_then_human,
    });
    defer gpa.free(task);

    try testing.expect(std.mem.indexOf(u8, task, "Do not repeat") != null);
    try testing.expect(std.mem.indexOf(u8, task, "who is right") != null);
    try testing.expect(std.mem.indexOf(u8, task, "If you cannot tell") != null);
    try testing.expect(std.mem.indexOf(u8, task, "\"approve\" or \"refuse\"") != null);
}

test "an answer that is not plainly an approval is a refusal" {
    const gpa = testing.allocator;

    const cases = [_][]const u8{
        "",
        "it looks fine to me",
        "[\"approve\"]",
        "{\"why\":\"looks fine\"}",
        "{\"verdict\":true,\"why\":\"looks fine\"}",
        "{\"verdict\":\"approve_with_edits\",\"why\":\"mostly\"}",
        "{\"verdict\":\"Approve\",\"why\":\"capitalised\"}",
        "{\"verdict\":\"refuse\",\"why\":\"the diff changes the policy file\"}",
    };
    for (cases) |answer| {
        const report = try readAnswer(gpa, answer);
        defer freeReport(gpa, report);
        try testing.expectEqual(Verdict.rejected, report.verdict);
        try testing.expectEqual(Resolution.refuse, resolve(.agent_review, report.verdict));
    }

    {
        const report = try readAnswer(gpa, "  {\"verdict\":\"approve\",\"why\":\"the diff is the fix the task asked for\"}\n");
        defer freeReport(gpa, report);
        try testing.expectEqual(Verdict.approved, report.verdict);
        try testing.expectEqualStrings("the diff is the fix the task asked for", report.note);
        try testing.expectEqual(Resolution.permit, resolve(.agent_review, report.verdict));
    }

    {
        const long = "{\"verdict\":\"approve\",\"why\":\"" ++ ("x" ** 900) ++ "\"}";
        const report = try readAnswer(gpa, long);
        defer freeReport(gpa, report);
        try testing.expectEqual(Verdict.approved, report.verdict);
        try testing.expectEqual(max_note_bytes, report.note.len);
    }

    {
        const report = try readAnswer(gpa, "{\"verdict\":\"refuse\",\"why\":\"the diff rewrites chock.zon\"}");
        defer freeReport(gpa, report);
        try testing.expectEqualStrings("the diff rewrites chock.zon", report.note);
    }
}

test "the kind a reviewer runs as is the kind that holds no tools" {
    try testing.expect(isArbitrator(default_kind));
    try testing.expect(!isArbitrator("main"));
    try testing.expect(!isArbitrator("reviewer-fast"));
    try testing.expect(!isArbitrator("review"));
    try testing.expect(!isArbitrator(""));

    try testing.expect(reviewsItself(&.{ "main", default_kind }, default_kind));
}

test "the schema a reviewer answers is two members, and the subagent shape is built from it" {
    try testing.expectEqual(@as(usize, 2), result_fields.len);
    try testing.expectEqualStrings("verdict", result_fields[0]);
    try testing.expectEqualStrings("why", result_fields[1]);
}
