//! How the loop asks somebody else whether an act may happen.
//!
//! ## Why this is a seam and not a call
//!
//! `lib/chock-broker/Broker.zig` is what answers this question, and
//! **`chock-core` imports no `chock-broker`**: the policy table stays in the
//! one process the agent cannot reach, and the whole broker moves into a
//! process of its own. A loop that imported the broker directly would be a loop
//! that has to change when that happens. So the loop holds a vtable,
//! `src/run.zig` fills it in, and the shape is the one `Loop.Deps.tool_runner`,
//! `Loop.Deps.spawner` and `chock_provider.retry.Sleeper` already use.
//!
//! ## The one call that gives the lock away, and why that is safe
//!
//! `Loop.run` takes the exclusive lock on the session log and holds it for the
//! whole session, so an implementation of this seam runs **inside** the process
//! that holds it and appends through the handle it is given. That is the same
//! arrangement `src/approval.zig` and `lib/chock-broker/socket.zig` are built
//! on, and it is why `decide` takes a `*Locked`: the broker writes the question
//! and the answer through it, and nothing here opens the log a second time.
//!
//! ## What comes back, and what deliberately does not
//!
//! `Answer` holds whether the act may happen, the name of the outcome, and one
//! sentence for the agent that asked. **It carries nothing a reviewer wrote.**
//! `lib/chock-broker/review.zig` is built around that asymmetry: the arbitrator
//! is told why an act is guarded and the calling agent is told only the rule and
//! what to do instead. `Answer.review_text` is filled from
//! `review.requesterText`, which takes an outcome and nothing else and has a
//! comptime guard to keep it that way, so there is no route here for a
//! reviewer's reasoning to travel back along.
//!
//! Every string in an `Answer` is a static one. A caller does not free it, and
//! an implementation cannot smuggle a heap allocation through it either.

const std = @import("std");
const chock_proto = @import("chock-proto");

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public. A vtable cannot take `anytype`, so this
/// seam needs the name where `Loop.run` itself does not.
pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// What the loop wants decided. The agent kind, the model alias and the spawn
/// chain are not here because the implementation already holds all three: they
/// are facts about the session and not about this act.
pub const Ask = struct {
    /// For example `chock_policy.ratchet.widen_action`.
    action: []const u8,
    /// One line: what the act does.
    summary: []const u8,
    /// The whole effect: show the effect, never a command string.
    detail: []const u8,
    /// The reason the agent gave for wanting this.
    reason: []const u8,
    /// The tool the agent called, which is part of the policy key.
    tool: []const u8,
    /// The call_id of the `tool.call` that caused this.
    tool_call_id: []const u8,
    /// Which part of Chock wanted this, for the person answering. See
    /// `chock_proto.event.ApprovalRequest.source`.
    source: []const u8 = "",
};

/// What was decided.
pub const Answer = struct {
    /// True only for the outcomes that let the act happen. **The one field a
    /// caller acts on**, and it is filled from `Broker.Outcome.permits`, which
    /// is the one place in Chock that folds every outcome into a yes or a no.
    permitted: bool,
    /// The outcome's own name, for the sentence the agent reads. Coarse enough
    /// to tell "weighed and declined" from "nobody was there", which section
    /// 8.2 keeps apart on purpose, and never a description of the machinery.
    outcome: []const u8,
    /// What the agent is told about a review, from
    /// `chock_broker.review.requesterText`, or empty when no reviewer took
    /// part. See this file's own top comment.
    review_text: []const u8 = "",
};

/// The seam itself.
pub const Arbiter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Decide one act. **This never fails**: every way of not reaching a
        /// decision is already an `Answer` that does not permit, because a
        /// caller with an error to handle is a caller with a branch that can be
        /// got wrong, and the safe direction for all of them is the same one.
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

/// An arbiter, and the session log handle its question and its answer travel
/// through.
///
/// **The handle arrives after the arbiter does, and that is why it is
/// optional.** A caller builds the arbiter before the session starts, and
/// `Loop.run` takes the log's exclusive lock only after that, so
/// `chock_core.Loop.GiveLocked` fills `locked` once and it stays at the same
/// address for the rest of the session. A question asked before it arrives has
/// nothing to write through, so `decide` answers `not_asked` rather than
/// permitting.
///
/// **This exists so a caller that is not the loop can still ask.**
/// `chock_core.mcp.Session` and `chock_core.plugin.Session` decide about a
/// tool a third party program supplies, and both of them run from inside a
/// turn, where `Loop.Deps.arbiter` is threaded per call and this is not. See
/// `chock_core.mcp.Session.asker`.
pub const Asker = struct {
    arbiter: Arbiter,
    /// Null until `chock_core.Loop.GiveLocked` hands the handle over. **Never
    /// unlocked by whoever stores it**: the pointer is the loop's own, and
    /// there is no second owner of the log. See `Loop.GiveLocked`.
    locked: ?*Locked = null,

    /// Decide one act, through an asker that may not be there at all.
    ///
    /// **Null does not permit, and neither does a handle that has not
    /// arrived.** Both answer `not_asked`, which is the same direction
    /// `Loop.Deps.arbiter` takes for a session that can ask nobody: a caller
    /// with nobody to ask refuses, and says that is what happened.
    pub fn decide(self: ?Asker, gpa: std.mem.Allocator, io: std.Io, ask: Ask) Answer {
        const one = self orelse return not_asked;
        const locked = one.locked orelse return not_asked;
        return one.arbiter.decide(gpa, io, locked, ask);
    }
};

/// The sentence an agent reads when an act it asked for was not permitted.
///
/// **One text, in one place.** `chock_core.Loop.gateToolCall`,
/// `chock_core.mcp.Session.dispatch` and `chock_core.plugin.Session.dispatch`
/// all turn the same `Answer` into the same refusal, and a second copy of this
/// sentence would be a second thing to keep true.
///
/// `subject` is what needed approval: a tool name, or the action a tool
/// declared it needs. The caller owns the result and frees it with `gpa.free`.
pub fn refusalText(
    gpa: std.mem.Allocator,
    subject: []const u8,
    answer: Answer,
) std.mem.Allocator.Error![]u8 {
    // **The rule and the alternative, never the reason.** `answer.outcome` and
    // `answer.review_text` are the only two members an `Answer` carries beside
    // `permitted`, and neither one ever holds a reviewer's own reasoning: see
    // this file's own top comment.
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

/// What a session with no arbiter answers.
///
/// **Null in `Loop.Deps` and this are two different facts, and the loop keeps
/// them apart.** A session that holds no arbiter says so, because "nobody could
/// be asked" and "somebody said no" are a distinction worth keeping, and a
/// message that implied the request had been weighed would send a model looking
/// for an argument that would change the answer.
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
    // **Two ways of having nobody to ask, and one answer for both.** A caller
    // that never named an arbiter has none, and a caller that named one before
    // `Loop.run` took the log's lock has no handle to write a question
    // through. Neither can reach a person, so neither permits, and both say
    // that rather than that somebody said no: a model told it was refused goes
    // looking for an argument that would change the answer.
    //
    // Mutation check: permit on either `orelse` in `Asker.decide` and the
    // matching case below runs.
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
    // **The count is the test.** An arbiter that was never reached cannot have
    // decided anything, so a refusal here is this file's and not one that
    // travelled through a handle that does not exist.
    try testing.expectEqual(@as(usize, 0), counted.asks);
}

test "the refusal an agent reads names the outcome, and carries a reviewer's sentence only when there was one" {
    // One sentence in one place, so the loop and both third party tool
    // sessions cannot drift apart on what a refused call says.
    const gpa = testing.allocator;

    const bare = try refusalText(gpa, "get_current_time", .{
        .permitted = false,
        .outcome = "refused_by_user",
    });
    defer gpa.free(bare);
    try testing.expect(std.mem.indexOf(u8, bare, "get_current_time") != null);
    try testing.expect(std.mem.indexOf(u8, bare, "refused_by_user") != null);
    // No reviewer took part, so there is no stray double space where its
    // sentence would have gone.
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

/// An `Arbiter` that counts what it was asked, so a test can pin that nobody
/// was reached.
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
