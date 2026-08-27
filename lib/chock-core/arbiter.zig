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

test "a session with no arbiter says so, and does not permit" {
    try testing.expect(!not_asked.permitted);
    try testing.expect(not_asked.outcome.len > 0);
    try testing.expectEqual(@as(usize, 0), not_asked.review_text.len);
}
