//! How the agent gives its own work back to the project it is working on.
//!
//! ## Why this is a seam and not a call
//!
//! The act itself is `workspace.apply`, which lives in
//! `lib/chock-broker/actions.zig`, and **`chock-core` imports no
//! `chock-broker`**: the policy table stays in the one process the agent cannot
//! reach. The act also needs the session's own worktree, its scratch object
//! store and the user's repository, and every one of those belongs to
//! `src/run.zig`. So the loop holds a vtable, `src/run.zig` fills it in, and the
//! shape is the one `arbiter.Arbiter`, `fetch.Fetcher` and `ask.Console`
//! already use.
//!
//! ## Why it is not `arbiter.Arbiter`
//!
//! An arbiter **decides** and does nothing else, and every string it gives back
//! is a static one. This one decides and then **acts**: it moves git objects
//! into the user's repository and moves a ref. The two are worth keeping apart,
//! because a caller that could act through the deciding seam is a caller that
//! can act without a decision.
//!
//! The decision inside this one is still the broker's. `src/run.zig` builds the
//! request, `chock_broker.actions.run` puts it to the policy table and, where
//! the table answers `ask`, to a person. **The agent asks and never decides**,
//! and there is nothing in `Ask` an agent could fill in to answer itself: see
//! the comptime guard in this file's own tests.
//!
//! ## It runs inside the log lock
//!
//! `Loop.run` takes the exclusive lock on the session log and holds it for the
//! whole session, so an implementation runs **inside** the process that holds it
//! and appends the question and the answer through the handle it is given. That
//! is the same arrangement `arbiter.Arbiter` is built on, and it is why `apply`
//! takes a `*Locked`.
//!
//! ## Only one act, on purpose
//!
//! There is one function here and it names one act. A general "ask for any
//! action" seam would need every action's own parameters to come from the
//! model, which is a much larger thing to get right, and it would be built with
//! one customer. When there is a second customer, this widens with it.

const std = @import("std");
const chock_proto = @import("chock-proto");

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public, the way `arbiter.zig` does.
pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// The one action name an agent may ask for, which is also the policy key the
/// project writes a rule for in `chock.zon`.
///
/// **Spelled here because `chock-core` imports no `chock-broker`**, where
/// `actions.Kind.workspace_apply.wireName()` spells it too. `src/run.zig`
/// imports both and pins the two together in a test, so the copy cannot drift.
pub const apply_action = "workspace.apply";

/// What the loop tells the implementation about the call that asked.
///
/// **There is nothing here that decides anything**, and that is the point: an
/// agent fills in a reason and nothing else, and a reason is an argument, not an
/// answer. See this file's own top comment.
pub const Ask = struct {
    /// Why the agent wants its work carried back. Written into the
    /// `approval.request` so a person reads the agent's own words.
    reason: []const u8,
    /// The `call_id` of the `tool.call` that asked. It goes on the
    /// `approval.request`, so a reader of the log joins the question to the call
    /// that raised it, and tells an agent's own request from the one the harness
    /// makes at the end of a run, which carries none.
    tool_call_id: []const u8,
};

/// What one attempt came to.
pub const Result = struct {
    /// Whether the user's own repository holds the work now. **The one field a
    /// caller acts on.**
    ///
    /// **True only when the work is really there**, which includes a second
    /// request for a commit an earlier one already carried. False for every
    /// other ending, including the ones that are nobody's fault: nothing was
    /// carried, and a model that read one of those as success would carry on
    /// believing its work was safe.
    carried: bool,
    /// What the agent is told, in full sentences. Owned by the allocator the
    /// call was given, and freed by the caller.
    ///
    /// **Built by the implementation, because every fact in it is one only
    /// `src/run.zig` holds**: how many files are uncommitted, which ref the work
    /// landed on, and which repository it landed in.
    output: []u8,
};

/// The seam itself.
pub const Handback = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Ask for the session's own commit to be carried into the user's
        /// repository, and carry it when the answer permits it.
        ///
        /// The only error is running out of memory. Every other way of not
        /// carrying the work is a `Result` that says so, because a caller with
        /// an error to handle is a caller with a branch that can be got wrong,
        /// and the safe direction for all of them is the same one.
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

/// What a session with no handback tells the agent.
///
/// **Null in `Loop.Deps` and a refusal are two different facts, and the loop
/// keeps them apart**, the same way `arbiter.not_asked` does. A session that
/// holds no handback was never able to carry work back at all, and saying it was
/// refused would send a model looking for an argument that would change the
/// answer.
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
    // Dotted, because `chock-policy`'s own prefix rule reads the dots.
    try testing.expect(std.mem.indexOfScalar(u8, apply_action, '.') != null);
}

test "a session with no handback says so, and does not imply a decision" {
    try testing.expect(not_offered.len > 0);
    try testing.expect(std.mem.indexOf(u8, not_offered, "not a decision") != null);
}
