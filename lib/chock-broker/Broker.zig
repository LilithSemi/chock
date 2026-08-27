//! The request, and the answer:
//!
//! 1. The agent calls the tool `request_action`.
//! 2. Chock builds an approval request.
//! 3. The broker evaluates the policy. `allow` or `deny` answers at once.
//! 4. `ask` sends the request to every client with the `approve` scope.
//! 5. A client shows the request to the user.
//! 6. If the user approves, the broker does the action outside the sandbox.
//! 7. Chock sends the result into the agent context.
//!
//! This file is steps 2 to 5. Step 6, the privileged work itself, is a later
//! task, and step 1 is the tool that calls this one.
//!
//! **Step 1 is not built.** There is no `request_action` in
//! `chock_core.tools.Tool`, so no tool call inside the sandbox reaches this
//! file. `lib/chock-policy/ratchet.zig` says why: the approval wall that used
//! to block it is gone, and this is waiting on the tool itself. Two callers
//! reach `request` today, and neither is an agent: `chock run` asks for
//! `workspace.apply` after the loop has ended, and the session arbiter asks
//! for `policy.widen` while it runs. Read the list above as the design and
//! not as what happens now.
//!
//! ## The table is the broker's own state
//!
//! A `Broker` holds a `*const chock_policy.table.Table`. Whichever process
//! holds the table is the broker. The loop never holds one and never decides
//! anything: it asks the broker, and the broker answers. The broker is the one
//! process the agent cannot reach, and a table the loop could read is a table
//! an agent that owns the loop can read.
//!
//! `Table.evaluateChain` is the verb this file calls, never
//! `evaluateKindAlone`. The answer is the intersection over the whole spawn
//! chain, so a child never holds a permission its parent lacks.
//!
//! ## And the session's own promises, folded into the same answer
//!
//! An agent may bind itself: "this task needs no network", said while it was
//! planning and written into the log as a `policy.self` event.
//! `Request.self_policy` carries those promises here and
//! `chock_policy.ratchet.narrow` folds them into the one decision, which makes
//! this file the place they are enforced.
//!
//! **That is not a detail of where the code sits.** A promise an agent checked
//! for itself is worth nothing, so the check is here, in the process the agent
//! cannot reach, over a record in the log that nothing can rewrite. The fold is
//! a minimum, so a promise can only ever narrow: no arrangement of promises
//! makes this broker permit something the table alone would have refused.
//!
//! ## The transport is the log. There is no channel of its own
//!
//! An approval travels as two events. `approval.request` is the question and
//! `approval.response` is the answer, and both go in the session log through
//! the same `Storage` every other event goes through. Nothing here opens a
//! socket. The same envelope is already the frame for the unix socket and for
//! server sent events, so a request that reaches the log reaches every client
//! with the `approve` scope with no second format.
//!
//! ## The request is written before the wait starts
//!
//! `request` appends the `approval.request` and only then looks for an
//! answer. A crash between asking and answering therefore leaves the question
//! on disk, and a client that reconnects reads it and can still answer. The
//! opposite order, wait first and write the question when the answer arrives,
//! reads simpler and loses every open question in a crash.
//!
//! ## The wait, and what it becomes in its own process
//!
//! `Loop.run` takes the storage lock for the whole session and holds it, so
//! nothing outside that process can append an `approval.response` today. The
//! wait can therefore not be a blocking read that never yields. It is a look,
//! a check against the deadline, and a `Waiter.wait` that gives control back,
//! repeated. Until the TUI exists, the thing that answers is whatever runs
//! inside that `wait` call.
//!
//! `Waiter` is the one seam, and there are three implementations of it now.
//! `SystemWaiter` only sleeps. `src/approval.zig` asks a person at this
//! process's own terminal. `lib/chock-broker/socket.zig` reads the unix
//! socket, **so an answer can come from a process that is not the one holding
//! the log lock**, which is what a daemon session, a subagent and a phone all
//! need.
//!
//! **The broker does not own the log for any of that, and it does not have to.**
//! What was missing was never a second writer; it was a way for an answer to
//! reach the writer there already. See `lib/chock-broker/socket.zig`'s own top
//! comment. The caller does not change either way: it still calls `request` and
//! still gets one `Outcome`, and nothing above this file learns which shape it
//! is talking to, which is the same promise `lib/chock-provider/Client.zig`
//! makes about the model backend.
//!
//! ## Nothing this broker writes carries a value it was told to keep out
//!
//! `redaction` holds those values and `scrubbed` replaces them once, at the
//! top of `request`, so every record written below that line is built out of
//! bytes that were already scanned. **The redacted record is what gets
//! hashed.** The log is append only and hash chained, so a value that lands in
//! it cannot be taken out again without breaking every record after it: there
//! is no cleanup, only prevention.
//!
//! `chock_core.Loop.appendAndApply` is the same seam for the records the loop
//! writes, and `lib/chock-core/redact.zig` carries the honest framing of what
//! redaction defeats and what it does not.
//!
//! ## Four outcomes, and none of them is a boolean
//!
//! See `event.ApprovalDecision`'s own comment. A security choice is never a
//! boolean, because a wrong boolean value reads as harmless, and because a
//! boolean cannot tell an expired request from a refused one. `Outcome` keeps
//! every case apart and `Outcome.permits` is the only place that folds them
//! into a yes or a no.
//!
//! ## A reviewer answers before anybody else does
//!
//! Two of the five decisions the table can give are answered by a reviewer
//! subagent, and `lib/chock-broker/review.zig` holds all of it: what the
//! reviewer is told, what it may answer, and the rule that a verdict never
//! widens what the table already decided. This file is the caller, and it keeps
//! three rules:
//!
//! * **A review is asked for only where the folded decision asked for one.**
//!   `Table.evaluateChain` answers first, so a `deny` never reaches a reviewer
//!   whatever the reviewer's own kind holds.
//! * **A review that could not run is a refusal.** `review_unavailable`, and
//!   it does not permit. An attacker's cheapest move against a review is to
//!   make it fail, so failing must not be the permissive direction.
//! * **`agent_then_human` spends nothing on a review it already knows cannot
//!   finish.** See `request`.

const std = @import("std");
const chock_proto = @import("chock-proto");
const chock_policy = @import("chock-policy");
const secrets_mod = @import("secrets.zig");
const review_mod = @import("review.zig");
const diagnostic = @import("diagnostic.zig");
/// Why the broker refused an act, or could not carry one out. One type for
/// the whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;
const table = chock_policy.table;

const Broker = @This();

/// The policy table, parsed once when the session started. See this file's
/// own top comment: whichever process holds this is the broker.
policy: *const table.Table,
/// How this broker learns the time, and how it gives control back between
/// two looks at the log. See this file's own top comment.
waiter: Waiter,
/// What runs a review, for the two decisions that need one. Null for a session
/// that can start no reviewer at all, and **a null is a refusal and never an
/// allow**: see `Outcome.review_unavailable`. That is the ordinary state of
/// every test of this file and of any caller that cannot run a child process.
reviewer: ?review_mod.Reviewer = null,
/// The credentials. The broker reads the store and nothing else does.
///
/// They are a field here, and not a parameter of the two functions below, for
/// the reason this whole file is shaped the way it is. A caller that had to
/// hold a `secrets.Store` to redact a tool result would be a caller holding
/// credentials, which that rule forbids, and it would be a caller that has to
/// change when the broker moves into its own process. A caller holds a `*const
/// Broker` and nothing else, the same way it already does to ask a question.
/// Empty by default, which redacts nothing and resolves no handle, and that is
/// the right answer for a session that was given no credentials.
secrets: secrets_mod.Store = .{},
/// What must not reach any record this broker writes. Empty by default, which
/// replaces nothing and costs one comparison.
///
/// **Values, and never a name.** A `secrets.Store` entry has a name, and a
/// name is what a tool definition spells as `{{secret:name}}` to put the value
/// into the environment of a sandboxed child. A redaction set that could be
/// named that way would be a route to the thing it protects, so this is a list
/// of values and `secrets.Redactor.initValues` is what reads it.
/// `askpass.Grants.redactor` holds the same shape for the same reason.
///
/// **A value too short to match on is the caller's to report.** A value of
/// four bytes sits inside ordinary words, inside hashes and inside base64, so
/// matching one would replace half of every request. The floor is
/// `chock_core.redact.min_secret_bytes` and `src/run.zig` applies it, because
/// there the values still have a name to report the skipped ones by. A short
/// value that reaches this field is matched like any other.
redaction: []const []const u8 = &.{},

/// How long a request waits for an answer, when the caller names no other
/// time. A request has a timeout, and a request which expires counts as a
/// refusal. Five minutes is long enough for a user to read a diff and short
/// enough that a session which nobody is watching stops instead of holding the
/// lock forever.
pub const default_timeout_ms: i64 = 5 * std.time.ms_per_min;

/// The longest a caller can make one request wait, whatever it asks for.
/// `Loop.run` holds the session lock for the whole session, so an open
/// request holds it too, and nothing else can append while it does. A caller
/// that asks for a year therefore stops the session for a year. One hour is
/// longer than any person waits at a prompt and short enough that a stuck
/// session frees the lock the same day. `request` reduces a longer timeout to
/// this value rather than refusing it, because the safe reading of "wait a
/// very long time" is "wait the longest this broker allows", and a refusal
/// would turn a bad number into a failed tool call.
pub const max_timeout_ms: i64 = 60 * std.time.ms_per_min;

/// How long the broker gives control away between two looks at the log. Only
/// an upper bound: the last wait before the deadline is shorter. This trades
/// how fast an answer is noticed against how often the log is read, and 50 ms
/// is below what a person notices.
pub const poll_interval_ms: u64 = 50;

/// Everything one approval needs.
pub const Request = struct {
    /// For example "git.push".
    action: []const u8,
    /// One line. This is what a client shows in a list.
    summary: []const u8,
    /// The whole effect, for example the diff of a commit. Show the diff,
    /// never the command string. The user approves the effect.
    detail: []const u8,
    /// The reason the agent gave for wanting this.
    reason: []const u8,
    /// The agent kind that asked. Selects the policy.
    agent_kind: []const u8,
    /// The alias of the model behind that agent. Part of the policy key.
    model_alias: []const u8,
    /// The tool the agent called. Part of the policy key.
    tool: []const u8,
    /// The call_id of the `tool.call` that caused this.
    tool_call_id: []const u8,
    /// Every parent of the asking agent, root first, and the reason each one
    /// gave for starting the next. The asking agent itself is not a link:
    /// `agent_kind` names it. See `policyChain`.
    spawn_chain: []const event.SpawnLink = &.{},
    /// How long to wait for an answer, in milliseconds from now.
    timeout_ms: i64 = default_timeout_ms,
    /// What the asking session promised about itself, folded from its own
    /// `policy.self` events. Empty for a session that promised nothing, which
    /// is every session that had no use for a promise.
    ///
    /// **The broker applies this, and the agent does not.** A check an agent
    /// performs on itself is worth nothing: the promise is enforced here, in
    /// the one process kept beyond the agent's reach, out of a record in the
    /// log that nothing can rewrite. See `chock_policy.ratchet`, and
    /// `src/run.zig`, which folds the log and fills this in.
    ///
    /// A caller that leaves it out loses nothing else: an empty list narrows
    /// no key at all, so `request` answers exactly what the table says.
    self_policy: []const chock_policy.ratchet.Restriction = &.{},
};

/// What one call to `request` ended as. Five cases, and every one of them is
/// a different fact. The approval flow names four, and `unknown_decision` is
/// the fifth, for an answer written by something newer than this broker.
///
/// This is not a boolean and it does not hold one. See this file's own top
/// comment.
pub const Outcome = enum {
    /// The policy table answered `allow`. Nobody was asked.
    allowed_by_policy,
    /// The policy table answered `deny`. Nobody was asked.
    denied_by_policy,
    /// A user answered yes.
    approved_by_user,
    /// A user answered no.
    refused_by_user,
    /// Nobody answered before the timeout. That counts as a refusal, and it
    /// still says expired, because "nobody was there" and "somebody said no"
    /// are two different facts about the same session.
    expired,
    /// The answer in the log names a decision this build does not know, so
    /// this build cannot act on it. It is not permission. See
    /// `findAnswer`.
    unknown_decision,
    /// The answer names this request, and it also says something that cannot
    /// be true of it: a different action, a different tool call, or a
    /// decision only this broker's own review writes. The two statements
    /// disagree, so the answer cannot be read as permission for either of
    /// them. See `findAnswer`.
    mismatched_answer,
    /// The `agent_review` decision: a reviewer agent read the request and
    /// said yes. No person was asked.
    approved_by_review,
    /// A reviewer agent read the request and said no.
    refused_by_review,
    /// The policy asked for a review and there was none to be had. **This is
    /// a refusal**, and it is its own outcome because "no reviewer could
    /// answer" and "the reviewer said no" are two different facts about the
    /// same session, the same way `expired` and `refused_by_user` are.
    ///
    /// Every way a review can fail lands here: no reviewer at all, a reviewer
    /// whose kind is already in the asking chain, a review nothing could pay
    /// for, a child that died, and an answer that cannot be read. A caller
    /// that told them apart would be a caller with a branch that can be got
    /// wrong, and the right act is the same for all of them.
    review_unavailable,

    /// True only for the three outcomes that let the action happen. The one
    /// place in Chock that folds every fact into a yes or a no, so a caller
    /// never writes that switch itself and never gets it wrong. The switch
    /// is exhaustive, so a new outcome fails the build here rather than
    /// falling into whichever branch an `else` happened to name.
    pub fn permits(self: Outcome) bool {
        return switch (self) {
            .allowed_by_policy, .approved_by_user, .approved_by_review => true,
            .denied_by_policy,
            .refused_by_user,
            .expired,
            .unknown_decision,
            .mismatched_answer,
            .refused_by_review,
            .review_unavailable,
            => false,
        };
    }

    /// How this outcome reads to the agent that asked, for
    /// `review.requesterText`. Null when no reviewer took part, in which case
    /// there is nothing of a review to say.
    ///
    /// **Coarse on purpose.** The asking agent learns that a review happened
    /// and how it went, and never which of the several ways a review can be
    /// unavailable this one was, because those name the machinery.
    pub fn reviewOutcome(self: Outcome) ?review_mod.ReviewOutcome {
        return switch (self) {
            .approved_by_review => .approved,
            .refused_by_review => .refused,
            .review_unavailable => .unavailable,
            .allowed_by_policy,
            .denied_by_policy,
            .approved_by_user,
            .refused_by_user,
            .expired,
            .unknown_decision,
            .mismatched_answer,
            => null,
        };
    }
};

/// What `request` can fail with. A refusal is not an error: it is an
/// `Outcome`. Everything here is either a fault of the log itself or a
/// request from outside to stop waiting.
pub const Error =
    std.mem.Allocator.Error ||
    // ReplayError, not the narrower StorageError: the broker reads the log
    // back to look for its answer, and a stored line that fails to parse is
    // as real a fault there as a write fault is.
    chock_proto.storage.ReplayError ||
    // The wait is the one place a request spends real time, so it is the one
    // place a cancellation can reach. See `Waiter.Wake`.
    std.Io.Cancelable;

/// The clock, and the way control leaves the broker between two looks at the
/// log. See this file's own top comment for what this becomes when the broker
/// runs in its own process.
///
/// `nowMs` must move forward as real time does. `request` ends its wait when
/// the clock reaches the deadline, so a clock that never moves makes that
/// loop run forever. That is not a case this file can recover from, because a
/// broker with no working clock cannot tell an open request from an expired
/// one at all, and answering either way would be a guess. It is bound by the
/// same trust `std.Io.sleep` places in the clock underneath it.
pub const Waiter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// How one call to `wait` ended.
    pub const Wake = enum {
        /// Control came back the ordinary way. The broker looks at the log
        /// again, and the deadline still decides when the wait ends. Coming
        /// back before the whole budget passed is this case too: an early
        /// return only makes the next look happen sooner.
        slept,
        /// Something outside asked this task to stop. The broker gives up
        /// the wait and `request` returns `error.Canceled`.
        ///
        /// This case exists because the alternative is worse. A `wait` that
        /// cannot wait and cannot say so turns the loop in `request` into a
        /// busy loop for the rest of the deadline, and that deadline can be
        /// an hour. It also loses the cancellation itself: `Loop.run` holds
        /// the session lock while a request is open, so a session nobody can
        /// stop is a session nobody can close either.
        ///
        /// The open `approval.request` stays in the log. That is the same
        /// state a crash leaves behind, and a client that reconnects can
        /// still read it and still answer it.
        canceled,
    };

    pub const VTable = struct {
        /// The time now, in milliseconds since the epoch. The same scale
        /// `event.ApprovalRequest.timeout_at_ms` uses.
        nowMs: *const fn (ptr: *anyopaque, io: std.Io) i64,
        /// Give control back to whatever can answer, for at most
        /// `budget_ms` milliseconds. See `Wake` for the two ways it ends.
        wait: *const fn (ptr: *anyopaque, io: std.Io, budget_ms: u64) Wake,
    };

    pub fn nowMs(self: Waiter, io: std.Io) i64 {
        return self.vtable.nowMs(self.ptr, io);
    }

    pub fn wait(self: Waiter, io: std.Io, budget_ms: u64) Wake {
        return self.vtable.wait(self.ptr, io, budget_ms);
    }
};

/// The real `Waiter`: the machine's own clock, and a sleep between two looks.
///
/// The clock is `.real`, because `timeout_at_ms` is a unix time that every
/// client reads, not a number private to this process. The sleep is `.awake`,
/// the monotonic clock, because a nap is a length of time and not a point in
/// one.
pub const SystemWaiter = struct {
    /// This waiter keeps no state. `Waiter.ptr` must still hold a pointer,
    /// so it holds the address of this one byte. Nothing reads the byte.
    /// `undefined` was here before, and `undefined` is a value a later reader
    /// is allowed to load, so an address that is real costs nothing and
    /// removes the question.
    var anchor: u8 = 0;

    pub fn waiter() Waiter {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = ptr;
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Waiter.Wake {
        _ = ptr;
        std.Io.sleep(io, .fromMilliseconds(@intCast(budget_ms)), .awake) catch |err| switch (err) {
            // Somebody asked this task to stop. Say so, rather than swallow
            // it and keep the session lock for the rest of the deadline.
            error.Canceled => return .canceled,
        };
        return .slept;
    }
};

/// Ask for one privileged action, and give back what was decided.
///
/// The policy answers first. `allow` and `deny` are answered at once, with no
/// question written and nobody asked, and each one still leaves an
/// `approval.response` in the log, because a signature over that record comes
/// later and a decision with no record cannot become a signed one.
///
/// `ask` writes the `approval.request` first and waits for an
/// `approval.response` that names it. See this file's own top comment for
/// both orders and for what the wait becomes later.
///
/// `storage` is where the answer is read from and `locked` is the caller's
/// proof that it holds the exclusive lock to write with. Both are needed,
/// because `Storage` has no `append` of its own: see
/// `lib/chock-proto/storage.zig`'s own top comment. `locked` is `anytype`
/// for the same reason `lib/chock-core/Loop.zig` takes it that way, which is
/// that `chock_proto.storage.Locked` is not `pub`, and the run time
/// generation check inside the backend, not the type system, is what proves
/// the handle is real.
pub fn request(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    given: Request,
    diag: ?*?Diagnostic,
) Error!Outcome {
    // Chock builds every one of these itself, out of names it already holds,
    // so an empty one is a broken caller and not a bad log. `Table` asserts
    // the same four names for the same reason.
    std.debug.assert(given.action.len > 0);
    std.debug.assert(given.agent_kind.len > 0);
    std.debug.assert(given.model_alias.len > 0);
    std.debug.assert(given.tool.len > 0);

    // **Once, here, and nothing below reads the argument again.** Every record
    // this function writes, the case a reviewer is given, and the question a
    // person is shown are all built out of `ask`, so one replacement at the
    // entrance covers all three and no path added later has to remember. The
    // arena lives as long as the call, which includes the whole wait.
    var scrub_arena = std.heap.ArenaAllocator.init(gpa);
    defer scrub_arena.deinit();
    const ask = try self.scrubbed(scrub_arena.allocator(), given);

    const chain = try policyChain(gpa, ask);
    defer gpa.free(chain);

    const key = table.Key{
        .agent_kind = ask.agent_kind,
        .model = ask.model_alias,
        .tool = ask.tool,
        .action = ask.action,
    };

    // **One evaluation, over the whole chain, and every branch below reads
    // this one answer.** A second evaluation anywhere under here, of the
    // asking kind alone, would be the escalation a review is most exposed to:
    // a reviewer consulted about a key its requester was denied.
    //
    // The session's own promises are folded into the same answer, and here
    // rather than at any call site, so every caller of this broker gets them
    // and no caller has to remember. `ratchet.narrow` is a minimum, exactly
    // like the fold over the chain above it, so the result is the narrowest of
    // the whole chain and every promise: see `chock_policy.ratchet`. It can
    // only lower the answer, so nothing below this line can be reached that
    // the table alone would not have reached.
    const decision = chock_policy.ratchet.narrow(
        self.policy.evaluateChain(chain, key, null),
        ask.self_policy,
        key.action,
    );
    switch (decision) {
        .allow => {
            _ = try appendAnswer(gpa, io, locked, ask, 0, .allowed_by_policy, "", self.waiter.nowMs(io), .{});
            return .allowed_by_policy;
        },
        .deny => {
            _ = try appendAnswer(gpa, io, locked, ask, 0, .denied_by_policy, "", self.waiter.nowMs(io), .{});
            return .denied_by_policy;
        },
        .ask => return self.askTheHuman(gpa, io, storage, locked, ask, .{}, diag),
        .agent_review, .agent_then_human => {},
    }

    return self.reviewed(gpa, io, storage, locked, ask, chain, decision, diag);
}

/// The two decisions that a reviewer answers first.
///
/// **A review that could not run is a refusal.** Every path out of here that
/// is not an approval refuses, and `review_unavailable` does not permit: see
/// `Outcome`. That is the rule the whole arrangement would be worthless
/// without, because otherwise the cheapest attack on a review is to make it
/// fail.
fn reviewed(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    ask: Request,
    chain: []const []const u8,
    decision: chock_policy.table.Decision,
    diag: ?*?Diagnostic,
) Error!Outcome {
    std.debug.assert(decision.needsReview());

    // **A review costs a whole subagent, so it is not spent on a question
    // whose second half already cannot be answered.** `agent_then_human` ends
    // with a person, and a caller that asked for no wait at all has told this
    // broker that nobody is there: `src/run.zig`'s own end of session apply
    // does exactly that, because `Loop.run` holds the log lock and no
    // `approval.response` can arrive while it does. Paying a model to answer
    // and then expiring anyway spends money for a result that was already
    // decided.
    if (decision.needsHuman() and ask.timeout_ms <= 0) {
        _ = diagnostic.note(diag, .{ .cannot_wait_for_a_person = .{
            .decision = decision,
            .action = ask.action,
        } });
        _ = try appendAnswer(gpa, io, locked, ask, 0, .expired, "", self.waiter.nowMs(io), .{});
        return .expired;
    }

    const report = self.runReview(gpa, io, ask, chain, decision, diag) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ReviewNotRun => {
            _ = try appendAnswer(gpa, io, locked, ask, 0, .review_unavailable, "", self.waiter.nowMs(io), .{});
            return .review_unavailable;
        },
    };
    defer review_mod.freeReport(gpa, report);

    // **The one string that arrives after `request` scrubbed its argument.** A
    // reviewer is a model, and it writes this note into the log and into the
    // question a person is shown. Its own context was built from a case this
    // broker already cleaned, so this is a second guard and not the first one.
    // It costs one scan of one line.
    const clean_note = try self.scrubText(gpa, report.note);
    defer if (clean_note) |note| gpa.free(note);
    const record = Record{ .verdict = report.verdict, .note = clean_note orelse report.note };

    switch (review_mod.resolve(decision, report.verdict)) {
        .permit => {
            _ = try appendAnswer(
                gpa,
                io,
                locked,
                ask,
                0,
                .approved_by_review,
                self.reviewer.?.kind,
                self.waiter.nowMs(io),
                record,
            );
            return .approved_by_review;
        },
        .refuse => {
            _ = try appendAnswer(
                gpa,
                io,
                locked,
                ask,
                0,
                .refused_by_review,
                self.reviewer.?.kind,
                self.waiter.nowMs(io),
                record,
            );
            return .refused_by_review;
        },
        // `agent_then_human`: the reviewer answered first and its verdict
        // goes with the request, so the person decides with the review in
        // front of them.
        .ask_the_human => return self.askTheHuman(gpa, io, storage, locked, ask, record, diag),
        // Unreachable by the assert above, and a refusal rather than a panic
        // if it ever is reached: a broker that cannot tell what it is doing
        // must not be the one that says yes.
        .not_a_review => {
            _ = diagnostic.note(diag, .{ .review_for_a_decision_that_asks_for_none = .{
                .decision = decision,
                .action = ask.action,
            } });
            _ = try appendAnswer(gpa, io, locked, ask, 0, .review_unavailable, "", self.waiter.nowMs(io), .{});
            return .review_unavailable;
        },
    }
}

/// Run one review, or say why there was none. **Every failure is
/// `error.ReviewNotRun`**, because the broker does the same thing with each of
/// them: see `Outcome.review_unavailable`.
fn runReview(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    ask: Request,
    chain: []const []const u8,
    decision: chock_policy.table.Decision,
    diag: ?*?Diagnostic,
) review_mod.ReviewError!review_mod.Report {
    const reviewer = self.reviewer orelse {
        _ = diagnostic.note(diag, .{ .no_reviewer = .{
            .decision = decision,
            .action = ask.action,
        } });
        return error.ReviewNotRun;
    };

    // **Before anything is spent.** A reviewer whose kind is already in the
    // chain that asked would be reviewing its own request, directly or one
    // level down, and a self review is not a review.
    if (review_mod.reviewsItself(chain, reviewer.kind)) {
        _ = diagnostic.note(diag, .{ .reviewer_reviews_itself = .{
            .reviewer_kind = reviewer.kind,
            .action = ask.action,
        } });
        return error.ReviewNotRun;
    }

    return reviewer.review(gpa, io, .{
        .action = ask.action,
        .summary = ask.summary,
        .detail = ask.detail,
        .reason = ask.reason,
        .chain = chain,
        .decision = decision,
    });
}

/// Write the question and wait for a person to answer it.
///
/// `record` is what a reviewer already said, for `agent_then_human`, and it is
/// empty for a plain `ask`. **It travels with the question**, so the person
/// decides with the review in front of them rather than being asked the same
/// thing twice with no memory in between.
fn askTheHuman(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    ask: Request,
    record: Record,
    diag: ?*?Diagnostic,
) Error!Outcome {
    const asked_at_ms = self.waiter.nowMs(io);
    // The bound is applied here and not at the call site, so every caller
    // gets it and no caller has to remember it. See `max_timeout_ms`.
    //
    // Only the upper end is bounded. A timeout of zero, or a negative one,
    // puts the deadline at or before the present moment, and the loop below
    // expires it on the first look with no wait at all. That is what "do not
    // wait" means and it is a legitimate thing to ask for, so there is
    // nothing for a lower bound to correct.
    const timeout_ms = @min(ask.timeout_ms, max_timeout_ms);
    const deadline_ms = asked_at_ms +| timeout_ms;

    // The question is on disk before the wait starts. A crash from here on
    // leaves it there to be answered by whoever reconnects.
    const request_id = try locked.append(gpa, io, .{
        .approval_request = .{
            .action = ask.action,
            .summary = ask.summary,
            .detail = ask.detail,
            .reason = ask.reason,
            .agent_kind = ask.agent_kind,
            .spawn_chain = ask.spawn_chain,
            .timeout_at_ms = deadline_ms,
            .tool_call_id = ask.tool_call_id,
            // The reviewer answers first, and its verdict goes with the diff.
            // Both are `.none` and empty for a plain `ask`.
            .review = record.verdict,
            .review_note = record.note,
        },
    }, asked_at_ms);

    var last_look_ms = asked_at_ms;
    while (true) {
        if (try findAnswer(gpa, io, storage, request_id, ask, diag)) |outcome| return outcome;

        const now_ms = self.waiter.nowMs(io);
        // A `Waiter` whose clock runs backwards would make the deadline
        // below meaningless. That is a broken `Waiter` and therefore a
        // mistake in this program, not a fault of the log.
        std.debug.assert(now_ms >= last_look_ms);
        last_look_ms = now_ms;

        if (now_ms >= deadline_ms) {
            _ = try appendAnswer(gpa, io, locked, ask, request_id, .expired, "", now_ms, record);
            return .expired;
        }

        // Never wait past the deadline, so the request expires when it said
        // it would and not one poll interval later.
        const left_ms: u64 = @intCast(deadline_ms - now_ms);
        switch (self.waiter.wait(io, @min(left_ms, poll_interval_ms))) {
            .slept => {},
            // The question stays in the log with no answer, which is what a
            // crash at this point leaves too. See `Waiter.Wake.canceled`.
            .canceled => return error.Canceled,
        }
    }
}

/// The agent kinds the policy is evaluated over, root first.
///
/// `Request.spawn_chain` names the parents of the agent that asked, which is
/// what `event.SpawnLink` documents, and `Table.evaluateChain` wants a chain
/// whose last link is the agent that asked. So the asking kind is added at
/// the end. A root agent has no parent, and its chain is one link long.
///
/// **This function is why `evaluateChain`'s own consistency check never
/// fires for the broker.** That check compares the chain's answer against the
/// asking kind's own answer, and it can only differ when the asking kind is
/// missing from the chain. The line below always puts it there. The two
/// therefore agree because `Table.intersect` is a minimum over the chain,
/// and a minimum over a set that holds the asking kind can never be stronger
/// than that kind alone. A child is never stronger than its parent, and this
/// line is what makes the broker obey that, so a change here that stops
/// appending the asking kind breaks the rule and not only a comment.
///
/// The caller frees the result. Only the array is owned. Each name still
/// belongs to `ask`.
fn policyChain(gpa: std.mem.Allocator, ask: Request) Error![]const []const u8 {
    const chain = try gpa.alloc([]const u8, ask.spawn_chain.len + 1);
    for (ask.spawn_chain, chain[0..ask.spawn_chain.len]) |link, *slot| slot.* = link.agent_kind;
    chain[ask.spawn_chain.len] = ask.agent_kind;
    return chain;
}

/// The request with every field that can carry bytes this broker did not
/// write itself replaced. See `redaction`, and see this file's own top comment
/// on why the replacement happens before the append and not after.
///
/// Everything is borrowed from `arena` and from `ask`, so the result is valid
/// for exactly as long as both. A broker with no values to replace gives its
/// argument straight back, uncopied.
fn scrubbed(self: *const Broker, arena: std.mem.Allocator, ask: Request) Error!Request {
    if (self.redaction.len == 0) return ask;

    var clean = ask;
    clean.summary = (try self.scrubText(arena, ask.summary)).?;
    clean.detail = (try self.scrubText(arena, ask.detail)).?;
    clean.reason = (try self.scrubText(arena, ask.reason)).?;

    // Each link's reason is what a parent agent said about starting the agent
    // below it. The kinds beside them are policy names this build wrote.
    if (ask.spawn_chain.len > 0) {
        const links = try arena.alloc(event.SpawnLink, ask.spawn_chain.len);
        for (ask.spawn_chain, links) |link, *slot| {
            slot.* = link;
            slot.reason = (try self.scrubText(arena, link.reason)).?;
        }
        clean.spawn_chain = links;
    }
    return clean;
}

// **Every field of `Request` is either replaced above or named here as one
// that holds no bytes an agent, a workspace or a model supplied.** A field in
// neither list fails the build, so a request that grows one is decided about
// here rather than written into a log that cannot be edited afterwards.
comptime {
    const replaced = [_][]const u8{ "summary", "detail", "reason", "spawn_chain" };
    // The four the policy key is built from, plus the call id and the two
    // numbers. Chock writes each of them out of names it already holds: an
    // action name, an agent kind, a model alias, a tool name, and the id of the
    // tool call it started itself. Replacing any of the first four would change
    // the key the policy is read with, which is a decision and not a redaction.
    // `self_policy` reaches the fold and no record.
    const chock_wrote_it = [_][]const u8{
        "action",       "agent_kind", "model_alias", "tool",
        "tool_call_id", "timeout_ms", "self_policy",
    };
    for (@typeInfo(Request).@"struct".fields) |field| {
        var listed = false;
        for (replaced ++ chock_wrote_it) |name| {
            if (std.mem.eql(u8, field.name, name)) listed = true;
        }
        if (!listed) {
            @compileError("this field of Request is neither replaced nor named as Chock's own: " ++ field.name);
        }
    }
}

/// One string with every value of `redaction` replaced, or null when this
/// broker holds none. **Null is the common answer**, and it is what keeps a
/// session that declared nothing from paying for a copy. The caller owns a
/// returned slice.
fn scrubText(
    self: *const Broker,
    gpa: std.mem.Allocator,
    said: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    if (self.redaction.len == 0) return null;
    var scan = try secrets_mod.Redactor.initValues(gpa, self.redaction);
    defer scan.deinit(gpa);
    try scan.push(gpa, said);
    return try scan.finish(gpa);
}

/// What a reviewer said, as it travels from `reviewed` into the log and, for
/// `agent_then_human`, into the question a person is asked.
///
/// **Two fields and no more, and the note never goes anywhere but the log.**
/// See `lib/chock-broker/review.zig`: the note is written for the person who
/// reads the record the next morning, and `review.requesterText` is what the
/// agent that asked reads instead. The default is what every decision no
/// reviewer took part in carries.
const Record = struct {
    verdict: event.ReviewVerdict = .none,
    note: []const u8 = "",
};

/// Write one `approval.response`, and give back the id of the line.
///
/// `request_id` is zero when the policy answered on its own and no question
/// was written. See `event.ApprovalResponse.request_id` for why zero cannot
/// be read as a real event id.
fn appendAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    ask: Request,
    request_id: u64,
    decision: event.ApprovalDecision,
    responder: []const u8,
    time_ms: i64,
    record: Record,
) Error!u64 {
    return locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = decision,
        .responder = responder,
        .action = ask.action,
        .tool_call_id = ask.tool_call_id,
        .review = record.verdict,
        .review_note = record.note,
    } }, time_ms);
}

/// The id of the question that is still open in `storage`, or null when there
/// is none.
///
/// **The newest one, and only while it has no answer.** A `Waiter` is what
/// calls this: the broker gives control away only for a request it has already
/// failed to find an answer for, so a question that reads as answered here is
/// one this waiter answered on an earlier look, and the right act then is to do
/// nothing and let the broker read it.
///
/// **It is here, and not in each waiter, because both waiters need the same
/// answer.** `src/approval.zig` asks a person and `lib/chock-broker/socket.zig`
/// asks whatever is on the other end of a unix socket, and the two must agree
/// about which question is open, or one of them answers a question the other
/// one is showing.
pub fn openRequest(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
) Error!?u64 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();

    var newest: ?u64 = null;
    var answered = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => {
                newest = parsed.value.id;
                answered = false;
            },
            .approval_response => |response| {
                if (newest) |id| {
                    if (response.request_id == id) answered = true;
                }
            },
            else => {},
        }
    }
    if (answered) return null;
    return newest;
}

/// Look through the log for the answer to one request, and give back what it
/// decided. Null when no answer is there yet.
///
/// **An answer names the request it answers.** More than one request can be
/// open at the same time, because one turn can hold more than one tool call
/// and because a subagent can ask while its parent waits. A search that took
/// the first `approval.response` it found would hand one request the answer a
/// user gave to another one, which is the whole reason `request_id` exists.
///
/// The replay starts at the request's own id, because no answer can come
/// before its own question. Every response after that point is still read,
/// so the id check is what does the work, not the offset. The offset is what
/// keeps a response written **earlier** than the question out of the search:
/// an id is a byte offset, and a log rewritten or replayed from another
/// session could hold a stale response that carries the same number.
///
/// **An answer that names this request must also agree with it.**
/// `event.ApprovalResponse` repeats the action and the tool call id, so one
/// line says what was decided and what it was decided about. When the answer
/// says both things and the second one names some other act, the two
/// statements disagree and neither can be trusted, so this refuses. An empty
/// field is not a disagreement: it means the writer did not say, which is
/// what the field's default is for.
fn findAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    request_id: u64,
    ask: Request,
    diag: ?*?Diagnostic,
) Error!?Outcome {
    var replay = try storage.replay(gpa, io, request_id);
    defer replay.deinit();

    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_response) continue;
        const answer = parsed.value.event.approval_response;
        if (answer.request_id != request_id) continue;
        if (disagrees(answer.action, ask.action) or
            disagrees(answer.tool_call_id, ask.tool_call_id))
        {
            // The two fields read out of the log belong to an event this
            // loop moves past at once, so the diagnostic keeps copies.
            if (diagnostic.wants(diag)) {
                var owned: Diagnostic = .{ .answer_is_about_another_request = .{
                    .request_id = request_id,
                    .answer_action = "",
                    .answer_tool_call_id = "",
                    .ask_action = ask.action,
                    .ask_tool_call_id = ask.tool_call_id,
                } };
                errdefer owned.deinit(gpa);
                const names = &owned.answer_is_about_another_request;
                names.answer_action = try gpa.dupe(u8, answer.action);
                names.answer_tool_call_id = try gpa.dupe(u8, answer.tool_call_id);
                _ = diagnostic.note(diag, owned);
            }
            return .mismatched_answer;
        }

        return switch (answer.decision) {
            .allowed_by_policy => .allowed_by_policy,
            .denied_by_policy => .denied_by_policy,
            .approved_by_user => .approved_by_user,
            .refused_by_user => .refused_by_user,
            .expired => .expired,
            // **The three a review writes are not answers.** This broker
            // writes them itself, out of `reviewed`, and it never reads one
            // back: a request that a reviewer settled has no open question at
            // all. So one found here is something other than this broker
            // claiming a review happened, which cannot be true of this
            // request, and the safe reading of an answer that cannot be true
            // is that the action does not happen.
            inline .approved_by_review, .refused_by_review, .review_unavailable => |_, tag| claimed: {
                // **A `ReviewDecision` and not `@tagName`.** The name used to
                // be a pointer into `.rodata`, and `Diagnostic.deinit` freed
                // it. `inline` makes `tag` known at compile time, so a
                // decision this switch names and the enumeration does not is
                // a compile error and never a message with the wrong word.
                _ = diagnostic.note(diag, .{ .answer_claims_a_review = .{
                    .request_id = request_id,
                    .decision = @field(Diagnostic.ReviewDecision, @tagName(tag)),
                } });
                break :claimed .mismatched_answer;
            },
            // A name a newer writer used. Keeping the log readable is
            // `event.zig`'s job and it does it. Acting on a decision this
            // build cannot read is not something any amount of goodwill
            // makes safe, so this refuses, and it says so.
            .unknown => |name| unknown: {
                // The name is read out of the log event this loop moves past
                // at once, so the diagnostic keeps a copy.
                if (diagnostic.wants(diag)) {
                    _ = diagnostic.note(diag, .{ .answer_names_an_unknown_decision = .{
                        .request_id = request_id,
                        .name = try gpa.dupe(u8, name),
                    } });
                }
                break :unknown .unknown_decision;
            },
        };
    }
    return null;
}

/// Redact one tool result and then append it. See
/// `lib/chock-broker/secrets.zig`'s own top comment on why the order is the
/// whole point.
///
/// This is here rather than only on `secrets.zig` so that the caller holds a
/// `*const Broker` and never a `secrets.Store`. See the `secrets` field.
///
/// **This is not the seam a live session's tool results go through, and it
/// must not be read as one.** `chock-core` imports no `chock-broker`, so the
/// loop could never reach this function. The loop's own seam is
/// `chock_core.Loop.appendAndApply`, which redacts every record it writes out
/// of `chock_core.redact.Policy`. What this covers is a broker that holds a
/// `secrets.Store`, and **nothing fills that store today**: a handle of the
/// shape `{{secret:name}}` has no producer in `src/`. This function is
/// therefore built and not on any road a session takes. It is kept because
/// redaction needs it the day the store is filled, and it is labelled so that
/// nobody reads it as cover that is already there.
pub fn appendToolResult(
    self: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    result: event.ToolResult,
    time_ms: i64,
) secrets_mod.AppendError!u64 {
    // **Both sets, because a broker that held one and wrote the other would be
    // the same fault twice.** `secrets` is scanned for by the call below and
    // `redaction` by this line, so a value in either one is gone whichever list
    // it came from and a caller has no third rule to learn.
    const clean = try self.scrubText(gpa, result.output);
    defer if (clean) |output| gpa.free(output);

    var scanned = result;
    if (clean) |output| scanned.output = output;
    return secrets_mod.appendToolResult(self.secrets, gpa, io, locked, scanned, time_ms);
}

/// Replace every `{{secret:name}}` in a child's environment with its value.
/// Call this where the sandbox launcher builds the environment and nowhere
/// else. Release the result with `secrets.freeEnv`.
pub fn resolveEnv(
    self: *const Broker,
    gpa: std.mem.Allocator,
    entries: []const []const u8,
    diag: ?*?Diagnostic,
) secrets_mod.ResolveError![][]u8 {
    return secrets_mod.resolveEnv(self.secrets, gpa, entries, diag);
}

/// A `Redactor` over everything this broker was told to keep out of the log,
/// for a tool result that arrives in pieces. Both `secrets` and `redaction`,
/// for the reason `appendToolResult` gives.
///
/// See `secrets.Redactor`, and see `appendToolResult` above on why the
/// `secrets` half is empty in every session today.
pub fn redactor(self: *const Broker, gpa: std.mem.Allocator) std.mem.Allocator.Error!secrets_mod.Redactor {
    const values = try gpa.alloc([]const u8, self.secrets.entries.len + self.redaction.len);
    defer gpa.free(values);
    for (self.secrets.entries, values[0..self.secrets.entries.len]) |entry, *slot| slot.* = entry.value;
    @memcpy(values[self.secrets.entries.len..], self.redaction);
    return secrets_mod.Redactor.initValues(gpa, values);
}

/// True when `said` names something, and what it names is not `expected`.
/// Empty is not a disagreement: `event.ApprovalResponse.action` and
/// `tool_call_id` both default to empty for a writer that does not know
/// them, so empty means "did not say" and never "not applicable".
fn disagrees(said: []const u8, expected: []const u8) bool {
    return said.len > 0 and !std.mem.eql(u8, said, expected);
}

const testing = std.testing;

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public, so the helpers below can hold a pointer
/// to a lock the test took. `request` itself still takes `locked: anytype`,
/// the way `lib/chock-core/Loop.zig` does.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// What a `TestWaiter` runs each time the broker gives control back. This
/// stands in for the client that answers, and for the second agent that asks
/// while the first one waits. `waits` counts from one.
const OnWait = *const fn (ctx: ?*anyopaque, io: std.Io, waits: usize) anyerror!void;

/// A `Waiter` a test drives. It never sleeps. `wait` runs `on_wait`, then
/// moves its own clock forward by the whole budget, so a test of the deadline
/// finishes at once instead of in real time.
const TestWaiter = struct {
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    /// True to hold the clock still, for a test that wants an unbounded
    /// number of looks rather than an expiry.
    frozen: bool = false,
    ctx: ?*anyopaque = null,
    on_wait: ?OnWait = null,
    /// The first error `on_wait` returned. The test checks it, because a
    /// `Waiter` cannot report one to the broker.
    failed: ?anyerror = null,
    /// The wait number at which this waiter reports a cancellation. Null for
    /// a waiter that is never cancelled, which is every test but one.
    cancel_at_wait: ?usize = null,

    fn waiter(self: *TestWaiter) Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Waiter.Wake {
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.on_wait) |answer| {
            answer(self.ctx, io, self.waits) catch |err| {
                if (self.failed == null) self.failed = err;
            };
        }
        if (!self.frozen) self.now_ms += @intCast(budget_ms);
        if (self.cancel_at_wait) |at| {
            if (self.waits >= at) return .canceled;
        }
        return .slept;
    }
};

/// A request with the parts these tests do not vary held still.
fn testRequest(action: []const u8) Request {
    return .{
        .action = action,
        .summary = "push the branch to origin",
        .detail = "a1b2c3 fix the parser\n",
        .reason = "the task asked for the change to be published",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "git",
        .tool_call_id = "call1",
    };
}

/// A broker over one policy source. The caller destroys the table with
/// `table.Table.destroy`.
fn testBroker(gpa: std.mem.Allocator, source: [:0]const u8, waiter: *TestWaiter) !Broker {
    return .{ .policy = try table.Table.parse(gpa, source, null), .waiter = waiter.waiter() };
}

/// The id of the first `approval.request` in the log that names `action`, or
/// null when there is none. This is the read a client that reconnects would
/// do to find the questions it must show.
fn findRequestId(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    action: []const u8,
) !?u64 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) continue;
        if (!std.mem.eql(u8, parsed.value.event.approval_request.action, action)) continue;
        return parsed.value.id;
    }
    return null;
}

/// One `approval.response` read back out of the log, with every text field
/// copied, so the caller can read it after the replay ends. `freeAnswer`
/// releases it.
const LoggedAnswer = struct {
    id: u64,
    request_id: u64,
    decision_name: []const u8,
    responder: []const u8,
    action: []const u8,
    tool_call_id: []const u8,
    /// What the record says a reviewer decided. `none` for every answer no
    /// reviewer took part in.
    review_name: []const u8,
    /// The reviewer's own words, which live in the log and reach the agent
    /// that asked through nothing at all. See `lib/chock-broker/review.zig`.
    review_note: []const u8,
};

/// Count of one kind of event in the log.
fn countKind(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    kind: event.Kind,
) !usize {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var count: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (std.meta.activeTag(parsed.value.event) == kind) count += 1;
    }
    return count;
}

/// The wire name of the decision in the one `approval.response` that names
/// `request_id`, plus the responder, the action and the call id, all copied
/// into `gpa`. An error when there is not exactly one such answer, since
/// "exactly one" is itself a fact these tests pin.
fn theAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    request_id: u64,
) !LoggedAnswer {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();

    var found: ?LoggedAnswer = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_response) continue;
        const answer = parsed.value.event.approval_response;
        if (answer.request_id != request_id) continue;
        if (found != null) return error.MoreThanOneAnswer;
        found = .{
            .id = parsed.value.id,
            .request_id = answer.request_id,
            .decision_name = try gpa.dupe(u8, answer.decision.wireName()),
            .responder = try gpa.dupe(u8, answer.responder),
            .action = try gpa.dupe(u8, answer.action),
            .tool_call_id = try gpa.dupe(u8, answer.tool_call_id),
            .review_name = try gpa.dupe(u8, answer.review.wireName()),
            .review_note = try gpa.dupe(u8, answer.review_note),
        };
    }
    return found orelse error.NoAnswer;
}

fn freeAnswer(gpa: std.mem.Allocator, answer: LoggedAnswer) void {
    gpa.free(answer.decision_name);
    gpa.free(answer.responder);
    gpa.free(answer.action);
    gpa.free(answer.tool_call_id);
    gpa.free(answer.review_name);
    gpa.free(answer.review_note);
}

/// Write an answer the way a client with the `approve` scope would. It fills
/// in neither `action` nor `tool_call_id`, on purpose: those two fields
/// carry a default, and a writer that does not know about them must still be
/// able to answer.
fn answerAsUser(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *LockedHandle,
    request_id: u64,
    decision: event.ApprovalDecision,
    responder: []const u8,
) !u64 {
    return locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = decision,
        .responder = responder,
    } }, 1_700_000_000_000);
}

/// Write an answer that says what it is about, the way a client that knows
/// the two later fields would. `answerAsUser` above leaves both empty.
fn answerAbout(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *LockedHandle,
    request_id: u64,
    decision: event.ApprovalDecision,
    action: []const u8,
    tool_call_id: []const u8,
) !u64 {
    return locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = decision,
        .responder = "ross",
        .action = action,
        .tool_call_id = tool_call_id,
    } }, 1_700_000_000_000);
}

/// The width `stalePoison` pads its responder to. Larger than the decimal
/// digits of any offset these tests reach, and larger than one digit, so the
/// padding is never negative.
const poison_width: usize = 24;

/// Append an `approval.response` that says yes to `request_id`, and make the
/// line the same number of bytes whatever `request_id` holds.
///
/// An event id is a byte offset, so a test that wants a response to name a
/// request that does not exist yet has to know that offset before it writes
/// the response, and writing the response is what moves it. The padding
/// breaks that circle: the responder loses one character for every digit the
/// id gains, so the line length never changes and the offsets after it never
/// move. A test can then measure the offset with one id and write the same
/// line again with the measured one.
fn stalePoison(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: *LockedHandle,
    request_id: u64,
) !void {
    var digits: [20]u8 = undefined;
    const printed = try std.fmt.bufPrint(&digits, "{d}", .{request_id});
    const padding: [poison_width]u8 = @splat('p');
    _ = try locked.append(gpa, io, .{ .approval_response = .{
        .request_id = request_id,
        .decision = .approved_by_user,
        .responder = padding[0 .. poison_width - printed.len],
    } }, 1_700_000_000_000);
}

/// A `Reviewer` a test drives. It starts no process and asks no model: the
/// seam is what those live behind. It counts its calls, because **a test that
/// only reads the outcome cannot tell a review that refused from a review that
/// never ran**, and several facts below are exactly about which of those
/// happened.
const TestReviewer = struct {
    kind: []const u8 = "arbiter",
    /// What this reviewer answers. Null to fail instead, which is what a
    /// budget with nothing left, a child that died, and a timed out review all
    /// reach the broker as.
    says: ?review_mod.Verdict = .approved,
    note: []const u8 = "the change is the one the task asked for",
    calls: usize = 0,
    /// What the last call was told, taken apart rather than kept whole.
    ///
    /// **A `Case` is borrowed for the length of the call**, and `Case.chain`
    /// in particular is an array `request` builds and frees, so a test that
    /// held the whole case would be reading freed memory a moment later. Each
    /// name in the chain still belongs to the `Request`, so those are safe to
    /// keep; the array around them is not.
    saw_action: []const u8 = "",
    saw_detail: []const u8 = "",
    saw_decision: ?chock_policy.table.Decision = null,
    saw_chain_len: usize = 0,
    saw_first_kind: []const u8 = "",
    /// A value the case must not carry, and whether it did. **Both are read
    /// inside the call**, for the lifetime reason above, and the answer is a
    /// boolean so that no failure message can print the value.
    never: []const u8 = "",
    saw_never: bool = false,

    fn reviewer(self: *TestReviewer) review_mod.Reviewer {
        return .{ .ptr = self, .vtable = &vtable, .kind = self.kind };
    }

    const vtable = review_mod.Reviewer.VTable{ .review = reviewFn };

    fn reviewFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        case: review_mod.Case,
    ) review_mod.ReviewError!review_mod.Report {
        _ = io;
        const self: *TestReviewer = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.saw_action = case.action;
        self.saw_detail = case.detail;
        self.saw_decision = case.decision;
        self.saw_chain_len = case.chain.len;
        self.saw_first_kind = if (case.chain.len == 0) "" else case.chain[0];
        if (self.never.len > 0 and std.mem.indexOf(u8, case.detail, self.never) != null) {
            self.saw_never = true;
        }
        const verdict = self.says orelse return error.ReviewNotRun;
        return .{ .verdict = verdict, .note = try gpa.dupe(u8, self.note) };
    }
};

/// One `approval.request` read back out of the log, with the two fields a
/// review fills in copied so the caller can read them after the replay ends.
const LoggedQuestion = struct {
    id: u64,
    review_name: []const u8,
    review_note: []const u8,

    fn free(self: LoggedQuestion, gpa: std.mem.Allocator) void {
        gpa.free(self.review_name);
        gpa.free(self.review_note);
    }
};

fn theQuestion(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    action: []const u8,
) !LoggedQuestion {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) continue;
        const question = parsed.value.event.approval_request;
        if (!std.mem.eql(u8, question.action, action)) continue;
        return .{
            .id = parsed.value.id,
            .review_name = try gpa.dupe(u8, question.review.wireName()),
            .review_note = try gpa.dupe(u8, question.review_note),
        };
    }
    return error.NoQuestion;
}

/// The one `approval.response` in the log, with every text field copied. Used
/// by the review tests, where the policy settles the request and no
/// `approval.request` envelope is written, so the answer names request zero.
fn theOnlyAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
) !LoggedAnswer {
    return theAnswer(gpa, io, storage, 0);
}

const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "git.push", .decision = .ask },
    \\        },
    \\    },
    \\}
;

test "a request appears in the log before the broker waits for an answer" {
    // A crash between asking and answering must be recoverable. The check
    // below runs inside the first `wait` call, which is the earliest moment
    // the broker gives control away, so a crash right there would still
    // leave the question on disk for whoever reconnects.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        saw_request_at: ?u64 = null,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            // The question must already be here, before this call answers it.
            self.saw_request_at = try findRequestId(self.gpa, io_inner, self.store, "git.push");
            const id = self.saw_request_at orelse return;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
        }
    };

    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (waiter.failed) |err| return err;

    // The request was already in the log the first time the broker gave
    // control away. Without this, the broker could have written the question
    // after the answer arrived, and a crash would lose it.
    try testing.expect(answerer.saw_request_at != null);
    try testing.expectEqual(Outcome.approved_by_user, outcome);
    try testing.expect(outcome.permits());

    // The answer names that exact question, and it is the only answer to it.
    const answer = try theAnswer(gpa, io, store, answerer.saw_request_at.?);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_by_user", answer.decision_name);
    try testing.expectEqualStrings("ross", answer.responder);
    // The question comes before its answer in the log, always.
    try testing.expect(answerer.saw_request_at.? < answer.id);
}

test "a policy of allow never appends a request, and the log says the policy allowed it" {
    // The user is not asked. The record still says why it happened, because a
    // signature over that record comes later and a decision with no record
    // cannot become a signed one.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const allow_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const broker = try testBroker(gpa, allow_the_push, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.allowed_by_policy, outcome);
    try testing.expect(outcome.permits());

    // Nobody was asked: no question was written, and the broker never gave
    // control away to wait for one.
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), waiter.waits);

    // The record is there, it says the policy decided, and it names what it
    // decided about.
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_response));
    const answer = try theAnswer(gpa, io, store, 0);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("allowed_by_policy", answer.decision_name);
    try testing.expectEqualStrings("git.push", answer.action);
    try testing.expectEqualStrings("call1", answer.tool_call_id);
    // Nobody acted, so there is nobody to name.
    try testing.expectEqualStrings("", answer.responder);

    // `request_id` is zero, because there is no request envelope to name.
    // Zero cannot be read as a real event id: byte zero of every log is
    // inside the header line, so no appended event ever sits there. This
    // proves it over the log this test just wrote.
    try testing.expectEqual(@as(u64, 0), answer.request_id);
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var events: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        events += 1;
        try testing.expect(parsed.value.id > 0);
    }
    try testing.expectEqual(@as(usize, 1), events);
}

test "a policy of deny never appends a request either" {
    // The same shape as `allow`, and the opposite answer. A denial the table
    // made on its own is written down too, for the same reason.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const deny_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const broker = try testBroker(gpa, deny_the_push, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.denied_by_policy, outcome);
    try testing.expect(!outcome.permits());

    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_response));

    const answer = try theAnswer(gpa, io, store, 0);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("denied_by_policy", answer.decision_name);
    try testing.expectEqualStrings("git.push", answer.action);
    try testing.expectEqualStrings("call1", answer.tool_call_id);
    try testing.expectEqualStrings("", answer.responder);
    try testing.expectEqual(@as(u64, 0), answer.request_id);
}

test "a request that expires is a refusal, and says expired rather than refused" {
    // Four outcomes, not two: allowed by policy, approved by the user, refused
    // by the user, expired. approval.response is an enum for this reason. An
    // expired request refuses the action, and the log still says nobody was
    // there, which is a different fact from somebody saying no.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    // Nothing ever answers. The clock moves forward by the whole wait budget
    // each time, so this reaches the deadline at once and sleeps for no real
    // time at all.
    var waiter = TestWaiter{};
    const started_at_ms = waiter.now_ms;

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 500;

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    try testing.expectEqual(Outcome.expired, outcome);
    try testing.expect(!outcome.permits());
    // Expired is its own outcome. It is not the outcome a user's no gives.
    try testing.expect(outcome != .refused_by_user);
    // It really waited: 500 ms of deadline at a 50 ms poll interval.
    try testing.expectEqual(@as(usize, 10), waiter.waits);

    // The question was written, and it names the time it would expire at.
    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    var replay = try store.replay(gpa, io, request_id);
    defer replay.deinit();
    const question = (try replay.next(io)).?;
    defer question.deinit();
    try testing.expectEqual(
        started_at_ms + ask.timeout_ms,
        question.value.event.approval_request.timeout_at_ms,
    );

    // One answer, and it says expired. A boolean could not tell this apart
    // from a refusal, which is why the field is not one.
    const answer = try theAnswer(gpa, io, store, request_id);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("expired", answer.decision_name);
    try testing.expect(!std.mem.eql(u8, "refused_by_user", answer.decision_name));
    // Nobody acted, so there is nobody to name.
    try testing.expectEqualStrings("", answer.responder);
}

test "an answer to a different request does not answer this one" {
    // Two requests can be open at once. An answer names its request.
    //
    // The first request is open when the second one starts, because the
    // second one is asked from inside the first one's own wait, which is
    // exactly what a subagent asking while its parent waits looks like. The
    // second is answered `approved_by_user` and lands in the log before the
    // first one's answer. A broker that took the first `approval.response`
    // it found would hand that yes to the first request. The first request
    // is answered `refused_by_user`, so the two answers cannot be confused.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const Nested = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        broker: *const Broker,
        inner_outcome: ?Outcome = null,
        outer_id: ?u64 = null,
        inner_id: ?u64 = null,
        /// The number of looks the outer request took after the inner one
        /// was answered and before the outer one was.
        looks_while_only_the_other_was_answered: usize = 0,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            switch (waits) {
                // The outer request is open and unanswered. Ask a second one
                // and answer only that one.
                1 => {
                    self.outer_id = try findRequestId(self.gpa, io_inner, self.store, "git.push");
                    var inner = testRequest("git.commit");
                    inner.tool_call_id = "call2";
                    // The inner request's own wait answers the inner request.
                    // It runs on the same waiter, so `waits` keeps counting.
                    self.inner_outcome = try self.broker.request(
                        self.gpa,
                        io_inner,
                        self.store,
                        self.locked,
                        inner,
                        null,
                    );
                },
                // Reached only from the inner request's own wait: answer the
                // inner request, and nothing else.
                2 => {
                    self.inner_id = try findRequestId(self.gpa, io_inner, self.store, "git.commit");
                    _ = try answerAsUser(
                        self.gpa,
                        io_inner,
                        self.locked,
                        self.inner_id.?,
                        .approved_by_user,
                        "ross",
                    );
                },
                // Back in the outer request. The inner answer is in the log
                // and it is not this request's answer, so the outer request
                // must still be waiting. Look once more, then answer it.
                3 => self.looks_while_only_the_other_was_answered += 1,
                else => _ = try answerAsUser(
                    self.gpa,
                    io_inner,
                    self.locked,
                    self.outer_id.?,
                    .refused_by_user,
                    "ross",
                ),
            }
        }
    };

    var nested = Nested{ .gpa = gpa, .store = store, .locked = &locked, .broker = &broker };
    waiter.ctx = &nested;
    waiter.on_wait = Nested.onWait;

    const outer = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (waiter.failed) |err| return err;

    // Two questions were open at the same time, and the first one was asked
    // first.
    try testing.expect(nested.outer_id != null);
    try testing.expect(nested.inner_id != null);
    try testing.expect(nested.outer_id.? < nested.inner_id.?);

    // The outer request kept waiting while only the inner one was answered.
    try testing.expect(nested.looks_while_only_the_other_was_answered > 0);

    // Each request got its own answer, and the two are different.
    try testing.expectEqual(Outcome.approved_by_user, nested.inner_outcome.?);
    try testing.expectEqual(Outcome.refused_by_user, outer);
    try testing.expect(nested.inner_outcome.?.permits());
    try testing.expect(!outer.permits());

    // The same fact read back out of the log, one answer for each question.
    const inner_answer = try theAnswer(gpa, io, store, nested.inner_id.?);
    defer freeAnswer(gpa, inner_answer);
    try testing.expectEqualStrings("approved_by_user", inner_answer.decision_name);

    const outer_answer = try theAnswer(gpa, io, store, nested.outer_id.?);
    defer freeAnswer(gpa, outer_answer);
    try testing.expectEqualStrings("refused_by_user", outer_answer.decision_name);

    // The yes to the inner request was written before the no to the outer
    // one. That ordering is what makes this test able to catch a broker that
    // takes the first answer it finds.
    try testing.expect(inner_answer.id < outer_answer.id);
}

test "the spawn chain reaches the request, with a reason at every level" {
    // "A subagent three levels down wants to push" is what the user most needs
    // before answering. The chain reaches two places, and this pins both: the
    // `approval.request` a client reads, and the policy key the table answers,
    // where a child is no stronger than its parent.
    const gpa = testing.allocator;
    const io = testing.io;

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "the user asked for the bug to be fixed" },
        .{ .agent_kind = "reviewer", .reason = "read the change before it is published" },
    };

    // First: the kinds above the asking agent all ask, so the request is
    // written, and it must carry the whole chain.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const Answerer = struct {
            gpa: std.mem.Allocator,
            store: chock_proto.storage.Storage,
            locked: *LockedHandle,

            fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                if (waits != 1) return;
                const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
                _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
            }
        };
        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.agent_kind = "fixer";
        ask.spawn_chain = &chain;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);

        const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
        var replay = try store.replay(gpa, io, request_id);
        defer replay.deinit();
        const question = (try replay.next(io)).?;
        defer question.deinit();
        const logged = question.value.event.approval_request;

        // Every level, in order, with the reason each one gave.
        try testing.expectEqual(@as(usize, 2), logged.spawn_chain.len);
        try testing.expectEqualStrings("main", logged.spawn_chain[0].agent_kind);
        try testing.expectEqualStrings(
            "the user asked for the bug to be fixed",
            logged.spawn_chain[0].reason,
        );
        try testing.expectEqualStrings("reviewer", logged.spawn_chain[1].agent_kind);
        try testing.expectEqualStrings(
            "read the change before it is published",
            logged.spawn_chain[1].reason,
        );
        // The agent that asked is named by the request itself, and it is not
        // a link, because it is nobody's parent.
        try testing.expectEqualStrings("fixer", logged.agent_kind);
    }

    // Second: the same chain against a policy where the root of the chain
    // denies the action and the asking kind allows it. The answer is `deny`,
    // so the root really reached the table. Without the chain, the asking
    // kind's own `allow` would have won and the push would have happened.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const the_root_denies: [:0]const u8 =
            \\.{
            \\    .policy = .{
            \\        .rules = .{
            \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
            \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
            \\            .{ .agent_kind = "fixer", .action = "git.push", .decision = .allow },
            \\        },
            \\    },
            \\}
        ;
        const broker = try testBroker(gpa, the_root_denies, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.agent_kind = "fixer";
        ask.spawn_chain = &chain;

        try testing.expectEqual(
            Outcome.denied_by_policy,
            try broker.request(gpa, io, store, &locked, ask, null),
        );

        // The asking kind alone would have allowed it. This is what makes
        // the line above a fact about the chain and not about the rules.
        var alone = testRequest("git.push");
        alone.agent_kind = "fixer";
        try testing.expectEqual(
            Outcome.allowed_by_policy,
            try broker.request(gpa, io, store, &locked, alone, null),
        );
    }
}

test "a decision this broker does not know is not permission" {
    // `event.ApprovalDecision` keeps a name it does not recognize instead of
    // failing the whole line, which is what keeps an old reader able to read
    // a new log. That rule is about reading. It is not a licence to act: a
    // decision this build cannot read is a decision it cannot carry out, and
    // the safe reading of an unreadable answer is that the action does not
    // happen.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            // Stands in for a client newer than this broker.
            _ = try answerAsUser(
                self.gpa,
                io_inner,
                self.locked,
                id,
                .{ .unknown = "approved_with_edits" },
                "ross",
            );
        }
    };
    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    if (waiter.failed) |err| return err;

    try testing.expectEqual(Outcome.unknown_decision, outcome);
    try testing.expect(!outcome.permits());

    // The answer is still in the log, with the spelling the newer client
    // used, so a build that does know the name reads it correctly.
    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    const answer = try theAnswer(gpa, io, store, request_id);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_with_edits", answer.decision_name);
}

test "a wait that reports a cancellation stops the request and leaves the question open" {
    // `Waiter.wait` returned void before this, so a `SystemWaiter` whose
    // sleep was cancelled swallowed the cancellation and looked again at
    // once. The result was a busy loop that ran until the deadline, which
    // can be an hour, while `Loop.run` held the session lock the whole time.
    // A cancellation now ends the wait on the first one.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{ .cancel_at_wait = 1 };
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    try testing.expectError(
        error.Canceled,
        broker.request(gpa, io, store, &locked, testRequest("git.push"), null),
    );

    // Exactly one wait. The default deadline is five minutes at a 50 ms poll
    // interval, so a broker that swallowed the cancellation would have waited
    // six thousand times instead.
    try testing.expectEqual(@as(usize, 1), waiter.waits);

    // The question is still in the log and it has no answer, which is the
    // same state a crash leaves. A client that reconnects can read it and
    // still answer it.
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_response));
}

test "a timeout longer than the broker's bound expires at the bound" {
    // `timeout_ms` had no upper bound before this. An open request holds the
    // session lock, so a caller that asked for a year stopped the session for
    // a year. The request now expires at `max_timeout_ms`, and the
    // `approval.request` a client reads says the reduced time, so the user is
    // never shown a deadline the broker will not keep.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const started_at_ms = waiter.now_ms;

    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = max_timeout_ms * 3;

    try testing.expectEqual(
        Outcome.expired,
        try broker.request(gpa, io, store, &locked, ask, null),
    );

    // The deadline in the log is the bound, not what the caller asked for.
    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    var replay = try store.replay(gpa, io, request_id);
    defer replay.deinit();
    const question = (try replay.next(io)).?;
    defer question.deinit();
    try testing.expectEqual(
        started_at_ms + max_timeout_ms,
        question.value.event.approval_request.timeout_at_ms,
    );

    // And it really stopped there: one look per poll interval over the bound,
    // and not one over what the caller asked for.
    try testing.expectEqual(
        @as(usize, @intCast(max_timeout_ms)) / poll_interval_ms,
        waiter.waits,
    );
}

test "a timeout of zero expires on the first look and never waits at all" {
    // The other end of the same clamp. "Do not wait" is a legitimate thing to
    // ask for, and it must still write the question and still leave the
    // record of the expiry, so a client that reads the log later sees that
    // the action was asked for and was not done.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 0;

    try testing.expectEqual(
        Outcome.expired,
        try broker.request(gpa, io, store, &locked, ask, null),
    );
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));

    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    const answer = try theAnswer(gpa, io, store, request_id);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("expired", answer.decision_name);
}

test "an answer that names this request and a different action is not permission" {
    // `event.ApprovalResponse` repeats the action and the tool call id so
    // that one line says what was decided and what it was decided about.
    // Nothing compared the two before this. An answer that says yes to
    // request 400 and also says it is about `git.commit`, when request 400 is
    // a `git.push`, states two facts that cannot both be true, and the broker
    // must not pick the one that grants.
    const gpa = testing.allocator;
    const io = testing.io;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        says_action: []const u8,
        says_call: []const u8,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAbout(
                self.gpa,
                io_inner,
                self.locked,
                id,
                .approved_by_user,
                self.says_action,
                self.says_call,
            );
        }
    };

    // A yes that names some other action. The two statements disagree.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .says_action = "git.commit",
            .says_call = "call1",
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.mismatched_answer, outcome);
        try testing.expect(!outcome.permits());
    }

    // A yes that names some other tool call, with the right action. One
    // disagreement is enough.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .says_action = "git.push",
            .says_call = "call9",
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.mismatched_answer, outcome);
    }

    // The same answer, agreeing with the request on both, is permission. This
    // is what makes the two blocks above a fact about disagreement and not
    // about the fields being filled in at all.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .says_action = "git.push",
            .says_call = "call1",
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
        try testing.expect(outcome.permits());
    }
}

test "an answer written before its own request does not answer it" {
    // `findAnswer` replays from the request's own id, never from zero,
    // because no answer can come before its own question. Nothing tested
    // that: moving the offset to zero left every other test in this file
    // passing. An id is a byte offset, so a log that was rewritten, or a
    // record copied in from another session, can hold a response that carries
    // the number a later request happens to get.
    //
    // Two passes. The first measures the offset the request lands at. The
    // second writes a yes that names exactly that offset, before the request
    // exists, and `stalePoison` keeps both passes the same length so the
    // offset does not move between them. The request must still expire.
    const gpa = testing.allocator;
    const io = testing.io;

    const measured: u64 = measure: {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        try stalePoison(gpa, io, &locked, 0);

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.timeout_ms = 100;
        _ = try broker.request(gpa, io, store, &locked, ask, null);
        break :measure (try findRequestId(gpa, io, store, "git.push")).?;
    };

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    try stalePoison(gpa, io, &locked, measured);

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 100;
    const outcome = try broker.request(gpa, io, store, &locked, ask, null);

    // The padding worked: the request landed where the poison says it did, so
    // the poison really does name this request and only its position keeps it
    // out.
    const request_id = (try findRequestId(gpa, io, store, "git.push")).?;
    try testing.expectEqual(measured, request_id);

    // And it was not read as the answer. A replay that started at zero would
    // have found the yes and returned `approved_by_user` here.
    try testing.expectEqual(Outcome.expired, outcome);
    try testing.expect(!outcome.permits());
}

test "a caller holding only a broker can redact and can resolve, and never holds a credential" {
    // The broker reads the store and nothing else does. This drives both
    // credential paths through a `*const Broker` alone, which is the only
    // thing a caller of this file holds. Nothing below names `secrets.Store`,
    // and that is the fact: a caller that had to name one would be a caller
    // holding credentials, and it would have to change when the broker moves
    // into its own process.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = Broker{
        .policy = try table.Table.parse(gpa, ask_every_action, null),
        .waiter = waiter.waiter(),
        .secrets = .{ .entries = &.{.{ .name = "aiand", .value = "sk-live-9f2c4a7b1d3e" }} },
    };
    defer table.Table.destroy(gpa, broker.policy);

    // The child's environment gets the value.
    const child_env = try broker.resolveEnv(gpa, &.{"AIAND_TOKEN={{secret:aiand}}"}, null);
    defer secrets_mod.freeEnv(gpa, child_env);
    try testing.expectEqualStrings("AIAND_TOKEN=sk-live-9f2c4a7b1d3e", child_env[0]);

    // The log gets the marker, and never the value, on the whole of a
    // result and on one that arrived in pieces.
    _ = try broker.appendToolResult(gpa, io, &locked, .{
        .call_id = "call1",
        .output = "AIAND_TOKEN=sk-live-9f2c4a7b1d3e\n",
        .is_error = false,
        .truncated = false,
    }, waiter.now_ms);

    var pieces = try broker.redactor(gpa);
    defer pieces.deinit(gpa);
    try pieces.push(gpa, "half is sk-live-9f2c");
    try pieces.push(gpa, "4a7b1d3e and that was all");
    const streamed = try pieces.finish(gpa);
    defer gpa.free(streamed);
    try testing.expectEqualStrings("half is [redacted] and that was all", streamed);

    _ = try broker.appendToolResult(gpa, io, &locked, .{
        .call_id = "call2",
        .output = streamed,
        .is_error = false,
        .truncated = false,
    }, waiter.now_ms);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "sk-live-9f2c4a7b1d3e") == null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "[redacted]") != null);
}

/// A policy where the agent that asks holds `agent_review` for the push and
/// the kind above it denies it outright. **The chain is what decides**, and a
/// broker that read the asking kind alone would consult a reviewer here.
const the_parent_denies_and_the_child_would_review: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
    \\            .{ .agent_kind = "coder", .action = "git.push", .decision = .agent_review },
    \\        },
    \\    },
    \\}
;

const review_the_push: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "git.push", .decision = .agent_review },
    \\        },
    \\    },
    \\}
;

const review_then_ask_about_the_push: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "git.push", .decision = .agent_then_human },
    \\        },
    \\    },
    \\}
;

test "a reviewer cannot approve what its requester was denied" {
    // The property a review is worth nothing without. A review that can widen
    // scope is not a review, it is a privilege escalation with one model call
    // in front of it.
    //
    // `evaluateChain` alone does not give this. It bounds what a reviewer may
    // do with its own tool calls, and a verdict is not a tool call: the act is
    // performed by the broker on the requester's behalf. What gives it is that
    // the decision the review is gated on is the one folded over the
    // requester's own chain, so a `deny` never reaches a reviewer at all.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    // A reviewer that says yes to everything. If it is ever asked, it approves.
    var arbiter = TestReviewer{ .says = .approved };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, the_parent_denies_and_the_child_would_review, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "the user asked for the fix" }};

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);

    // Denied by the policy, and not by the reviewer, because the reviewer was
    // never consulted at all. The call count is the load bearing half: an
    // outcome of `denied_by_policy` alone would also be reached by a broker
    // that paid for a review and then threw the answer away.
    try testing.expectEqual(Outcome.denied_by_policy, outcome);
    try testing.expect(!outcome.permits());
    try testing.expectEqual(@as(usize, 0), arbiter.calls);

    // And the asking kind on its own really does hold `agent_review`, so the
    // line above is a fact about the chain and not about the rules. Without
    // this, a policy that simply denied everything would pass the test.
    try testing.expectEqual(
        chock_policy.table.Decision.agent_review,
        broker.policy.evaluateKindAlone(.{
            .agent_kind = "coder",
            .model = "main",
            .tool = "git",
            .action = "git.push",
        }),
    );

    // The same request with no parent above it does reach the reviewer and is
    // approved. That is what makes the block above a fact about the parent's
    // `deny` rather than about this reviewer never being called by anything.
    const alone = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.approved_by_review, alone);
    try testing.expectEqual(@as(usize, 1), arbiter.calls);
}

test "a reviewer cannot review its own request, and pays nothing to find out" {
    // A self review is not a review. The check reads the whole chain and not
    // only the agent that asked, so a reviewer that itself asks for something
    // reviewable cannot be handed its own question one level down.
    const gpa = testing.allocator;
    const io = testing.io;

    const cases = [_]struct { asker: []const u8, parent: []const u8 }{
        // The agent that asked is the reviewer kind.
        .{ .asker = "arbiter", .parent = "main" },
        // One level down: an arbiter started a worker and the worker asks, so
        // the review would be the arbiter deciding about its own subtree.
        .{ .asker = "worker", .parent = "arbiter" },
    };

    for (cases) |one| {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .kind = "arbiter", .says = .approved };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.agent_kind = one.asker;
        ask.spawn_chain = &.{.{ .agent_kind = one.parent, .reason = "started it" }};

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.review_unavailable, outcome);
        try testing.expect(!outcome.permits());
        // Nothing was spent. The check runs before the reviewer is called, so
        // a self review costs no model call at all.
        try testing.expectEqual(@as(usize, 0), arbiter.calls);

        // The record says a review was asked for and none happened, which is
        // not the same fact as a reviewer saying no.
        const answer = try theOnlyAnswer(gpa, io, store);
        defer freeAnswer(gpa, answer);
        try testing.expectEqualStrings("review_unavailable", answer.decision_name);
        try testing.expectEqualStrings("none", answer.review_name);
    }

    // The same policy, the same reviewer, and a chain it is not in. Approved.
    // Without this the block above would pass against a broker that refused
    // every review.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .kind = "arbiter", .says = .approved };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "started it" }};
        try testing.expectEqual(
            Outcome.approved_by_review,
            try broker.request(gpa, io, store, &locked, ask, null),
        );
        try testing.expectEqual(@as(usize, 1), arbiter.calls);
    }
}

test "a review that could not run refuses, and never allows" {
    // The cheapest attack on a review is to make it fail, so failing must be
    // the refusing direction. Three ways a review does not happen, and one
    // outcome for all three.
    const gpa = testing.allocator;
    const io = testing.io;

    // A session that can start no reviewer at all, which is every caller
    // without the session directories and the credential a child needs.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, review_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);
        try testing.expect(broker.reviewer == null);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.review_unavailable, outcome);
        try testing.expect(!outcome.permits());
        // Nobody was asked and no question was written: a review is not a
        // question a person can answer.
        try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
        try testing.expectEqual(@as(usize, 0), waiter.waits);
    }

    // A reviewer that could not be paid for, could not be started, or ran out
    // of time. Every one of them reaches the broker as `ReviewNotRun`.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .says = null };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.review_unavailable, outcome);
        try testing.expect(!outcome.permits());
        // It really was asked, so this is a review that ran and failed rather
        // than one that was never started.
        try testing.expectEqual(@as(usize, 1), arbiter.calls);
    }

    // A reviewer that answered nothing at all. `none` is not an approval.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .says = .none };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.refused_by_review, outcome);
        try testing.expect(!outcome.permits());
    }
}

test "a reviewer that says yes permits, and the record says who and why" {
    // The other half of every refusal above. A review that decides is written
    // down with the verdict and the reviewer's own words, because the person
    // who reads the record the next morning is who the record is for, and an
    // unread record is the same as no oversight while looking like some.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{
        .kind = "arbiter",
        .says = .approved,
        .note = "the push carries only the parser fix the task named",
    };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.approved_by_review, outcome);
    try testing.expect(outcome.permits());

    // Nobody was asked and nothing waited: that is the whole point of a
    // reviewer, and a broker that also opened a question would stop a session
    // nobody is watching.
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
    try testing.expectEqual(@as(usize, 0), waiter.waits);

    const answer = try theOnlyAnswer(gpa, io, store);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("approved_by_review", answer.decision_name);
    // Who decided. A signature over this record comes later, and a record
    // that does not name the decider cannot become a signed one.
    try testing.expectEqualStrings("arbiter", answer.responder);
    try testing.expectEqualStrings("approved", answer.review_name);
    try testing.expectEqualStrings("the push carries only the parser fix the task named", answer.review_note);
    try testing.expectEqualStrings("git.push", answer.action);

    // The reviewer read the case the broker already built: the same action,
    // the same effect, and the same chain the policy was evaluated over. It
    // names nothing of its own, which is why it cannot widen anything.
    try testing.expectEqualStrings("git.push", arbiter.saw_action);
    try testing.expectEqualStrings("a1b2c3 fix the parser\n", arbiter.saw_detail);
    try testing.expectEqual(chock_policy.table.Decision.agent_review, arbiter.saw_decision.?);
    try testing.expectEqual(@as(usize, 1), arbiter.saw_chain_len);
    try testing.expectEqualStrings("coder", arbiter.saw_first_kind);
}

test "a reviewer that says no is its own refusal, and the reason stays in the log" {
    // "The reviewer said no" and "there was no reviewer" are two different
    // facts about one session, the same way `refused_by_user` and `expired`
    // are. A caller that folded them would tell an agent to try again in the
    // one case where trying again is pointless.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{
        .says = .rejected,
        .note = "the diff rewrites chock.zon, which is the file the policy is in",
    };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
    try testing.expectEqual(Outcome.refused_by_review, outcome);
    try testing.expect(!outcome.permits());
    try testing.expect(outcome != .review_unavailable);

    const answer = try theOnlyAnswer(gpa, io, store);
    defer freeAnswer(gpa, answer);
    try testing.expectEqualStrings("refused_by_review", answer.decision_name);
    try testing.expectEqualStrings("rejected", answer.review_name);
    try testing.expect(std.mem.indexOf(u8, answer.review_note, "chock.zon") != null);

    // The reviewer's own words are in the log and nowhere else. What the agent
    // that asked reads is `review.requesterText`, which takes an outcome and
    // has no parameter a note could travel in: see that file's own comptime
    // block. This is the one line that says the two are different texts.
    const said = review_mod.requesterText(outcome.reviewOutcome().?);
    try testing.expect(std.mem.indexOf(u8, said, "chock.zon") == null);
    try testing.expect(std.mem.indexOf(u8, said, answer.review_note) == null);
}

test "agent_then_human puts the review in front of the person and still needs a yes" {
    // The reviewer answers first, and its verdict goes with the diff. Two
    // yeses, and the reviewer's is not one of the two that count on its own.
    const gpa = testing.allocator;
    const io = testing.io;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        decision: event.ApprovalDecision,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, self.decision, "ross");
        }
    };

    // The reviewer approves and the person approves: the act happens.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .decision = .approved_by_user,
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var arbiter = TestReviewer{
            .says = .approved,
            .note = "the diff is the parser fix and nothing else",
        };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
        try testing.expect(outcome.permits());
        try testing.expectEqual(@as(usize, 1), arbiter.calls);

        // The question the person was shown carries the review. Without this
        // the person is asked the same thing twice with no memory in between,
        // which is the version of `agent_then_human` that is worth nothing.
        const question = try theQuestion(gpa, io, store, "git.push");
        defer question.free(gpa);
        try testing.expectEqualStrings("approved", question.review_name);
        try testing.expectEqualStrings(
            "the diff is the parser fix and nothing else",
            question.review_note,
        );
    }

    // The reviewer approves and the person says no: the person's answer is
    // what decides, and no question the reviewer answered can overrule it.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{
            .gpa = gpa,
            .store = store,
            .locked = &locked,
            .decision = .refused_by_user,
        };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var arbiter = TestReviewer{ .says = .approved };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.refused_by_user, outcome);
        try testing.expect(!outcome.permits());
    }

    // The reviewer says no: nobody is woken up at all. A person asked about
    // something a reviewer already refused is a person asked for nothing, and
    // approval fatigue is what produced `yolo` as a default in another
    // harness.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        var arbiter = TestReviewer{ .says = .rejected };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.refused_by_review, outcome);
        try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
        try testing.expectEqual(@as(usize, 0), waiter.waits);
    }
}

test "agent_then_human pays for no review when nobody can answer the second half" {
    // A review costs a whole subagent. `Loop.run` holds the exclusive lock on
    // the session log for the whole session, so nothing can append an
    // `approval.response` while a turn runs, and `src/run.zig` says so by
    // asking with a timeout of zero. Paying a model to answer and then
    // expiring anyway spends money on a result that was already decided.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    var arbiter = TestReviewer{ .says = .approved };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.timeout_ms = 0;

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    try testing.expectEqual(Outcome.expired, outcome);
    try testing.expect(!outcome.permits());
    try testing.expectEqual(@as(usize, 0), arbiter.calls);
    // And no question either, because there is nobody to read one.
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));

    // `agent_review` with the same timeout is not affected: a reviewer needs
    // nobody to be awake, which is the whole reason it exists. Without this
    // the clamp above would read as "a timeout of zero refuses everything".
    {
        var review_backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const review_store = review_backing.storage();
        defer review_store.close(io);
        var review_locked = try review_store.lock(io);
        defer review_locked.unlock(io) catch {};

        var review_waiter = TestWaiter{};
        var review_arbiter = TestReviewer{ .says = .approved };
        const review_broker = Broker{
            .policy = try table.Table.parse(gpa, review_the_push, null),
            .waiter = review_waiter.waiter(),
            .reviewer = review_arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, review_broker.policy);

        var no_wait = testRequest("git.push");
        no_wait.timeout_ms = 0;
        try testing.expectEqual(
            Outcome.approved_by_review,
            try review_broker.request(gpa, io, review_store, &review_locked, no_wait, null),
        );
        try testing.expectEqual(@as(usize, 1), review_arbiter.calls);
    }
}

test "a promise the session made narrows the answer, and never widens it" {
    // The ratchet, at the place it is enforced. The promise is a fact folded
    // out of the session's own log, and the broker is what reads it: an agent
    // that applied its own promise to itself would be applying nothing.
    const gpa = testing.allocator;
    const io = testing.io;

    const allow_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    // Without a promise the table's own answer stands, so the difference below
    // is the promise and nothing else.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, allow_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        try testing.expectEqual(Outcome.allowed_by_policy, outcome);
    }

    // The same table, and a session that promised not to push. The act does
    // not happen, nobody is asked, and the record says the policy decided,
    // because the promise is part of the policy this session runs under.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, allow_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "git.*", .ceiling = .deny, .reason = "this task changes nothing remote" },
        };
        ask.self_policy = &promised;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.denied_by_policy, outcome);
        try testing.expect(!outcome.permits());
        try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
        try testing.expectEqual(@as(usize, 0), waiter.waits);
    }

    // And the direction that would be an escalation. A table that denies, and
    // a promise that says `allow`: the promise is a ceiling and never a floor,
    // so it cannot lift what the project decided. A minimum taken the wrong way
    // round would answer `allowed_by_policy` here.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const deny_the_push: [:0]const u8 =
            \\.{
            \\    .policy = .{
            \\        .rules = .{
            \\            .{ .action = "git.push", .decision = .deny },
            \\        },
            \\    },
            \\}
        ;
        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, deny_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "git.push", .ceiling = .allow, .reason = "I would like to push" },
        };
        ask.self_policy = &promised;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.denied_by_policy, outcome);
        try testing.expect(!outcome.permits());
    }

    // A promise about a different act leaves this one where the table put it.
    // Without this line the two above would also pass for a broker that
    // refused everything as soon as a session promised anything at all.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, allow_the_push, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest("git.push");
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "net.fetch", .ceiling = .deny, .reason = "this task needs no network" },
        };
        ask.self_policy = &promised;

        try testing.expectEqual(
            Outcome.allowed_by_policy,
            try broker.request(gpa, io, store, &locked, ask, null),
        );
    }
}

test "a promise can turn an allow into a review, so the acceptance modes carry it too" {
    // A promise is written in the same five words the table answers in, so all
    // five reach this broker by the same route and none of them needs a branch
    // of its own. An agent that promised "not without a reviewer" gets exactly
    // that, out of a table that would have let the act through unwatched.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const allow_the_push: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    var waiter = TestWaiter{};
    var arbiter = TestReviewer{ .says = .approved, .note = "the push is what the task asked for" };
    const broker = Broker{
        .policy = try table.Table.parse(gpa, allow_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    const promised = [_]chock_policy.ratchet.Restriction{
        .{ .action = "git.push", .ceiling = .agent_review, .reason = "somebody should read this first" },
    };
    ask.self_policy = &promised;

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    try testing.expectEqual(Outcome.approved_by_review, outcome);
    try testing.expectEqual(@as(usize, 1), arbiter.calls);
    // The reviewer was asked about the decision the promise produced, and not
    // about the one the table gave.
    try testing.expectEqual(chock_policy.table.Decision.agent_review, arbiter.saw_decision.?);

    // And a session with no reviewer gets a refusal for the same promise,
    // because a review that could not run never becomes an allow.
    {
        var second_backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const second = second_backing.storage();
        defer second.close(io);
        var second_locked = try second.lock(io);
        defer second_locked.unlock(io) catch {};

        var plain_waiter = TestWaiter{};
        const no_reviewer = try testBroker(gpa, allow_the_push, &plain_waiter);
        defer table.Table.destroy(gpa, no_reviewer.policy);

        const refused = try no_reviewer.request(gpa, io, second, &second_locked, ask, null);
        try testing.expectEqual(Outcome.review_unavailable, refused);
        try testing.expect(!refused.permits());
    }
}

test "a request to widen a promise is judged like any other act, by the acceptance modes" {
    // The release valve of the ratchet, and the reason there is no second
    // approval path anywhere. A widening is an action name,
    // `chock_policy.ratchet.widen_action`, so a project that wants one
    // possible writes one rule for it and the review carries the rest.
    const gpa = testing.allocator;
    const io = testing.io;

    const widen_needs_both: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "policy.widen", .decision = .agent_then_human },
        \\        },
        \\    },
        \\}
    ;

    // The reviewer reads it, and then a person does. Both said yes, so the
    // widening is authorised.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        const Answerer = struct {
            gpa: std.mem.Allocator,
            store: chock_proto.storage.Storage,
            locked: *LockedHandle,

            fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                if (waits != 1) return;
                const id = (try findRequestId(
                    self.gpa,
                    io_inner,
                    self.store,
                    chock_policy.ratchet.widen_action,
                )).?;
                _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
            }
        };

        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        var arbiter = TestReviewer{
            .says = .approved,
            .note = "the task really does need the network the agent gave up",
        };
        const broker = Broker{
            .policy = try table.Table.parse(gpa, widen_needs_both, null),
            .waiter = waiter.waiter(),
            .reviewer = arbiter.reviewer(),
        };
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest(chock_policy.ratchet.widen_action);
        ask.summary = "raise the promise about net.fetch from deny to ask";
        ask.tool = "restrict_self";
        // The promises this session already holds travel with the request, and
        // none of them covers the act of widening itself, so the promise does
        // not answer the question of whether it may be lifted.
        const promised = [_]chock_policy.ratchet.Restriction{
            .{ .action = "net.fetch", .ceiling = .deny, .reason = "the plan said no network" },
        };
        ask.self_policy = &promised;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.approved_by_user, outcome);
        try testing.expectEqual(@as(usize, 1), arbiter.calls);

        // The person was shown what the reviewer said, which for a widening is
        // the whole point: the agent is reporting that it was wrong about the
        // task when it planned it.
        const question = try theQuestion(gpa, io, store, chock_policy.ratchet.widen_action);
        defer question.free(gpa);
        try testing.expectEqualStrings("approved", question.review_name);
        try testing.expect(std.mem.indexOf(u8, question.review_note, "really does need") != null);
    }

    // A project that writes no rule for it gets `ask`, and a session whose
    // caller cannot wait gets an expiry, which is a refusal. So the default
    // answer to "may I widen" is no.
    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var waiter = TestWaiter{};
        const broker = try testBroker(gpa, ".{}", &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        var ask = testRequest(chock_policy.ratchet.widen_action);
        ask.timeout_ms = 0;

        const outcome = try broker.request(gpa, io, store, &locked, ask, null);
        try testing.expectEqual(Outcome.expired, outcome);
        try testing.expect(!outcome.permits());
    }
}

test "a decision only the broker's own review writes is not an answer a client can give" {
    // `approved_by_review` is written by `reviewed` and read back by nothing:
    // a request a reviewer settled has no open question at all. One found as
    // the answer to a question a person was asked is something else claiming
    // a review happened, and the safe reading of an answer that cannot be
    // true is that the action does not happen.
    const gpa = testing.allocator;
    const io = testing.io;

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,
        decision: event.ApprovalDecision,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, self.decision, "ross");
        }
    };

    for ([_]event.ApprovalDecision{ .approved_by_review, .refused_by_review, .review_unavailable }) |claimed| {
        var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked, .decision = claimed };
        var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
        const broker = try testBroker(gpa, ask_every_action, &waiter);
        defer table.Table.destroy(gpa, broker.policy);

        const outcome = try broker.request(gpa, io, store, &locked, testRequest("git.push"), null);
        if (waiter.failed) |err| return err;
        try testing.expectEqual(Outcome.mismatched_answer, outcome);
        try testing.expect(!outcome.permits());
    }
}

/// An invented value with no meaning anywhere, long enough that the floor
/// `src/run.zig` applies before it fills `redaction` would keep it.
const fake_key = "sk-broker-test-000000000000";

test "a value this broker keeps out is in none of the log's own bytes" {
    // **The half that cannot be undone later.** The log is append only and hash
    // chained, so a value written here stays here: taking it out afterwards
    // breaks the chain of every record that follows. There is no cleanup, only
    // prevention, and this is the test that says prevention happened.
    //
    // Every field of the question carries it, because a redaction of the detail
    // alone would pass a test that only read the detail.
    //
    // Mutation check: return `ask` from `scrubbed` and the raw byte search
    // below fails.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
        }
    };

    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };

    const broker = Broker{
        .policy = try table.Table.parse(gpa, ask_every_action, null),
        .waiter = waiter.waiter(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.summary = "push the client that reads " ++ fake_key;
    ask.detail = "a1b2c3 add the client\n+const token = \"" ++ fake_key ++ "\";\n";
    ask.reason = "the task named " ++ fake_key;
    ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "the user pasted " ++ fake_key }};

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    if (waiter.failed) |err| return err;
    try testing.expectEqual(Outcome.approved_by_user, outcome);

    // **The log's own bytes, and not a parsed field.** This is what `chockd`
    // serves and what an export ships, so it is the only search that answers
    // the question.
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, fake_key) == null);

    // Four fields carried it and four markers stand where it was. A count, so
    // that a redaction of three of the four is a failure and not a pass.
    try testing.expectEqual(
        @as(usize, 4),
        std.mem.count(u8, backing.bytes.items, secrets_mod.redacted_marker),
    );

    // **The record still says what happened.** A person reading it the next
    // morning learns that a secret was in the commit and where. What is lost is
    // the value alone.
    const question_id = (try findRequestId(gpa, io, store, "git.push")).?;
    var replay = try store.replay(gpa, io, question_id);
    defer replay.deinit();
    const parsed = (try replay.next(io)).?;
    defer parsed.deinit();
    const question = parsed.value.event.approval_request;
    try testing.expect(std.mem.indexOf(u8, question.detail, "a1b2c3 add the client") != null);
    try testing.expect(std.mem.indexOf(u8, question.detail, "+const token = ") != null);
    try testing.expectEqualStrings("git.push", question.action);
    try testing.expectEqualStrings("main", question.spawn_chain[0].agent_kind);

    // **And the chain still holds over it.** Redaction rewrites bytes that are
    // about to be hashed, so the record that is hashed has to be the redacted
    // one. It is: the replacement happens before `Locked.append`.
    const report = try chock_proto.storage.verify(store, gpa, io);
    try testing.expectEqual(chock_proto.chain.Verdict.intact, report.verdict);
    try testing.expect(report.events > 0);
    try testing.expectEqual(report.events, report.chained);

    // **And this is why prevention is all there is.** The record after this one
    // carries the hash of these bytes, so one byte changed inside the marker is
    // found. A session that wrote the value and tried to take it out afterwards
    // would leave exactly this verdict behind. Last, because it spoils the log.
    const marker_at = std.mem.indexOf(u8, backing.bytes.items, secrets_mod.redacted_marker).?;
    backing.bytes.items[marker_at + 1] = 'X';
    const forged = try chock_proto.storage.verify(store, gpa, io);
    try testing.expectEqual(chock_proto.chain.Verdict.broken, forged.verdict);
}

test "a reviewer reads a clean case, and the note it writes is scanned again" {
    // Two facts about the one path that adds text after `request` scrubbed its
    // argument. The reviewer is a model: what it is shown leaves the machine,
    // and what it answers is written into the question a person is shown and
    // into the record of the decision.
    //
    // `agent_then_human`, so the note lands in both records.
    //
    // Mutation check: pass `report.note` into `Record` and the raw byte search
    // fails. Drop the `scrubbed` call in `request` and `saw_never` is true.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const Answerer = struct {
        gpa: std.mem.Allocator,
        store: chock_proto.storage.Storage,
        locked: *LockedHandle,

        fn onWait(ctx: ?*anyopaque, io_inner: std.Io, waits: usize) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            if (waits != 1) return;
            const id = (try findRequestId(self.gpa, io_inner, self.store, "git.push")).?;
            _ = try answerAsUser(self.gpa, io_inner, self.locked, id, .approved_by_user, "ross");
        }
    };

    var answerer = Answerer{ .gpa = gpa, .store = store, .locked = &locked };
    var waiter = TestWaiter{ .ctx = &answerer, .on_wait = Answerer.onWait };
    var arbiter = TestReviewer{
        .kind = "arbiter",
        .says = .approved,
        .note = "the commit adds " ++ fake_key ++ " and the task asked for it",
        .never = fake_key,
    };

    const broker = Broker{
        .policy = try table.Table.parse(gpa, review_then_ask_about_the_push, null),
        .waiter = waiter.waiter(),
        .reviewer = arbiter.reviewer(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.detail = "a1b2c3 add the client\n+const token = \"" ++ fake_key ++ "\";\n";

    const outcome = try broker.request(gpa, io, store, &locked, ask, null);
    if (waiter.failed) |err| return err;
    try testing.expectEqual(Outcome.approved_by_user, outcome);

    // The reviewer ran, and what it was shown held no value. A model that is
    // shown one can repeat it anywhere, and a provider is the one place a
    // repeat leaves the machine.
    try testing.expectEqual(@as(usize, 1), arbiter.calls);
    try testing.expect(!arbiter.saw_never);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, fake_key) == null);

    // The note is in both records and both are clean, and the reviewer's own
    // words around the value are still there for the person who reads them.
    const question = try theQuestion(gpa, io, store, "git.push");
    defer question.free(gpa);
    try testing.expect(std.mem.indexOf(u8, question.review_note, secrets_mod.redacted_marker) != null);
    try testing.expect(std.mem.indexOf(u8, question.review_note, "the task asked for it") != null);

    // The same note on the other record it can reach. A person answered above,
    // so the response there is the client's own line and carries no note at
    // all; `agent_review` is the decision where this broker writes the note
    // into the answer itself.
    var review_backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const review_store = review_backing.storage();
    defer review_store.close(io);
    var review_locked = try review_store.lock(io);
    defer review_locked.unlock(io) catch {};

    var quiet = TestWaiter{};
    const review_only = Broker{
        .policy = try table.Table.parse(gpa, review_the_push, null),
        .waiter = quiet.waiter(),
        .reviewer = arbiter.reviewer(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, review_only.policy);

    try testing.expectEqual(
        Outcome.approved_by_review,
        try review_only.request(gpa, io, review_store, &review_locked, ask, null),
    );
    try testing.expect(std.mem.indexOf(u8, review_backing.bytes.items, fake_key) == null);

    const answer = try theOnlyAnswer(gpa, io, review_store);
    defer freeAnswer(gpa, answer);
    try testing.expect(std.mem.indexOf(u8, answer.review_note, secrets_mod.redacted_marker) != null);
    try testing.expect(std.mem.indexOf(u8, answer.review_note, "the task asked for it") != null);
}

test "a broker with nothing to keep out copies nothing" {
    // The property that lets this sit in front of every request: a session that
    // declared no credential pays one comparison, and the question it writes is
    // byte for byte the one it wrote before this seam existed.
    //
    // **Pointers, and not a comparison of the strings.** A clean string comes
    // back equal whether it was copied or not, so equality would pass against a
    // version that scanned and copied every request in every session.
    //
    // Mutation check: drop the `redaction.len` test in `scrubbed` and every
    // expectation below fails.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var waiter = TestWaiter{};
    const broker = try testBroker(gpa, ask_every_action, &waiter);
    defer table.Table.destroy(gpa, broker.policy);

    var ask = testRequest("git.push");
    ask.spawn_chain = &.{.{ .agent_kind = "main", .reason = "the user asked for the fix" }};

    const same = try broker.scrubbed(arena_state.allocator(), ask);
    try testing.expectEqual(ask.summary.ptr, same.summary.ptr);
    try testing.expectEqual(ask.detail.ptr, same.detail.ptr);
    try testing.expectEqual(ask.reason.ptr, same.reason.ptr);
    try testing.expectEqual(ask.spawn_chain.ptr, same.spawn_chain.ptr);
}

test "a value with no name is kept out of a tool result, whole or in pieces" {
    // `secrets.Store` and `redaction` are two lists with one job. A broker that
    // scanned for the named half and wrote the other would be the same fault
    // twice, and a caller would have a third rule to learn.
    //
    // Mutation check: pass `result` instead of `scanned` in `appendToolResult`
    // and the first search fails. Build the redactor from `self.secrets` alone
    // and the streamed half fails.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{};
    const broker = Broker{
        .policy = try table.Table.parse(gpa, ask_every_action, null),
        .waiter = waiter.waiter(),
        .redaction = &.{fake_key},
    };
    defer table.Table.destroy(gpa, broker.policy);

    _ = try broker.appendToolResult(gpa, io, &locked, .{
        .call_id = "call1",
        .output = "TOKEN=" ++ fake_key ++ "\nHOME=/home/ross\n",
        .is_error = false,
        .truncated = false,
    }, waiter.now_ms);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, fake_key) == null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "HOME=/home/ross") != null);

    // The hard case: a streamed result cut through the middle of the value, so
    // neither piece holds it and both look clean.
    var pieces = try broker.redactor(gpa);
    defer pieces.deinit(gpa);
    try pieces.push(gpa, "half is " ++ fake_key[0..9]);
    try pieces.push(gpa, fake_key[9..] ++ " and that was all");
    const streamed = try pieces.finish(gpa);
    defer gpa.free(streamed);
    try testing.expect(std.mem.indexOf(u8, streamed, fake_key) == null);
    try testing.expect(std.mem.indexOf(u8, streamed, secrets_mod.redacted_marker) != null);
}
