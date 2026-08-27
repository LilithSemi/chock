//! The agent loop: the thing that joins a model client, a session log, and a
//! tool runner into a session that actually goes back and forth.
//!
//! **The log is the truth, and the context is a view of it.** Every turn,
//! `Loop.run` builds the request the model sees by folding the log so far,
//! through `context.zig`, never by keeping its own separate copy of "the
//! conversation." A resume replays the same log through the same fold and
//! gets the same context back: see `lib/chock-proto/state.zig`.
//!
//! **An event is written before the action it describes happens.** A model's
//! reply is appended as a `message` event, and each tool call inside it is
//! appended as its own `tool.call` event, before `deps.tools.dispatch` ever
//! runs. A crash between the model answering and the tool running is then
//! replayable: the call is already on disk, even if the result never
//! arrives. Writing the call after running the tool, because it reads
//! simpler, is the mistake this ordering exists to rule out.
//!
//! **The API key never reaches here.** `deps.client` is the neutral
//! `chock_provider.Client.Client` interface: `Loop.run` never sees a
//! credential, only a value that can send a request and stream a reply. See
//! `Client.zig`'s own top comment.
//!
//! ## The tool runner seam
//!
//! `deps.tools` is `ToolRunner`, a `ptr`/`vtable` interface in the same
//! style `chock_provider.Client.Client` already uses, not a bare call to
//! `chock_core.tools.Registry.dispatch`. Two reasons:
//!
//! * `Registry.dispatch` must run from a single threaded process: see
//!   `tools.zig`'s own top comment. A caller that wants to drive `Loop.run`
//!   from the ordinary, multi threaded test binary, the way every test in
//!   this file does, cannot call it directly, the same reason
//!   `test/core/tools.zig` runs every real tool call through a dedicated
//!   probe process instead of inside its own test binary.
//! * `Registry.dispatch` needs an `env` and a built `sandbox.Config`, which
//!   in turn comes from a `chock_workspace.Workspace`. `lib/chock-core/tools.zig`'s
//!   own top comment is explicit that this library does not import
//!   `chock-workspace`: `dispatch` takes an already built `sandbox.Config`,
//!   never a `Workspace` itself. `Loop.zig` sits beside `tools.zig` in the
//!   same library and keeps the same rule.
//!
//! ## The approval seam
//!
//! **The broker is built, and no tool call goes through it.** `Loop.run` never
//! asks anyone whether a tool call may run: every call `deps.tools` accepts, it
//! runs. The place a broker's decision would slot in is between appending the
//! `tool.call` event, step 4a below, and calling `deps.tools.dispatch`, step
//! 4b: a broker that refuses would append an `approval.request`, wait for an
//! `approval.response`, and either call `deps.tools.dispatch` or build a
//! refusal `tool.result` directly, without ever calling it. Nothing here
//! reserves a field or a branch for that yet, because a stub that always
//! approves is worse than no stub. The seam is this comment and the gap between
//! those two steps, not a type.
//!
//! The broker does run today, and it runs outside this file: `src/run.zig`
//! asks it for `workspace.apply` after `run` returns, so the session's own
//! commit can reach the user's repository. That is the same rule read from the
//! other side: the agent never holds the capability, and nothing about the
//! sandbox it ran in changes because an approval happened.
//!
//! ## The spawn seam
//!
//! **A `spawn_agent` call never reaches `deps.tool_runner`.** A spawn is
//! measured against how deep this agent already is and how many subagents it
//! has already started, and a tool runner holds neither number, so `runTool`
//! answers it here and `tools.Registry` refuses it outright. See `runSpawn`.
//!
//! **The child itself is a process, and this library does not start one.**
//! `deps.spawner` is the seam, for the same reasons `deps.tool_runner` is one:
//! a child needs a session directory, a credential, and a single threaded
//! caller, and `Sandbox.spawn` forks, so a tree built from threads would
//! deadlock the first time a child ran a tool. See
//! `lib/chock-core/subagent.zig`, which owns everything about a child except
//! the two events this loop appends around one.
//!
//! ## A full context is not a way for a session to stop
//!
//! **A context overflow is not a failure. It is the condition compaction
//! exists to answer.** This loop used to read the provider's 400 the same way
//! it read every other refusal and end the session, throwing away work that
//! nothing was wrong with. Two triggers now, and both are wanted:
//!
//! * **A threshold Chock chooses**, from the model's own context limit, read
//!   at the top of a turn from `chock_proto.state.Session.last_input_tokens`.
//!   Compacting only when a provider refuses means always compacting at the
//!   worst moment, on the providers that happen to say so, and never on one
//!   that truncates in silence.
//! * **The overflow itself**, as a backstop: catch it, compact, and take the
//!   same turn again.
//!
//! **A transport fault is a different thing and must not reach either.** A 429
//! and a 5xx look identical to an overflow at this call site and they want the
//! opposite answer, which is to send the same request again after a wait. See
//! `chock_provider.failure.classify`, which is what keeps the two apart, and
//! `chock_provider.retry`, which is the wait. `sendWithRetry` below is where
//! the two meet: a refusal is classified once, and either compaction answers
//! it, or a wait does, or the session ends. **Neither path ever becomes the
//! other**: compacting because of a rate limit would throw away turns nothing
//! was wrong with, and waiting for a full context would wait forever.
//!
//! **Only a refused response is retried, not a broken connection.** A dropped
//! or stalled stream is `AssembledReply.failed`, it carries whatever text
//! already arrived, and repeating a turn that half happened is a larger change
//! than this one. It ends the session exactly as it always did.

const std = @import("std");
const chock_cost = @import("chock-cost");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");
const sandbox = @import("chock-sandbox");
const tools = @import("tools.zig");
const context = @import("context.zig");
const compaction = @import("compaction.zig");
const notices = @import("notices.zig");
const task_table = @import("tasks.zig");
const subagent = @import("subagent.zig");
const self_policy = @import("self_policy.zig");
const arbiter_mod = @import("arbiter.zig");
const fetch_mod = @import("fetch.zig");
const ask_mod = @import("ask.zig");
const redact = @import("redact.zig");

const event = chock_proto.event;
const message = chock_provider.message;
const retry = chock_provider.retry;
const subagents = chock_policy.subagents;
const ratchet = chock_policy.ratchet;

/// What `ToolRunner.dispatch` can fail with. Named after `tools.Error`
/// itself: see that file's own `Error` for why it is
/// `sandbox.Sandbox.SpawnError`, the set of faults a retry cannot fix, never
/// the ordinary "the command exited 1" or "the tool name does not exist"
/// facts, which travel back as an `is_error` `ToolResult` instead. `Loop.run`
/// still does not propagate this: see `runTool` below.
pub const DispatchError = tools.Error;

/// The interface `Loop.run` calls to run one tool call. See this file's own
/// top comment for why this is an interface and not a direct call to
/// `tools.Registry.dispatch`.
pub const ToolRunner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        dispatch: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            call: event.ToolCall,
        ) DispatchError!event.ToolResult,
    };

    pub fn dispatch(
        self: ToolRunner,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        return self.vtable.dispatch(self.ptr, allocator, io, call);
    }
};

/// The real `ToolRunner`: forwards straight into `tools.Registry.dispatch`.
/// `env` and `sandbox_config` are not owned: the caller keeps both alive for
/// as long as this value is in use, the same borrowing `Registry.dispatch`
/// itself already asks of its own caller.
pub const SandboxToolRunner = struct {
    env: *const std.process.Environ.Map,
    sandbox_config: sandbox.Config,
    /// Everything about this session a tool needs beyond the workspace: the
    /// knowledgebase directory, the session identifier a note records as its
    /// provenance, and the per call deadline. See `tools.Context`. Not owned:
    /// the caller keeps every string in it alive for as long as this value is
    /// in use, the same borrowing `env` and `sandbox_config` already ask for.
    context: tools.Context = .{},

    pub fn runner(self: *const SandboxToolRunner) ToolRunner {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        const self: *SandboxToolRunner = @ptrCast(@alignCast(ptr));
        return tools.Registry.dispatchWith(allocator, io, self.env, self.sandbox_config, call, self.context);
    }
};

/// Told about each event as `Loop.run` appends it. Optional: `Loop.run`
/// behaves the same with none, and every test in this file except the one
/// that pins this behaviour uses none.
///
/// **This exists because the log is the only output a caller has, and a
/// caller cannot read it while `run` holds the exclusive lock on it.** A
/// session of ten turns is minutes of a silent terminal otherwise, and a
/// caller that wants to show what is happening has nowhere else to look. It
/// is also the seam an interface needs: a client that renders a turn as it
/// lands attaches here, and nothing else about `run` changes.
///
/// **`onEvent` returns nothing, and that is deliberate.** An observer is
/// watching, never deciding. A printer that fails, for example because
/// standard output is a closed pipe, must not end a session that is doing
/// real work, and an observer that could refuse an event would be a second
/// place where a session can be stopped, which is the broker's job and not
/// this one's. The seam a decision belongs at is named in this file's own
/// top comment, and it is not here.
///
/// `id` is the event's own byte offset in the log, the same value a replay
/// reports. `ev` is borrowed and is valid only for the duration of the call.
///
/// ## `onPiece`, and why an event is not enough
///
/// **A turn produces one `message` event, at the end, and a turn takes
/// minutes.** Measured: a real session ran 5.3 minutes over about 57 model
/// calls and showed nothing at all while any of them was in flight, because
/// `onEvent` is only reached once the whole reply is assembled and appended.
/// The provider was streaming the entire time. `chock_provider.Client` hands
/// over each piece the moment one read of the connection produces it, and
/// `test/core/client.zig` pins that an early piece arrives before a later one
/// is even sent. That stream stopped here.
///
/// So an observer is told two different things. `onEvent` is the log, and
/// nothing about it changes. `onPiece` is the model's own words, in the order
/// it produced them, at the time it produced them.
pub const Observer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        onEvent: *const fn (ptr: *anyopaque, id: u64, ev: event.Event) void,
        onPiece: *const fn (ptr: *anyopaque, piece: Piece) void,
        onNotice: *const fn (ptr: *anyopaque, text: []const u8) void,
    };

    pub fn onEvent(self: Observer, id: u64, ev: event.Event) void {
        self.vtable.onEvent(self.ptr, id, ev);
    }

    /// Told what the harness itself is about to do, in one sentence, when it
    /// is something a person watching would otherwise read as a hang.
    ///
    /// **A wait is the case this exists for.** A session that is refused by a
    /// rate limit waits, and the wait can be a minute long. Without this the
    /// terminal shows nothing for that minute, which is exactly the silence
    /// `onPiece` was added to end, and a user who cannot tell a wait from a
    /// hang presses Ctrl-C on a session that was about to carry on.
    ///
    /// **Not an event, and deliberately not in the log.** This says what the
    /// harness is doing now, not what the session is. The facts a replay needs
    /// are already events: every attempt appends its own `usage`, and a
    /// session that gives up appends a `session.end` that says how many
    /// attempts were made.
    ///
    /// `text` is borrowed and is valid only for the duration of the call.
    pub fn onNotice(self: Observer, text: []const u8) void {
        self.vtable.onNotice(self.ptr, text);
    }

    /// Told about one piece of the model's reply as it arrives, before the
    /// turn is finished and long before anything is appended to the log.
    ///
    /// **What is shown here is not yet in the log, and that is the one
    /// difference from `onEvent`.** Every piece of a turn that completes is in
    /// the `message` event that closes the turn, so the two agree in the
    /// ordinary case. A turn the provider cuts off partway is the case where
    /// they do not: `run` appends a `session.end` naming the fault, and the
    /// partial reply is not appended, so a person saw words that no replay
    /// will produce. An observer that must not show a word the log may never
    /// hold uses `onEvent` alone.
    ///
    /// `piece` is borrowed and is valid only for the duration of the call.
    pub fn onPiece(self: Observer, piece: Piece) void {
        self.vtable.onPiece(self.ptr, piece);
    }
};

/// One piece of a model's reply, as the provider produced it. See
/// `Observer.onPiece`.
///
/// **Two members, and a tool call is deliberately not one of them.** A tool
/// call arrives as fragments of a JSON argument list, so the early ones are
/// half an object and say nothing a person can read, and the `tool.call` event
/// already carries the whole call the moment it is known. Usage is not one
/// either: it is a number the `usage` event records, not a word the model
/// said.
pub const Piece = union(enum) {
    /// A piece of the model's answer text.
    text: []const u8,
    /// A piece of the model's reasoning. **Kept apart from `text` rather than
    /// folded into it**, because an observer that shows the two the same way
    /// would put the model's private working out in the middle of its answer,
    /// and only the observer can decide what to do about that.
    reasoning: []const u8,
};

/// Forwards each streamed delta to an `Observer` as a `Piece`. One per turn,
/// on `runTurn`'s own stack: it holds a borrowed observer and nothing else.
///
/// **The translation is here and not in the observer** so that no implementer
/// of `Observer` has to import `chock-provider` to be told what the model
/// said. See `Piece` for the two deltas that are dropped.
const PieceWatcher = struct {
    observer: Observer,

    fn watcher(self: *PieceWatcher) chock_provider.Client.Watcher {
        return .{ .ctx = self, .on_delta = onDelta };
    }

    fn onDelta(ctx: ?*anyopaque, delta: chock_provider.Client.Delta) void {
        const self: *PieceWatcher = @ptrCast(@alignCast(ctx.?));
        switch (delta) {
            .text => |text| self.observer.onPiece(.{ .text = text }),
            .reasoning => |text| self.observer.onPiece(.{ .reasoning = text }),
            .reasoning_signature, .tool_call, .usage, .stop_reason => {},
        }
    }
};

/// How many times the model may ask for the same tool, with the same
/// arguments, one call after another, before `Loop.run` stops the session
/// with `no_progress`.
///
/// **A turn count is the wrong stop condition and this is the right one.**
/// `Loop.run` used to stop at 50 turns, and the red team run of 2026-08-21
/// showed both faults of that in one session: it stopped a session that was
/// still working, at an arbitrary number, and it took 50 turns to notice a
/// loop that was already plain by turn 3, where the model called the same
/// read on the same four paths sixteen times. A turn count conflates "this
/// is taking a while", which is fine, with "this has stopped making
/// progress", which is not. So there is no turn limit by default: a session
/// ends when the model answers with no tool call, and this is what catches
/// the model that never will.
///
/// **Three, chosen with the retry in mind.** A tool call can fail for a
/// reason that is gone a moment later, and a model that repeats the call
/// once is doing the right thing, so a limit of 2 would stop a healthy
/// session. By the third identical call the same question has already been
/// answered the same way twice, and a fourth answer cannot be new.
///
/// **Counted inside a window, not over consecutive calls.** See
/// `no_progress_window`: the run of identical calls this used to count is
/// only the simplest loop, and the red team run of 2026-08-21 showed the
/// other one.
pub const no_progress_repeats: usize = 3;

/// How many of the most recent tool calls `Progress` looks at when it decides
/// whether the session is looping.
///
/// **Five, because that is the smallest window a two call cycle fits in.**
/// The detector used to hold one previous call and count identical calls in a
/// row, so any different call reset the count. The red team run of
/// 2026-08-21 walked straight through it: the model alternated two `bash`
/// calls, A B A B A, which never reaches two identical calls in a row and so
/// never fired, while being a model plainly making no progress. A B A B A
/// needs five slots. Four cannot hold it, and a larger window would only let
/// a longer cycle in, which the second condition below already handles
/// better than a wider window does.
pub const no_progress_window: usize = 5;

/// How many different calls the window may hold and still count as a loop.
///
/// **Two, and this is the condition that keeps real work alive.** "Three
/// identical calls within the last five" on its own stops the most ordinary
/// thing a coding agent does: build, edit, build, edit, build, where the two
/// edits differ and the build is identical every time. That is a model
/// fixing one compile error at a time, which is exactly the session nobody
/// may interrupt. The loop and the fix differ in what sits between the
/// repeats: a loop returns to the same other call, and work does not.
///
/// So a session is stopped only when the window holds at most this many
/// different calls **and** one of them was asked `no_progress_repeats` times.
/// A B A B A has two, and is stopped. A B A C A has three, and runs on. A
/// read, then an edit, then the same read again has two different calls and
/// only two of either, so it is not stopped either, and it is the pattern the
/// window was picked around.
///
/// **A longer cycle still gets through**, A B A C A B A C A and so on, and
/// that is the deliberate limit of this detector: past a two call cycle,
/// looping and working stop being separable by counting alone, and a
/// detector that guesses would stop healthy sessions. The budget, section
/// 10.2, is what bounds those.
pub const no_progress_distinct: usize = 2;

/// What a session still holds at a turn boundary that its log does not.
///
/// **Only the loop can count this**, because the two tables live beside the
/// loop and nothing outside the process can read them. It is handed to
/// `Deps.handover` so a caller can refuse to give away a session that would
/// lose work by moving. See `chock_broker.handover` for what a refusal reads
/// like, and `src/detach.zig` for the table of everything a running session
/// holds and what becomes of each part.
///
/// Counts and not a boolean, so a refusal can say how many and a person knows
/// what to wait for.
pub const InFlight = struct {
    /// Background commands started and not yet recorded in the log.
    tasks: usize = 0,
    /// Subagents started in the background and not yet recorded in the log.
    children: usize = 0,
};

/// Everything one call to `Loop.run` needs.
pub const Deps = struct {
    /// The model backend. See `chock_provider.Client.Client`'s own top
    /// comment: a caller cannot tell which implementation this is, and it
    /// never carries a credential.
    client: chock_provider.Client.Client,
    /// The session log. `Loop.run` takes the exclusive lock on it for the
    /// whole call: the process holding this lock is the owner.
    storage: chock_proto.storage.Storage,
    /// Runs one tool call. See this file's own top comment.
    tool_runner: ToolRunner,
    /// The tools the model is offered, in the shape
    /// `chock_provider.message.Request.tools` wants. A caller ordinarily
    /// builds this with `tools.Registry.definitions` and also passes it to
    /// `lib/chock-core/prompt.zig`'s own `build`, so the prompt's tool list
    /// and the request's own tool list can never drift apart from each
    /// other.
    tool_definitions: []const message.ToolDefinition,
    /// The model name on the wire, for example "glm4.7-flash:A3B".
    model: []const u8,
    /// The alias of `model` on the roster. A session can mix models across
    /// turns, so every `message` event this loop appends carries this, and a
    /// later reader can say which alias produced which turn.
    model_alias: []const u8,
    /// The agent kind that selects the policy. **This loop never evaluates the
    /// policy table**, which stays the broker's job: see this file's own top
    /// comment. The value reaches the `session.start` event and the
    /// `approval.request` this loop writes for a budget, and
    /// `lib/chock-policy/table.zig` is what keys a rule on it when a caller
    /// asks that table a question.
    agent_kind: []const u8,
    /// What kind of agent this is, for the one question the policy table does
    /// not answer: whether this agent holds any tool at all. See
    /// `tools.Role`.
    ///
    /// **The loop reads it because two tool calls never reach the tool
    /// runner.** `spawn_agent`, `update_plan` and `restrict_self` are answered
    /// here, so a gate that lived only in `tools.Registry.dispatchWith` would
    /// leave an arbitrator able to start a subagent. See `runTool`.
    ///
    /// **The name of the kind is not read here.** Which kinds are arbitrators
    /// is `lib/chock-broker/review.zig`'s question, and this library imports
    /// no `chock-broker`: the caller answers it and passes the answer.
    role: tools.Role = .worker,
    /// Every parent between the root of the spawn tree and this agent, root
    /// first, and this agent itself left out. See `event.SpawnLink`. Empty
    /// for a session a person started.
    ///
    /// **Every parent, and not the nearest one.** A caller that passed one link
    /// would leave a grandchild folding two kinds, neither of them the root's,
    /// and would report depth 2 at every depth, so `max_depth` would bound
    /// nothing. `src/run.zig`'s own `spawnChain` reads the whole chain off the
    /// command line its parent wrote, and `test/core/tree.zig` is what runs a
    /// tree deep enough to tell.
    ///
    /// Two things read it: the `approval.request` this loop writes, which
    /// carries the whole chain, and the depth half of `deps.subagents`,
    /// because the length of this chain is how deep this agent is.
    spawn_chain: []const event.SpawnLink = &.{},
    /// The session that started this one, or empty for a session a person
    /// started. It reaches the `session.start` event, which is the child's own
    /// half of the two way link a subagent tree is rebuilt from: the parent
    /// appends `session.spawn` naming the child, and this names the parent.
    ///
    /// **Nothing in this loop reads it back.** A parent is a fact about where
    /// this session came from, not a thing it can ask anything of: the parent
    /// process holds the exclusive lock on its own log for its whole session.
    parent_session: []const u8 = "",
    /// What starts a subagent, or null for a session that can start none. See
    /// `lib/chock-core/subagent.zig`, and `runSpawn`, which is the only thing
    /// that calls it.
    ///
    /// **A seam, for the same reason `tool_runner` is one.** A child is a
    /// process, and a process needs a session directory, a credential, and a
    /// single threaded caller, none of which this library has or wants. A
    /// caller with none of that passes null, and a spawn the limits allow then
    /// says so: see `spawn_has_no_spawner_detail`.
    spawner: ?subagent.Spawner = null,
    /// The children this session started and did not wait for, or null for a
    /// session that can start none that way. See
    /// `lib/chock-core/subagent.zig`'s own `Table`.
    ///
    /// **Null is the wait shape and nothing else**, which is every caller that
    /// existed before this: a spawn that asks to carry on is then refused and
    /// says so, rather than quietly waiting instead. See
    /// `spawn_cannot_carry_on_detail`.
    children: ?*subagent.Table = null,
    /// How deep and how wide the spawn tree of this project may grow, read
    /// from `chock.zon` by the caller. See `lib/chock-policy/subagents.zig`.
    /// The default is a 6 by 6 tree.
    ///
    /// **A `max_width` of zero refuses every spawn**, which is how a project
    /// turns subagents off, and it is the case this loop was tested at
    /// first: see `runSpawn`.
    subagents: subagents.Limits = .{},
    /// The system prompt. Built once by the caller, ordinarily with
    /// `lib/chock-core/prompt.zig`'s own `build`, and sent unchanged on
    /// every turn.
    system_prompt: []const u8,
    /// Stop after this many turns, whatever the session is doing. **Null,
    /// which is no limit, is the default**: nobody knows in advance how many
    /// turns a task needs, and a limit that stops a healthy session is a
    /// limit that makes the tool untrustworthy. `no_progress_repeats` is what
    /// stops a session that has stopped working, and a budget is what bounds
    /// what one costs. This stays for a caller that genuinely wants a turn
    /// count, and ends the session `turn_limit`.
    max_turns: ?usize = null,
    /// Told about each event as it is appended. See `Observer`. Null for a
    /// caller that only wants the log.
    observer: ?Observer = null,
    /// Asked at every safe point whether this session should stop now. Null,
    /// the default, is a session nothing can interrupt.
    ///
    /// **A function and not a flag, because the caller owns how it is set.**
    /// `src/interrupt.zig` sets its own flag from a signal handler and passes
    /// `requested` here; a client with a cancel button would pass something
    /// else. Neither shape reaches this file.
    ///
    /// **It must be safe to call from anywhere and must not fail.** It is read
    /// while `run` holds the exclusive lock on the session log, so anything
    /// that took a lock of its own, or allocated, could deadlock the session
    /// it was asked about.
    ///
    /// See `run` for where it is read and what is written when it says yes.
    canceled: ?*const fn () bool = null,
    /// Asked at every **turn boundary**, and nowhere else, whether another
    /// process should become the owner of this session now. Null, the default,
    /// is a session nothing else can take.
    ///
    /// **The turn boundary alone, and this is the whole difference from
    /// `canceled`.** `canceled` is read at three safe points, and one of them
    /// is the gap between two tool calls of one turn. A session that stopped
    /// there leaves an assistant message whose `tool_use` parts have no
    /// matching `tool.result`, which a person pressing Ctrl-C has accepted and
    /// a handover must not produce: the next owner has to send that context to
    /// a provider, and a provider refuses it. At the top of a turn every tool
    /// result of the last turn is already in the log, so the next owner sends
    /// what this one would have sent.
    ///
    /// It is given what this session still holds that the log does not, because
    /// only the loop can count it: see `InFlight`. The answer is the caller's,
    /// and `src/handover.zig` is what turns it into a socket exchange. Nothing
    /// about a socket reaches this file.
    ///
    /// **It may wait, and `canceled` may not.** This is called once per turn
    /// with the lock held and nothing half written, and the caller is expected
    /// to answer at once unless a client is really asking.
    handover: ?*const fn (io: std.Io, in_flight: InFlight) bool = null,
    /// Every background task of this session, or null for a session that runs
    /// none. See `lib/chock-core/tasks.zig`.
    ///
    /// **The loop drains it and the tool runner fills it.** The same table is
    /// in `tools.Context`, where a `run_command` call starts a task, and here,
    /// where a finished one is recorded and delivered. It is the caller that
    /// owns it, because it outlives every tool call and every turn.
    tasks: ?*task_table.Table = null,
    /// What this session may spend, read from `chock.zon` by the caller. Null
    /// for a project that set no cap. That file stays beyond the agent's reach,
    /// so **the model cannot raise its own budget**, and
    /// `test/workspace/escape.zig` proves it.
    budget: ?chock_cost.budget.Budget = null,
    /// Whether the endpoint behind `client` bills anybody. A caller builds
    /// this from the provider instance, ordinarily with
    /// `chock_cost.prices.billingFor`. See `chock_cost.prices.Billing`: free
    /// and unknown are different, and a local model is free.
    billing: chock_cost.prices.Billing = .billed,
    /// When to fold the context into a summary, and what to keep. See
    /// `lib/chock-core/compaction.zig`. **The default knows no context limit**,
    /// so a caller that says nothing gets the overflow backstop and no
    /// threshold: a guessed limit would compact a session that had room.
    compaction: compaction.Policy = .{},
    /// How many times a refused request is sent again, and how long to wait
    /// first. See `lib/chock-provider/retry.zig`. **This is not compaction**,
    /// and the two answer different refusals: see this file's own top comment.
    ///
    /// The default retries. A caller that wants a refusal to end the session
    /// at once asks for `max_attempts` of 1.
    retry: retry.Policy = .{},
    /// What the harness tells the agent that the agent cannot work out for
    /// itself. See `lib/chock-core/notices.zig`.
    ///
    /// **This never touches `system_prompt`**, and a test in this file pins
    /// that the prompt is byte identical across two turns carrying different
    /// notices. A value that changes every turn, put at the front of a
    /// request, invalidates the provider's cache on every turn, and the bill
    /// lands on exactly the long sessions notices exist to help.
    notices: notices.Policy = .{},
    /// How many files in the user's own project are not committed, and so are
    /// not in the workspace the agent sees. Measured by the caller before the
    /// session starts, because only the caller can see the user's real
    /// repository: see `src/run.zig`'s own `handleUncommitted`, which already
    /// prints this number for the user and, before this existed, told the
    /// agent nothing.
    ///
    /// Zero for a clean tree, and zero for an overlay workspace, which copies
    /// the whole project directory and hides nothing.
    uncommitted_files: usize = 0,
    /// What performs the wait between two attempts. Null, the default, is the
    /// machine's own clock.
    ///
    /// **A seam, so that no test of the backoff measures elapsed time.** A
    /// test that slept for real would be slow and would still prove nothing
    /// about the number it was given: see `retry.Sleeper`, and
    /// `chock_broker.Broker.Waiter`, which is the same seam for the same
    /// reason.
    sleeper: ?retry.Sleeper = null,
    /// Who decides an act this loop is not allowed to decide for itself, or
    /// null for a session that can ask nobody. See `lib/chock-core/arbiter.zig`.
    ///
    /// **One act reaches it today**, and it is the one this loop would
    /// otherwise be deciding about itself: a request to widen a promise the
    /// session already made. See `runRestrictSelf`. The policy table stays the
    /// broker's, and nothing in this file ever reads one.
    ///
    /// **Null is a refusal that says so.** `arbiter.not_asked` is what a
    /// session with none answers, and the words a model gets back then say
    /// nobody could be asked rather than implying the request was weighed,
    /// and those two are kept apart.
    arbiter: ?arbiter_mod.Arbiter = null,
    /// What reads a URL for the agent, or null for a session that can read
    /// none. See `lib/chock-core/fetch.zig`.
    ///
    /// **A seam for the reason `arbiter` is one.** Which host may be read is a
    /// row of the policy table, the table is the broker's, and nothing in this
    /// file reads one.
    ///
    /// **Null is a refusal that says so.** `fetch_mod.has_no_fetcher` is what a
    /// session with none answers, because a tool that came back with an empty
    /// page would have a model reason about a page nobody read.
    fetcher: ?fetch_mod.Fetcher = null,
    /// What puts a question to the person, or null for a session that can ask
    /// nobody. See `lib/chock-core/ask.zig`.
    ///
    /// **A seam for the reason `arbiter` is one**, and for one more of its own:
    /// what asks a person is a terminal or a display, and nothing under `lib/`
    /// writes to a device.
    ///
    /// **This is not the arbiter and must never become it.** An arbiter decides
    /// whether an act may happen; this asks a person for a fact and grants
    /// nothing whatever they type. Read `ask.zig`'s own top comment before
    /// joining the two.
    ///
    /// **Null is a refusal that says so.** `ask_mod.has_no_asker` is what a
    /// session with none answers, and it tells the model to decide for itself
    /// rather than to ask again.
    asker: ?ask_mod.Asker = null,
    /// What must not reach the provider. See `lib/chock-core/redact.zig`,
    /// and read its top comment before trusting this for anything: it is
    /// protection against an accident and it is not a boundary.
    ///
    /// **The default is inert**, so a project that declared nothing sends
    /// exactly the bytes it sent before this field existed. The caller builds
    /// a live one, because only the caller can see the credential store and
    /// the project's own declarations: `chock-core` imports no `chock-auth`,
    /// and this file's own top comment keeps it that way.
    ///
    /// **It reaches the log and the request, at two seams.**
    /// `appendAndApply` is where a record is cleaned, which is the seam that
    /// matters: the log is append only and hash chained, so a credential
    /// written there cannot be taken out again. `sendOnce` is where the request
    /// is cleaned, which catches the one part of a request the log does not
    /// hold, the system prompt. See `redact.zig`'s own top comment.
    redact: redact.Policy = .{},
};

/// How the `session.end` this loop writes for a session stopped by its budget
/// starts. Exported so a caller that shows this to a person, or a test that
/// pins it, does not carry a copy of a sentence written here.
///
/// **Nothing reads this to decide anything.** `event.SessionEndReason` has a
/// member for the budget, and `src/main.zig` reads that member and never the
/// text: a code inferred from a message is a code a reword can change, which
/// is the fault the turn limit's own detail prefix used to carry.
pub const budget_detail_prefix = "the session budget was reached";

/// The action name the budget's `approval.request` carries. Hitting a cap is
/// an approval rather than a crash: **a session that dies at a cap with no
/// chance to answer loses work the user already paid for.**
pub const budget_action = "budget.raise";

pub const Error =
    std.mem.Allocator.Error ||
    chock_provider.Client.SendError ||
    // ReplayError, not the narrower StorageError alone: foldExisting below
    // reads the log back through Storage.replay before run's own first
    // append, and a stored line that fails to parse, event.DecodeError, is
    // as real a fault there as a storage fault is.
    chock_proto.storage.ReplayError;

/// Run a session to completion: repeat a turn until the model answers with
/// no tool call.
///
/// First folds whatever `deps.storage` already holds, the same replay a resume
/// or a `/daemonize` handover would do. A caller that wants the very first turn
/// to answer a prompt appends that prompt as a `message` event, with its own
/// lock/append/unlock, before calling `run`; `run` itself starts from whatever
/// is already there, nothing more.
///
/// Appends `session.start` only when the fold found none already, so
/// calling `run` again on a session that has already started, to continue
/// it after a reconnect, does not write a second one on top of the first.
/// Appends `session.end` before returning in every case, so a caller reading
/// the log back always sees a session that ended, never one that stops mid
/// conversation with nothing saying why. See `Error` for what can still
/// escape without it: only an allocation failure or a storage fault, neither
/// of which leaves anything more to say into the very log that failed.
///
/// **An interrupt is part of "in every case", and it used to be the hole in
/// it.** A signal does not run a deferred append, so a session somebody
/// stopped with Ctrl-C left a log ending on whatever event happened to be
/// last, and "the user stopped it" and "the process died mid write" read
/// identically to anything replaying that log. `deps.canceled` closes that:
/// it is read at every safe point, and a session that is asked to stop
/// appends a `session.end` with reason `canceled_by_user` like any other
/// ending. The safe points are the top of each turn and the gap between two
/// tool calls of one turn, which are the two places `run` holds the lock
/// legitimately and has nothing half written. A model call already in flight
/// is read to its end first: see `src/interrupt.zig` on the second press,
/// which is what a user with no patience for that has instead.
///
/// **The person at the keyboard is asked first.** Both are read at the top of
/// the same turn, and a Ctrl-C recorded as a handover would tell the person who
/// pressed it that their session moved somewhere.
pub fn run(allocator: std.mem.Allocator, io: std.Io, deps: Deps) Error!void {
    var locked = try deps.storage.lock(io);
    defer locked.unlock(io) catch {};

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    // What the harness knows and the model cannot. Held here, beside
    // `Progress`, because both are memory of the session that the context
    // itself does not carry. See `lib/chock-core/notices.zig`.
    var telling = notices.State{};
    defer telling.deinit(allocator);

    try foldExisting(allocator, io, deps.storage, &session, &telling);
    // A log with nothing in it is a session that starts now. Every other case
    // reads the start out of the log, so a resumed session says how old it
    // really is rather than how long this process has been running.
    if (telling.started_ms == null) telling.started_ms = nowMs(io, deps);

    // session_start is the only event that ever sets agent_kind, so an
    // empty one here means the fold found none: either the log was empty,
    // or it held only events, such as a seeded prompt, appended before this
    // session was ever marked started.
    if (session.agent_kind.len == 0) {
        _ = try appendAndApply(allocator, io, &locked, &session, deps, .{
            .session_start = .{
                .agent_kind = deps.agent_kind,
                .model_alias = deps.model_alias,
                // The child's own half of the two way link. See
                // `Deps.parent_session`.
                .parent_session = deps.parent_session,
                // The kinds the policy table folds, written into the log the
                // session starts. `parent_session` names one identifier, and
                // the answer the table gives depends on every kind from the
                // root down to this agent, so a reader with this log alone
                // could not re-derive a decision without it. See
                // `event.SessionStart.spawn_chain`.
                .spawn_chain = deps.spawn_chain,
            },
        });
    }

    var progress = Progress{};
    defer progress.deinit(allocator);
    var watch = ContextWatch{};

    var turn: usize = 0;
    while (deps.max_turns == null or turn < deps.max_turns.?) : (turn += 1) {
        if (try runTurn(allocator, io, &locked, &session, deps, &progress, &watch, &telling, turn)) {
            return recordAtTheEnd(allocator, io, &locked, &session, deps);
        }
    }

    const detail = try std.fmt.allocPrint(
        allocator,
        "the caller asked for at most {d} turns, and the session reached that with no final answer",
        .{deps.max_turns.?},
    );
    defer allocator.free(detail);
    _ = try appendAndApply(allocator, io, &locked, &session, deps, .{ .session_end = .{
        .reason = .turn_limit,
        .detail = detail,
    } });
    // The turn limit is a way for a session to stop like any other, so the same
    // last records are written here: see `recordAtTheEnd`.
    try recordAtTheEnd(allocator, io, &locked, &session, deps);
}

/// The last thing a session writes, after `session.end` and after the last
/// turn, whichever way the session stopped.
///
/// **Every way a session stops comes through here.** A final answer, a turn
/// limit, a budget that refused the next turn, and a user who canceled are four
/// stop reasons and one ending, so what the log holds at the end of a session
/// does not depend on which of them happened.
///
/// **The record only, and never a message.** The conversation is over by here,
/// and words written into a log that nothing will read are words put into a
/// conversation that ended: see `TaskDelivery`.
///
/// **A child is waited for and a background command is not**, and the
/// difference is not a preference. `subagent.Table.deinit` has to wait in any
/// case, because a child writes into a session directory below this session's
/// own scratchpad, which the caller is about to remove, so the wait happens
/// either way; doing it here is what stops the parent's log losing the answer.
/// Then every `session.spawn` in the log has an `agent.complete` after it,
/// which is a property a replay can rely on. A background command has no such
/// forced wait and no log of its own, and a session that is over must not sit
/// for half an hour on a build whose output nobody will read: `src/run.zig`
/// ends those instead.
fn recordAtTheEnd(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
) Error!void {
    // A background task that finished while the last turn ran still ran, and
    // the log is the truth about what happened in a session.
    try recordFinishedTasks(allocator, io, locked, session, deps, .record_only);
    if (deps.children) |table| table.waitAll();
    try recordFinishedChildren(allocator, io, locked, session, deps, .record_only);
}

/// What the compaction watch remembers between turns, which is one thing:
/// whether the agent has already been told a compaction is coming since the
/// last one happened.
///
/// **Everything else it needs is folded from the log.** How full the context
/// is comes from `chock_proto.state.Session.last_input_tokens`, so a resumed
/// session knows it before it sends anything, and a compaction resets it there
/// rather than here.
const ContextWatch = struct {
    warned: bool = false,
};

/// What the last `no_progress_window` tool calls of the session look like.
/// `Progress.observe` builds one per call, and `isLoop` is the whole stop
/// condition. See `no_progress_repeats`, `no_progress_window` and
/// `no_progress_distinct` for why it takes both numbers and not one.
const Observation = struct {
    /// How many tool calls the window holds. Below `no_progress_window` only
    /// for the first few calls of a session.
    seen: usize,
    /// How many of those are the call just made.
    repeats: usize,
    /// How many different calls the window holds altogether.
    distinct: usize,

    fn isLoop(self: Observation) bool {
        return self.repeats >= no_progress_repeats and self.distinct <= no_progress_distinct;
    }
};

/// The last `no_progress_window` tool calls of the session. See
/// `no_progress_repeats` for why this, and not a turn count, is what stops a
/// session that has stopped working, and `no_progress_window` for why one
/// previous call was not enough to see a loop.
///
/// Owns its copy of every call's tool name and arguments: the values
/// `runTurn` reads them from belong to one turn's own reply and are freed
/// with it, and these have to outlive that.
const Progress = struct {
    /// The window, as a ring. Each entry is one call's tool and arguments,
    /// joined. Null for a slot no call has reached yet, which only happens in
    /// the first `no_progress_window` calls of a session.
    calls: [no_progress_window]?[]u8 = @splat(null),
    /// Which slot the next call overwrites, so the oldest call is the one
    /// that leaves.
    next: usize = 0,

    fn deinit(self: *Progress, allocator: std.mem.Allocator) void {
        for (self.calls) |entry| {
            if (entry) |owned| allocator.free(owned);
        }
        self.* = undefined;
    }

    /// Record one tool call and say what the window looks like with it in.
    fn observe(
        self: *Progress,
        allocator: std.mem.Allocator,
        tool: []const u8,
        arguments: []const u8,
    ) std.mem.Allocator.Error!Observation {
        // The tool and the arguments are joined with a byte no tool name
        // holds, so "read" with arguments "x" and "read x" with no arguments
        // cannot be mistaken for each other.
        const key = try std.fmt.allocPrint(allocator, "{s}\x00{s}", .{ tool, arguments });
        if (self.calls[self.next]) |leaving| allocator.free(leaving);
        self.calls[self.next] = key;
        self.next = (self.next + 1) % no_progress_window;

        var seen: usize = 0;
        var repeats: usize = 0;
        var distinct: usize = 0;
        for (self.calls, 0..) |entry, index| {
            const call = entry orelse continue;
            seen += 1;
            if (std.mem.eql(u8, call, key)) repeats += 1;
            // The first slot holding this text is the one that counts it, so
            // a call in the window three times is one different call.
            var first = true;
            for (self.calls[0..index]) |earlier| {
                const before = earlier orelse continue;
                if (std.mem.eql(u8, before, call)) first = false;
            }
            if (first) distinct += 1;
        }
        return .{ .seen = seen, .repeats = repeats, .distinct = distinct };
    }
};

/// Run one turn: build the request from the current fold, send it, log the
/// reply, and run every tool call the reply asked for. Returns `true` when
/// this turn was the session's last one, because the model answered with no
/// tool call: `run`'s own loop stops there. Returns `false` to ask for
/// another turn.
fn runTurn(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    progress: *Progress,
    watch: *ContextWatch,
    telling: *notices.State,
    turn_index: usize,
) Error!bool {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Before anything this turn does, and before the budget check, because a
    // session the user has already stopped must not spend another turn's
    // money to find that out.
    if (try endIfCanceled(allocator, io, locked, session, deps)) return true;

    // A background command that finished since the last turn. Here, and not
    // between two tool calls of one turn, which is the other place this loop
    // reads the interrupt flag. Two reasons, and either one alone is enough:
    // a turn already in flight cannot act on what it is told, because the
    // model chose its tool calls before any of them ran, and the messages
    // between an assistant turn and its own tool results are the one place a
    // provider requires an exact shape, which a message from the harness
    // inserted in the middle would break. See `deliverFinishedTasks`.
    try recordFinishedTasks(allocator, io, locked, session, deps, .tell_the_agent);

    // A subagent that finished since the last turn, at the same point and for
    // the same reasons. See `recordFinishedChildren`.
    try recordFinishedChildren(allocator, io, locked, session, deps, .tell_the_agent);

    // **After both drains, and before the request.** After, because what is
    // still running is what a handover would lose, and a task that finished
    // one moment ago is already in the log and loses nothing: asking first
    // would refuse handovers over work that was already safe. Before, because
    // a session about to change hands must not spend a turn's money, and must
    // not compact a context the next owner would compact again.
    if (try endIfHandedOver(allocator, io, locked, session, deps)) return true;

    // **Before the request, because money cannot be un-spent.** Section
    // 10.2. A turn refused here sends nothing at all, which is the fact the
    // test named for it pins.
    if (try refuseForBudget(allocator, io, locked, session, deps)) return true;

    // **Before the request, and from a threshold Chock chose**, so a session
    // compacts at a moment it picked rather than at the one a provider forces
    // on it. This is the trigger that also covers a provider which truncates
    // in silence and never refuses at all. See `watchContext`.
    try watchContext(allocator, io, locked, session, deps, watch, telling);

    const messages = try context.build(arena, session);
    const request = message.Request{
        .model = deps.model,
        // Never touched by a notice, and this is the whole reason notices sit
        // at the end of the context instead. See `Deps.notices`.
        .system = deps.system_prompt,
        .messages = try withNotice(allocator, arena, io, session, deps, telling, turn_index, messages),
        .tools = deps.tool_definitions,
    };

    var piece_watcher: ?PieceWatcher = if (deps.observer) |watching|
        .{ .observer = watching }
    else
        null;
    const reply = try sendWithRetry(
        allocator,
        arena,
        io,
        locked,
        session,
        deps,
        request,
        if (piece_watcher) |*watching| watching.watcher() else null,
    ) orelse return true;
    defer chock_provider.Client.freeUsage(allocator, reply.usage);

    switch (reply.outcome) {
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            const class = chock_provider.failure.classify(status_error.status, status_error.body);

            // **The backstop.** A refusal that says the request was too large
            // is the one refusal that answers itself: fold the context and
            // take the same turn again. A transport fault never reaches here,
            // because `classify` names it something else. See this file's own
            // top comment.
            if (class == .context_overflow) {
                if (try compactNow(allocator, io, locked, session, deps, telling)) {
                    watch.warned = false;
                    return false;
                }
                // Nothing left to fold: the kept tail alone is larger than
                // this model can take. Ending here is what stops a session
                // compacting in a circle, and every turn it did is in the log.
                const detail = try std.fmt.allocPrint(
                    allocator,
                    "the request was larger than the model can take, and the context cannot be made " ++
                        "shorter than it already is: {s}",
                    .{status_error.body},
                );
                defer allocator.free(detail);
                _ = try appendAndApply(allocator, io, locked, session, deps, .{
                    .session_end = .{ .reason = .errored, .detail = detail },
                });
                return true;
            }

            const detail = try std.fmt.allocPrint(
                allocator,
                "the model backend answered with status {d} ({s}): {s}",
                .{ @intFromEnum(status_error.status), @tagName(class), status_error.body },
            );
            defer allocator.free(detail);
            _ = try appendAndApply(allocator, io, locked, session, deps, .{
                .session_end = .{ .reason = .errored, .detail = detail },
            });
            return true;
        },
        .failed => |failed| {
            defer chock_provider.Client.freeAssembledMessage(allocator, failed.partial);
            // A stall gets a sentence of its own, because the fault is not
            // that something broke. The connection is open and the provider
            // simply stopped saying anything, which is the one case a person
            // watching cannot tell apart from a model still working. See
            // `chock_provider.Client.default_gap_ns`.
            const detail = if (failed.err == error.StreamStalled) try std.fmt.allocPrint(
                allocator,
                "the model backend went quiet partway through its reply: nothing at all arrived " ++
                    "for long enough that the session stopped waiting",
                .{},
            ) else try std.fmt.allocPrint(
                allocator,
                "the reply from the model backend did not complete: {s}",
                .{@errorName(failed.err)},
            );
            defer allocator.free(detail);
            _ = try appendAndApply(allocator, io, locked, session, deps, .{
                .session_end = .{ .reason = .errored, .detail = detail },
            });
            return true;
        },
        .message => |reply_message| {
            defer chock_provider.Client.freeAssembledMessage(allocator, reply_message);

            // The event before the action: the whole reply, tool_use parts
            // included, is durable in the log before any of those tool
            // calls run. See this file's own top comment.
            _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
                .role = .assistant,
                .content = reply_message.content,
                .model_alias = deps.model_alias,
            } });
            // The agent has just spoken, which is one of the three times the
            // clock notice reports. See `notices.State.observeEvent`.
            telling.observeEvent(nowMs(io, deps), true);

            // **Before the tool loop, because a turn that said nothing asked
            // for nothing.** See `saidSomething` for what counts, and
            // `chock_proto.event.SessionEndReason.empty_response` for the
            // measured session that made this necessary.
            if (!saidSomething(reply_message)) {
                const detail = try emptyReplyDetail(allocator, reply.stopReason(), turn_index);
                defer allocator.free(detail);
                _ = try appendAndApply(allocator, io, locked, session, deps, .{
                    .session_end = .{ .reason = .empty_response, .detail = detail },
                });
                return true;
            }

            var ran_a_tool = false;
            for (reply_message.content) |part| {
                if (part != .tool_use) continue;
                // Before the call runs, not after: the whole point is that a
                // call which has already been answered the same way twice
                // has nothing left to tell anybody. See
                // `no_progress_repeats`.
                const observed = try progress.observe(
                    allocator,
                    part.tool_use.tool,
                    part.tool_use.arguments,
                );
                if (observed.isLoop()) {
                    const detail = try std.fmt.allocPrint(
                        allocator,
                        "the last {d} tool calls were only {d} different calls, and {s} with the " ++
                            "same arguments was {d} of them",
                        .{ observed.seen, observed.distinct, part.tool_use.tool, observed.repeats },
                    );
                    defer allocator.free(detail);
                    _ = try appendAndApply(allocator, io, locked, session, deps, .{
                        .session_end = .{ .reason = .no_progress, .detail = detail },
                    });
                    return true;
                }
                // Kept for the next turn, not for this one: a turn already in
                // flight cannot act on what it is doing. See
                // `notices.State.observeCall`.
                try telling.observeCall(
                    allocator,
                    part.tool_use.tool,
                    part.tool_use.arguments,
                    observed.repeats,
                );
                ran_a_tool = true;
                try runTool(allocator, io, locked, session, deps, telling, part.tool_use);
                // Between two tool calls of one turn, and after the result of
                // the one just run is in the log. A turn that asked for six
                // tool calls is minutes of work, and a user who pressed
                // Ctrl-C in the middle of it should not have to sit through
                // the other five.
                if (try endIfCanceled(allocator, io, locked, session, deps)) return true;
            }

            if (!ran_a_tool) {
                _ = try appendAndApply(allocator, io, locked, session, deps, .{
                    .session_end = .{ .reason = .finished, .detail = "" },
                });
                return true;
            }
            return false;
        },
    }
}

/// Whether one model turn carried anything the session can use.
///
/// **A tool call, or text with a character in it, and nothing else counts.**
/// Those are the only two things a turn can carry that go anywhere: a tool call
/// is work to do, and text is the answer a person reads. A reply that holds
/// only a reasoning block is a model that thought and then said nothing, which
/// leaves the loop with nothing to run and the person with nothing to read, so
/// it is empty by this measure even though its content list is not.
///
/// Whitespace alone is not an answer. A turn of one newline reads as `finished`
/// with an empty answer, which is the same false OK as no content at all.
fn saidSomething(reply: chock_provider.message.Message) bool {
    for (reply.content) |part| switch (part) {
        .tool_use => return true,
        .text => |text| if (std.mem.trim(u8, text, &std.ascii.whitespace).len != 0) return true,
        else => {},
    };
    return false;
}

/// What the log says about a turn that carried nothing. Caller owns the result.
///
/// **The provider's own word first, when it sent one.** `stop_reason` is
/// `end_turn`, `max_tokens`, `refusal`, or whatever else the provider said, and
/// a Chock that invented a reason of its own while holding that word would be
/// throwing away the only explanation anybody has. See
/// `chock_provider.Client.Delta.stop_reason`.
///
/// **The turn number, because the first turn and a later one are different
/// facts.** A session whose first turn carried nothing did no work at all. A
/// session whose fifth turn carried nothing did four turns of work that is
/// still in the log and still in the workspace. Both end the same way, because
/// the loop has no signal but this one for "the model is done", and a model
/// that is done says so in words. The number is what tells a person which of
/// the two they are reading.
fn emptyReplyDetail(
    allocator: std.mem.Allocator,
    stop_reason: []const u8,
    turn_index: usize,
) std.mem.Allocator.Error![]u8 {
    const which = if (turn_index == 0)
        "the first turn of the session"
    else
        "a turn of the session";
    return if (stop_reason.len == 0) std.fmt.allocPrint(
        allocator,
        "the model backend answered {s} with no text and no tool call, and gave no stop reason",
        .{which},
    ) else std.fmt.allocPrint(
        allocator,
        "the model backend answered {s} with no text and no tool call, and said it stopped " ++
            "because of {s}",
        .{ which, stop_reason },
    );
}

/// Send one turn's request, and send it again after a wait when the provider
/// refused it for a reason a wait fixes.
///
/// Returns the reply the turn acts on, or null when the session was ended
/// here, which tells `runTurn` this turn was the last one.
///
/// **A 429 is the most recoverable error there is.** It names its own limit,
/// and it often names how long to wait as well. Before this existed a session
/// measured on 2026-08-22 ended on one, with 105 changed files in its
/// workspace and a `Retry-After` in the response nothing read. See
/// `chock_provider.retry` for the wait itself, and this file's own top comment
/// for why this is separate from compaction and must stay separate.
///
/// Hand one request to the provider, once.
///
/// **This is the only place in `chock-core` that calls a
/// `chock_provider.Client`**, which is what makes it the only place secret
/// redaction has to be. A second call to `Client.sendAndAssemble` or
/// `Client.sendAndAssembleWatching` anywhere in this library would be a way
/// past `deps.redact`, so there is not one, and the two tests named for the
/// two paths through this function are what keep it that way: one goes
/// through `sendWithRetry` for an ordinary turn, the other through
/// `askForSummary` for a compaction.
///
/// **This seam is the smaller of the two, and it is not the important one.**
/// Nearly all of a request is built out of the log by `context.build`, and
/// `appendAndApply` already cleaned every record the log holds. What this
/// catches is the part of a request that was never a record: the system
/// prompt, which the caller hands to this loop directly. See
/// `lib/chock-core/redact.zig`'s own top comment.
///
/// `arena` is the turn's arena, so the rewritten request lives exactly as
/// long as the turn that sent it. An inert `deps.redact`, which is the
/// default, allocates nothing at all.
fn sendOnce(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    deps: Deps,
    request: message.Request,
    watcher: ?chock_provider.Client.Watcher,
) Error!chock_provider.Client.AssembledReply {
    const outbound = try redact.request(arena, deps.redact, request);
    return chock_provider.Client.sendAndAssembleWatching(deps.client, allocator, outbound, watcher);
}

fn sendWithRetry(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    request: message.Request,
    watcher: ?chock_provider.Client.Watcher,
) Error!?chock_provider.Client.AssembledReply {
    const sleeper = deps.sleeper orelse retry.SystemSleeper.sleeper();

    var attempts: usize = 0;
    while (true) {
        attempts += 1;
        const answer = try sendOnce(allocator, arena, deps, request, watcher);
        // This iteration owns `answer` until it either hands it back to the
        // caller or frees it below. The flag is what keeps a fault between
        // here and one of those two, an allocation failure or a log that
        // cannot be written, from leaking a refusal body of several kilobytes
        // on every attempt.
        var held = true;
        errdefer if (held) freeReply(allocator, answer);

        try appendUsage(allocator, io, locked, session, deps, answer.usage);

        const refusal = switch (answer.outcome) {
            .status_error => |status_error| status_error,
            // A reply, or a broken stream. Neither is this function's
            // business: see this file's own top comment on why a broken
            // connection is not retried here.
            .message, .failed => return answer,
        };

        const class = chock_provider.failure.classify(refusal.status, refusal.body);
        const decision = retry.decide(
            deps.retry,
            class,
            attempts,
            refusal.retry_after_s,
            retry.jitterFrom(io),
        );

        switch (decision) {
            .stop => |why| switch (why) {
                // Compaction answers the overflow and the caller answers the
                // rest. Both already read `status_error` themselves.
                .not_retryable => return answer,
                .attempts_spent, .wait_too_long => {
                    const detail = try givingUpDetail(allocator, why, attempts, refusal);
                    defer allocator.free(detail);
                    held = false;
                    freeReply(allocator, answer);
                    _ = try appendAndApply(allocator, io, locked, session, deps, .{
                        .session_end = .{ .reason = .errored, .detail = detail },
                    });
                    return null;
                },
            },
            .wait_ms => |wait_ms| {
                if (deps.observer) |watching| {
                    const notice = try waitingNotice(allocator, deps.retry, class, attempts, wait_ms);
                    defer allocator.free(notice);
                    watching.onNotice(notice);
                }
                // Freed before the wait, not after: the wait can be a minute
                // long, and a body of several kilobytes held across every
                // attempt of every turn is a leak with a slow fuse.
                held = false;
                freeReply(allocator, answer);

                sleeper.sleep(io, wait_ms);

                // A safe point, and the one this function adds. A user who
                // pressed Ctrl-C during a minute of waiting must not then sit
                // through the request the wait was for.
                if (try endIfCanceled(allocator, io, locked, session, deps)) return null;
            },
        }
    }
}

/// Free everything one `AssembledReply` owns, whichever outcome it carried.
/// `sendWithRetry` calls this for a reply it is done with, and the caller of
/// `sendWithRetry` frees the one it is handed the same way it always did.
fn freeReply(allocator: std.mem.Allocator, reply: chock_provider.Client.AssembledReply) void {
    chock_provider.Client.freeUsage(allocator, reply.usage);
    switch (reply.outcome) {
        .status_error => |status_error| allocator.free(status_error.body),
        .message => |said| chock_provider.Client.freeAssembledMessage(allocator, said),
        .failed => |failed| chock_provider.Client.freeAssembledMessage(allocator, failed.partial),
    }
}

/// What the `session.end` says when the retry gives up. **Both numbers are
/// here on purpose**: how many attempts were made, so a user knows the wait
/// happened at all, and what the provider last said, so they know what to fix.
fn givingUpDetail(
    allocator: std.mem.Allocator,
    why: retry.Stop,
    attempts: usize,
    refusal: chock_provider.Client.StatusError,
) std.mem.Allocator.Error![]u8 {
    return switch (why) {
        .attempts_spent => std.fmt.allocPrint(
            allocator,
            "the model backend refused {d} attempts at the same request, and the last one " ++
                "answered with status {d}: {s}",
            .{ attempts, @intFromEnum(refusal.status), refusal.body },
        ),
        .wait_too_long => std.fmt.allocPrint(
            allocator,
            "the model backend asked for a wait of {d} seconds after {d} attempts, which is " ++
                "longer than this session waits, and it answered with status {d}: {s}",
            .{
                refusal.retry_after_s orelse 0,
                attempts,
                @intFromEnum(refusal.status),
                refusal.body,
            },
        ),
        // `decide` never returns this one with a wait or a give up of its
        // own: the caller answers it. A message here would be a message
        // nobody reads.
        .not_retryable => unreachable,
    };
}

/// The one line a person watching sees while the session waits. See
/// `Observer.onNotice` for why a wait that says nothing is worse than no wait.
fn waitingNotice(
    allocator: std.mem.Allocator,
    policy: retry.Policy,
    class: chock_provider.failure.Class,
    attempts: usize,
    wait_ms: u64,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "the model backend answered {t}, so this turn waits {d}.{d:0>1} seconds and asks again " ++
            "(attempt {d} of {d})",
        .{ class, wait_ms / 1000, (wait_ms % 1000) / 100, attempts + 1, policy.max_attempts },
    );
}

/// Stop the session cleanly when the caller has asked it to. Returns true
/// when the session was stopped, which is what tells `runTurn` to say this
/// turn was the last one.
fn endIfCanceled(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
) Error!bool {
    const asked = deps.canceled orelse return false;
    if (!asked()) return false;

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .session_end = .{
        .reason = .canceled_by_user,
        .detail = "the session was asked to stop, and stopped at its next safe point",
    } });
    return true;
}

/// Give this session to another process, when one has asked for it and the
/// caller has agreed. Returns true when the session was stopped, which is what
/// tells `runTurn` this turn was the last one.
///
/// **The event is what makes this a handover and not a stop.** A log that
/// ended with `canceled_by_user` would tell the next reader that a person said
/// no, and the fold is the truth about a session, so the next owner reads this
/// reason and the tools that report on a session read it too. `src/main.zig`
/// gives it an exit code of its own for the same reason.
///
/// **This appends nothing else**, and in particular it writes nothing about the
/// workspace. The workspace is named by the `workspace.open` event that the
/// caller already wrote when it built one, so the next owner finds it by
/// folding the log and not by reading a note this function left.
///
/// The counts come from the two tables the caller owns. A caller with neither
/// says nothing is in flight, which is true: a session with no table cannot
/// have started a background task or a background child.
fn endIfHandedOver(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
) Error!bool {
    const asked = deps.handover orelse return false;
    const in_flight = InFlight{
        .tasks = if (deps.tasks) |table| table.runningCount() else 0,
        .children = if (deps.children) |table| table.runningCount() else 0,
    };
    if (!asked(io, in_flight)) return false;

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .session_end = .{
        .reason = .handed_over,
        .detail = "another process asked for this session, and this one let go of it at a turn boundary",
    } });
    return true;
}

/// Whether a finished task is only recorded, or recorded and told to the agent.
const TaskDelivery = enum {
    /// Both events: the record, and the message that carries it into the
    /// model's context. What the top of every turn does.
    tell_the_agent,
    /// The record alone. What the end of a session does: there is no turn left
    /// to read a message, and appending one after `session.end` would put words
    /// in a conversation that is over.
    record_only,
};

/// Record every background task that finished since the last turn, and tell
/// the agent about it.
///
/// **Two events per task, and neither one replaces the other.** The
/// `task.complete` event is the record: that the task ran, how it ended, where
/// the output is, and how large it was, and a replay reads those from a typed
/// event rather than from a sentence. The `message` event is the delivery: only
/// a message re-enters the model's context, per
/// `lib/chock-proto/state.zig`'s own fold, so a `task.complete` alone would be
/// a fact the log holds and the agent never hears.
///
/// **The agent acting on a result therefore leaves a trace of having been
/// told**, which is the property that makes a background result reviewable at
/// all: without it, a turn that suddenly knows a build failed reads as a model
/// that guessed.
///
/// **Neither event carries the output.** A build writes megabytes, and the log
/// is the one file a session cannot afford to bloat.
///
/// **A task still running when the session ends is not recorded here**, and
/// cannot be: the log is closed at that point and nothing will read a message
/// written into it. The `tool.call` that started it is still in the log, so a
/// reader sees that it was asked for, and `src/run.zig` ends it rather than
/// waiting out its own bound for work nobody will read.
fn recordFinishedTasks(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    delivery: TaskDelivery,
) Error!void {
    const table = deps.tasks orelse return;
    const finished = try table.take(allocator);
    defer task_table.freeCompletions(allocator, finished);

    for (finished) |one| {
        _ = try appendAndApply(allocator, io, locked, session, deps, .{ .task_complete = .{
            .task_id = one.id,
            .command = one.command,
            .status = one.status,
            .code = one.code,
            .output_path = one.output_path,
            .output_bytes = one.output_bytes,
            .truncated = one.truncated,
        } });

        if (delivery == .record_only) continue;

        const text = try taskFinishedText(allocator, one);
        defer allocator.free(text);
        const content = [_]event.ContentPart{.{ .text = text }};
        _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
            .role = .user,
            .content = &content,
        } });
    }
}

/// What the agent is told about one finished task. Caller owns the result.
///
/// It names the file rather than quoting it, and it says how to read it: the
/// output is bounded at `tasks.max_output_bytes`, which is far past what a
/// model may take in one result, so "here is the whole thing" is not an option
/// this can offer.
fn taskFinishedText(
    allocator: std.mem.Allocator,
    one: task_table.Completion,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.print(allocator, "[chock] the background task {s} finished: {s}\n", .{ one.id, one.command });
    switch (one.status) {
        .exited => try text.print(allocator, "It exited with status {d}.\n", .{one.code}),
        .signaled => try text.print(allocator, "A signal ended it: signal {d}.\n", .{one.code}),
        .timed_out => try text.print(
            allocator,
            "It ran past its {d} minute limit and was stopped, so the work is not finished.\n",
            .{task_table.default_timeout_ns / (60 * std.time.ns_per_s)},
        ),
        .did_not_run => try text.appendSlice(
            allocator,
            "It produced no exit status: read the output for why.\n",
        ),
        .unknown => |name| try text.print(allocator, "It ended as {s}.\n", .{name}),
    }
    try text.print(
        allocator,
        "Its output is {d} bytes at {s}. That file is read only. Read it with run_command, for " ++
            "example {{\"argv\":[\"tail\",\"-n\",\"40\",\"{s}\"]}}.\n",
        .{ one.output_bytes, one.output_path, one.output_path },
    );
    if (one.truncated) {
        try text.appendSlice(
            allocator,
            "The command wrote more than the file kept, so the end of the output is missing.\n",
        );
    }
    return text.toOwnedSlice(allocator);
}

/// Record every subagent that finished since the last turn, and tell the agent
/// about it.
///
/// **The same two events, and the same reason for both**, as
/// `recordFinishedTasks`: `agent.complete` is the record a replay reads, and
/// only a `message` re-enters the model's context. A parent that acts on a
/// child's answer therefore leaves a trace of having been told, which is what
/// makes a subagent's answer reviewable at all.
///
/// **The parent appends both, because the child cannot write the parent's
/// log.** The parent holds the exclusive lock on it for the whole session, and
/// the parent is the process that started the child, so the parent is what sees
/// it end. That rule holds whichever shape the spawn took: see `runSpawn`,
/// which appends the very same event for a child it waited for.
///
/// **Neither event carries the child's turns.** The child has a log of its own,
/// and `agent.complete` names it: see `lib/chock-core/subagent.zig`.
fn recordFinishedChildren(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    delivery: TaskDelivery,
) Error!void {
    const table = deps.children orelse return;
    const finished = try table.take(allocator);
    defer subagent.freeCompletions(allocator, finished);

    for (finished) |one| {
        _ = try appendAndApply(allocator, io, locked, session, deps, .{ .agent_complete = .{
            .child_session = one.child_session,
            .child_agent_kind = one.agent_kind,
            .outcome = one.outcome,
            .result = one.result,
            .scratchpad_path = one.scratchpad_path,
        } });

        if (delivery == .record_only) continue;

        const text = try childFinishedText(allocator, one);
        defer allocator.free(text);
        const content = [_]event.ContentPart{.{ .text = text }};
        _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
            .role = .user,
            .content = &content,
        } });
    }
}

/// What the agent is told about one subagent it did not wait for. Caller owns
/// the result.
///
/// It carries the answer itself, which `subagent.readReport` already bounded at
/// `subagent.max_result_bytes`, and names the scratchpad rather than reading
/// it: a child answers with a verdict and a path, so a parent with several
/// children does not spend its whole context reading.
fn childFinishedText(
    allocator: std.mem.Allocator,
    one: subagent.Completion,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.print(
        allocator,
        "[chock] the subagent {s} ({s}) you started earlier has finished: {s}.\n",
        .{ one.child_session, one.agent_kind, one.outcome.wireName() },
    );
    try text.print(allocator, "What it answered: {s}\n", .{one.result});
    if (one.scratchpad_path.len != 0) {
        try text.print(
            allocator,
            "Anything longer than that answer is in its scratchpad at {s}.\n",
            .{one.scratchpad_path},
        );
    }
    return text.toOwnedSlice(allocator);
}

/// Append the `usage` event for one turn: what the provider reported, plus
/// the fields only this loop knows, plus a cost computed from the price table
/// when the provider reported none.
///
/// Written for every turn, including one the provider refused, because the
/// refusal still consumed tokens. A provider that reported nothing at all
/// still gets an event, with `cost` unknown and every count zero: **that is
/// the log saying the session is unmeasurable**, and it is a different record
/// from a turn that was free.
fn appendUsage(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    reported: event.Usage,
) Error!void {
    var usage = reported;
    usage.model = deps.model;
    usage.model_alias = deps.model_alias;

    const cost = chock_cost.prices.costFor(deps.model, reported, deps.billing);
    // The version is stamped only on a number this table produced. A cost
    // the provider itself reported is the provider's, and claiming a table
    // version for it would send somebody looking in the wrong place.
    if (cost == .known and reported.cost == .unknown) {
        usage.price_table_version = chock_cost.prices.version;
    }
    usage.cost = cost;

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .usage = usage });
}

/// Check the cap before a request goes out, and stop the session cleanly when
/// this turn would pass it. Returns true when the session was stopped.
///
/// **Hitting a cap is an approval, not a crash**, and this needs no new
/// mechanism: the broker already carries a decision to the user and back
/// through `approval.request` and `approval.response`. So this appends the
/// request, naming the cap, the total so far and what the next turn is
/// projected to cost, and then ends the session.
///
/// **Nothing answers that request yet**, because `Loop.run` holds no broker:
/// see this file's own top comment on the approval seam. An unanswered request
/// is a refusal, and a refusal is the safe direction for a budget, so ending
/// here is that refusal. Everything the session did so far is already in the
/// log, which is what stops a cap from losing work the user already paid for.
fn refuseForBudget(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
) Error!bool {
    const cap = deps.budget orelse return false;
    const spend = session.spend;
    // Decided by the project owner: a cap over an unknown cost cannot be
    // enforced. The session was warned about that once at the start, by the
    // caller, and then runs. Refusing here instead would block work to protect
    // a number Chock cannot measure.
    if (!spend.enforceable()) return false;
    if (spend.turns == 0) return false;
    // A cap written in one currency and turns billed in another cannot be
    // compared at all, and inventing an exchange rate here would be worse
    // than not enforcing: the same rule as an unknown cost, one level up.
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, cap.currency)) return false;

    // The projection is the mean of the turns so far. A turn's cost depends
    // on how much context it carries, which grows through a session, so the
    // mean under estimates the next turn slightly and the cap can be passed
    // by that much. The alternative, projecting the largest turn so far,
    // stops a session early every time one turn was unusually big. Chock
    // takes the small overshoot: the total is updated after the reply lands
    // anyway, so the cap was never going to be exact to the cent.
    const projected = spend.amount / @as(f64, @floatFromInt(spend.turns));
    if (spend.amount + projected <= cap.max_cost) return false;

    const summary = try std.fmt.allocPrint(
        allocator,
        "the session has spent {d:.4} {s} of a {d:.4} {s} budget, and the next turn is " ++
            "projected to cost about {d:.4} {s}",
        .{ spend.amount, spend.currency, cap.max_cost, cap.currency, projected, spend.currency },
    );
    defer allocator.free(summary);

    _ = try appendAndApply(allocator, io, locked, session, deps, .{
        .approval_request = .{
            .action = budget_action,
            .summary = summary,
            .detail = summary,
            .reason = "the next turn would take the session past the budget in chock.zon",
            .agent_kind = deps.agent_kind,
            // The whole chain, root first, because "a subagent three levels
            // down reached its budget" is the fact the user needs before
            // answering.
            .spawn_chain = deps.spawn_chain,
            // Already past: nothing here waits, so the request is expired the
            // moment it is written. A reader that folds this log sees a refusal
            // and not a question still open.
            .timeout_at_ms = std.Io.Timestamp.now(io, .real).toMilliseconds(),
            .tool_call_id = "",
        },
    });
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .approval_response = .{
        .request_id = 0,
        .decision = .expired,
        .responder = "",
        .action = budget_action,
        .tool_call_id = "",
    } });

    const detail = try std.fmt.allocPrint(allocator, budget_detail_prefix ++ ": {s}", .{summary});
    defer allocator.free(detail);
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .session_end = .{
        .reason = .budget_reached,
        .detail = detail,
    } });
    return true;
}

/// Look at how full the context is, and either tell the agent a compaction is
/// coming or do one.
///
/// **The notice comes first and it comes on an earlier turn**, because an
/// agent told at the moment of the compaction has no turn left to act on it.
/// `Policy.warn_at` is below `Policy.compact_at` for exactly that. What the
/// notice asks for is a knowledgebase entry, because **memory survives a
/// compaction and context does not**, and the dead ends matter most: an agent
/// that ruled something out, was compacted, and tried it again pays the whole
/// detour a second time.
///
/// Does nothing at all when the context limit is unknown. A guessed limit
/// would compact a session that had plenty of room, and the backstop in
/// `runTurn` already covers a provider that refuses.
fn watchContext(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    watch: *ContextWatch,
    telling: *notices.State,
) Error!void {
    const used = session.last_input_tokens;
    // Zero is "nobody has measured this yet", never "the context is empty":
    // see `Session.last_input_tokens`.
    if (used == 0) return;

    if (compaction.shouldCompact(deps.compaction, used)) {
        if (try compactNow(allocator, io, locked, session, deps, telling)) watch.warned = false;
        return;
    }

    if (!compaction.shouldWarn(deps.compaction, used) or watch.warned) return;

    const limit = deps.compaction.context_limit_tokens.?;
    const at = compaction.thresholdTokens(deps.compaction, deps.compaction.compact_at).?;
    const text = try compaction.noticeText(allocator, used, at, limit, offersMemory(deps));
    defer allocator.free(text);

    // A `system` role message, because the harness is the one speaking. It is
    // an ordinary event in the log, so it reaches the model through the same
    // fold every other turn does, and the compaction that follows folds it
    // away with the rest.
    const parts = [_]event.ContentPart{.{ .text = text }};
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
        .role = .system,
        .content = &parts,
    } });
    watch.warned = true;
}

/// Whether this session offers the tool that writes a note. **A tool that is
/// not offered is never named**, the same rule the prompt keeps: naming one
/// costs the agent a turn to find out it does not exist. Read from the
/// definitions the request itself carries, and matched against the enum, so a
/// renamed tool fails the build rather than the session.
fn offersMemory(deps: Deps) bool {
    for (deps.tool_definitions) |definition| {
        if (std.mem.eql(u8, definition.name, @tagName(tools.Tool.write_memory))) return true;
    }
    return false;
}

/// Fold the middle of the context into one summary and append the
/// `compaction` event. Returns false when there was nothing worth folding,
/// which the caller must handle: see `compaction.plan`.
///
/// **The log loses nothing.** This appends one event and `Session.apply`
/// builds the shorter view from it, so a replay of the same log reaches the
/// same context and the user can still read every turn that was folded.
///
/// **The model writes the summary, and the harness stands in when it cannot.**
/// A model produces a far better summary, because it knows which of the last
/// thirty turns mattered, and it costs one call. The harness one is free and
/// says only what happened. The event records which of the two answered:
/// `model_alias` is the alias when a model wrote it and empty when Chock did,
/// so a thin summary is never left ambiguous.
fn compactNow(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    telling: *notices.State,
) Error!bool {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `folding.folded` borrows `session.context`, so the transcript and the
    // fallback summary are both built from it before anything appends an
    // event that would fold the context again. The `usage` event
    // `askForSummary` writes does not touch the context, which is why it can
    // sit between them.
    const folding = try compaction.plan(arena, session, deps.compaction) orelse return false;
    const rendered = try compaction.transcript(arena, folding.folded, deps.compaction);

    var summary: []const u8 = undefined;
    var wrote_it: []const u8 = "";
    if (try askForSummary(allocator, arena, io, locked, session, deps, rendered)) |text| {
        summary = text;
        wrote_it = deps.model_alias;
    } else {
        summary = try compaction.harnessSummary(arena, folding.folded, deps.compaction);
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .compaction = .{
        .summary = summary,
        .from_id = folding.from_id,
        .through_id = folding.through_id,
        .kept_ranges = folding.kept_ranges,
        .model_alias = wrote_it,
    } });

    // **Here and not at either caller**, because both of them fold for
    // different reasons and a second author would arm one and forget the
    // other. What the notice does with this depends on the session: one whose
    // agent keeps no task list is told nothing at all. See
    // `notices.State.observeCompaction`.
    telling.observeCompaction();
    return true;
}

/// Ask the model for the summary, or null when it could not give one.
///
/// **The request carries one user message and no tools.** The folded span
/// cannot be replayed as real messages: a `tool` role message needs the
/// `tool_use` part it answers beside it, and a span cut anywhere breaks that
/// pairing, which providers refuse outright. So the span is rendered to text
/// and bounded. See `compaction.transcript`.
///
/// **The call's own usage is recorded like any other turn's.** It is a real
/// model call and it costs real money, so a budget checked against a total
/// that skipped it would under count exactly the sessions that compact most.
///
/// Null on every refusal and every empty reply, never an error: a compaction
/// that could not reach the model still has to happen, and the fallback in
/// `compactNow` is what happens instead. An allocation failure is the one
/// thing that still escapes, because at that point there is nothing left to
/// build a fallback with either.
fn askForSummary(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    rendered: []const u8,
) Error!?[]const u8 {
    const asked = try compaction.summaryPrompt(arena, rendered);
    const parts = [_]message.ContentPart{.{ .text = asked }};
    const messages = [_]message.Message{.{ .role = .user, .content = &parts }};
    const request = message.Request{
        .model = deps.model,
        .system = compaction.summary_system,
        .messages = &messages,
    };

    // Through `sendOnce`, and not through `Client.sendAndAssemble` directly:
    // the text a compaction sends is the context itself, rendered, so it
    // carries whatever a tool result carried. A second road to the provider
    // is how a redactor is bypassed. See `sendOnce`.
    const reply = sendOnce(allocator, arena, deps, request, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer chock_provider.Client.freeUsage(allocator, reply.usage);
    try appendUsage(allocator, io, locked, session, deps, reply.usage);

    switch (reply.outcome) {
        .status_error => |status_error| {
            allocator.free(status_error.body);
            return null;
        },
        .failed => |failed| {
            chock_provider.Client.freeAssembledMessage(allocator, failed.partial);
            return null;
        },
        .message => |reply_message| {
            defer chock_provider.Client.freeAssembledMessage(allocator, reply_message);
            var out: std.ArrayList(u8) = .empty;
            for (reply_message.content) |part| {
                if (part == .text) try out.appendSlice(arena, part.text);
            }
            const joined = try out.toOwnedSlice(arena);
            // A reply of only whitespace, or of nothing but reasoning, is a
            // reply with no summary in it. The harness one is better than an
            // empty summary standing in for thirty turns.
            if (std.mem.trim(u8, joined, " \t\r\n").len == 0) return null;
            return joined;
        },
    }
}

/// Append the `tool.call` event, run the call, then append the `tool.result`
/// event and the `message` event that feeds the result back into the
/// context for the next turn. See this file's own top comment for the
/// ordering this exists to guarantee, and for why `deps.tool_runner`
/// failing outright, `DispatchError`, still does not end the session: it
/// becomes an `is_error` result the model can read and try something else
/// with, the same as an ordinary failed command already does.
fn runTool(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    telling: *notices.State,
    tool_use: message.ToolCall,
) Error!void {
    const call = event.ToolCall{
        .call_id = tool_use.call_id,
        .tool = tool_use.tool,
        .arguments = tool_use.arguments,
    };
    // Written before dispatch runs: a crash here still leaves proof in the
    // log that the model asked for this call, even if it never finishes.
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .tool_call = call });

    // **An arbitrator holds no tools, and this is where that is enforced for
    // the four the tool runner never sees.** `spawn_agent`, `update_plan`,
    // `restrict_self` and `set_title` are answered by this file, so a gate that
    // sat only in
    // `tools.Registry.dispatchWith` would leave an arbitrator able to start a
    // subagent with a tool set of its own. See `Deps.role`.
    //
    // The call and its result are still appended, like every other, so the log
    // of a reviewer that tried shows what it tried.
    const dispatched = if (!deps.role.holdsTools())
        event.ToolResult{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, tools.arbitrator_holds_no_tool),
            .is_error = true,
            .truncated = false,
        }
    else if (std.mem.eql(u8, call.tool, spawn_tool_name))
        try runSpawn(allocator, io, locked, session, deps, call)
    else if (std.mem.eql(u8, call.tool, plan_tool_name))
        try runPlanUpdate(allocator, io, locked, session, deps, call)
    else if (std.mem.eql(u8, call.tool, restrict_tool_name))
        try runRestrictSelf(allocator, io, locked, session, deps, call)
    else if (std.mem.eql(u8, call.tool, fetch_tool_name))
        try runFetch(allocator, io, session, deps, call)
    else if (std.mem.eql(u8, call.tool, ask_tool_name))
        try runAskUser(allocator, io, deps, call)
    else if (std.mem.eql(u8, call.tool, title_tool_name))
        try runSetTitle(allocator, io, locked, session, deps, call)
    else
        deps.tool_runner.dispatch(allocator, io, call) catch |err| event.ToolResult{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try std.fmt.allocPrint(allocator, "tool dispatch failed: {s}", .{@errorName(err)}),
            .is_error = true,
            .truncated = false,
        };
    defer allocator.free(dispatched.call_id);
    defer allocator.free(dispatched.output);
    // **Only when there is one**, because the empty default is a constant and
    // not an allocation. See `event.ToolResult.note`.
    defer if (dispatched.note.len != 0) allocator.free(dispatched.note);

    // **The one place output that is not text is stood in for.** See
    // `tools.outputForModel`: bytes that are not valid UTF-8 serialize as a
    // JSON array rather than a JSON string, which changes the shape of a
    // content part and ends the session with a provider 400, and which a
    // replay of the same log cannot parse back either. The check belongs
    // here and not in an adapter, because every adapter would need its own
    // copy and the second one would be forgotten. It belongs after
    // `deps.tool_runner`, and not only inside `tools.Registry.dispatch`,
    // for the same reason one level down: `ToolRunner` is an interface, and a
    // runner in its own process comes later, so a check that only ran inside
    // today's one implementation would be a check the next implementation has
    // to remember.
    const note = try tools.outputForModel(allocator, dispatched.output);
    defer if (note) |owned| allocator.free(owned);
    var result = dispatched;
    if (note) |owned| result.output = owned;

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .tool_result = result });

    // What this read found, so that the next turn can be told when a read
    // found nothing new. After the result is in the log and before anything
    // else, because the fact is about this result and not about the turn.
    try noteRead(allocator, telling, result, call);

    // The turn that actually re-enters the context: tool.result itself does
    // not, per lib/chock-proto/state.zig's own fold, only a message event
    // does. Role .tool is the shape an OpenAI compatible history expects
    // for a tool's own answer: see lib/chock-proto/event.zig's own doc
    // comment on Role.tool.
    //
    // **`result.note` is not here, and that is the whole guarantee behind
    // it.** Only these three fields become a content part, so Chock's own
    // sentence to the person never reaches the model. See
    // `event.ToolResult.note`.
    const feedback = [_]event.ContentPart{.{ .tool_result = .{
        .call_id = result.call_id,
        .output = result.output,
        .is_error = result.is_error,
    } }};
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
        .role = .tool,
        .content = &feedback,
    } });
}

/// The name of the tool a model calls to start a subagent. Read from the
/// `tools.Tool` enum itself, so the name the loop matches on and the name the
/// model is offered cannot drift apart.
pub const spawn_tool_name = @tagName(tools.Tool.spawn_agent);

/// What a `spawn_agent` call gets when the limits allow a subagent and this
/// caller gave `Loop.run` no way to start one.
///
/// **A session with no spawner is a real case, not a stub.** Every test of
/// this loop drives one, and so does any caller that runs a session without
/// the session directories, the credential, and the single threaded process a
/// child needs. The model is told exactly that, because a tool that answered
/// "done" would have the model wait for work nobody is doing.
pub const spawn_has_no_spawner_detail = "no subagent was started: the limits in chock.zon allow " ++
    "one, and this session was started with no way to run a child process. Do the work yourself.";

/// What a `spawn_agent` call gets when the parent has already promised every
/// last unit of its own budget. See `chock_core.subagent.budgetSlice`: a slice
/// of nothing is not a session, it is a child that would be refused on its
/// first turn.
/// What a `spawn_agent` call that asked to carry on gets when this session was
/// started with no way to run a child beside its own work. See `Deps.children`.
///
/// **It names the other shape**, because the work can still be done: a spawn
/// that waits needs nothing this session lacks.
pub const spawn_cannot_carry_on_detail = "no subagent was started: this session cannot run a " ++
    "subagent while it works. Ask again without \"background\", and the subagent's answer comes " ++
    "back in that call.";

pub const spawn_no_budget_detail = "no subagent was started: this session has spent or promised " ++
    "the whole budget in chock.zon, so there is nothing left to give a subagent. Do the work " ++
    "yourself, or stop and say what is left.";

/// Answer a `spawn_agent` call, in place of the tool runner.
///
/// **A spawn is not a sandboxed tool call and must not be one.** It is
/// measured against two numbers that only the session holds: how deep this
/// agent is in the spawn tree, which is the length of `deps.spawn_chain`, and
/// how many subagents this agent has already started, which is the number of
/// `session.spawn` events `session` has folded. A `tools.Registry` holds
/// neither, so it refuses a spawn outright: see `tools.spawn_needs_a_session`.
///
/// The width comes from the folded log and never from a counter of this
/// call's own, so a session that is resumed, or handed over to the daemon,
/// counts the children it really has rather than starting again at zero.
///
/// **The limits are answered before the arguments are read.** A refusal that
/// first complained about a missing field would hide the limit that is the
/// real answer, and the limit is true whatever the call said.
///
/// ## Two events, and the order they are in is the point
///
/// `session.spawn` is appended **before** the child runs, and `agent.complete`
/// after it ends. That is the rule the whole log keeps: an event is written
/// before the act it describes happens, so a crash in between still leaves
/// proof that the child was asked for. It is also what makes the width count
/// right: a parent that died mid spawn resumes with that child already
/// counted.
fn runSpawn(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    const standing = subagents.Standing{
        .depth = deps.spawn_chain.len + 1,
        .width = session.children.items.len,
    };
    if (subagents.check(deps.subagents, standing)) |refusal| {
        return spawnRefusal(
            allocator,
            call,
            try subagents.explain(allocator, refusal, deps.subagents, standing),
        );
    }

    const spawner = deps.spawner orelse return spawnRefusal(
        allocator,
        call,
        try allocator.dupe(u8, spawn_has_no_spawner_detail),
    );

    const parsed = std.json.parseFromSlice(
        tools.SpawnAgentArgs,
        allocator,
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return spawnRefusal(allocator, call, try allocator.dupe(
        u8,
        spawn_tool_name ++ " needs a JSON object with the fields: \"agent_kind\", \"task\"",
    ));
    defer parsed.deinit();

    if (parsed.value.agent_kind.len == 0 or parsed.value.task.len == 0) {
        return spawnRefusal(allocator, call, try allocator.dupe(
            u8,
            "no subagent was started: \"agent_kind\" and \"task\" both have to say something. " ++
                "A subagent reads the task and nothing else.",
        ));
    }

    // What is left of this session's cap, divided by the children the limits
    // still allow. A slice and not the whole remainder: see
    // `chock_core.subagent.budgetSlice`. The cap covers the tree and not each
    // agent in it.
    const committed = subagent.committedToChildren(session.children.items, deps.budget);
    const children_left = deps.subagents.max_width - standing.width;
    const slice = subagent.budgetSlice(deps.budget, session.spend, committed, children_left);
    if (slice == null and subagent.nothingLeft(deps.budget, session.spend, committed)) {
        return spawnRefusal(allocator, call, try allocator.dupe(u8, spawn_no_budget_detail));
    }

    const request = subagent.Request{
        .agent_kind = parsed.value.agent_kind,
        .task = parsed.value.task,
        .shape = if (parsed.value.result_fields) |fields|
            if (fields.len == 0) .prose else .{ .schema = fields }
        else
            .prose,
        .reason = subagent.reasonFor(parsed.value.task),
        .budget = slice,
    };

    // **Which shape the spawn asked for, answered before anything is built.** A
    // caller with no table cannot run a child beside the parent's own work, and
    // a spawn that asked to carry on is told so rather than quietly waiting
    // instead: a model that thought its turn would continue and found it had
    // not is a model that planned the wrong next step.
    const mode: subagent.Mode = if (parsed.value.background orelse false) .carry_on else .wait;
    if (mode == .carry_on and deps.children == null) {
        return spawnRefusal(allocator, call, try allocator.dupe(u8, spawn_cannot_carry_on_detail));
    }

    const prepared = spawner.prepare(allocator, io, request) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ChildNotStarted => return spawnRefusal(allocator, call, try allocator.dupe(
            u8,
            "no subagent was started: the session it needs could not be built. The reason is on " ++
                "this run's own output.",
        )),
    };
    defer subagent.freePrepared(allocator, prepared);

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .session_spawn = .{
        .child_session = prepared.child_session,
        .child_agent_kind = request.agent_kind,
        .reason = request.reason,
        .budget_max_cost = if (slice) |one| one.max_cost else 0,
        .budget_currency = if (slice) |one| one.currency else "",
    } });

    // **The turn carries on from here, and the answer arrives later.** No
    // `agent.complete` is appended now: the child has not finished, and an event
    // written for an act that has not happened is the one thing the log never
    // does. `recordFinishedChildren` appends it at the top of the turn after the
    // child ends, which is the same safe point a background command's own
    // completion is delivered at and for the same reason.
    if (mode == .carry_on) {
        try deps.children.?.start(io, request, prepared);
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try spawnStartedText(allocator, prepared, request),
            // Not an error: the spawn did what it was asked to do. The outcome
            // is a separate fact that arrives on a later turn.
            .is_error = false,
            .truncated = false,
        };
    }

    const report = spawner.run(allocator, io, request, prepared) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // The child was recorded as spawned and could not be run. That is a
        // child that never said anything, which is exactly what `died` means,
        // and it reaches the log as one rather than as a gap.
        error.ChildNotStarted => subagent.Report{
            .outcome = .died,
            .result = try allocator.dupe(u8, "the subagent's process could not be started"),
        },
    };
    defer subagent.freeReport(allocator, report);

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .agent_complete = .{
        .child_session = prepared.child_session,
        .child_agent_kind = request.agent_kind,
        .outcome = report.outcome,
        .result = report.result,
        .scratchpad_path = prepared.scratchpad_path,
    } });

    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = try spawnResultText(allocator, prepared, request, report),
        // Anything but a finished child is an error the model has to act on:
        // it did not get the answer it asked for, and a result it read as
        // success would have it carry on as though it had.
        .is_error = report.outcome != .finished,
        .truncated = false,
    };
}

/// A `spawn_agent` call that started nothing. `output` is already owned by the
/// allocator and is handed straight on.
///
/// **Always an error result.** No subagent exists, whichever branch answered,
/// so a model that read one of these as success would wait for an answer that
/// never comes.
fn spawnRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    output: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = output,
        .is_error = true,
        .truncated = false,
    };
}

/// The name of the tool a model calls to keep a task list.
pub const plan_tool_name = @tagName(tools.Tool.update_plan);

/// How many steps one session's task list may hold.
///
/// **Sixty four, which is far more than a plan a person can read and far less
/// than a model can generate.** The list is in the log and a reader has to be
/// able to take it in at a glance, so a bound is what stops a model turning
/// its whole reasoning into steps. A call that would pass the bound changes
/// nothing and says the number, rather than keeping the front of a list the
/// agent did not write.
pub const max_plan_steps: usize = 64;

/// How long one step's identifier, subject, and blocker may be.
///
/// The subject is a few words: it is read in a terminal, one step per line.
/// A model that wants to say more has its own answer to say it in, and the
/// session log to say it in permanently.
pub const max_plan_id_bytes: usize = 32;
pub const max_plan_subject_bytes: usize = 200;
pub const max_plan_blocked_by_bytes: usize = 200;

/// Answer an `update_plan` call, in place of the tool runner.
///
/// **A task list is an event in the session log, and a tool runner has no
/// log.** `Loop.run` holds the exclusive lock on it for the whole session, so
/// this call is answered here for exactly the reason a spawn is: see
/// `runSpawn`, and `tools.plan_needs_a_session`, which is what a caller driving
/// a dispatch with no loop around it gets instead.
///
/// ## Only what changed is appended
///
/// The steps the model sends are compared against the plan the fold already
/// holds, and the event carries the ones that are new or different. Three
/// things follow, and all three matter:
///
/// * **A call that changes nothing appends nothing.** A model that repeats its
///   whole list every turn does not fill the log with copies of it.
/// * A person watching sees one line per step that really moved, which is what
///   makes a crossed off step readable at all.
/// * The fold merges by identifier, so the whole list is still rebuilt by
///   replaying the log from the start. See `chock_proto.state.Plan`.
///
/// ## Nothing here is enforced against the agent
///
/// The list is the agent's own statement of intent. An agent that discovers
/// the task was wrong should change the list, and the value is that the change
/// is visible, not that the plan binds anything. So this refuses a call it
/// cannot record, and it never refuses a plan it disagrees with.
fn runPlanUpdate(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    // A scratch arena for the parse and for the steps this builds. Only the
    // result the caller frees comes out of `allocator`.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSlice(
        tools.UpdatePlanArgs,
        arena,
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return planRefusal(allocator, call, try allocator.dupe(
        u8,
        plan_tool_name ++ " needs a JSON object with one field, \"steps\", holding a list of " ++
            "objects with \"id\", \"subject\" and \"status\".",
    ));

    const given = parsed.value.steps;
    if (given.len == 0) {
        return planRefusal(allocator, call, try allocator.dupe(
            u8,
            "the task list was not changed: \"steps\" was empty. Name the steps you mean to do, " ++
                "or leave the task list alone.",
        ));
    }

    // **Every step is checked before any of them is written.** A call half
    // applied would leave a list the agent did not ask for and cannot see.
    var changed: std.ArrayList(event.PlanStep) = .empty;
    var added: usize = 0;
    for (given) |step| {
        if (planFieldRefusal(step)) |detail| {
            return planRefusal(allocator, call, try allocator.dupe(u8, detail));
        }
        const status = tools.planStatusFor(step.status) orelse return planRefusal(
            allocator,
            call,
            try std.fmt.allocPrint(
                allocator,
                "the task list was not changed: \"{s}\" is not a status. Use one of: {s}.",
                .{ step.status, tools.plan_status_names_text },
            ),
        );

        const blocked_by: []const u8 = step.blocked_by orelse "";
        const known = session.plan.find(step.id);
        if (known == null) added += 1;
        if (!planStepMoved(known, step.subject, status, blocked_by)) continue;
        try changed.append(arena, .{
            .id = step.id,
            .subject = step.subject,
            .status = status,
            .blocked_by = blocked_by,
        });
    }

    if (session.plan.steps.items.len + added > max_plan_steps) {
        return planRefusal(allocator, call, try std.fmt.allocPrint(
            allocator,
            "the task list was not changed: a task list holds at most {d} steps, and this call " ++
                "would make {d}. Keep the list to the work, and say the detail in your answer.",
            .{ max_plan_steps, session.plan.steps.items.len + added },
        ));
    }

    // **Nothing changed, so nothing is appended.** The `tool.call` beside this
    // already records that the agent asked, which is the fact a replay needs.
    if (changed.items.len == 0) {
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try planText(allocator, session.plan, "The task list is already this."),
            .is_error = false,
            .truncated = false,
        };
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{
        .plan_update = .{ .steps = changed.items },
    });

    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        // The whole list, and not only what changed. The model reads this on
        // its next turn, and a list it can see in full is a list it does not
        // have to hold in its attention.
        .output = try planText(allocator, session.plan, "The task list is now:"),
        .is_error = false,
        .truncated = false,
    };
}

/// Why this step cannot be recorded, or null when it can. The bounds are here
/// and not in the fold, because the fold reads logs that are already written
/// and this is the one place that decides what gets written.
fn planFieldRefusal(step: tools.PlanStepArgs) ?[]const u8 {
    if (step.id.len == 0) {
        return "the task list was not changed: every step needs an \"id\", which is the short " ++
            "name you use to report that step again.";
    }
    if (step.id.len > max_plan_id_bytes) {
        return "the task list was not changed: an \"id\" is a short name you repeat, not a " ++
            "sentence.";
    }
    if (step.subject.len > max_plan_subject_bytes) {
        return "the task list was not changed: a \"subject\" is a few words, read one step to " ++
            "a line. Say the detail in your answer instead.";
    }
    const blocked_by: []const u8 = step.blocked_by orelse "";
    if (blocked_by.len > max_plan_blocked_by_bytes) {
        return "the task list was not changed: \"blocked_by\" is a few words.";
    }
    // **A step is read one to a line**, on the terminal while the session runs
    // and in `chock plan` afterwards. A line break inside a step would put one
    // step on two lines and the next reader would take the second half for a
    // step of its own.
    if (hasALineBreak(step.id) or hasALineBreak(step.subject) or hasALineBreak(blocked_by)) {
        return "the task list was not changed: a step is read one to a line, so no part of one " ++
            "may hold a line break. Say the detail in your answer instead.";
    }
    return null;
}

fn hasALineBreak(text: []const u8) bool {
    return std.mem.indexOfAny(u8, text, "\n\r") != null;
}

/// Whether this step says anything the folded plan does not already hold.
///
/// **An empty subject is not a change.** `chock_proto.state.Plan.apply` reads
/// it as "keep the words you have", so a call that only moves a status must
/// not count as a reword.
fn planStepMoved(
    known: ?*chock_proto.state.Plan.Step,
    subject: []const u8,
    status: event.PlanStatus,
    blocked_by: []const u8,
) bool {
    const step = known orelse return true;
    if (!std.mem.eql(u8, step.status.wireName(), status.wireName())) return true;
    if (!std.mem.eql(u8, step.blocked_by, blocked_by)) return true;
    return subject.len != 0 and !std.mem.eql(u8, step.subject, subject);
}

/// An `update_plan` call that recorded nothing. Always an error result: a
/// model that read one of these as success would believe the user could watch
/// a list nobody kept.
fn planRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    output: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = output,
        .is_error = true,
        .truncated = false,
    };
}

/// The whole task list as the model reads it back, one step to a line, under
/// `heading`. Caller owns the result.
fn planText(
    allocator: std.mem.Allocator,
    plan: chock_proto.state.Plan,
    heading: []const u8,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.appendSlice(allocator, heading);
    try text.append(allocator, '\n');
    for (plan.steps.items) |step| {
        try text.print(allocator, "  [{s}] {s} {s}", .{ step.status.wireName(), step.id, step.subject });
        if (step.blocked_by.len != 0) try text.print(allocator, " (waiting on: {s})", .{step.blocked_by});
        try text.append(allocator, '\n');
    }

    const counts = plan.counts();
    try text.print(
        allocator,
        "{d} of {d} left to do. A step you decided not to do is \"abandoned\", never dropped.\n",
        .{ counts.left(), counts.total() },
    );
    return text.toOwnedSlice(allocator);
}

/// The name of the tool a model calls to bind itself.
pub const restrict_tool_name = @tagName(tools.Tool.restrict_self);

/// Answer a `restrict_self` call, in place of the tool runner.
///
/// **Narrowing is free, and widening needs authorisation.**
/// `lib/chock-policy/ratchet.zig` holds the rule and the reasoning; this is the
/// caller.
///
/// **A promise is an event in the session log, and a tool runner has no log.**
/// Answered here for exactly the reason a spawn and a task list are: see
/// `runSpawn`, and `tools.restrict_needs_a_session`, which is what a caller
/// driving a dispatch with no loop around it gets instead.
///
/// ## What this loop decides, and what it does not
///
/// It decides whether the proposal narrows what this session already promised,
/// which is a comparison against the session's own folded log and nothing else.
/// **It never reads the policy table**: the table is the broker's, and
/// `chock-core` holds none. So a promise that repeats a rule the project
/// already has is recorded like any other, and a promise is never measured
/// against what the project allows.
///
/// **Nothing here enforces a promise either.** The record is what binds, and
/// `lib/chock-broker/Broker.zig` is what reads it, in the one process the
/// agent cannot reach. A check the agent's own loop performed would be a check
/// inside the thing being checked.
///
/// ## A widening nobody permits writes nothing at all
///
/// The `tool.call` beside this already records that the agent asked, which is
/// the fact a replay needs and the one a person wants in the morning: an agent
/// asking to widen its own promise is saying it was wrong about the task when
/// it planned it. What is not written is a `policy.self` event, so the fold
/// cannot come back with a wider ceiling however the request was worded.
///
/// **A widening is put to somebody**, and `runWiden` is where. It is measured
/// against `chock_policy.ratchet.widen_action` like any other act, by the
/// acceptance modes the policy names, and `deps.arbiter` is the seam onto the
/// broker that answers. A session that can reach nobody says so rather than
/// implying the answer was weighed.
///
/// A widening that is permitted is the one thing that writes a `policy.self`
/// event which lifts rather than adds. See `runWiden`.
fn runRestrictSelf(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    // A scratch arena for the parse and for the promises this reads. Only the
    // result the caller frees comes out of `allocator`.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSlice(
        tools.RestrictSelfArgs,
        arena,
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return restrictRefusal(allocator, call, try allocator.dupe(
        u8,
        restrict_tool_name ++ " needs a JSON object with three fields: \"action\", \"ceiling\" " ++
            "and \"reason\".",
    ));

    const ceiling = ratchet.ceilingNamed(parsed.value.ceiling) orelse return restrictRefusal(
        allocator,
        call,
        try std.fmt.allocPrint(
            allocator,
            "nothing was promised: \"{s}\" is not a ceiling. Use one of: {s}.",
            .{ parsed.value.ceiling, ratchet.ceiling_names_text },
        ),
    );

    const proposal = ratchet.Restriction{
        .action = parsed.value.action,
        .ceiling = ceiling,
        .reason = parsed.value.reason,
    };
    if (ratchet.refusalFor(proposal)) |detail| {
        return restrictRefusal(allocator, call, try allocator.dupe(u8, detail));
    }
    // A promise is read one to a line, on the terminal and in the log, so no
    // part of one may hold a line break. The same rule a plan step keeps.
    if (hasALineBreak(proposal.action) or hasALineBreak(proposal.reason)) {
        return restrictRefusal(allocator, call, try allocator.dupe(
            u8,
            "nothing was promised: a promise is read one to a line, so no part of one may hold " ++
                "a line break. Say the detail in your answer instead.",
        ));
    }

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    switch (ratchet.classify(ratchet.ceilingFor(held, proposal.action), ceiling)) {
        .narrows => {},
        // **A ceiling of `allow` promises nothing at all**, so a call that
        // reaches here with one was asking to be let out of something rather
        // than to give something up, and it named a pattern no promise of this
        // session covers. Told apart from the case below because the two want
        // different next steps, and a model that read "nothing changed" would
        // think its own narrower promise had gone.
        .no_change => if (ceiling == .allow) return restrictRefusal(
            allocator,
            call,
            try promiseText(
                allocator,
                held,
                "Nothing was promised and nothing was lifted: a ceiling of \"allow\" gives up " ++
                    "nothing. If you meant to be let out of a promise, name exactly the action " ++
                    "you promised, and that is a widening, which you cannot do. You have " ++
                    "promised:",
            ),
        ) else return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try promiseText(
                allocator,
                held,
                "Nothing changed: you already hold this, or something narrower. You have promised:",
            ),
            // Not an error. What the agent asked for is true of this session
            // already, so there is nothing for it to do differently.
            .is_error = false,
            .truncated = false,
        },
        .widens => return runWiden(allocator, io, locked, session, deps, call, proposal, held),
    }

    if (session.self_policy.restrictions.items.len >= ratchet.max_restrictions) {
        return restrictRefusal(allocator, call, try std.fmt.allocPrint(
            allocator,
            "nothing was promised: a session holds at most {d} promises, and this one already " ++
                "holds them. Nothing removes one, so there is no room for another.",
            .{ratchet.max_restrictions},
        ));
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .policy_self = .{
        .restrictions = &.{.{
            .action = proposal.action,
            .ceiling = self_policy.wireCeiling(ceiling),
            .reason = proposal.reason,
        }},
    } });

    const now_held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = try promiseText(
            allocator,
            now_held,
            "Promised. This holds for the rest of the session and you cannot take it back. " ++
                "You have promised:",
        ),
        .is_error = false,
        .truncated = false,
    };
}

/// A `restrict_self` call that asks to be let out of a promise this session
/// already made.
///
/// **This is the release valve, and it is one action name and nothing more.**
/// See `chock_policy.ratchet`'s own top comment: a widening is the archetypal
/// thing an arbitrator should judge rather than a table, because it is an agent
/// saying in the log that it was wrong about the task when it planned it. The
/// policy already has the two review decisions for that, and `Broker.request`
/// already runs them, so there is no second approval path here.
/// `ratchet.widen_action` is the key a project writes a rule for in
/// `chock.zon`, which stays beyond the agent's reach.
///
/// **The agent does not decide this, and this loop does not either.**
/// `deps.arbiter` is a seam onto the process that holds the policy table, and a
/// session with none refuses and says nobody could be asked, which is a
/// different fact from being told no.
///
/// ## Two things have to be true before anybody is asked
///
/// * **The proposal names exactly a promise this session holds.** A session
///   that promised `git.*` and asks to be let out of `git.push` is asking about
///   something it never promised as such, and `ratchet.ceilingFor` would still
///   hold `git.*` against it afterwards, so the lift would be recorded and
///   change nothing. Refusing here is what stops an authorised yes from being
///   worth nothing.
/// * **There is somebody to ask.** Paying for a review, or writing a question,
///   for a session that can reach nobody spends something for an answer that is
///   already decided. That is the same rule `Broker.reviewed` keeps for
///   `agent_then_human` with no time to wait.
///
/// ## What an authorised widening writes
///
/// One `policy.self` with `authorised` set, which
/// `chock_proto.state.SelfPolicy.apply` folds as a replacement by exact name
/// rather than as one more term of the minimum. **That flag is the only thing
/// that can lift a promise, and this is the only place it is written**, after
/// an answer from a process the agent cannot reach. See
/// `event.PolicySelf.authorised` for why it is on the event and not on a
/// restriction, and for what an older reader does with it.
fn runWiden(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
    proposal: ratchet.Restriction,
    held: []const ratchet.Restriction,
) Error!event.ToolResult {
    const was = ratchet.ceilingFor(held, proposal.action);

    if (!promisedExactly(session, proposal.action)) {
        const list = try promiseText(allocator, held, "You have promised:");
        defer allocator.free(list);
        return restrictRefusal(allocator, call, try std.fmt.allocPrint(
            allocator,
            "nothing was promised and nothing was lifted: \"{s}\" is held at \"{t}\" by a promise " ++
                "that was written under a different name, so lifting it means naming exactly the " ++
                "promise you made. Use the name the list shows.\n{s}",
            .{ proposal.action, was, list },
        ));
    }

    const arbiter = deps.arbiter orelse return restrictRefusal(allocator, call, try std.fmt.allocPrint(
        allocator,
        "nothing was lifted: you promised at most \"{t}\" for \"{s}\" and this asks for \"{t}\", " ++
            "which is more. Widening a promise has to be authorised by somebody other than you, " ++
            "and {s}, so nobody weighed this. That is not a decision against you. Do the part of " ++
            "the task that does not need it, or stop and say what is left and why.",
        .{ was, proposal.action, proposal.ceiling, arbiter_mod.not_asked.outcome },
    ));

    const detail = try std.fmt.allocPrint(
        allocator,
        "the promise \"{s}\" was made at \"{t}\" and would be held at \"{t}\" instead.\n" ++
            "the agent's reason: {s}\n",
        .{ proposal.action, was, proposal.ceiling, proposal.reason },
    );
    defer allocator.free(detail);
    const summary = try std.fmt.allocPrint(
        allocator,
        "let this session out of its own promise about \"{s}\", from \"{t}\" to \"{t}\"",
        .{ proposal.action, was, proposal.ceiling },
    );
    defer allocator.free(summary);

    const answer = arbiter.decide(allocator, io, locked, .{
        .action = ratchet.widen_action,
        .summary = summary,
        .detail = detail,
        .reason = proposal.reason,
        .tool = restrict_tool_name,
        .tool_call_id = call.call_id,
    });

    if (!answer.permitted) {
        return restrictRefusal(allocator, call, try std.fmt.allocPrint(
            allocator,
            "nothing was lifted: you asked to be let out of your promise about \"{s}\", and the " ++
                "answer was \"{s}\". {s}{s}Do the part of the task that does not need it, or " ++
                "stop and say what is left and why.",
            .{
                proposal.action,
                answer.outcome,
                answer.review_text,
                if (answer.review_text.len == 0) "" else " ",
            },
        ));
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{
        .policy_self = .{
            // The one place this flag is ever set. See this function's own doc
            // comment.
            .authorised = true,
            .restrictions = &.{.{
                .action = proposal.action,
                .ceiling = self_policy.wireCeiling(proposal.ceiling),
                .reason = proposal.reason,
            }},
        },
    });

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const now_held = try self_policy.restrictionsFrom(
        arena_state.allocator(),
        session.self_policy.restrictions.items,
    );
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = try promiseText(
            allocator,
            now_held,
            "Lifted. Somebody other than you weighed this and allowed it, and it is in the log " ++
                "with their answer. You have promised:",
        ),
        .is_error = false,
        .truncated = false,
    };
}

/// Whether this session holds a promise written under exactly this name.
///
/// **Exact and never a pattern**, which is the rule `ratchet.ceilingFor`
/// already keeps for the question it answers, and the rule
/// `chock_proto.state.SelfPolicy.apply` folds an authorised lift by. The three
/// have to agree, or a lift is authorised, recorded, and then still held down
/// by a promise under a wider name.
fn promisedExactly(session: *const chock_proto.state.Session, action: []const u8) bool {
    for (session.self_policy.restrictions.items) |one| {
        if (std.mem.eql(u8, one.action, action)) return true;
    }
    return false;
}

/// A `restrict_self` call that promised nothing. `output` is already owned by
/// the allocator and is handed straight on.
///
/// **Always an error result.** Nothing was written, whichever branch answered,
/// so a model that read one of these as success would believe a wall was there
/// and would plan around one that is not.
fn restrictRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    output: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = output,
        .is_error = true,
        .truncated = false,
    };
}

/// The name of the tool a model calls to read a page.
pub const fetch_tool_name = @tagName(tools.Tool.fetch_url);

/// Answer a `fetch_url` call, in place of the tool runner.
///
/// **Answered here for one reason: a promise binds it.** `restrict_self` offers
/// `"net.fetch"` at `"deny"` in its own description, and the promises of a
/// session live in the fold of its log, which only this loop holds. A tool
/// runner is handed one call and knows nothing about the session around it, so
/// a fetch that went there would run under the project's policy and past the
/// session's own word. See `tools.fetch_needs_a_session`, which is what a
/// dispatch with no loop around it gets instead.
///
/// **This loop still decides nothing.** It parses the call, folds the promises
/// out of the log, and hands both across `deps.fetcher`, which is a seam onto
/// the process that holds the policy table. Nothing here reads a table, and
/// nothing here opens a socket. `lib/chock-policy/ratchet.zig` states why the
/// narrowing happens on the far side and not here: a check an agent's own loop
/// performs on itself is worth nothing.
fn runFetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    // A scratch arena for the parse and for the promises this reads. Only the
    // result the caller frees comes out of `allocator`.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSlice(
        tools.FetchUrlArgs,
        arena,
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return fetchRefusal(allocator, call, try allocator.dupe(
        u8,
        fetch_tool_name ++ " needs a JSON object with one field, \"url\", holding the whole URL.",
    ));

    const fetcher = deps.fetcher orelse return fetchRefusal(
        allocator,
        call,
        try allocator.dupe(u8, fetch_mod.has_no_fetcher),
    );

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    const answer = try fetcher.fetch(allocator, io, .{
        .url = parsed.value.url,
        .self_policy = held,
        .tool = call.tool,
    });
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = answer.text,
        .is_error = answer.is_error,
        .truncated = false,
        // Carried straight through. The seam wrote it for the person, this
        // file has nothing to add to it, and `runTool` frees it with the
        // output it belongs to.
        .note = answer.note,
    };
}

/// A `fetch_url` call that read nothing. `output` is already owned by the
/// allocator and is handed straight on.
///
/// **Always an error result.** No page arrived, whichever branch answered, and
/// a model that read one of these as success would go on to quote a page it
/// never saw.
fn fetchRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    output: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = output,
        .is_error = true,
        .truncated = false,
    };
}

/// The name of the tool a model calls to ask the person a question.
pub const ask_tool_name = @tagName(tools.Tool.ask_user);

/// Answer an `ask_user` call, in place of the tool runner.
///
/// **Answered here because a tool runner has nobody to ask.** A `Registry` runs
/// one call inside a sandbox that holds no terminal, and it is built to know
/// nothing that outlives the call. The session is what has a person attached to
/// it, so the loop carries the question across `deps.asker` and `src/run.zig` is
/// what puts it on a screen. See `tools.ask_needs_a_session`, which is what a
/// dispatch with no loop around it gets instead.
///
/// **This is not an approval and it writes no `approval.request`.** It grants
/// nothing, whatever the person types. `lib/chock-core/ask.zig`'s own top
/// comment says at length why the two paths stay apart, and why a later reader
/// must not join them.
///
/// **Nothing here writes to the log either.** The question is already in the
/// `tool.call` this loop appended, and the answer goes into the `tool.result` it
/// appends next, both through the handle it already holds: see `runTool`.
fn runAskUser(
    allocator: std.mem.Allocator,
    io: std.Io,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    // A scratch arena for the parse alone. Only the result the caller frees
    // comes out of `allocator`.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSlice(
        tools.AskUserArgs,
        arena,
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return askRefusal(allocator, call, try allocator.dupe(
        u8,
        ask_tool_name ++ " needs a JSON object with a \"question\" field holding what you want " ++
            "to know, and an optional \"options\" field holding a list of answers you would take.",
    ));

    const question = ask_mod.Question{
        .text = parsed.value.question,
        .options = parsed.value.options orelse &.{},
    };
    // **Checked before anybody is disturbed.** Every one of these is the model's
    // own to fix, so no person's attention is spent on a question they cannot
    // read: see `ask.check`.
    if (ask_mod.check(question)) |why| {
        return askRefusal(allocator, call, try allocator.dupe(u8, why));
    }

    const asker = deps.asker orelse return askRefusal(
        allocator,
        call,
        try allocator.dupe(u8, ask_mod.has_no_asker),
    );

    const answer = try asker.ask(allocator, io, question);
    defer switch (answer) {
        .answered => |said| allocator.free(said),
        else => {},
    };
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = try ask_mod.resultText(allocator, answer),
        .is_error = ask_mod.isError(answer),
        .truncated = false,
    };
}

/// An `ask_user` call that reached nobody. `output` is already owned by the
/// allocator and is handed straight on.
///
/// **Always an error result.** No answer arrived, whichever branch answered, and
/// a model that read one of these as success would go on to quote an answer
/// nobody gave.
fn askRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    output: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = output,
        .is_error = true,
        .truncated = false,
    };
}

/// The name of the tool a model calls to name this session.
pub const title_tool_name = @tagName(tools.Tool.set_title);

/// The longest title one session may be given.
///
/// **One hundred and twenty bytes, and it is narrower than a plan step's
/// subject on purpose.** A step is read on a line of its own; a title is read at
/// the end of a `chock sessions` row that already carries an identifier, a
/// timestamp, a state, a turn count and a model name. A title that ran past the
/// width of a terminal would push the one thing on the row a reader is scanning
/// for off the screen.
///
/// **Refused and never cut.** A cut title says something the agent did not say,
/// and the sentence that stops is exactly the sentence that named the thing. The
/// model is the one thing here that can fix it, so it is told the bound and
/// writes a shorter one. The same rule `chock_core.ask.max_question_bytes`
/// keeps, for the same reason.
pub const max_title_bytes: usize = 120;

/// Answer a `set_title` call, in place of the tool runner.
///
/// **A title is an event in the session log, and a tool runner has no log.**
/// `Loop.run` holds the exclusive lock on it for the whole session, so this
/// call is answered here for exactly the reason `runPlanUpdate` is. See
/// `tools.title_needs_a_session`, which is what a caller driving a dispatch
/// with no loop around it gets instead.
///
/// ## The log cannot edit a title, so a later one supersedes it
///
/// The log is append only and hash chained, so there is no writing over the
/// title a session already has. A second call appends a second event and the
/// fold takes the last, which is the same shape `chock_core.memory` keeps for a
/// note: writing a name that exists adds a version rather than replacing one,
/// and every name the session went by stays in the record.
///
/// **This is what makes "name it early" safe advice.** A title written at the
/// end is a title about work that is understood, and a session that is
/// interrupted or runs out of budget never reaches the end: 15 of the 23
/// sessions on the machine this was written on have no end event at all. So the
/// model is told to name the session as soon as it knows what the work is, and
/// to say so again if the work turns out to be something else.
///
/// ## What is refused, and what a reader still has to do
///
/// A title is put in front of a person in a listing, so this refuses one that is
/// not one line of text: empty, longer than `max_title_bytes`, carrying a line
/// break, carrying any other control character, or not valid UTF-8. Every one of
/// those is the model's own to fix and the answer says so.
///
/// **A reader must not rely on any of it.** A log is a file on disk that another
/// build, or a person with an editor, can write, so `src/sessions.zig` filters
/// what it prints as well. This stops a bad title being written; that stops a
/// bad title being obeyed.
fn runSetTitle(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    // A scratch arena for the parse alone. Only the result the caller frees
    // comes out of `allocator`.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSlice(
        tools.SetTitleArgs,
        arena,
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return titleRefusal(allocator, call, try allocator.dupe(
        u8,
        title_tool_name ++ " needs a JSON object with one field, \"title\", holding a few words " ++
            "on one line.",
    ));

    // Trimmed before it is measured and before it is written, so a title with a
    // trailing space is not a different title from the same words without one.
    const title = std.mem.trim(u8, parsed.value.title, " \t");
    if (titleRefusalText(title)) |why| {
        return titleRefusal(allocator, call, try allocator.dupe(u8, why));
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{
        .session_title = .{ .title = title },
    });

    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        // The name is read back, so a model that shortened a long one can see
        // which of its attempts is the one a person will read.
        .output = try std.fmt.allocPrint(
            allocator,
            "This session is now called: {s}\nCall " ++ title_tool_name ++ " again if the work " ++
                "turns out to be something else, and the later name is the one a person sees.",
            .{title},
        ),
        .is_error = false,
        .truncated = false,
    };
}

/// Why this title cannot be recorded, or null when it can.
///
/// **Every one of these is the model's own to fix**, so each sentence says what
/// to send instead. Here and not in the fold, because the fold reads logs that
/// are already written and this is the one place that decides what gets written.
pub fn titleRefusalText(title: []const u8) ?[]const u8 {
    if (title.len == 0) return "this session was not named: \"title\" was empty. Write what the " ++
        "session is about, in a few words.";
    if (title.len > max_title_bytes) return "this session was not named: a title is longer than " ++
        max_title_text ++ " bytes. It is read at the end of a row beside the session's " ++
        "identifier and its time, so name the work in a few words and say the detail in your " ++
        "answer.";
    // **A title is one line, and a line break is refused rather than replaced.**
    // A listing puts one title on one row, so text after a line break is text
    // the agent wrote and nobody reads. Every other control character goes with
    // it: a title is shown on a terminal, and an escape sequence in one would
    // drive the terminal of whoever ran `chock sessions`.
    for (title) |byte| {
        // Only ASCII control characters are checked byte by byte, which is safe
        // over UTF-8: every byte of a multi byte character is 0x80 or above, so
        // none of them can be mistaken for one.
        if (byte == '\n' or byte == '\r') return "this session was not named: a title is one " ++
            "line, and this one has a line break in it. Put the whole name on one line.";
        if (byte < 0x20 or byte == 0x7F) return "this session was not named: a title is plain " ++
            "text, and this one has a control character in it. Send the words alone.";
    }
    // Bytes that are not valid UTF-8 serialize as an array of integers rather
    // than a string, which is a log line no replay of this build can read back.
    // The same fault `tools.outputForModel` stands in for on a tool result, and
    // a title is short enough to simply refuse.
    if (!std.unicode.utf8ValidateSlice(title)) return "this session was not named: a title has " ++
        "to be text, and these bytes are not valid UTF-8. Send the words alone.";
    return null;
}

const max_title_text = std.fmt.comptimePrint("{d}", .{max_title_bytes});

/// A `set_title` call that named nothing. `output` is already owned by the
/// allocator and is handed straight on.
fn titleRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    output: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = output,
        .is_error = true,
        .truncated = false,
    };
}

/// Every promise this session holds, as the model reads it back, one to a
/// line, under `heading`. Caller owns the result.
///
/// **The whole list, and not only what changed.** A model that has just bound
/// itself is a model about to plan around the binding, and a list it can see
/// in full is one it does not have to hold in its attention. The same reason
/// `planText` prints the whole task list.
fn promiseText(
    allocator: std.mem.Allocator,
    held: []const ratchet.Restriction,
    heading: []const u8,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.appendSlice(allocator, heading);
    try text.append(allocator, '\n');
    for (held) |one| {
        try text.print(allocator, "  {s} at most {t}: {s}\n", .{ one.action, one.ceiling, one.reason });
    }
    if (held.len == 0) try text.appendSlice(allocator, "  nothing\n");
    return text.toOwnedSlice(allocator);
}

/// What the parent's model reads about the child that just ended. Caller owns
/// the result.
///
/// **The answer and a path, never the child's transcript.** Six children each
/// returning a page of prose is a parent that spends its whole context
/// reading; the child's own log holds every turn, and the scratchpad holds
/// whatever the child wrote down.
fn spawnResultText(
    allocator: std.mem.Allocator,
    prepared: subagent.Prepared,
    request: subagent.Request,
    report: subagent.Report,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.print(allocator, "the {s} subagent {s} ended {s}.\n", .{
        request.agent_kind,
        prepared.child_session,
        report.outcome.wireName(),
    });
    try text.print(allocator, "It said: {s}\n", .{report.result});
    if (prepared.scratchpad_path.len != 0) {
        try text.print(
            allocator,
            "Anything it wrote down is in its own scratchpad, at {s} on the host. It is not in " ++
                "your workspace and you cannot read it with read_file.\n",
            .{prepared.scratchpad_path},
        );
    }
    return text.toOwnedSlice(allocator);
}

/// What the parent's model reads about a child that has only just started.
/// Caller owns the result.
///
/// **It says plainly that there is no answer yet and how the answer arrives**,
/// because a model that read this as the child's verdict would carry on as
/// though it had one.
fn spawnStartedText(
    allocator: std.mem.Allocator,
    prepared: subagent.Prepared,
    request: subagent.Request,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "the {s} subagent {s} is running. It has not answered yet, and there is nothing for you " ++
            "to read in the meantime: you are told what it answered at the start of a later " ++
            "turn. Carry on with your own work until then.\n",
        .{ request.agent_kind, prepared.child_session },
    );
}

/// The real world time now, from the clock the caller injected or from the
/// machine's own when it injected none.
///
/// **Separate from the timestamp `appendAndApply` writes on an event.** An
/// event's time is a fact about the log and must be the real one whatever a
/// test wants. This is what a notice says about the world, and a test that
/// pins a notice names the time itself rather than measuring the one it got.
fn nowMs(io: std.Io, deps: Deps) i64 {
    const clock = deps.notices.clock orelse
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    return clock.now();
}

/// The messages this turn sends, with this turn's notice on the end when one
/// applies, and the messages themselves when none does.
///
/// **On the end, and as its own message.** The system prompt is not rebuilt,
/// so the provider's cache keeps the same prefix it had last turn: see
/// `Deps.notices`. The role is `user` and not `system` because
/// `chock_provider.anthropic.buildRequest` folds a `system` role message into
/// the top level `system` field, which is the one place this must never reach.
///
/// **Two allocators, and mixing them is a leak.** `telling` owns its memory
/// from `allocator`, the one that lives as long as the session, so `render`
/// gets that one and its result is freed with it. The message the request
/// carries has to outlive the call and is copied into `arena`, which is the
/// turn's own and frees the copy with everything else the turn built.
fn withNotice(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    session: *const chock_proto.state.Session,
    deps: Deps,
    telling: *notices.State,
    turn_index: usize,
    messages: []message.Message,
) Error![]message.Message {
    const rendered = try notices.render(allocator, deps.notices, telling, .{
        .index = turn_index,
        .now_ms = nowMs(io, deps),
        .goal = firstUserText(session),
        .spent_percent = spentPercent(session, deps),
        .uncommitted_files = deps.uncommitted_files,
        // Built into the turn's own arena, and empty for the sessions that
        // keep no list at all. See `unfinishedPlan`.
        .unfinished_plan = try unfinishedPlan(arena, session),
    }) orelse return messages;
    defer allocator.free(rendered);

    if (deps.observer) |watching| watching.onNotice(rendered);

    const text = try arena.dupe(u8, rendered);
    const parts = try arena.alloc(message.ContentPart, 1);
    parts[0] = .{ .text = text };

    const grown = try arena.alloc(message.Message, messages.len + 1);
    @memcpy(grown[0..messages.len], messages);
    grown[messages.len] = .{ .role = .user, .content = parts };
    return grown;
}

/// The steps of the agent's own task list that are neither done nor abandoned,
/// in the order the fold holds them.
///
/// **Empty for every session whose agent never wrote a list**, and empty for
/// one whose steps are all finished or given up. That is what keeps the notice
/// which reads it from firing on a session with nothing to be reminded of: see
/// `notices.renderCompactedPlan`.
///
/// **An unrecognized status counts as unfinished.** `Plan.Counts.left` already
/// makes that choice and for the same reason: a status this build has no member
/// for is not finished work, and a step dropped from the list because a newer
/// writer named it something else is a step that vanished in silence.
///
/// Every string is borrowed from `session`'s own arena, so the slice this
/// builds in `arena` is valid for as long as the turn that reads it.
fn unfinishedPlan(
    arena: std.mem.Allocator,
    session: *const chock_proto.state.Session,
) Error![]notices.Step {
    var left: std.ArrayList(notices.Step) = .empty;
    for (session.plan.steps.items) |step| {
        switch (step.status) {
            .done, .abandoned => continue,
            .pending, .in_progress, .unknown => {},
        }
        try left.append(arena, .{
            .id = step.id,
            .subject = step.subject,
            .status = step.status.wireName(),
        });
    }
    return left.toOwnedSlice(arena);
}

/// The task, word for word: the text of the first `user` message the fold
/// holds. Empty when the session has none, and empty after a compaction folded
/// it away, which cannot happen while `compaction.Policy.protect_head_entries`
/// is at least one.
///
/// Borrowed from `session`'s own arena, so it is valid for as long as the turn
/// that read it.
fn firstUserText(session: *const chock_proto.state.Session) []const u8 {
    for (session.context.items) |entry| {
        const said = switch (entry.data) {
            .message => |m| m,
            .summary => continue,
        };
        if (std.meta.activeTag(said.role) != .user) continue;
        for (said.content) |part| {
            if (part == .text and part.text.len != 0) return part.text;
        }
    }
    return "";
}

/// How much of the budget is spent, in whole percent, or null when there is no
/// number a percentage could honestly be taken of.
///
/// **Null in every case `refuseForBudget` refuses to enforce**, and for the
/// same reasons: a total with an unpriced turn in it is not a total, and a cap
/// in one currency cannot be compared with turns billed in another. A
/// percentage of a number Chock cannot measure is a made up number, and a made
/// up number told to a model is worse than silence.
fn spentPercent(session: *const chock_proto.state.Session, deps: Deps) ?u8 {
    const cap = deps.budget orelse return null;
    if (cap.max_cost <= 0) return null;
    const spend = session.spend;
    if (!spend.enforceable()) return null;
    if (spend.turns == 0) return null;
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, cap.currency)) return null;

    const fraction = spend.amount / cap.max_cost * 100;
    // A total that is not a number is a total Chock cannot measure, which is
    // the same answer as an unpriced turn. It is also the one value
    // `@intFromFloat` below has no defined answer for, so the check earns its
    // place twice.
    if (std.math.isNan(fraction)) return null;
    if (fraction <= 0) return 0;
    if (fraction >= 100) return 100;
    return @intFromFloat(fraction);
}

/// Record what a `read_file` call found, so the next turn can be told when a
/// read found nothing new.
///
/// **Nothing is recorded unless both halves are certain.** A call whose path
/// this library cannot read, and a result with no `file_hash` in it, both
/// leave the record untouched: see `tools.fileHashIn`. A failed read is not a
/// read at all.
fn noteRead(
    allocator: std.mem.Allocator,
    telling: *notices.State,
    result: event.ToolResult,
    call: event.ToolCall,
) Error!void {
    if (result.is_error) return;
    if (!std.mem.eql(u8, call.tool, @tagName(tools.Tool.read_file))) return;

    const hash = tools.fileHashIn(result.output) orelse return;
    const path = try tools.readPathIn(allocator, call.arguments) orelse return;
    defer allocator.free(path);

    try telling.observeRead(allocator, path, hash);
}

/// Append `ev` to the log through `locked`, then fold it into `session`
/// right away, so the next turn's `context.build` sees it with no extra
/// read of storage. `locked` is `anytype` because `chock_proto.storage.Locked`
/// is not `pub`: see that type's own doc comment on why a runtime generation
/// check, not the type system, is what actually proves a caller holds a real
/// lock. Every real caller of this function already holds one, from
/// `deps.storage.lock` in `run`, so the check always passes here; `anytype`
/// only works around the type being unnameable, not around the check
/// itself.
///
/// **This is where a secret is taken out, and it is the only place it can
/// be.** The log is append only and hash chained, so a credential written here
/// cannot be taken out later without breaking the chain: there is no cleanup
/// after the fact and only prevention is left. Every record this loop writes
/// goes through this one function, so `deps.redact` covers a tool result, a
/// diff, a compaction summary, an approval detail and the `session.end` detail
/// of a provider refusal, without a list of the kinds that matter. See
/// `lib/chock-core/redact.zig`.
///
/// **The redacted record is what is hashed and what is folded.** The
/// replacement happens before `Locked.append`, so the chain runs over the bytes
/// the file holds, and `session.apply` takes the same bytes, so the context the
/// next turn renders is clean as well.
///
/// **The scratch arena is released here.** `Locked.append` serializes what it is
/// given and `Session.apply` copies what it keeps, and `Observer.onEvent`
/// borrows for the duration of the call alone.
fn appendAndApply(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    ev: event.Event,
) Error!u64 {
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    // An inert policy, which is the default, gives back `ev` itself and
    // allocates nothing at all.
    const clean = try redact.event(scratch.allocator(), deps.redact, ev);

    const time_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    const offset = try locked.append(allocator, io, clean, time_ms);
    try session.apply(.{ .id = offset, .session = "", .time_ms = time_ms, .event = clean });
    // After the append and after the fold, never before either: an observer
    // that was told about an event the log does not hold would be showing a
    // user something a replay of the same session will not produce. See
    // `Observer`.
    if (deps.observer) |watching| watching.onEvent(offset, clean);
    return offset;
}

/// Fold every event `storage` already holds into `session`, from the start.
/// Called once, at the top of `run`, before anything new is appended: see
/// `run`'s own doc comment on why a call that continues an existing session
/// must see it the same way a fresh replay would, session_start included,
/// rather than starting from an empty `Session` every time.
fn foldExisting(
    allocator: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    session: *chock_proto.state.Session,
    telling: *notices.State,
) Error!void {
    var replay = try storage.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        // The log's own timestamps, so a resumed session says when it really
        // started and when the agent really last spoke. See
        // `notices.State.observeEvent`.
        const spoke = parsed.value.event == .message and
            std.meta.activeTag(parsed.value.event.message.role) == .assistant;
        telling.observeEvent(parsed.value.time_ms, spoke);
    }
}

// Every test here drives Loop.run against a Storage.Memory (no file, no
// tmpDir) and a FakeClient and FakeToolRunner (no socket, no sandbox): see
// this file's own top comment on why ToolRunner is an interface. The one
// test that needs a real HTTP round trip, "the API key is in no event in
// the log", needs test/core/fake_provider.zig, which this file cannot
// import directly (Zig 0.16 refuses a relative @import outside a module's
// own root), so it lives in test/core/loop.zig instead, the same reason
// test/core/client.zig exists next to lib/chock-provider/Client.zig.

const testing = std.testing;

/// One `Client.send` call's worth of scripted deltas. `FakeClient` plays
/// back one `FakeTurn` per call, in order, and never loops back to the
/// start: a test that wants N turns gives exactly N entries.
const FakeTurn = struct {
    deltas: []const chock_provider.Client.Delta = &.{},
    /// When set, this call answers with a refusal instead of the deltas, the
    /// same shape a real provider's non-2xx response reaches
    /// `Client.sendAndAssemble` in. A test that wants a context overflow, or a
    /// rate limit, scripts one of these.
    refusal: ?Refusal = null,
    /// Run at the start of this call, before anything is answered. **A test
    /// that needs something to happen partway through a session drives it from
    /// here**, which is the same seam `RecordingSleeper.on_wait` gives for the
    /// same reason. Null for a turn that only answers.
    before: ?*const fn () void = null,

    const Refusal = struct {
        status: std.http.Status = .bad_request,
        body: []const u8,
        /// What this refusal's own `Retry-After` header said, in seconds. A
        /// real provider sends one on a 429: see
        /// `chock_provider.Client.StatusError.retry_after_s`.
        retry_after_s: ?u64 = null,
    };
};

/// The refusal a llama.cpp server sent on 2026-08-21, word for word, which is
/// the session that made compaction the blocking gap. Used by the tests that
/// pin the backstop, so they answer the real wire and not a paraphrase of it.
const measured_overflow_body =
    \\{"error":{"code":400,"message":"request (77857 tokens) exceeds the available context size (65536 tokens)","type":"exceed_context_size_error"}}
;

const FakeClient = struct {
    turns: []const FakeTurn,
    calls: usize = 0,
    /// When true, `send` serializes each request it is given through the
    /// same adapter a real OpenAI compatible session uses, and keeps the
    /// bytes of the last one. **The bytes, and not the `message.Request`
    /// value**: a `[]const u8` that is valid UTF-8 and one that is not are
    /// the same Zig type, and only the serializer tells them apart. A test
    /// that read the value would pass either way. See
    /// `tools.outputForModel`.
    record_requests: bool = false,
    /// Owned by whoever set `record_requests`, and freed with the same
    /// allocator `run` was given.
    last_request_json: ?[]u8 = null,
    /// When set, every request's system prompt and last message is kept, one
    /// entry per model call. See `SeenRequests`, and the notice tests at the
    /// bottom of this file.
    seen: ?*SeenRequests = null,

    fn send(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: chock_provider.Client.OnDelta,
        ctx: ?*anyopaque,
    ) chock_provider.Client.SendError!chock_provider.Client.SendResult {
        const self: *FakeClient = @ptrCast(@alignCast(ptr));
        if (self.record_requests) {
            if (self.last_request_json) |old| allocator.free(old);
            self.last_request_json = try chock_provider.openai.buildRequest(allocator, .{
                .model = request.model,
                .system = request.system,
                .messages = request.messages,
                .tools = request.tools,
            });
        }
        if (self.seen) |seen| try seen.record(request);
        std.debug.assert(self.calls < self.turns.len);
        const turn = self.turns[self.calls];
        self.calls += 1;
        if (turn.before) |hook| hook();
        if (turn.refusal) |refusal| return .{ .status_error = .{
            .status = refusal.status,
            .body = try allocator.dupe(u8, refusal.body),
            .retry_after_s = refusal.retry_after_s,
        } };
        for (turn.deltas) |delta| try on_delta(ctx, delta);
        return .ok;
    }

    fn client(self: *FakeClient) chock_provider.Client.Client {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_provider.Client.Client.VTable{ .send = send };
};

/// A `retry.Sleeper` that never sleeps and remembers every wait it was asked
/// for.
///
/// **No test in this file measures elapsed time.** A test that slept for real
/// would be slow, would be flaky on a loaded machine, and would still prove
/// nothing about the number the policy computed. This records the number
/// instead, which is the fact worth pinning: see `Deps.sleeper`.
const RecordingSleeper = struct {
    allocator: std.mem.Allocator,
    waits: std.ArrayList(u64) = .empty,
    /// Run at each wait, so a test can make something happen partway through
    /// a retry, for example set the cancel flag. Null for a test that only
    /// wants the numbers.
    on_wait: ?*const fn () void = null,

    fn deinit(self: *RecordingSleeper) void {
        self.waits.deinit(self.allocator);
    }

    fn sleeper(self: *RecordingSleeper) retry.Sleeper {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = retry.Sleeper.VTable{ .sleep = sleepFn };

    fn sleepFn(ptr: *anyopaque, io: std.Io, wait_ms: u64) void {
        _ = io;
        const self: *RecordingSleeper = @ptrCast(@alignCast(ptr));
        self.waits.append(self.allocator, wait_ms) catch return;
        if (self.on_wait) |hook| hook();
    }
};

/// A `ToolRunner` that always answers the same way, and counts its own
/// calls. `storage_to_check`, when set, replays `storage` from the start
/// inside `dispatch`, before returning, and records whether a `tool.call`
/// event for this exact call is already there: see "an event is in the log
/// before the action it describes happens" below.
const FakeToolRunner = struct {
    output: []const u8,
    is_error: bool = false,
    /// What the person is told, or empty. See `event.ToolResult.note`.
    note: []const u8 = "",
    storage_to_check: ?chock_proto.storage.Storage = null,
    saw_call_in_log: bool = false,
    calls: usize = 0,

    fn dispatch(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        const self: *FakeToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        if (self.storage_to_check) |storage| {
            self.saw_call_in_log = callIsInLog(allocator, io, storage, call.call_id) catch false;
        }
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, self.output),
            .is_error = self.is_error,
            .truncated = false,
            // Owned by the same allocator the output is, and empty when there
            // is none: the loop frees it only when it holds something.
            .note = if (self.note.len == 0) "" else try allocator.dupe(u8, self.note),
        };
    }

    fn runner(self: *FakeToolRunner) ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatch };
};

/// A `ToolRunner` whose first call fails and whose every later call
/// succeeds. This is the transient fault a legitimate retry answers, and it
/// is why `no_progress_repeats` is not 2.
const FailsOnceToolRunner = struct {
    calls: usize = 0,

    fn dispatch(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        _ = io;
        const self: *FailsOnceToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        const first = self.calls == 1;
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, if (first) "could not reach the host" else "ok"),
            .is_error = first,
            .truncated = false,
        };
    }

    fn runner(self: *FailsOnceToolRunner) ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatch };
};

/// True when `storage` already holds a `tool.call` event whose `call_id`
/// matches `call_id`. A fresh replay from the start every time: cheap
/// enough for a test, and it is exactly the read a resuming client would
/// actually do.
fn callIsInLog(
    allocator: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    call_id: []const u8,
) !bool {
    var replay = try storage.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .tool_call and std.mem.eql(u8, parsed.value.event.tool_call.call_id, call_id)) {
            return true;
        }
    }
    return false;
}

/// A folded `Session` built from a fresh replay of every event `storage`
/// currently holds. Used only by tests that want to compare two folds of
/// the same log: see "the context the model sees is a fold over the log".
fn foldFromStart(allocator: std.mem.Allocator, io: std.Io, storage: chock_proto.storage.Storage) !chock_proto.state.Session {
    var session = chock_proto.state.Session.init(allocator);
    errdefer session.deinit();
    var replay = try storage.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
    }
    return session;
}

fn testDeps(client: chock_provider.Client.Client, storage: chock_proto.storage.Storage, tool_runner: ToolRunner) Deps {
    return .{
        .client = client,
        .storage = storage,
        .tool_runner = tool_runner,
        .tool_definitions = &.{},
        .model = "test-model",
        .model_alias = "main",
        .agent_kind = "coder",
        .system_prompt = "you are a test agent",
    };
}

test "a turn with no tool call appends a message event and stops" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();

    var saw_message = false;
    var saw_finished_end = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .message => |m| {
                try testing.expectEqual(event.Role.assistant, std.meta.activeTag(m.role));
                try testing.expectEqualStrings("all done", m.content[0].text);
                saw_message = true;
            },
            .session_end => |e| {
                try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(e.reason));
                saw_finished_end = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_message);
    try testing.expect(saw_finished_end);
}

test "a turn with a tool call appends the call, runs it, and appends the result" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();

    var call_id: ?u64 = null;
    var result_id: ?u64 = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .tool_call => |c| {
                try testing.expectEqualStrings("call1", c.call_id);
                call_id = parsed.value.id;
            },
            .tool_result => |r| {
                try testing.expectEqualStrings("call1", r.call_id);
                try testing.expect(!r.is_error);
                try testing.expectEqualStrings("ok", r.output);
                result_id = parsed.value.id;
            },
            else => {},
        }
    }

    // Assert the order in the log. A result before its call is a log that
    // cannot be folded back into a conversation.
    try testing.expect(call_id != null);
    try testing.expect(result_id != null);
    try testing.expect(call_id.? < result_id.?);
}

test "the context the model sees is a fold over the log, and a resume gives the same one" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "wrapped up" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // Two independent folds of the same, now finished, log: a session built by
    // replaying it once, and a second session built by replaying it again from
    // the start. A resume must produce the same context, and this is exactly
    // that guarantee, proven over a log Loop.run itself produced rather than
    // one built by hand.
    var first = try foldFromStart(allocator, io, store);
    defer first.deinit();
    var second = try foldFromStart(allocator, io, store);
    defer second.deinit();

    try testing.expectEqual(first.context.items.len, second.context.items.len);
    // Four entries: the assistant's tool_use turn, the tool's own answer fed
    // back as a message, and the assistant's final plain answer. Pinning
    // the count, not just that the two folds agree with each other, is what
    // stops this test passing on two folds that equally threw everything
    // away.
    try testing.expectEqual(@as(usize, 3), first.context.items.len);
    for (first.context.items, second.context.items) |a, b| {
        try testing.expectEqual(std.meta.activeTag(a.data), std.meta.activeTag(b.data));
        switch (a.data) {
            .message => |am| try expectMessagesEqual(am, b.data.message),
            .summary => |as| try testing.expectEqualStrings(as, b.data.summary),
        }
    }
}

fn expectMessagesEqual(a: chock_proto.state.OwnedMessage, b: chock_proto.state.OwnedMessage) !void {
    try testing.expectEqual(std.meta.activeTag(a.role), std.meta.activeTag(b.role));
    try testing.expectEqual(a.content.len, b.content.len);
    for (a.content, b.content) |ap, bp| {
        try testing.expectEqual(std.meta.activeTag(ap), std.meta.activeTag(bp));
        switch (ap) {
            .text => |at| try testing.expectEqualStrings(at, bp.text),
            .tool_use => |at| {
                try testing.expectEqualStrings(at.call_id, bp.tool_use.call_id);
                try testing.expectEqualStrings(at.tool, bp.tool_use.tool);
                try testing.expectEqualStrings(at.arguments, bp.tool_use.arguments);
            },
            .tool_result => |at| {
                try testing.expectEqualStrings(at.call_id, bp.tool_result.call_id);
                try testing.expectEqualStrings(at.output, bp.tool_result.output);
                try testing.expectEqual(at.is_error, bp.tool_result.is_error);
            },
            .reasoning, .unknown => {},
        }
    }
}

test "a second run on a started session does not append a second session.start" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // One plain answer for each run. A reconnect calls `run` again on the log
    // the first call left behind, which is the case `run`'s own doc comment
    // describes.
    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .text = "first" }} },
        .{ .deltas = &.{.{ .text = "second" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var starts: usize = 0;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .session_start) starts += 1;
    }
    // The log is the truth and the session is a fold of it. A second
    // session.start makes the folded agent_kind depend on which of the two the
    // replay read last, so the count is the fact to pin.
    try testing.expectEqual(@as(usize, 1), starts);
    // Both calls must have done a turn. Without this, a `run` that returned
    // early on an already started session would pass the count above while
    // doing nothing at all.
    try testing.expectEqual(@as(usize, 2), fake_client.calls);
}

test "an event is in the log before the action it describes happens" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok", .storage_to_check = store };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // The check ran inside dispatch, before dispatch itself returned: a
    // crash right there would still leave the tool.call event replayable.
    try testing.expect(fake_tools.saw_call_in_log);
}

test "the API key is in no event in the log" {
    // The strongest structural guarantee this file can give without a real
    // socket: nothing on Deps, and nothing this file builds from it, ever
    // holds a credential. The stronger, end to end version of this fact,
    // driven through a real HttpClient and a real key over the wire, lives
    // in test/core/loop.zig: see this file's own top comment for why that
    // one test needs fake_provider.zig and cannot live here.
    comptime {
        // Four substring searches per field, at comptime, and `Deps` grows
        // with every milestone. The default quota runs out well before the
        // check is wrong.
        @setEvalBranchQuota(10_000);
        for (@typeInfo(Deps).@"struct".fields) |field| {
            const suspect = std.mem.indexOf(u8, field.name, "key") != null or
                std.mem.indexOf(u8, field.name, "token") != null or
                std.mem.indexOf(u8, field.name, "secret") != null or
                std.mem.indexOf(u8, field.name, "credential") != null;
            if (suspect) @compileError("Loop.Deps must not hold a credential field: " ++ field.name);
        }
    }
}

test "a tool that fails does not end the session" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "recovered and finished" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "boom", .is_error = true };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 2), fake_client.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_failed_result = false;
    var saw_finished_end = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .tool_result => |r| {
                try testing.expect(r.is_error);
                saw_failed_result = true;
            },
            .session_end => |e| {
                try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(e.reason));
                saw_finished_end = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_failed_result);
    try testing.expect(saw_finished_end);
}

/// The one `session.end` a finished log holds. Fails when a log holds none,
/// which is a session that stopped with nothing saying why.
fn endReasonOf(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
) !event.SessionEndReason {
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var found: ?event.SessionEndReason = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        // A tag copy only: the parsed value's own strings die with `parsed`,
        // and no caller of this reads `unknown`'s name.
        found = switch (parsed.value.event.session_end.reason) {
            .unknown => .{ .unknown = "" },
            inline else => |_, tag| @unionInit(event.SessionEndReason, @tagName(tag), {}),
        };
    }
    return found orelse error.NoSessionEnd;
}

/// The `detail` of the one `session.end` a finished log holds. Caller owns the
/// result. Used by the tests that pin what a user is told when a session gives
/// up: a reason alone says a session ended, and only the detail says what to
/// act on.
fn endDetailOf(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
) ![]u8 {
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var found: ?[]u8 = null;
    errdefer if (found) |owned| allocator.free(owned);
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        if (found) |owned| allocator.free(owned);
        found = try allocator.dupe(u8, parsed.value.event.session_end.detail);
    }
    return found orelse error.NoSessionEnd;
}

/// The text of the last assistant `message` event in the log. Caller owns the
/// result. This is what a session actually produced, as opposed to the fact
/// that it ended without an error.
fn lastAssistantText(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
) ![]u8 {
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var found: ?[]u8 = null;
    errdefer if (found) |owned| allocator.free(owned);
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .message) continue;
        const said = parsed.value.event.message;
        if (said.role != .assistant) continue;
        for (said.content) |part| {
            if (part != .text) continue;
            if (found) |owned| allocator.free(owned);
            found = try allocator.dupe(u8, part.text);
        }
    }
    return found orelse error.NoAssistantMessage;
}

test "a first turn the provider answers with nothing ends the session empty_response" {
    // The red team run of 2026-08-26 reported clean when nothing had happened.
    // Its log held three lines: 7367 input tokens, 0 output tokens, an empty
    // assistant message, and `session.end` saying `finished`. The process
    // exited 0, so a run that got nothing back read exactly like a run that
    // did the work. See `event.SessionEndReason.empty_response`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // One turn, no deltas at all: the provider was reached and said nothing.
    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // Asked once and never again: there is nothing to carry into a second turn.
    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));

    // **Never `finished`.** This is the whole fault: the two were the same
    // word, and a script could not tell an answer from an absence.
    try testing.expect(std.meta.activeTag(reason) != event.SessionEndReason.finished);

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.indexOf(u8, detail, "the first turn") != null);
    try testing.expect(std.mem.indexOf(u8, detail, "gave no stop reason") != null);
}

test "an empty turn carries the provider's own stop reason into the log" {
    // `output_tokens: 0` beside a clean end says the provider explained itself
    // and the reader threw the word away. Two earlier faults in this project
    // had the same shape: `DenyBlockNotValid` swallowing Zoir's diagnostics,
    // and std collapsing an unknown content encoding into `HttpHeadersInvalid`.
    // See `chock_provider.Client.Delta.stop_reason`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{.{ .stop_reason = "refusal" }} }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    // The provider's own word, and not a sentence Chock made up in its place.
    try testing.expect(std.mem.indexOf(u8, detail, "refusal") != null);
}

test "a turn that carries only reasoning is empty, because nothing runs and nobody reads it" {
    // A model that thought and then said nothing leaves the loop with no tool
    // to run and the person with no answer, so a content list that is not
    // empty is still an empty turn. See `saidSomething`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{
            .{ .reasoning = "the user wants me to try an escape, and I will not" },
            .{ .reasoning_signature = "SIG==" },
        } }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));
}

test "a turn of nothing but whitespace is an empty turn" {
    // A newline is not an answer, and a session that ended `finished` with one
    // is the same false OK as one that ended `finished` with nothing.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{ .{ .text = " " }, .{ .text = "\n" } } }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));
}

test "an empty turn after real work ends empty_response, and says it was not the first turn" {
    // The other half of the decision. The loop has one signal for "this turn
    // was the last one", which is "it asked for no tool", so a later empty turn
    // reaches the same place a first one does and produced no answer in the
    // same way. The work it did before is in the log and in the workspace, and
    // the detail is what tells a person the two apart.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "run_command",
            .arguments = "{\"argv\":[\"true\"]}",
        } }} },
        .{ .deltas = &.{} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.indexOf(u8, detail, "the first turn") == null);
}

test "a final turn with text and no tool call still ends the session finished" {
    // The regression this pins: the empty turn check must not turn an ordinary
    // completion into a fault. A model that answers and asks for nothing more
    // is a session that finished.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{ .{ .text = "the build is green" }, .{ .stop_reason = "end_turn" } } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "the same tool with the same arguments, three times in a row, ends the session no_progress" {
    // The red team run of 2026-08-21: the model called the same read on the
    // same paths sixteen times, and a 50 turn limit took 50 turns to notice
    // what was plain by turn 3. See `no_progress_repeats`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // Ten identical turns are offered. The detector must stop long before
    // the tenth, and nothing else here can stop this loop at all: no turn
    // limit, no budget, and never a turn with plain text.
    const looping_turns = [_]FakeTurn{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "run_command",
            .arguments = "{\"argv\":[\"readlink\",\"-f\",\"/proc/self\"]}",
        } }} },
    } ** 10;
    var fake_client = FakeClient{ .turns = &looping_turns };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    const deps = testDeps(fake_client.client(), store, fake_tools.runner());
    try testing.expectEqual(@as(?usize, null), deps.max_turns);

    try run(allocator, io, deps);

    // Three turns asked, and the third call never ran: a call already
    // answered the same way twice has nothing left to say.
    try testing.expectEqual(@as(usize, 3), fake_client.calls);
    try testing.expectEqual(@as(usize, 2), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.no_progress, std.meta.activeTag(reason));
}

test "a legitimate retry does not trip the no progress detector" {
    // A tool call can fail for a reason that is gone a moment later, and a
    // model that repeats the call once is doing the right thing. A detector
    // that fired on the second identical call would stop a healthy session.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const same_call = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "call1",
        .name = "run_command",
        .arguments = "{\"argv\":[\"git\",\"fetch\"]}",
    } }} };
    var fake_client = FakeClient{
        .turns = &.{
            same_call,
            same_call,
            .{ .deltas = &.{.{ .text = "it worked the second time" }} },
        },
    };
    var fake_tools = FailsOnceToolRunner{};

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 3), fake_client.calls);
    try testing.expectEqual(@as(usize, 2), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "an alternation of two calls ends the session no_progress" {
    // The red team run of 2026-08-21 walked straight through the old rule.
    // The model alternated two `bash` calls, A B A B A, and a detector that
    // held one previous call reset its count on every turn and never fired,
    // while the model plainly made no progress. This test used to pin that
    // behaviour as correct. See `no_progress_window`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const read_a = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "call1",
        .name = "read_file",
        .arguments = "{\"path\":\"a\"}",
    } }} };
    const read_b = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "call2",
        .name = "read_file",
        .arguments = "{\"path\":\"b\"}",
    } }} };
    // More alternation than the detector may need, and one plain text turn
    // at the end. The text turn is not there to end the session: it is there
    // so that a detector which never fires ends this test on the reason
    // check below, rather than running the fake client out of turns and
    // failing as a crash nobody can read.
    var fake_client = FakeClient{ .turns = &.{
        read_a,
        read_b,
        read_a,
        read_b,
        read_a,
        read_b,
        read_a,
        read_b,
        read_a,
        read_b,
        .{ .deltas = &.{.{ .text = "read them both, over and over" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // The fifth turn is the first that can hold A B A B A, and the fifth
    // call never ran: the window is full of two calls the session already
    // has both answers to.
    try testing.expectEqual(@as(usize, 5), fake_client.calls);
    try testing.expectEqual(@as(usize, 4), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.no_progress, std.meta.activeTag(reason));
}

test "build, edit, build, edit, build is work and is not stopped" {
    // The false positive the window alone would cause, and the reason for
    // `no_progress_distinct`. A model fixing one compile error at a time
    // repeats the identical build call every time, and the edits between are
    // different from each other. Three identical calls inside five, and it
    // is the healthiest session a coding agent has. Without the second
    // condition this test fails and the tool becomes untrustworthy.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const build = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "build",
        .name = "run_command",
        .arguments = "{\"argv\":[\"zig\",\"build\",\"test\"]}",
    } }} };
    const first_fix = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "fix1",
        .name = "edit_file",
        .arguments = "{\"path\":\"a.zig\",\"old_string\":\"u8\",\"new_string\":\"u16\"}",
    } }} };
    const second_fix = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "fix2",
        .name = "edit_file",
        .arguments = "{\"path\":\"b.zig\",\"old_string\":\"i32\",\"new_string\":\"i64\"}",
    } }} };
    var fake_client = FakeClient{ .turns = &.{
        build,
        first_fix,
        build,
        second_fix,
        build,
        .{ .deltas = &.{.{ .text = "it builds" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 6), fake_client.calls);
    try testing.expectEqual(@as(usize, 5), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "read, edit, read of one file is not a loop" {
    // The pattern the window was picked around. A model reads a file, edits
    // it, and reads it back to see what it wrote. The two reads are
    // identical calls with different answers, and there are only two of
    // them, so nothing here may stop the session.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const read = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "read",
        .name = "read_file",
        .arguments = "{\"path\":\"a.zig\"}",
    } }} };
    const edit = FakeTurn{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "edit",
        .name = "edit_file",
        .arguments = "{\"path\":\"a.zig\",\"old_string\":\"u8\",\"new_string\":\"u16\"}",
    } }} };
    var fake_client = FakeClient{ .turns = &.{
        read,
        edit,
        read,
        .{ .deltas = &.{.{ .text = "the edit landed" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 4), fake_client.calls);
    try testing.expectEqual(@as(usize, 3), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "the window holds the last calls only, so an old repeat leaves it" {
    // `Progress` is a ring of `no_progress_window` calls, not a tally that
    // grows forever. A call that has fallen out of the window must not still
    // be counted, or a long session would end on repeats that are twenty
    // turns apart. Read straight off `observe`, which is where the counting
    // lives.
    const allocator = testing.allocator;

    var progress = Progress{};
    defer progress.deinit(allocator);

    // Two of the same call, then a full window of different ones, then the
    // same call again. The first two are gone by then.
    _ = try progress.observe(allocator, "read_file", "{\"path\":\"a\"}");
    _ = try progress.observe(allocator, "read_file", "{\"path\":\"a\"}");
    for (0..no_progress_window) |index| {
        var buffer: [64]u8 = undefined;
        const arguments = try std.fmt.bufPrint(&buffer, "{{\"path\":\"f{d}\"}}", .{index});
        _ = try progress.observe(allocator, "read_file", arguments);
    }
    const observed = try progress.observe(allocator, "read_file", "{\"path\":\"a\"}");

    try testing.expectEqual(@as(usize, no_progress_window), observed.seen);
    try testing.expectEqual(@as(usize, 1), observed.repeats);
    try testing.expect(!observed.isLoop());
}

test "the same call twice is not a loop, and the third time inside the window is" {
    // The two numbers `isLoop` reads, pinned directly. A detector that fired
    // on the second identical call would stop a legitimate retry, and one
    // that needed the calls to be next to each other would miss a cycle.
    const allocator = testing.allocator;

    var straight = Progress{};
    defer straight.deinit(allocator);
    const once = try straight.observe(allocator, "run_command", "{\"argv\":[\"git\",\"fetch\"]}");
    try testing.expect(!once.isLoop());
    const twice = try straight.observe(allocator, "run_command", "{\"argv\":[\"git\",\"fetch\"]}");
    try testing.expectEqual(@as(usize, 2), twice.repeats);
    try testing.expect(!twice.isLoop());
    const thrice = try straight.observe(allocator, "run_command", "{\"argv\":[\"git\",\"fetch\"]}");
    try testing.expectEqual(@as(usize, 3), thrice.repeats);
    try testing.expectEqual(@as(usize, 1), thrice.distinct);
    try testing.expect(thrice.isLoop());

    var cycle = Progress{};
    defer cycle.deinit(allocator);
    const a = "{\"argv\":[\"bash\",\"-c\",\"find / | head\"]}";
    const b = "{\"argv\":[\"bash\",\"-c\",\"find /\"]}";
    _ = try cycle.observe(allocator, "run_command", a);
    _ = try cycle.observe(allocator, "run_command", b);
    _ = try cycle.observe(allocator, "run_command", a);
    const fourth = try cycle.observe(allocator, "run_command", b);
    // Four calls in, neither has been asked three times, so nothing fires.
    try testing.expect(!fourth.isLoop());
    const fifth = try cycle.observe(allocator, "run_command", a);
    try testing.expectEqual(@as(usize, 3), fifth.repeats);
    try testing.expectEqual(@as(usize, 2), fifth.distinct);
    try testing.expect(fifth.isLoop());
}

test "a session of more than fifty turns runs to completion" {
    // Fifty was the old limit, and it stopped sessions that were still
    // working. Pinned above that number on purpose: without this, removing
    // the limit would be untested and a later change could put one back.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const working_turns = 60;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Each turn asks for something different, which is what a session doing
    // real work looks like, and is what keeps the no progress detector out
    // of this test.
    const turns = try arena.alloc(FakeTurn, working_turns + 1);
    for (turns[0..working_turns], 0..) |*turn, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "call{d}", .{index}),
            .name = "read_file",
            .arguments = try std.fmt.allocPrint(arena, "{{\"path\":\"file{d}\"}}", .{index}),
        } };
        turn.* = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "read all sixty" };
    turns[working_turns] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, working_turns + 1), fake_client.calls);
    try testing.expectEqual(@as(usize, working_turns), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "a caller that asks for a turn limit gets one, and the session ends turn_limit" {
    // `--max-turns` stays for a caller that wants it, and it ends the
    // session with a reason of its own rather than an `errored` end told
    // apart by a sentence.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // Three different calls, so the no progress detector cannot be what
    // stops this: only the limit can.
    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c1", .name = "read_file", .arguments = "{\"path\":\"a\"}" } }} },
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c2", .name = "read_file", .arguments = "{\"path\":\"b\"}" } }} },
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c3", .name = "read_file", .arguments = "{\"path\":\"c\"}" } }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.max_turns = 3;

    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 3), fake_client.calls);
    try testing.expectEqual(@as(usize, 3), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.turn_limit, std.meta.activeTag(reason));
}

/// Records every event it is told about, so a test can compare what an
/// observer saw against what the log holds.
const RecordingObserver = struct {
    allocator: std.mem.Allocator,
    ids: std.ArrayList(u64) = .empty,
    kinds: std.ArrayList(event.Kind) = .empty,
    /// The number of events the log held at the moment each `onEvent` call
    /// arrived. See the test below.
    log_lengths: std.ArrayList(usize) = .empty,
    /// When set, read after each call, so the test can prove the event was
    /// already durable before the observer heard about it.
    log_to_measure: ?*const chock_proto.storage.Memory = null,
    /// Everything this observer was told, pieces and events in one list, in
    /// the order it was told. **The order is the whole point**: a test that
    /// only counted pieces would pass on an implementation that replayed them
    /// all after the turn finished, which is the silence this seam exists to
    /// end. See the test named for it.
    trace: std.ArrayList(Step) = .empty,
    /// One entry per `Observer.onNotice` call, copied: the text is borrowed
    /// for the call.
    notices: std.ArrayList([]u8) = .empty,

    const Step = union(enum) {
        event: event.Kind,
        /// The text of one piece, copied: `Piece` is borrowed for the call.
        piece: []u8,
    };

    fn deinit(self: *RecordingObserver) void {
        self.ids.deinit(self.allocator);
        self.kinds.deinit(self.allocator);
        self.log_lengths.deinit(self.allocator);
        for (self.trace.items) |step| switch (step) {
            .piece => |owned| self.allocator.free(owned),
            .event => {},
        };
        self.trace.deinit(self.allocator);
        for (self.notices.items) |owned| self.allocator.free(owned);
        self.notices.deinit(self.allocator);
    }

    fn observer(self: *RecordingObserver) Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn onEventFn(ptr: *anyopaque, id: u64, ev: event.Event) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        self.ids.append(self.allocator, id) catch return;
        self.kinds.append(self.allocator, std.meta.activeTag(ev)) catch return;
        self.trace.append(self.allocator, .{ .event = std.meta.activeTag(ev) }) catch return;
        if (self.log_to_measure) |backing| {
            self.log_lengths.append(self.allocator, backing.bytes.items.len) catch return;
        }
    }

    fn onPieceFn(ptr: *anyopaque, piece: Piece) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        const text = switch (piece) {
            .text => |t| t,
            .reasoning => |t| t,
        };
        const owned = self.allocator.dupe(u8, text) catch return;
        self.trace.append(self.allocator, .{ .piece = owned }) catch {
            self.allocator.free(owned);
            return;
        };
    }

    /// Every notice this observer was told, in order. See `Observer.onNotice`:
    /// the test named for the rate limit reads this to prove a person watching
    /// was told the session was waiting and not hung.
    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        const owned = self.allocator.dupe(u8, text) catch return;
        self.notices.append(self.allocator, owned) catch {
            self.allocator.free(owned);
            return;
        };
    }

    /// Where the first piece is in `trace`, or null when none arrived.
    fn firstPiece(self: *const RecordingObserver) ?usize {
        for (self.trace.items, 0..) |step, index| {
            if (step == .piece) return index;
        }
        return null;
    }

    /// Where the first event of `kind` is in `trace`, or null when none is.
    fn firstEvent(self: *const RecordingObserver, kind: event.Kind) ?usize {
        for (self.trace.items, 0..) |step, index| {
            if (step == .event and step.event == kind) return index;
        }
        return null;
    }

    const vtable = Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };
};

test "an observer is told about every event, in order, and never about one the log does not hold" {
    // The seam `chock run` needs. `run` holds the exclusive lock for the
    // whole session, so nothing outside this process can read the log while
    // it works: without this, a caller has no way at all to show a user what
    // is happening until the session is over.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var watcher = RecordingObserver{ .allocator = allocator, .log_to_measure = &backing };
    defer watcher.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.observer = watcher.observer();
    try run(allocator, io, deps);

    // Every event the log holds, in the same order and with the same
    // identifiers. Comparing against the log rather than against a list
    // written by hand is what keeps this test honest when the loop's own
    // sequence of events changes.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var index: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try testing.expect(index < watcher.ids.items.len);
        try testing.expectEqual(parsed.value.id, watcher.ids.items[index]);
        try testing.expectEqual(std.meta.activeTag(parsed.value.event), watcher.kinds.items[index]);
        index += 1;
    }
    // The observer heard about exactly as many events as the log holds, so it
    // was told about none the log does not have.
    try testing.expectEqual(index, watcher.ids.items.len);
    // Nine: session.start, this turn's usage, the assistant's tool_use turn,
    // tool.call, tool.result, the tool's answer fed back as a message, the
    // second turn's usage, the assistant's final answer, and session.end.
    // Pinning the count, and not only that the two agree, is what stops this
    // passing on an observer that saw nothing against a log that held
    // nothing.
    try testing.expectEqual(@as(usize, 9), index);

    // Each call arrived after its own event was already in the log: the
    // length the observer measured is past the offset it was given every
    // time. An observer told before the append would show a user something a
    // replay will not produce.
    for (watcher.ids.items, watcher.log_lengths.items) |id, length| {
        try testing.expect(length > id);
    }
}

test "a piece of the model's answer reaches the observer before the turn that holds it is over" {
    // **The fact this whole seam exists for.** A test that only asked whether
    // any output appeared would pass on the loop as it was: the answer already
    // appears, as one block, at the end of the turn. What was missing is that
    // it appears while the turn is still running, and a turn is minutes. So
    // what is pinned here is the order: a piece reached the observer before
    // the `message` event that closes the turn was appended.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{
            .{ .text = "I will " },
            .{ .text = "read the file " },
            .{ .text = "first." },
        } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var watcher = RecordingObserver{ .allocator = allocator };
    defer watcher.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.observer = watcher.observer();
    try run(allocator, io, deps);

    const first_piece = watcher.firstPiece() orelse return error.NoPieceArrived;
    const message_event = watcher.firstEvent(.message) orelse return error.NoMessageEvent;
    try testing.expect(first_piece < message_event);

    // And every piece of the answer, not only the first one, was on the screen
    // before the turn ended. A stream that delivered one piece early and the
    // rest at the end would be the same silence in a thinner disguise.
    var pieces_before: usize = 0;
    for (watcher.trace.items[0..message_event]) |step| {
        if (step == .piece) pieces_before += 1;
    }
    try testing.expectEqual(@as(usize, 3), pieces_before);

    // In the order the model produced them, and byte for byte.
    const expected = [_][]const u8{ "I will ", "read the file ", "first." };
    var seen: usize = 0;
    for (watcher.trace.items[0..message_event]) |step| {
        if (step != .piece) continue;
        try testing.expectEqualStrings(expected[seen], step.piece);
        seen += 1;
    }
}

test "streaming the pieces changes nothing about the log, which still gains one message event per turn" {
    // The other half of the seam, and the one a reader of a session depends
    // on: this changes what a person sees, never what is recorded. Two runs of
    // the same script, one watched and one not, and the logs must be the same
    // shape with the same words in them.
    const allocator = testing.allocator;
    const io = testing.io;

    const script: []const FakeTurn = &.{
        .{ .deltas = &.{ .{ .text = "one " }, .{ .text = "two " }, .{ .text = "three" } } },
    };

    var watched_backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const watched_store = watched_backing.storage();
    defer watched_store.close(io);
    var watched_client = FakeClient{ .turns = script };
    var watched_tools = FakeToolRunner{ .output = "unused" };
    var watcher = RecordingObserver{ .allocator = allocator };
    defer watcher.deinit();
    var watched_deps = testDeps(watched_client.client(), watched_store, watched_tools.runner());
    watched_deps.observer = watcher.observer();
    try run(allocator, io, watched_deps);

    var plain_backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const plain_store = plain_backing.storage();
    defer plain_store.close(io);
    var plain_client = FakeClient{ .turns = script };
    var plain_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(plain_client.client(), plain_store, plain_tools.runner()));

    var watched_kinds: std.ArrayList(event.Kind) = .empty;
    defer watched_kinds.deinit(allocator);
    var messages: usize = 0;
    var answer: []const u8 = "";
    var watched_replay = try watched_store.replay(allocator, io, 0);
    defer watched_replay.deinit();
    while (try watched_replay.next(io)) |parsed| {
        defer parsed.deinit();
        try watched_kinds.append(allocator, std.meta.activeTag(parsed.value.event));
        if (parsed.value.event != .message) continue;
        messages += 1;
        // Copied out of the parsed value, which is freed with it.
        answer = try allocator.dupe(u8, parsed.value.event.message.content[0].text);
    }
    defer allocator.free(answer);

    var index: usize = 0;
    var plain_replay = try plain_store.replay(allocator, io, 0);
    defer plain_replay.deinit();
    while (try plain_replay.next(io)) |parsed| {
        defer parsed.deinit();
        try testing.expect(index < watched_kinds.items.len);
        try testing.expectEqual(std.meta.activeTag(parsed.value.event), watched_kinds.items[index]);
        index += 1;
    }
    try testing.expectEqual(index, watched_kinds.items.len);

    // One `message` event for the turn, holding the whole answer joined, and
    // not one event per piece.
    try testing.expectEqual(@as(usize, 1), messages);
    try testing.expectEqualStrings("one two three", answer);
}

test "the model's reasoning reaches the observer as reasoning, and never as answer text" {
    // The two are different things to show, and only the observer can decide
    // what to do with each: see `Piece`. A loop that folded them together
    // would put the model's private working out in the middle of its answer
    // with no way for a printer to separate them again.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{
            .{
                .deltas = &.{
                    .{ .reasoning = "weighing the approach" },
                    // Neither of these is a word the model said, so neither reaches
                    // the observer as a piece: see `Piece`.
                    .{ .reasoning_signature = "SIG==" },
                    .{ .usage = .{ .input_tokens = 10, .output_tokens = 2 } },
                    .{ .text = "the answer" },
                },
            },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var kinds = KindRecordingObserver{ .allocator = allocator };
    defer kinds.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.observer = kinds.observer();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 2), kinds.pieces.items.len);
    try testing.expectEqual(Piece.reasoning, kinds.pieces.items[0]);
    try testing.expectEqual(Piece.text, kinds.pieces.items[1]);
}

/// Records which kind each piece was, and nothing else. Only the reasoning
/// test above uses it.
const KindRecordingObserver = struct {
    allocator: std.mem.Allocator,
    pieces: std.ArrayList(std.meta.Tag(Piece)) = .empty,

    fn deinit(self: *KindRecordingObserver) void {
        self.pieces.deinit(self.allocator);
    }

    fn observer(self: *KindRecordingObserver) Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn onEventFn(ptr: *anyopaque, id: u64, ev: event.Event) void {
        _ = ptr;
        _ = id;
        _ = ev;
    }

    fn onPieceFn(ptr: *anyopaque, piece: Piece) void {
        const self: *KindRecordingObserver = @ptrCast(@alignCast(ptr));
        self.pieces.append(self.allocator, std.meta.activeTag(piece)) catch return;
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        _ = ptr;
        _ = text;
    }

    const vtable = Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };
};

/// The flag the cancel tests below read through a function pointer, which is
/// the shape `Deps.canceled` takes. A file scope variable, because a function
/// pointer carries no context of its own: the real one is a signal handler's
/// flag in `src/interrupt.zig`, which is the same shape for the same reason.
var test_cancel_asked: bool = false;

fn testCanceled() bool {
    return test_cancel_asked;
}

/// A user pressing Ctrl-C while the session is waiting out a rate limit. Given
/// to `RecordingSleeper.on_wait` by the test named for it.
fn askForCancelDuringWait() void {
    test_cancel_asked = true;
}

/// A `ToolRunner` that asks for the session to stop as soon as it has run
/// `after` calls. This is a user pressing Ctrl-C in the middle of a turn: the
/// stop arrives while `run` holds the log's exclusive lock and is partway
/// through a turn of several tool calls.
const CancelingToolRunner = struct {
    after: usize,
    calls: usize = 0,

    fn dispatch(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        _ = io;
        const self: *CancelingToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        if (self.calls >= self.after) test_cancel_asked = true;
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, "ok"),
            .is_error = false,
            .truncated = false,
        };
    }

    fn runner(self: *CancelingToolRunner) ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatch };
};

/// What the handover tests below answer, and what the loop told them. File
/// scope for the reason `test_cancel_asked` is: `Deps.handover` is a function
/// pointer and carries no context of its own.
var test_handover_agree: bool = false;
/// How many times the loop asked, and what it said was in flight the last time.
var test_handover_asks: usize = 0;
var test_handover_seen: InFlight = .{};

fn testHandover(io: std.Io, in_flight: InFlight) bool {
    _ = io;
    test_handover_asks += 1;
    test_handover_seen = in_flight;
    return test_handover_agree;
}

/// A `ToolRunner` that agrees to a handover as soon as it has run `after`
/// calls. **This is what pins that the loop does not stop in the middle of a
/// turn**: the answer turns true while a turn is already running, and the loop
/// still has to finish that turn's tool calls before it stops.
const HandingOverToolRunner = struct {
    after: usize,
    calls: usize = 0,

    fn dispatch(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        _ = io;
        const self: *HandingOverToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        if (self.calls >= self.after) test_handover_agree = true;
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, "ok"),
            .is_error = false,
            .truncated = false,
        };
    }

    fn runner(self: *HandingOverToolRunner) ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatch };
};

test "a session handed over ends its log saying so, and not saying a person canceled it" {
    // **The reason is what makes this a handover and not a stop.** The fold is
    // the truth about a session, so the process taking over reads this reason,
    // `chock sessions` reads it, and `src/main.zig` turns it into an exit code
    // of its own. A log that said `canceled_by_user` would tell every one of
    // them that a person said no.
    //
    // Mutation check: write `canceled_by_user` in `endIfHandedOver` and the
    // last two lines stop holding, which is a handover a script reads as a
    // refusal.
    const allocator = testing.allocator;
    const io = testing.io;

    test_handover_agree = true;
    test_handover_asks = 0;
    defer test_handover_agree = false;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{.{ .text = "never sent" }} }},
    };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    // Two real tables, both empty, so what reaches the hook is what these
    // answer and not a value this test made up.
    var tasks = task_table.Table{ .gpa = allocator, .dir = "/tmp", .runner = undefined };
    var children = subagent.Table{ .gpa = allocator, .spawner = undefined };
    deps.tasks = &tasks;
    deps.children = &children;
    deps.handover = testHandover;
    try run(allocator, io, deps);

    // **Nothing was spent.** The ask is answered before the request is built,
    // so a session that changes hands does not pay for a turn the next owner
    // will send again.
    try testing.expectEqual(@as(usize, 0), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), test_handover_asks);

    // **And what the hook was told came from the two tables.** Nothing here
    // ever started a task or a child, so both counts are zero, which is the one
    // state that permits a handover. Mutation check: read `startedCount`
    // instead of `runningCount`, or read one table twice, and a session with a
    // finished task would refuse every handover for the rest of its life.
    try testing.expectEqual(@as(usize, 0), test_handover_seen.tasks);
    try testing.expectEqual(@as(usize, 0), test_handover_seen.children);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var last_kind: ?event.Kind = null;
    var ends: usize = 0;
    var reason: ?event.SessionEndReason = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        last_kind = std.meta.activeTag(parsed.value.event);
        if (parsed.value.event != .session_end) continue;
        ends += 1;
        reason = parsed.value.event.session_end.reason;
    }
    try testing.expectEqual(event.Kind.session_end, last_kind.?);
    try testing.expectEqual(@as(usize, 1), ends);
    try testing.expectEqual(event.SessionEndReason.handed_over, std.meta.activeTag(reason.?));
    try testing.expect(std.meta.activeTag(reason.?) != .canceled_by_user);
}

test "a session nobody asked for runs exactly as one with no handover hook at all" {
    // The other half, and the one that would break every session if it were
    // wrong. `Deps.handover` is read on every turn, so an answer of no has to
    // cost nothing and change nothing.
    //
    // Mutation check: make `endIfHandedOver` stop when the hook answers false,
    // and every session ends on its first turn.
    const allocator = testing.allocator;
    const io = testing.io;

    test_handover_agree = false;
    test_handover_asks = 0;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const one_call = [_]chock_provider.Client.Delta{
        .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
    };
    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &one_call },
            .{ .deltas = &.{.{ .text = "done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.handover = testHandover;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
    // Asked once per turn, and never inside one.
    try testing.expectEqual(@as(usize, 2), test_handover_asks);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var reason: ?event.SessionEndReason = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        reason = parsed.value.event.session_end.reason;
    }
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason.?));
}

test "a handover agreed to mid turn waits for the turn to end, so no tool call is left unanswered" {
    // **The whole reason this is not `Deps.canceled`.** `canceled` is read
    // between two tool calls of one turn, and a session stopped there leaves an
    // assistant message whose `tool_use` parts have no matching `tool.result`.
    // A person pressing Ctrl-C has accepted that. A handover must not produce
    // it, because the next owner has to send that context to a provider, and a
    // provider refuses a `tool_use` with no result.
    //
    // The runner below agrees while the first of two tool calls is running.
    //
    // Mutation check: call `endIfHandedOver` from the tool call loop as well,
    // beside `endIfCanceled`, and the second call below never runs, so the log
    // holds a `tool.call` the next owner can never answer.
    const allocator = testing.allocator;
    const io = testing.io;

    test_handover_agree = false;
    test_handover_asks = 0;
    defer test_handover_agree = false;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const two_calls = [_]chock_provider.Client.Delta{
        .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
        .{ .tool_call = .{ .index = 1, .id = "call2", .name = "run_command", .arguments = "{\"x\":1}" } },
    };
    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &two_calls },
            // Never sent: the next turn boundary is where the session stops.
            .{ .deltas = &.{.{ .text = "unreachable" }} },
        },
    };
    var fake_tools = HandingOverToolRunner{ .after = 1 };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.handover = testHandover;
    try run(allocator, io, deps);

    // **Both calls ran**, even though the answer turned to yes during the
    // first. That is the difference from a Ctrl-C, which stops after one.
    try testing.expectEqual(@as(usize, 2), fake_tools.calls);
    // And the turn after it was never sent.
    try testing.expectEqual(@as(usize, 1), fake_client.calls);

    // Every tool call in the log has its result, which is what a provider needs
    // and what the next owner is about to send.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var calls: usize = 0;
    var results: usize = 0;
    var reason: ?event.SessionEndReason = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .tool_call => calls += 1,
            .tool_result => results += 1,
            .session_end => |end| reason = end.reason,
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, 2), calls);
    try testing.expectEqual(calls, results);
    try testing.expectEqual(event.SessionEndReason.handed_over, std.meta.activeTag(reason.?));
}

test "a person at the keyboard beats another process asking for the session" {
    // Both answers are read at the top of the same turn, so the order decides
    // what the log says. A Ctrl-C recorded as a handover would tell the person
    // who pressed it that their session moved somewhere, and would tell a
    // script that a task carries on when the person stopped it.
    //
    // Mutation check: read `endIfHandedOver` before `endIfCanceled` and the
    // reason below becomes `handed_over`.
    const allocator = testing.allocator;
    const io = testing.io;

    test_cancel_asked = true;
    test_handover_agree = true;
    defer test_cancel_asked = false;
    defer test_handover_agree = false;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "never sent" }} }} };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.canceled = testCanceled;
    deps.handover = testHandover;
    try run(allocator, io, deps);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var reason: ?event.SessionEndReason = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        reason = parsed.value.event.session_end.reason;
    }
    try testing.expectEqual(event.SessionEndReason.canceled_by_user, std.meta.activeTag(reason.?));
}

test "a session that is stopped still ends its log, and says it was the user who stopped it" {
    // **The hole this closes.** A signal does not run a deferred append, so a
    // killed session left a log ending on whatever event happened to be last,
    // and a reader could not tell that apart from a process that died mid
    // write. A real log from a killed session ended on a `tool.result` with no
    // `session.end` at all.
    const allocator = testing.allocator;
    const io = testing.io;

    test_cancel_asked = false;
    defer test_cancel_asked = false;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // Two tool calls in one turn. The first one asks for the stop, so the
    // session is interrupted partway through a turn, which is the moment a
    // person actually presses the key.
    const two_calls = [_]chock_provider.Client.Delta{
        .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
        .{ .tool_call = .{ .index = 1, .id = "call2", .name = "run_command", .arguments = "{\"x\":1}" } },
    };
    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &two_calls },
            // Never reached: the session stops before it asks for another turn.
            .{ .deltas = &.{.{ .text = "unreachable" }} },
        },
    };
    var fake_tools = CancelingToolRunner{ .after = 1 };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.canceled = testCanceled;
    try run(allocator, io, deps);

    // The second tool call of the same turn never ran: the stop is read
    // between two calls, not only between two turns.
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
    // And no second turn was ever sent.
    try testing.expectEqual(@as(usize, 1), fake_client.calls);

    // The log ends, and it ends saying who ended it.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var last_kind: ?event.Kind = null;
    var ends: usize = 0;
    var reason: ?event.SessionEndReason = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        last_kind = std.meta.activeTag(parsed.value.event);
        if (parsed.value.event != .session_end) continue;
        ends += 1;
        reason = parsed.value.event.session_end.reason;
    }
    // The last event, and not merely one somewhere in the middle: a reader
    // walking the log to its end is the one this is for.
    try testing.expectEqual(event.Kind.session_end, last_kind.?);
    try testing.expectEqual(@as(usize, 1), ends);
    try testing.expectEqual(
        event.SessionEndReason.canceled_by_user,
        std.meta.activeTag(reason.?),
    );
}

test "a session stopped before its first turn spends nothing at all" {
    // The other safe point, and the order that matters at it: a session the
    // user has already stopped must not send one more model call, and must not
    // be refused for a budget either, because neither of those is what
    // happened to it.
    const allocator = testing.allocator;
    const io = testing.io;

    test_cancel_asked = true;
    defer test_cancel_asked = false;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "never sent" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.canceled = testCanceled;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 0), fake_client.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.canceled_by_user, std.meta.activeTag(reason));
}

test "a session nobody stops runs to the end, so the check costs a healthy session nothing" {
    // The other half. `canceled` says no for the whole session here, and the
    // session must behave exactly as it does with no `canceled` at all: the
    // reason a stop is read at two points per turn is that it is cheap, and a
    // check that ended healthy sessions would be worse than the silence it
    // replaced.
    const allocator = testing.allocator;
    const io = testing.io;

    test_cancel_asked = false;
    defer test_cancel_asked = false;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.canceled = testCanceled;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "a session with no observer behaves exactly as it did before there was one" {
    // The field is optional, and the default must change nothing. Without
    // this, adding the seam could quietly change the log every other test in
    // this file reads.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "all done" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    const deps = testDeps(fake_client.client(), store, fake_tools.runner());
    try testing.expect(deps.observer == null);
    try run(allocator, io, deps);

    var events: usize = 0;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        events += 1;
    }
    // session.start, the turn's usage, the assistant's message, session.end.
    try testing.expectEqual(@as(usize, 4), events);
}

/// Append one event to `store` outside `run`, the way `src/run.zig` seeds a
/// session's first message. The budget tests below use it to put a session's
/// earlier spending in the log before `run` folds it, and the spawn tests use
/// it to put a session's earlier children there.
fn seedEvent(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
    ev: event.Event,
) !void {
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};
    _ = try locked.append(allocator, io, ev, 0);
}

/// Fold every event `store` holds and give back the spend. Two calls on the
/// same log must agree: see the replay test below.
fn foldSpend(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
) !chock_proto.state.Spend {
    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
    }
    return session.spend;
}

test "a cap is checked before the request, and a refused turn sends nothing at all" {
    // Money cannot be un-spent, so the check happens before the request goes
    // out and not after the reply lands. Counting the client's calls is what
    // makes that visible: a check placed after the send would leave this at
    // one, with the money already gone.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // A turn that already spent the whole budget. The projection for the
    // next turn is the same amount again, so the next turn cannot fit.
    try seedEvent(allocator, io, store, .{ .usage = .{
        .input_tokens = 1000,
        .output_tokens = 500,
        .cost = .{ .known = .{ .value = 4.90, .currency = "USD" } },
        .model = "test-model",
    } });

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "never asked for" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.budget = .{ .max_cost = 5.00, .currency = "USD" };
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 0), fake_client.calls);

    var saw_request = false;
    var saw_response = false;
    var end_detail: []const u8 = "";
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => |request| {
                saw_request = true;
                try testing.expectEqualStrings(budget_action, request.action);
            },
            .approval_response => |response| {
                saw_response = true;
                // No answer before the timeout is a refusal, and a refusal is
                // the safe direction for a budget. Nothing answers this one, so
                // it is expired.
                try testing.expectEqual(
                    event.ApprovalDecision.expired,
                    std.meta.activeTag(response.decision),
                );
            },
            .session_end => |ended| {
                // A reason of its own, not `errored`: reaching a cap the user
                // wrote is not a fault, and a reader that had to match on a
                // sentence to tell the two apart would drift the first time
                // the sentence was reworded.
                try testing.expectEqual(
                    event.SessionEndReason.budget_reached,
                    std.meta.activeTag(ended.reason),
                );
                end_detail = try allocator.dupe(u8, ended.detail);
            },
            else => {},
        }
    }
    defer allocator.free(end_detail);

    // Hitting a cap is an approval, not a crash: the record of the question
    // and of its refusal is in the log, which is what lets a user raise the
    // cap and continue instead of losing the work.
    try testing.expect(saw_request);
    try testing.expect(saw_response);
    try testing.expect(std.mem.startsWith(u8, end_detail, budget_detail_prefix));
}

test "a session under a cap it has not reached runs, and its usage lands in the log" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedEvent(allocator, io, store, .{ .usage = .{
        .input_tokens = 100,
        .cost = .{ .known = .{ .value = 0.01, .currency = "USD" } },
    } });

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{
        .{ .text = "all done" },
        .{ .usage = .{ .input_tokens = 1200, .output_tokens = 150 } },
    } }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.budget = .{ .max_cost = 5.00, .currency = "USD" };
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_client.calls);

    const spend = try foldSpend(allocator, io, store);
    try testing.expectEqual(@as(u64, 2), spend.turns);
    try testing.expectEqual(@as(u64, 1300), spend.input_tokens);
    try testing.expectEqual(@as(u64, 150), spend.output_tokens);
    // "test-model" is in no price table, so this turn could not be priced and
    // the total is no longer one a cap may be enforced against. That is the
    // honest answer, and it is why the loop stops enforcing rather than
    // guessing.
    try testing.expectEqual(@as(u64, 1), spend.unpriced_turns);
    try testing.expect(!spend.enforceable());
}

test "a provider that reports no usage still gets a usage event, saying the cost is unknown" {
    // A provider with no usage capability reports its cost as unknown. That is
    // the whole behaviour. The session runs, and the log says plainly that it
    // could not be measured, which is what a reader needs to tell an unmeasured
    // session apart from a free one.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "all done" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var saw_usage = false;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .usage) continue;
        saw_usage = true;
        const usage = parsed.value.event.usage;
        try testing.expectEqual(event.Cost.unknown, std.meta.activeTag(usage.cost));
        try testing.expect(usage.cost != .free);
        try testing.expectEqualStrings("test-model", usage.model);
        try testing.expectEqualStrings("main", usage.model_alias);
        // Nothing computed this, so no table version is claimed for it.
        try testing.expectEqualStrings("", usage.price_table_version);
    }
    try testing.expect(saw_usage);
}

test "a free provider under a cap runs to completion, because free is not unknown" {
    // The other half of the three states. A local llama.cpp server costs
    // nothing, and a session against it must run under a cap without
    // trouble, however many turns it takes.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.budget = .{ .max_cost = 0.01, .currency = "USD" };
    deps.billing = .free;
    try run(allocator, io, deps);

    // Both turns ran: a cap that stopped a free session would be reading
    // "cost nothing" as "cost unknown".
    try testing.expectEqual(@as(usize, 2), fake_client.calls);

    const spend = try foldSpend(allocator, io, store);
    try testing.expectEqual(@as(u64, 2), spend.turns);
    try testing.expectEqual(@as(u64, 0), spend.unpriced_turns);
    try testing.expect(spend.enforceable());
    try testing.expectEqual(@as(f64, 0), spend.amount);
}

test "the cost of a session survives a replay: two folds of one log agree" {
    // The log is the truth, and a total that lives only in the running process
    // is lost on a /daemonize, on a reconnect, and on a replay. Folding twice
    // is how this project already pins that for the context, and the total gets
    // the same test.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{
            .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
            .{ .usage = .{ .input_tokens = 1200, .output_tokens = 40 } },
        } },
        .{ .deltas = &.{
            .{ .text = "done" },
            .{ .usage = .{ .input_tokens = 1800, .output_tokens = 90 } },
        } },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.billing = .free;
    try run(allocator, io, deps);

    const first = try foldSpend(allocator, io, store);
    const second = try foldSpend(allocator, io, store);
    try testing.expectEqual(first.turns, second.turns);
    try testing.expectEqual(first.input_tokens, second.input_tokens);
    try testing.expectEqual(first.output_tokens, second.output_tokens);
    try testing.expectEqual(first.amount, second.amount);
    try testing.expectEqual(first.unpriced_turns, second.unpriced_turns);
    // And the numbers are the ones the two turns actually reported, so this
    // is not two folds agreeing on nothing.
    try testing.expectEqual(@as(u64, 2), first.turns);
    try testing.expectEqual(@as(u64, 3000), first.input_tokens);
    try testing.expectEqual(@as(u64, 130), first.output_tokens);
}

test "a cap in one currency and turns billed in another is not enforced" {
    // Inventing an exchange rate here would be worse than not enforcing: the
    // number it produced would look like a real total and stop a session for
    // a reason nobody could check. The same answer an unknown cost gets, one
    // level up.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedEvent(allocator, io, store, .{ .usage = .{
        .cost = .{ .known = .{ .value = 99.0, .currency = "EUR" } },
    } });

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "still asked for" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.budget = .{ .max_cost = 5.00, .currency = "USD" };
    try run(allocator, io, deps);

    // The turn went out: 99 EUR against a 5 USD cap is not 99 > 5, it is two
    // numbers that cannot be compared.
    try testing.expectEqual(@as(usize, 1), fake_client.calls);
}

test "a tool that answers with bytes that are not UTF-8 leaves a JSON string in the request, never an array" {
    // The fault this pins ended every session that read any binary file: a
    // git object, an image, an archive, a compiled program. See
    // `tools.outputForModel` for the measurement.
    //
    // **The assertion is on the serialized request and not on the Zig
    // value.** Both shapes are a valid `[]const u8`, so a test that read
    // `messages[n].content[0].tool_result.output` would pass either way.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const compressed = [_]u8{ 0x78, 0x9c, 0x4b, 0xca, 0xc9, 0xff, 0xfe, 0x80, 0x81, 0x00 };

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "read_file", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "that file is binary" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{ .output = &compressed };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    // The session ran its second turn, so it survived the tool result.
    try testing.expectEqual(@as(usize, 2), fake_client.calls);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, "\"content\":\"[chock: binary output, 10 bytes, not shown]\"") != null);
    // The exact shape that made the provider answer 400. Written out rather
    // than described, because this is the thing that must never appear.
    try testing.expect(std.mem.indexOf(u8, json, "[120,156,75,202,201,255,254,128,129,0]") == null);

    // And the log holds the stand in too, so a replay of this session can
    // still be parsed back. A log line with an array where a string belongs
    // is a session that cannot be resumed.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .tool_result) continue;
        try testing.expectEqualStrings("[chock: binary output, 10 bytes, not shown]", parsed.value.event.tool_result.output);
        saw_result = true;
    }
    try testing.expect(saw_result);
}

test "a result's note reaches the log and never the model" {
    // **A tool result has two readers.** `output` is written for the model and
    // says what the agent may do next. The note is written for the person and
    // says what the person may do, and the split exists because one string
    // cannot do both: the project owner read a refusal addressed to the model
    // as a message addressed to him and reported a working refusal as a fault.
    //
    // **The guarantee is that only three fields become a content part.** So
    // this is asserted on the serialized request, not on a Zig value: a test
    // that read the neutral message would pass even if the note were folded
    // into the output on the way out.
    //
    // Mutation check: add `note` to the `feedback` part in `runTool` and the
    // request assertion fails; drop `.note` from the event `runFetch` and
    // `runTool` build and the log assertion fails.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "understood" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{
        .output = "exit status: 2\nsocktype: SOCK_RAW\n",
        .is_error = true,
        .note = "a tool call gets no network at all",
    };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    // The bytes the model really got. The output is there and the note is not.
    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, "SOCK_RAW") != null);
    try testing.expect(std.mem.indexOf(u8, json, "no network at all") == null);

    // And the log kept it, so a replay shows the person what the person was
    // shown at the time.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .tool_result) continue;
        try testing.expectEqualStrings(
            "a tool call gets no network at all",
            parsed.value.event.tool_result.note,
        );
        saw_result = true;
    }
    try testing.expect(saw_result);
}

test "ordinary text output reaches the request unchanged, multi byte characters included" {
    // The other half of the check above: it must not mangle what it was not
    // written for. Every character past the first here is more than one
    // byte.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "read_file", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "read it" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{ .output = "caf\u{00e9} \u{65e5}\u{672c} \u{2192} ok" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, "\"content\":\"caf\u{00e9} \u{65e5}\u{672c} \u{2192} ok\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "binary output") == null);
}

test "a megabyte with no newline survives the turn as a JSON string" {
    // Long is not the same fact as binary, and a plausible thing a real
    // command prints. `tools.max_output_bytes` is what bounds a real tool
    // call; this runner is not the sandbox one, so it carries the whole
    // megabyte and the point is that the turn still goes out as a string.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const long = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(long);
    @memset(long, 'x');

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "that is a lot" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{ .output = long };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, "\"content\":\"xxxx") != null);
    try testing.expect(std.mem.indexOf(u8, json, "binary output") == null);
}

// `lib/chock-core/redact.zig` holds the mechanism and the honest framing.
// These pin what only a whole session can show: that the one chokepoint really
// is on every road out, that the log's own bytes never hold the value, that a
// log written this way still verifies, and that a project which declared
// nothing is untouched.
//
// **No assertion below prints the value.** Every check is a boolean over a
// haystack, because `expectEqualStrings` prints both sides and one of those
// sides is the thing this whole feature exists to keep out of print. The
// storage is `chock_proto.storage.Memory`, so nothing here reaches a disk
// either.

/// An invented value with no meaning anywhere. The only value in this file
/// that stands in for a credential.
const fake_key = "sk-loop-test-000000000000000000";

/// Every byte the log holds, in the shape another client would be served.
fn logBytes(backing: *const chock_proto.storage.Memory) []const u8 {
    return backing.bytes.items;
}

test "a credential in a tool result is in none of the log's own bytes" {
    // **The half that cannot be undone later.** The log is append only and
    // hash chained, so a credential written here stays here: taking it out
    // afterwards breaks the chain of every record that follows. So there is no
    // cleanup, only prevention, and this is the test that says prevention
    // happened.
    //
    // The realistic accident: a program printed the key back inside its own
    // error message, twice, once in the command it echoed and once in the
    // failure. Both go, and the words around them stay, so the model can
    // still act on the error.
    //
    // Mutation check: append `ev` instead of `clean` in `appendAndApply` and
    // the raw byte search below fails.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const said = "curl -H auth:" ++ fake_key ++ "\n401 for key " ++ fake_key ++ ", check it\n";

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "the key is wrong" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{ .output = said };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.redact = .{ .secrets = &.{.{ .value = fake_key, .source = .credential }} };
    try run(allocator, io, deps);
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    // **The log's own bytes, and not a parsed field.** This is what `chockd`
    // serves and what an export ships, so it is the only search that answers
    // the question.
    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), fake_key) == null);

    const json = fake_client.last_request_json.?;
    // Every appearance, and not the first one.
    try testing.expect(std.mem.indexOf(u8, json, fake_key) == null);
    try testing.expectEqual(
        @as(usize, 2),
        std.mem.count(u8, json, redact.Source.credential.marker()),
    );
    // **A marker and not silence.** A model handed a gap retries the read and
    // burns turns on a value it will never see. A model handed this stops
    // asking. The rest of the message is still there for it to act on.
    try testing.expect(std.mem.indexOf(u8, json, "401 for key ") != null);
    try testing.expect(std.mem.indexOf(u8, json, ", check it") != null);

    // **The record still says what happened.** A marker stands where the value
    // was, so a reader learns a secret was there and which layer caught it.
    // What is lost is the value alone.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .tool_result) continue;
        const output = parsed.value.event.tool_result.output;
        try testing.expectEqual(
            @as(usize, 2),
            std.mem.count(u8, output, redact.Source.credential.marker()),
        );
        try testing.expect(std.mem.indexOf(u8, output, "401 for key ") != null);
        saw_result = true;
    }
    try testing.expect(saw_result);

    // **And the chain still holds over it.** Redaction rewrites bytes that are
    // about to be hashed, so the record that is hashed has to be the redacted
    // one. It is: the replacement happens before `Locked.append`.
    const report = try chock_proto.storage.verify(store, allocator, io);
    try testing.expectEqual(chock_proto.chain.Verdict.intact, report.verdict);
    try testing.expect(report.events > 0);
    try testing.expectEqual(report.events, report.chained);

    // **And this is why prevention is all there is.** The record after this one
    // carries the hash of these bytes, so one byte changed inside the marker is
    // found. A session that wrote the value and tried to take it out later would
    // leave exactly this verdict behind, which is the reason the replacement has
    // to happen before the append. Last, because it spoils the log.
    const marker_at = std.mem.indexOf(u8, logBytes(&backing), redact.Source.credential.marker()).?;
    backing.bytes.items[marker_at + 1] = 'X';
    const forged = try chock_proto.storage.verify(store, allocator, io);
    try testing.expectEqual(chock_proto.chain.Verdict.broken, forged.verdict);
}

test "the funnel is the append, so a kind nobody listed is covered too" {
    // **Why `appendAndApply` is the seam and `Broker.appendToolResult` is
    // not.** A tool result is not the only record that carries bytes a
    // workspace supplied: a `session.end` written from a provider refusal
    // carries the body that provider sent back, and that body is where a
    // credential most often echoes. `chock-core` imports no `chock-broker` at
    // all, so a redactor over one event kind in the broker could never have
    // been on this road.
    //
    // Mutation check: redact only `.tool_result` in `appendAndApply` and this
    // fails while the test above still passes.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // A refusal the retry policy gives up on, so `sendWithRetry` writes a
    // `session.end` holding the provider's own words.
    const refused = "rate limited for key " ++ fake_key;
    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{ .status = .too_many_requests, .body = refused } },
        .{ .refusal = .{ .status = .too_many_requests, .body = refused } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.redact = .{ .secrets = &.{.{ .value = fake_key, .source = .credential }} };
    deps.retry = .{ .max_attempts = 2, .first_wait_ms = 1 };
    deps.sleeper = sleeper.sleeper();
    try run(allocator, io, deps);

    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), fake_key) == null);

    // The `session.end` really was written with the provider's words in it, so
    // this is not a test that passed because nothing was recorded.
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_end = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        const detail = parsed.value.event.session_end.detail;
        if (std.mem.indexOf(u8, detail, "rate limited for key ") == null) continue;
        try testing.expect(std.mem.indexOf(u8, detail, redact.Source.credential.marker()) != null);
        saw_end = true;
    }
    try testing.expect(saw_end);
}

test "a project that declared nothing sends byte for byte what it sent before" {
    // The property that lets this ship at all. The output below is exactly
    // the shape the best effort patterns look for, and none of them runs,
    // because `redact.Policy` is inert until somebody fills it in.
    //
    // Mutation check: give `redact.Policy.heuristics` a default of true and
    // both assertions fail.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const shaped = "AKIAIOSFODNN7EXAMPLE and ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "read it" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{ .output = shaped };

    // No `deps.redact` at all, which is what a caller that never heard of it
    // passes.
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, shaped) != null);
    try testing.expect(std.mem.indexOf(u8, json, "[chock: redacted") == null);
}

test "the compaction call is redacted too, so the second road out is not a way past" {
    // **The whole reason `sendOnce` exists.** A compaction sends the rendered
    // context to the provider through a request this loop builds by hand, so
    // a redactor that sat in the ordinary turn alone would let every secret
    // in the context out on the turn the session got long.
    //
    // Mutation check: call `Client.sendAndAssemble` directly in
    // `askForSummary` and this fails while every other test in this file
    // still passes.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    const leaked = [_]event.ContentPart{.{ .text = "the file held " ++ fake_key }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .assistant, .content = &leaked } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 60000, .output_tokens = 10 } },
            } },
            .{ .deltas = &.{.{ .text = "SUMMARY WRITTEN AT THE THRESHOLD" }} },
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
        .seen = &seen,
    };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.compaction = .{ .context_limit_tokens = 65536 };
    deps.redact = .{ .secrets = &.{.{ .value = fake_key, .source = .credential }} };
    try run(allocator, io, deps);

    // The compaction really happened, so this is not a test that passed
    // because nothing was sent.
    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);

    var saw_summary_call = false;
    for (seen.items.items) |one| {
        try testing.expect(std.mem.indexOf(u8, one.system, fake_key) == null);
        try testing.expect(std.mem.indexOf(u8, one.tail, fake_key) == null);
        if (!std.mem.eql(u8, one.system, compaction.summary_system)) continue;
        saw_summary_call = true;
        // The context it rendered really did carry the value, so the marker
        // is what stands where it was.
        try testing.expect(std.mem.indexOf(u8, one.tail, redact.Source.credential.marker()) != null);
    }
    try testing.expect(saw_summary_call);
}

// The two sessions measured on 2026-08-21: one grew from 2323 to 19534 input
// tokens and slowed by four times with it, and the next died outright on
// `request (77857 tokens) exceeds the available context size (65536 tokens)`.
// `compaction` was already an event kind and this loop never wrote one.
//
// **A compaction test that only says the context got smaller is vacuous.**
// Each of these names the fact it pins: that the summary is there, that what
// `kept_ranges` named survived word for word, that the user's own task was
// never folded, and that a second fold of the same log builds the same
// context.

/// Put `count` assistant messages in `store`, each holding `text` with its
/// own number, so a test starts with a context long enough to fold.
fn seedMessages(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
    text: []const u8,
    count: usize,
) !void {
    for (0..count) |i| {
        const body = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ text, i });
        defer allocator.free(body);
        const parts = [_]event.ContentPart{.{ .text = body }};
        try seedEvent(allocator, io, store, .{ .message = .{ .role = .assistant, .content = &parts } });
    }
}

/// Every `compaction` event in `store`, as the ids and the fields a test
/// wants to talk about. The summary text is copied, because the parsed value
/// it came from dies with the replay.
const FoundCompaction = struct {
    id: u64,
    summary: []u8,
    from_id: u64,
    through_id: u64,
    kept_ranges: []event.EventRange,
    model_alias: []u8,

    fn deinit(self: *FoundCompaction, allocator: std.mem.Allocator) void {
        allocator.free(self.summary);
        allocator.free(self.kept_ranges);
        allocator.free(self.model_alias);
    }
};

fn firstCompaction(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: chock_proto.storage.Storage,
) !?FoundCompaction {
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .compaction) continue;
        const found = parsed.value.event.compaction;
        return .{
            .id = parsed.value.id,
            .summary = try allocator.dupe(u8, found.summary),
            .from_id = found.from_id,
            .through_id = found.through_id,
            .kept_ranges = try allocator.dupe(event.EventRange, found.kept_ranges),
            .model_alias = try allocator.dupe(u8, found.model_alias),
        };
    }
    return null;
}

/// Every text part of every `.message` context entry of a folded session,
/// joined, plus every `.summary` entry. What a test reads to say a turn
/// survived a compaction word for word, or did not.
fn contextText(allocator: std.mem.Allocator, session: *const chock_proto.state.Session) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (session.context.items) |entry| switch (entry.data) {
        .summary => |text| {
            try out.appendSlice(allocator, text);
            try out.append(allocator, '\n');
        },
        .message => |m| for (m.content) |part| {
            if (part != .text) continue;
            try out.appendSlice(allocator, part.text);
            try out.append(allocator, '\n');
        },
    };
    return out.toOwnedSlice(allocator);
}

test "a session that overflows its context compacts, takes the turn again, and does not end errored" {
    // **The whole point.** Before this, the measured 400 below ended the
    // session and threw away every turn it had already done. A context
    // overflow is not a failure: it is the condition compaction answers.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: make the parser accept tabs" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var fake_client = FakeClient{
        .turns = &.{
            // The turn the provider refuses, because the request is too large.
            .{ .refusal = .{ .body = measured_overflow_body } },
            // The summary call the compaction makes.
            .{ .deltas = &.{.{ .text = "the parser work is half done and the tab case is open" }} },
            // The same turn, taken again with the shorter context.
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // The session finished. It used to end `errored` on exactly this body.
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    try testing.expectEqual(@as(usize, 3), fake_client.calls);

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expectEqualStrings("the parser work is half done and the tab case is open", found.summary);
    // A model wrote it, and the event says which alias did.
    try testing.expectEqualStrings("main", found.model_alias);
    try testing.expectEqual(@as(usize, 1), found.kept_ranges.len);
}

test "a compaction folds the middle and leaves the task and the recent turns word for word" {
    // **Not "the context got smaller".** The task the user gave is protected
    // out of the folded span altogether, because a session that forgets what
    // it was asked is worse than one that runs out of context. The recent
    // turns are inside the span and named in `kept_ranges`, which is what
    // that field is for.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: make the parser accept tabs" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{ .body = measured_overflow_body } },
        .{ .deltas = &.{.{ .text = "SUMMARY OF THE MIDDLE" }} },
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var session = try foldFromStart(allocator, io, store);
    defer session.deinit();
    const text = try contextText(allocator, &session);
    defer allocator.free(text);

    // The task, word for word, and it comes before the summary: the fold
    // leaves the protected head where it was.
    // **Each failure carries the whole context.** Control reaches a block
    // below only when the text is not in `text` at all, so the comparison
    // cannot hold, and `expectEqualStrings` prints both sides: a reader sees
    // the context the fold really left. A write to the terminal would put the
    // same words into every passing run of this suite as well, and `zig
    // build` reads any run step that wrote to standard error as a failure.
    const task_at = std.mem.indexOf(u8, text, "TASK: make the parser accept tabs") orelse {
        try testing.expectEqualStrings("TASK: make the parser accept tabs", text);
        return error.TheUsersOwnTaskWasFoldedAway;
    };
    const summary_at = std.mem.indexOf(u8, text, "SUMMARY OF THE MIDDLE") orelse {
        try testing.expectEqualStrings("SUMMARY OF THE MIDDLE", text);
        return error.TheCompactionLeftNoSummary;
    };
    try testing.expect(task_at < summary_at);

    // Every kept turn, word for word, and after the summary.
    for (0..6) |i| {
        const recent = try std.fmt.allocPrint(allocator, "RECENT-{d}", .{i});
        defer allocator.free(recent);
        const at = std.mem.indexOf(u8, text, recent) orelse {
            // The same shape as the two above: the failure names the turn
            // that did not survive and prints the context beside it.
            try testing.expectEqualStrings(recent, text);
            return error.AKeptTurnDidNotSurviveTheCompaction;
        };
        try testing.expect(summary_at < at);
    }

    // And the folded middle is gone from the context, while the log still
    // holds every one of those events.
    try testing.expect(std.mem.indexOf(u8, text, "MIDDLE-0") == null);
    try testing.expect(std.mem.indexOf(u8, text, "MIDDLE-4") == null);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var middles: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .message) continue;
        for (parsed.value.event.message.content) |part| {
            if (part == .text and std.mem.startsWith(u8, part.text, "MIDDLE-")) middles += 1;
        }
    }
    try testing.expectEqual(@as(usize, 5), middles);
}

test "two folds of a log holding a compaction build the same context, entry for entry" {
    // **The guarantee that matters most.** The log is the truth and the
    // context is a view of it, and a compaction changes the view and nothing
    // else. A resume, a `/daemonize` handover and a phone attaching to the
    // session all replay the same events, so a fold that was not a function of
    // the log would show three readers three different conversations.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: make the parser accept tabs" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{ .body = measured_overflow_body } },
        .{ .deltas = &.{.{ .text = "SUMMARY OF THE MIDDLE" }} },
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // The log must actually hold a compaction, or this test pins the
    // ordinary case a second time and pins nothing new.
    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);

    var first = try foldFromStart(allocator, io, store);
    defer first.deinit();
    var second = try foldFromStart(allocator, io, store);
    defer second.deinit();

    try testing.expectEqual(first.context.items.len, second.context.items.len);
    for (first.context.items, second.context.items) |a, b| {
        try testing.expectEqual(a.id, b.id);
        try testing.expectEqual(std.meta.activeTag(a.data), std.meta.activeTag(b.data));
        try testing.expectEqualStrings(a.model_alias, b.model_alias);
        switch (a.data) {
            .summary => |text| try testing.expectEqualStrings(text, b.data.summary),
            .message => |m| try expectMessagesEqual(m, b.data.message),
        }
    }

    // And the fold really did shorten the view: twelve seeded entries plus
    // the two turns of the session cannot still all be there.
    try testing.expect(first.context.items.len < 12);
}

test "a rate limit ends the session and never compacts, however much its body says about tokens" {
    // **The two failure classes must not be folded together.** A 429 and a
    // context overflow look identical at this call site and want opposite
    // answers: one is the same request sent again after a wait, the other is
    // a smaller request. A loop that compacted on a 429 would throw away
    // turns that had nothing wrong with them and then meet the same limit.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedMessages(allocator, io, store, "MIDDLE", 12);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{
            .status = .too_many_requests,
            .body =
            \\{"error":{"message":"Rate limit reached on tokens per min (TPM): Limit 10000, Used 9999","type":"tokens"}}
            ,
        } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    // One attempt, so this test is about the classification alone. The wait
    // that a 429 now gets is the subject of its own tests below, and a policy
    // that retried here would only make this one slower without making it say
    // anything more about compaction.
    deps.retry.max_attempts = 1;
    try run(allocator, io, deps);

    // One call, so no summary was ever asked for, and no compaction happened.
    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expect(try firstCompaction(allocator, io, store) == null);
    try testing.expectEqual(
        event.SessionEndReason.errored,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

/// The body a 429 carried in the session that ended on 2026-08-22 and took
/// 105 changed files with it, in the provider's own words. The retry tests use
/// it so they answer the real wire and not a paraphrase of it.
const measured_rate_limit_body =
    \\{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your rate limit of 500,000 input tokens per minute"}}
;

test "a rate limit is waited out, and the reply after the wait is the session's real answer" {
    // **The whole point of the retry.** A session that ends on a 429 loses
    // everything it had done; a session that waits gets the answer. So this
    // pins the answer itself and not merely that a second attempt happened: a
    // retry that came back with an error would satisfy "it retried" and would
    // still have lost the session.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{ .status = .too_many_requests, .body = measured_rate_limit_body } },
        .{ .deltas = &.{.{ .text = "the answer the session was for" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();
    var watching = RecordingObserver{ .allocator = allocator };
    defer watching.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    deps.observer = watching.observer();
    try run(allocator, io, deps);

    // Exactly two sends, and exactly one wait between them.
    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), sleeper.waits.items.len);
    // **The wait is never zero.** A retry that came straight back would meet
    // the same per minute limit and spend the attempt for nothing.
    try testing.expect(sleeper.waits.items[0] > 0);

    // The session finished, and what it finished with is the model's real
    // reply.
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    const said = try lastAssistantText(allocator, io, store);
    defer allocator.free(said);
    try testing.expectEqualStrings("the answer the session was for", said);

    // And a person watching was told, so a minute of silence does not read as
    // a hang. See `Observer.onNotice`.
    try testing.expectEqual(@as(usize, 1), watching.notices.items.len);
    try testing.expect(std.mem.indexOf(u8, watching.notices.items[0], "rate_limited") != null);
}

test "the wait is exactly what the provider's Retry-After asked for" {
    // ai& sends `Retry-After` on a 429, and the provider knows its own window
    // when this loop does not. The number is pinned, not the fact that
    // something was waited: a wait built from the wrong number either hammers
    // or hangs.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{
            .status = .too_many_requests,
            .body = measured_rate_limit_body,
            .retry_after_s = 37,
        } },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    // No spread, so the number below is the header's own and nothing else.
    // The spread's own arithmetic is pinned in `chock_provider.retry`, and it
    // only ever adds: see `retry.waitMs`.
    deps.retry.retry_after_spread_ms = 0;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), sleeper.waits.items.len);
    try testing.expectEqual(@as(u64, 37_000), sleeper.waits.items[0]);

    // **Not the backoff's own number.** The default first step is 2 seconds,
    // so a loop that ignored the header would have waited about one, and this
    // test would pass on it if it only asserted that a wait happened.
    try testing.expect(sleeper.waits.items[0] != retry.waitMs(deps.retry, 1, null, 0));
}

test "the attempts run out, and the session says how many were made and what the provider last said" {
    // A retry with no bound is a session that never ends. When the bound is
    // reached the user has to be able to tell "it waited and the provider kept
    // refusing" from "it gave up at once", which is the count, and they need
    // the provider's own words to know what to fix.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const refused = FakeTurn{ .refusal = .{
        .status = .too_many_requests,
        .body = measured_rate_limit_body,
    } };
    var fake_client = FakeClient{ .turns = &.{ refused, refused, refused } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    deps.retry.max_attempts = 3;
    try run(allocator, io, deps);

    // Three sends, which is the bound, and two waits, which is one fewer:
    // nothing waits after the attempt it has decided not to make.
    try testing.expectEqual(@as(usize, 3), fake_client.calls);
    try testing.expectEqual(@as(usize, 2), sleeper.waits.items.len);
    // And the backoff grew rather than repeating one wait.
    try testing.expect(sleeper.waits.items[1] > sleeper.waits.items[0]);

    try testing.expectEqual(
        event.SessionEndReason.errored,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.indexOf(u8, detail, "3 attempts") != null);
    try testing.expect(std.mem.indexOf(u8, detail, "500,000 input tokens per minute") != null);
}

test "a Retry-After longer than the session waits ends it at once instead of retrying blind" {
    // Clamping the wait would send the request again inside a window the
    // provider said was still shut. Ending and saying so is the honest answer,
    // and the log keeps everything the session did first.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{
            .status = .too_many_requests,
            .body = measured_rate_limit_body,
            .retry_after_s = 3_600,
        } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 0), sleeper.waits.items.len);
    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.indexOf(u8, detail, "3600 seconds") != null);
}

test "a bad request is never waited on, because no wait makes it succeed" {
    // The other half of the classification. A retry that fired on every
    // refusal would sit for a minute in front of an unknown model name, and
    // then again, and then end with the same message it could have given at
    // once.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{
            .status = .bad_request,
            .body =
            \\{"error":{"message":"The model `gpt-9` does not exist","code":"model_not_found"}}
            ,
        } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 0), sleeper.waits.items.len);
    try testing.expectEqual(
        event.SessionEndReason.errored,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "a full context still compacts and is never waited on, and a rate limit never compacts" {
    // **The pair the classification exists for, in one test.** A limit on
    // input tokens per minute is partly a context size problem, which makes
    // joining the two paths tempting. Joined, a rate limit would throw away
    // turns nothing was wrong with, and a full context would wait forever for
    // a window that is not going to open.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedMessages(allocator, io, store, "MIDDLE", 12);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .refusal = .{ .body = measured_overflow_body } },
            // The summary `compactNow` asks the model for.
            .{ .deltas = &.{.{ .text = "a summary of the work so far" }} },
            .{ .deltas = &.{.{ .text = "the turn, taken again on a smaller context" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var sleeper = RecordingSleeper{ .allocator = allocator };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    try run(allocator, io, deps);

    // The overflow compacted, and nothing waited for it.
    var folded = (try firstCompaction(allocator, io, store)).?;
    defer folded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), sleeper.waits.items.len);
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "a session canceled during a wait ends as canceled, and never sends the request the wait was for" {
    // A wait can be a minute long, so it is a safe point of its own. Without
    // this, Ctrl-C during a wait was answered only after the request the wait
    // was for had already been sent and answered.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .refusal = .{ .status = .too_many_requests, .body = measured_rate_limit_body } },
            // Scripted, and never reached: reaching it is the failure this test
            // is named for.
            .{ .deltas = &.{.{ .text = "should never be sent" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    test_cancel_asked = false;
    defer test_cancel_asked = false;
    var sleeper = RecordingSleeper{ .allocator = allocator, .on_wait = askForCancelDuringWait };
    defer sleeper.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.sleeper = sleeper.sleeper();
    deps.canceled = testCanceled;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), sleeper.waits.items.len);
    try testing.expectEqual(
        event.SessionEndReason.canceled_by_user,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "a context that cannot be made shorter ends the session instead of compacting in a circle" {
    // A task and one turn cannot be folded into anything smaller. Ending
    // here, with the log intact, is what stops a session compacting forever
    // on a model whose limit the kept tail alone already passes.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });

    var fake_client = FakeClient{ .turns = &.{
        .{ .refusal = .{ .body = measured_overflow_body } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expect(try firstCompaction(allocator, io, store) == null);
    try testing.expectEqual(
        event.SessionEndReason.errored,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "a threshold Chock chose compacts before any provider refuses anything" {
    // **Compacting only when a provider refuses is compacting at the worst
    // moment.** It also never fires on a provider that truncates in silence
    // and says nothing. This client refuses nothing at all, and the session
    // compacts anyway, from the model's own limit and the token count the
    // last reply reported.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var fake_client = FakeClient{
        .turns = &.{
            // A turn that works, and reports a context past three quarters of
            // 65536, which is 49152.
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 60000, .output_tokens = 10 } },
            } },
            // The summary call the threshold makes, before the next turn is sent.
            .{ .deltas = &.{.{ .text = "SUMMARY WRITTEN AT THE THRESHOLD" }} },
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.compaction = .{ .context_limit_tokens = 65536 };
    try run(allocator, io, deps);

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expectEqualStrings("SUMMARY WRITTEN AT THE THRESHOLD", found.summary);
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "an approaching compaction asks the agent to save what it learned, and asks before it folds" {
    // **Memory survives a compaction and context does not**, so the moment
    // before one is the best moment to write a note. The ordering is the part
    // that makes it work at all: a notice that arrived with the compaction
    // would give the agent no turn to act on it, and this pins that the
    // notice event is in the log before the compaction event.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var fake_client = FakeClient{
        .turns = &.{
            // Past 60 per cent of 65536, which is 39321, and short of 49152.
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 40000 } },
            } },
            // Now past the compaction threshold.
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call2", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 60000 } },
            } },
            .{ .deltas = &.{.{ .text = "SUMMARY" }} },
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    const offered = [_]message.ToolDefinition{
        .{ .name = "run_command", .description = "", .parameters = .null },
        .{ .name = "write_memory", .description = "", .parameters = .null },
    };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.tool_definitions = &offered;
    deps.compaction = .{ .context_limit_tokens = 65536 };
    try run(allocator, io, deps);

    var notice_id: ?u64 = null;
    var warnings: usize = 0;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .message) continue;
        const m = parsed.value.event.message;
        if (m.role != .system) continue;
        for (m.content) |part| {
            if (part != .text) continue;
            // The threshold is named, in tokens, because a warning with no
            // number is a warning nobody can act on.
            try testing.expect(std.mem.indexOf(u8, part.text, "49152") != null);
            try testing.expect(std.mem.indexOf(u8, part.text, "65536") != null);
            try testing.expect(std.mem.indexOf(u8, part.text, "write_memory") != null);
            try testing.expect(std.mem.indexOf(u8, part.text, "dead ends") != null);
            warnings += 1;
            if (notice_id == null) notice_id = parsed.value.id;
        }
    }
    // Once, not once a turn: an agent told the same thing every turn stops
    // reading it.
    try testing.expectEqual(@as(usize, 1), warnings);

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expect(notice_id.? < found.id);
}

test "a session with no write_memory is never told to call it as a compaction approaches" {
    // The same rule the prompt keeps. A tool that is not offered is not
    // named, because naming one costs the agent a turn to find out.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedMessages(allocator, io, store, "MIDDLE", 12);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{
            .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
            .{ .usage = .{ .input_tokens = 40000 } },
        } },
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.compaction = .{ .context_limit_tokens = 65536 };
    try run(allocator, io, deps);

    var saw_notice = false;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .message) continue;
        const m = parsed.value.event.message;
        if (m.role != .system) continue;
        for (m.content) |part| {
            if (part != .text) continue;
            try testing.expect(std.mem.indexOf(u8, part.text, "write_memory") == null);
            try testing.expect(std.mem.indexOf(u8, part.text, "49152") != null);
            saw_notice = true;
        }
    }
    try testing.expect(saw_notice);
}

test "a compaction whose summary call is refused still folds, and the event says no model wrote it" {
    // A summary call that fails must not end a session that was only out of
    // room. The harness one says what happened rather than what was learned,
    // and the empty `model_alias` is what tells a reader which of the two
    // they are looking at, so a thin summary is never left ambiguous.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
    try seedMessages(allocator, io, store, "MIDDLE", 5);
    try seedMessages(allocator, io, store, "RECENT", 6);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .refusal = .{ .body = measured_overflow_body } },
            // The summary call itself fails, with a fault that is not an overflow.
            .{ .refusal = .{ .status = .internal_server_error, .body = "the summariser fell over" } },
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expectEqualStrings("", found.model_alias);
    try testing.expect(std.mem.startsWith(u8, found.summary, compaction.harness_summary_first_line));
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

// Every test here drives a real `run` and reads the answer out of the log,
// rather than calling `subagents.check` a second time: what the limits say on
// their own is already tested in `lib/chock-policy/subagents.zig`, and what
// these pin is that the loop measures the right two numbers and that nothing
// starts when it refuses.

/// A `subagent.Spawner` that starts no process at all.
///
/// **The seam earns its keep here.** A real child is `chock run`, which needs
/// a project, a credential, a session directory and a single threaded caller,
/// and this test binary is none of those. What these tests pin is what the
/// loop does around a child: which events it writes, in which order, what it
/// asks for, and what it tells the model afterwards. A real child process is
/// pinned in `test/core/subagent.zig`, against a real log on disk.
const FakeSpawner = struct {
    child_session: []const u8 = "01CHILDAA",
    scratchpad_path: []const u8 = "/tmp/chock/01SPAWN/agents/01CHILDAA/scratch",
    outcome: event.AgentOutcome = .finished,
    result: []const u8 = "the diff is safe to apply",
    /// True to answer `prepare` with a fault, the way a session directory that
    /// cannot be made would.
    prepare_fails: bool = false,
    /// True to answer `run` with a fault, which is a child that was already
    /// recorded as spawned and never started.
    run_fails: bool = false,

    prepared: usize = 0,
    ran: usize = 0,
    /// What the loop asked for, copied into buffers of this value's own so
    /// nothing here borrows a turn's arena.
    seen_budget: ?f64 = null,
    seen_kind: [64]u8 = @splat(0),
    seen_kind_len: usize = 0,
    seen_task: [1024]u8 = @splat(0),
    seen_task_len: usize = 0,
    seen_reason: [256]u8 = @splat(0),
    seen_reason_len: usize = 0,

    fn spawner(self: *FakeSpawner) subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn kind(self: *const FakeSpawner) []const u8 {
        return self.seen_kind[0..self.seen_kind_len];
    }

    fn task(self: *const FakeSpawner) []const u8 {
        return self.seen_task[0..self.seen_task_len];
    }

    fn reason(self: *const FakeSpawner) []const u8 {
        return self.seen_reason[0..self.seen_reason_len];
    }

    fn keep(into: []u8, from: []const u8) usize {
        const len = @min(into.len, from.len);
        @memcpy(into[0..len], from[0..len]);
        return len;
    }

    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
    ) subagent.Error!subagent.Prepared {
        _ = io;
        const self: *FakeSpawner = @ptrCast(@alignCast(ptr));
        self.prepared += 1;
        if (self.prepare_fails) return error.ChildNotStarted;

        self.seen_kind_len = keep(&self.seen_kind, request.agent_kind);
        self.seen_reason_len = keep(&self.seen_reason, request.reason);
        self.seen_budget = if (request.budget) |one| one.max_cost else null;
        // The task as the child would really read it, schema requirement and
        // all: a spawner is what hands the task over, so this is where the
        // real one would carry the same text.
        const written = try subagent.taskFor(allocator, request.task, request.shape);
        defer allocator.free(written);
        self.seen_task_len = keep(&self.seen_task, written);

        return .{
            .child_session = try allocator.dupe(u8, self.child_session),
            .log_path = try allocator.dupe(u8, "/tmp/chock/01CHILDAA.jsonl"),
            .scratchpad_path = try allocator.dupe(u8, self.scratchpad_path),
        };
    }

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
        prepared: subagent.Prepared,
    ) subagent.Error!subagent.Report {
        _ = io;
        _ = request;
        _ = prepared;
        const self: *FakeSpawner = @ptrCast(@alignCast(ptr));
        self.ran += 1;
        if (self.run_fails) return error.ChildNotStarted;
        return .{ .outcome = self.outcome, .result = try allocator.dupe(u8, self.result) };
    }
};

/// What one `spawn_agent` call left behind. `output` is owned by the caller.
const SpawnAttempt = struct {
    output: []u8,
    is_error: bool,
    /// How many times the tool runner was asked to run anything. **Zero is
    /// the assertion**: a spawn that reached a runner is a spawn that reached
    /// a sandbox.
    runner_calls: usize,
    /// How many `session.spawn` events the log holds afterwards. A refused
    /// spawn must add none.
    spawn_events: usize,
    /// How many `agent.complete` events the log holds afterwards. A spawn that
    /// started nothing must add none of these either.
    complete_events: usize,
    /// The slice of the budget the child was given, or null when it was given
    /// no cap.
    child_budget: f64,
    /// The currency that slice is written in, borrowed from the log's own copy
    /// only for the length of the replay, so this keeps the length alone.
    child_budget_named_currency: bool,
    /// True when the refusal reached the model's own context, and not only
    /// the log.
    reached_the_model: bool,
    /// How many turns in the parent's own voice the parent's log holds. **Two
    /// is the assertion**, whatever the child did: a subagent's turns are in
    /// the subagent's log, and a parent that took a child's transcript into
    /// its own context would have more.
    assistant_turns: usize,
};

/// What one call to `attemptSpawn` sets up.
const SpawnCase = struct {
    limits: subagents.Limits = .{},
    /// The parents of the agent that asks, so its depth is one more than this.
    chain: []const event.SpawnLink = &.{},
    /// How many children it has already started.
    already_started: usize = 0,
    /// The slice each of those children was given, which is money the parent
    /// has promised and cannot promise again.
    committed_each: f64 = 0,
    /// What starts the child, or null for a session that can start none.
    spawner: ?subagent.Spawner = null,
    /// The arguments the model's own `spawn_agent` call carries.
    arguments: []const u8 = "{\"agent_kind\":\"reviewer\",\"task\":\"read the diff\"}",
    budget: ?chock_cost.budget.Budget = null,
    /// What this session has already spent, as a `usage` event seeded before
    /// the first turn.
    spent: f64 = 0,
};

/// Run one session whose only turn calls `spawn_agent`. The caller frees
/// `SpawnAttempt.output`.
fn attemptSpawn(allocator: std.mem.Allocator, io: std.Io, case: SpawnCase) !SpawnAttempt {
    var backing = try chock_proto.storage.Memory.init(allocator, "01SPAWN");
    const store = backing.storage();
    defer store.close(io);

    if (case.spent != 0) {
        try seedEvent(allocator, io, store, .{ .usage = .{
            .model_alias = "main",
            .model = "test-model",
            .input_tokens = 1000,
            .cost = .{ .known = .{ .value = case.spent, .currency = "USD" } },
        } });
    }

    // The children this agent already has. Only the count and the slices they
    // were given are read, so the names are there to make the log readable.
    for (0..case.already_started) |index| {
        var id_buffer: [32]u8 = undefined;
        const child = try std.fmt.bufPrint(&id_buffer, "01CHILD{d}", .{index});
        try seedEvent(allocator, io, store, .{ .session_spawn = .{
            .child_session = child,
            .child_agent_kind = "reviewer",
            .reason = "an earlier piece of the work",
            .budget_max_cost = case.committed_each,
            .budget_currency = if (case.committed_each == 0) "" else "USD",
        } });
    }

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "spawn1",
            .name = spawn_tool_name,
            .arguments = case.arguments,
        } }} },
        .{ .deltas = &.{.{ .text = "understood" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.subagents = case.limits;
    deps.spawn_chain = case.chain;
    deps.spawner = case.spawner;
    deps.budget = case.budget;
    try run(allocator, io, deps);

    var attempt = SpawnAttempt{
        .output = &.{},
        .is_error = false,
        .runner_calls = fake_tools.calls,
        .spawn_events = 0,
        .complete_events = 0,
        .child_budget = 0,
        .child_budget_named_currency = false,
        .reached_the_model = false,
        .assistant_turns = 0,
    };
    errdefer allocator.free(attempt.output);

    var found = false;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_spawn => |spawn| {
                attempt.spawn_events += 1;
                if (std.mem.eql(u8, spawn.child_session, "01CHILDAA")) {
                    attempt.child_budget = spawn.budget_max_cost;
                    attempt.child_budget_named_currency = spawn.budget_currency.len != 0;
                }
            },
            .agent_complete => attempt.complete_events += 1,
            .tool_result => |result| {
                if (!std.mem.eql(u8, result.call_id, "spawn1")) continue;
                if (found) return error.MoreThanOneResult;
                found = true;
                attempt.output = try allocator.dupe(u8, result.output);
                attempt.is_error = result.is_error;
            },
            // The turn that re-enters the context. A refusal the model never
            // reads is a refusal that changes nothing about what it does
            // next.
            .message => |written| {
                // Every turn in the parent's own voice. The parent's model
                // took two turns, whatever the child did, and a loop that
                // folded a child's transcript into its parent would have more.
                if (written.role == .assistant) attempt.assistant_turns += 1;
                if (written.role != .tool) continue;
                for (written.content) |part| {
                    if (part != .tool_result) continue;
                    if (std.mem.eql(u8, part.tool_result.call_id, "spawn1")) {
                        attempt.reached_the_model = true;
                    }
                }
            },
            else => {},
        }
    }
    if (!found) return error.NoSpawnResult;
    return attempt;
}

test "a spawn under a limit of zero is refused, names the limit, and starts nothing" {
    // The degenerate case, built and proven before anything spawns at all.
    // A maximum of zero subagents disables subagents entirely, which is a
    // real setting a project can want, and it is the boundary of the limit.
    const allocator = testing.allocator;
    const io = testing.io;

    // With a spawner, so a refusal cannot pass for want of one: the limits are
    // what must refuse, and there is a real way to start a child right there.
    var spawner = FakeSpawner{};
    const attempt = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 0 },
        .spawner = spawner.spawner(),
    });
    defer allocator.free(attempt.output);

    // The refusal names the field of chock.zon and the value it holds, so a
    // person reading the log knows what to change.
    try testing.expect(std.mem.indexOf(u8, attempt.output, "max_width to 0") != null);
    try testing.expect(std.mem.indexOf(u8, attempt.output, "chock.zon") != null);
    try testing.expect(attempt.is_error);
    try testing.expect(attempt.reached_the_model);

    // No tree, and no child process. The tool runner is what reaches a
    // sandbox, and it was never asked for anything. The spawner was not asked
    // to prepare a session either, so nothing was made on disk for a child
    // that is never going to exist.
    try testing.expectEqual(@as(usize, 0), attempt.runner_calls);
    try testing.expectEqual(@as(usize, 0), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 0), attempt.complete_events);
    try testing.expectEqual(@as(usize, 0), spawner.prepared);
    try testing.expectEqual(@as(usize, 0), spawner.ran);

    // The other limit at zero refuses the same call and says depth, so
    // neither limit is a spelling of the other.
    const by_depth = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 0, .max_width = 6 },
        .spawner = spawner.spawner(),
    });
    defer allocator.free(by_depth.output);
    try testing.expect(std.mem.indexOf(u8, by_depth.output, "max_depth to 0") != null);
    try testing.expectEqual(@as(usize, 0), by_depth.spawn_events);
    try testing.expectEqual(@as(usize, 0), spawner.ran);
}

test "a limit of one lets the first spawn past the limits and refuses the second" {
    // The step above zero, and the first place an off by one lives. The
    // width comes from the `session.spawn` events the log holds, so an agent
    // with one child already is at its limit and an agent with none is not.
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    const first = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 1 },
        .spawner = spawner.spawner(),
    });
    defer allocator.free(first.output);
    // Past the limits, so a child really ran, and the parent was told.
    try testing.expectEqual(@as(usize, 1), spawner.ran);
    try testing.expectEqual(@as(usize, 1), first.spawn_events);
    try testing.expectEqual(@as(usize, 1), first.complete_events);
    try testing.expect(!first.is_error);
    // A spawn never reaches the tool runner, whether it is refused or not: it
    // is measured against numbers only the session holds.
    try testing.expectEqual(@as(usize, 0), first.runner_calls);

    const second = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 1 },
        .already_started = 1,
        .spawner = spawner.spawner(),
    });
    defer allocator.free(second.output);
    try testing.expect(std.mem.indexOf(u8, second.output, "max_width to 1") != null);
    try testing.expect(std.mem.indexOf(u8, second.output, "already started 1 subagent") != null);
    // The one child it already had, and no second one.
    try testing.expectEqual(@as(usize, 1), second.spawn_events);
    try testing.expectEqual(@as(usize, 0), second.complete_events);
    // And the spawner was not asked to run anything for the refused call.
    try testing.expectEqual(@as(usize, 1), spawner.ran);
}

test "the width the loop measures is the number of session.spawn events in the log" {
    // Every value on both sides of the boundary, not one point of it. The
    // seventh child of an agent at the default width is refused, and so is
    // every one after it: a check that stopped refusing again after the
    // first time would pass a test that only asked once.
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    for (0..subagents.default_max_width + 3) |already_started| {
        const attempt = try attemptSpawn(allocator, io, .{
            .already_started = already_started,
            .spawner = spawner.spawner(),
        });
        defer allocator.free(attempt.output);

        if (already_started < subagents.default_max_width) {
            // One more child, so the log holds the ones it had and this one.
            try testing.expectEqual(already_started + 1, attempt.spawn_events);
            try testing.expectEqual(@as(usize, 1), attempt.complete_events);
        } else {
            try testing.expect(std.mem.indexOf(u8, attempt.output, "max_width to 6") != null);
            try testing.expectEqual(already_started, attempt.spawn_events);
            try testing.expectEqual(@as(usize, 0), attempt.complete_events);
        }
        // Whichever way it went, no tool runner was asked for anything.
        try testing.expectEqual(@as(usize, 0), attempt.runner_calls);
    }
}

test "the depth the loop measures is the length of the spawn chain" {
    // The chain names every parent and leaves the asking agent out, so an
    // agent with five parents is the sixth level and starts no seventh.
    const allocator = testing.allocator;
    const io = testing.io;

    const parents = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "split the work" },
        .{ .agent_kind = "planner", .reason = "read the tree" },
        .{ .agent_kind = "reader", .reason = "read one file" },
        .{ .agent_kind = "reviewer", .reason = "review one change" },
        .{ .agent_kind = "fixer", .reason = "fix one line" },
        .{ .agent_kind = "checker", .reason = "check the fix" },
        .{ .agent_kind = "reporter", .reason = "say what happened" },
    };

    var spawner = FakeSpawner{};
    for (0..parents.len + 1) |links| {
        const attempt = try attemptSpawn(allocator, io, .{
            .chain = parents[0..links],
            .spawner = spawner.spawner(),
        });
        defer allocator.free(attempt.output);

        // The agent itself is one more than the number of its parents.
        if (links + 1 < subagents.default_max_depth) {
            try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
            try testing.expectEqual(@as(usize, 1), attempt.complete_events);
        } else {
            try testing.expect(std.mem.indexOf(u8, attempt.output, "max_depth to 6") != null);
            try testing.expectEqual(@as(usize, 0), attempt.spawn_events);
            try testing.expectEqual(@as(usize, 0), attempt.complete_events);
        }
        try testing.expectEqual(@as(usize, 0), attempt.runner_calls);
    }
}

test "a spawn the limits allow writes the spawn before the child runs and the completion after" {
    // The order is the point. An event is written before the act it describes,
    // so a parent that died mid spawn leaves proof that the child was asked
    // for, and the width count is right when it resumes.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01SPAWN");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "spawn1",
            .name = spawn_tool_name,
            .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"read the diff\\nand say what is wrong\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "understood" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var spawner = FakeSpawner{};

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.spawner = spawner.spawner();
    try run(allocator, io, deps);

    var order: std.ArrayList(event.Kind) = .empty;
    defer order.deinit(allocator);
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_spawn => |spawn| {
                try order.append(allocator, .session_spawn);
                try testing.expectEqualStrings("01CHILDAA", spawn.child_session);
                try testing.expectEqualStrings("reviewer", spawn.child_agent_kind);
                // The reason is one short line of the task, so a person
                // reading the log, or a user answering an approval a subagent
                // raised, knows what the child was for.
                try testing.expectEqualStrings("read the diff", spawn.reason);
            },
            .agent_complete => |done| {
                try order.append(allocator, .agent_complete);
                try testing.expectEqualStrings("01CHILDAA", done.child_session);
                try testing.expectEqual(event.AgentOutcome.finished, done.outcome);
                try testing.expectEqualStrings("the diff is safe to apply", done.result);
                // The third place the event points at, and the one the bulk of
                // a child's work is in.
                try testing.expectEqualStrings(spawner.scratchpad_path, done.scratchpad_path);
            },
            else => {},
        }
    }

    try testing.expectEqual(@as(usize, 2), order.items.len);
    try testing.expectEqual(event.Kind.session_spawn, order.items[0]);
    try testing.expectEqual(event.Kind.agent_complete, order.items[1]);

    // And the child really was prepared before it was run, which is what makes
    // the identifier in `session.spawn` the identifier of the child that ran.
    try testing.expectEqual(@as(usize, 1), spawner.prepared);
    try testing.expectEqual(@as(usize, 1), spawner.ran);
    try testing.expectEqualStrings("reviewer", spawner.kind());
    // The whole task, not the one line reason: the child reads this and
    // nothing else.
    try testing.expectEqualStrings("read the diff\nand say what is wrong", spawner.task());
}

test "a subagent's turns are not in its parent's log, whatever the child said" {
    // Each session stays independently replayable, which is what `chockd`
    // serves and what a resume reads. A parent that folded a child's
    // transcript into its own context would have the child's turns twice, in
    // two logs, and a resume of the parent would replay them again.
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{ .result = "the parser refuses an empty file" };
    const attempt = try attemptSpawn(allocator, io, .{ .spawner = spawner.spawner() });
    defer allocator.free(attempt.output);

    // Two turns in the parent's own voice: the one that called the tool, and
    // the one that answered afterwards.
    try testing.expectEqual(@as(usize, 2), attempt.assistant_turns);
    try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 1), attempt.complete_events);

    // What the parent does get is the answer and where the rest of it is, in
    // the result of the call it made.
    try testing.expect(std.mem.indexOf(u8, attempt.output, "the parser refuses an empty file") != null);
    try testing.expect(std.mem.indexOf(u8, attempt.output, spawner.scratchpad_path) != null);
    try testing.expect(attempt.reached_the_model);
    try testing.expect(!attempt.is_error);
}

test "a child that did not finish is an error result, and the reason reaches the model" {
    // A model that read "the child died" as success would carry on as though
    // it had an answer. Each outcome that is not `finished` therefore comes
    // back as an error result, and names itself.
    const allocator = testing.allocator;
    const io = testing.io;

    const cases = [_]event.AgentOutcome{ .died, .no_progress, .budget, .refused };
    for (cases) |outcome| {
        var spawner = FakeSpawner{ .outcome = outcome, .result = "what it managed to say" };
        const attempt = try attemptSpawn(allocator, io, .{ .spawner = spawner.spawner() });
        defer allocator.free(attempt.output);

        try testing.expect(attempt.is_error);
        try testing.expect(std.mem.indexOf(u8, attempt.output, outcome.wireName()) != null);
        try testing.expect(attempt.reached_the_model);
        // The child is still recorded, both halves: it was started, and it
        // ended. A child that vanished from the log would be a child nobody
        // could account for.
        try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
        try testing.expectEqual(@as(usize, 1), attempt.complete_events);
    }

    // A child that was recorded and could not be started at all is `died` too,
    // because a child that never said anything is exactly what that means.
    var broken = FakeSpawner{ .run_fails = true };
    const attempt = try attemptSpawn(allocator, io, .{ .spawner = broken.spawner() });
    defer allocator.free(attempt.output);
    try testing.expect(attempt.is_error);
    try testing.expect(std.mem.indexOf(u8, attempt.output, "died") != null);
    try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 1), attempt.complete_events);
}

test "the child is given a slice of the budget, and the slice is in the parent's own log" {
    // The cap covers the whole tree, and the processes of a tree share no
    // memory. So the parent divides what it has left, and records what it gave
    // away: a parent that resumed and counted from zero could hand the same
    // money out twice.
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    const first = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 4 },
        .spawner = spawner.spawner(),
        .budget = .{ .max_cost = 8.0, .currency = "USD" },
        .spent = 4.0,
    });
    defer allocator.free(first.output);

    // Four left, four children still allowed, so one each.
    try testing.expectEqual(@as(f64, 1.0), spawner.seen_budget.?);
    try testing.expectEqual(@as(f64, 1.0), first.child_budget);
    try testing.expect(first.child_budget_named_currency);

    // A session with no cap of its own gives no cap, because there is nothing
    // to divide. That is the same answer the parent runs under.
    var uncapped = FakeSpawner{};
    const no_cap = try attemptSpawn(allocator, io, .{ .spawner = uncapped.spawner() });
    defer allocator.free(no_cap.output);
    try testing.expectEqual(@as(?f64, null), uncapped.seen_budget);
    try testing.expectEqual(@as(f64, 0), no_cap.child_budget);
    try testing.expect(!no_cap.child_budget_named_currency);

    // A session that has promised the rest of its cap to earlier children
    // starts no more. **This is the half a cap measured against spending alone
    // would miss**: the parent has spent very little and has nothing left to
    // give, because a child's spending never reaches the parent's own log.
    var refused = FakeSpawner{};
    const nothing_left = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 4 },
        .already_started = 3,
        .committed_each = 0.5,
        .spawner = refused.spawner(),
        .budget = .{ .max_cost = 2.0, .currency = "USD" },
        .spent = 0.5,
    });
    defer allocator.free(nothing_left.output);
    try testing.expectEqualStrings(spawn_no_budget_detail, nothing_left.output);
    try testing.expectEqual(@as(usize, 0), refused.prepared);
    // The three it already had, and no fourth.
    try testing.expectEqual(@as(usize, 3), nothing_left.spawn_events);
    try testing.expectEqual(@as(usize, 0), nothing_left.complete_events);
}

test "the shape the spawn asked for is what the child is told to produce" {
    // The caller chooses, not the child. `result_fields` names what the parent
    // will branch on, and the requirement reaches the child in the one place
    // it reads: the task.
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    const schema = try attemptSpawn(allocator, io, .{
        .spawner = spawner.spawner(),
        .arguments =
        \\{"agent_kind":"reviewer","task":"review the parser","result_fields":["verdict","notes_path"]}
        ,
    });
    defer allocator.free(schema.output);

    try testing.expect(std.mem.startsWith(u8, spawner.task(), "review the parser"));
    try testing.expect(std.mem.indexOf(u8, spawner.task(), "one JSON object") != null);
    try testing.expect(std.mem.indexOf(u8, spawner.task(), "\"verdict\"") != null);
    try testing.expect(std.mem.indexOf(u8, spawner.task(), "\"notes_path\"") != null);

    // With no fields named, the child is asked for nothing but the work.
    var plain = FakeSpawner{};
    const prose = try attemptSpawn(allocator, io, .{ .spawner = plain.spawner() });
    defer allocator.free(prose.output);
    try testing.expectEqualStrings("read the diff", plain.task());
}

test "a spawn with no spawner, and one with arguments that say nothing, both start nothing" {
    // Two different refusals, and neither may read as a child at work: a model
    // told "done" would wait for an answer nobody is producing.
    const allocator = testing.allocator;
    const io = testing.io;

    const none = try attemptSpawn(allocator, io, .{});
    defer allocator.free(none.output);
    try testing.expectEqualStrings(spawn_has_no_spawner_detail, none.output);
    try testing.expect(none.is_error);
    try testing.expectEqual(@as(usize, 0), none.spawn_events);

    var spawner = FakeSpawner{};
    const empty = try attemptSpawn(allocator, io, .{
        .spawner = spawner.spawner(),
        .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"\"}",
    });
    defer allocator.free(empty.output);
    try testing.expect(std.mem.indexOf(u8, empty.output, "\"task\"") != null);
    try testing.expect(empty.is_error);
    try testing.expectEqual(@as(usize, 0), spawner.prepared);

    // Arguments that are not an object at all say which fields are needed,
    // rather than failing the turn.
    const broken = try attemptSpawn(allocator, io, .{
        .spawner = spawner.spawner(),
        .arguments = "not json",
    });
    defer allocator.free(broken.output);
    try testing.expect(std.mem.indexOf(u8, broken.output, "agent_kind") != null);
    try testing.expectEqual(@as(usize, 0), spawner.prepared);

    // And a child whose session could not even be prepared is recorded
    // nowhere: nothing was started, so nothing is in the log.
    var unbuildable = FakeSpawner{ .prepare_fails = true };
    const failed = try attemptSpawn(allocator, io, .{ .spawner = unbuildable.spawner() });
    defer allocator.free(failed.output);
    try testing.expect(failed.is_error);
    try testing.expectEqual(@as(usize, 0), failed.spawn_events);
    try testing.expectEqual(@as(usize, 0), failed.complete_events);
}

test "the child's session.start names the parent, and the kinds above it" {
    // The tree is rebuilt from two links: the parent's `session.spawn` names
    // the child, and this names the parent. A child log with an empty
    // `parent_session` is a root, and a subagent is not one.
    //
    // **The kinds go in beside the identifier.** The policy table answers a
    // child's key by folding every kind from the root down, so a reader who
    // holds this log and not the parent's can re-derive the answer only if
    // the kinds are here. See `event.SessionStart.spawn_chain`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01CHILDAA");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "done" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "split the work" },
        .{ .agent_kind = "planner", .reason = "read the parser first" },
    };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.parent_session = "01PARENTA";
    deps.spawn_chain = &chain;
    try run(allocator, io, deps);

    var found = false;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_start) continue;
        found = true;
        const start = parsed.value.event.session_start;
        try testing.expectEqualStrings("01PARENTA", start.parent_session);
        try testing.expectEqual(@as(usize, 2), start.spawn_chain.len);
        try testing.expectEqualStrings("main", start.spawn_chain[0].agent_kind);
        try testing.expectEqualStrings("split the work", start.spawn_chain[0].reason);
        try testing.expectEqualStrings("planner", start.spawn_chain[1].agent_kind);
    }
    try testing.expect(found);
}

/// Holds a subagent inside its own `run` until a test lets it out, so a test
/// drives the order the parent's work and the child's ending happen in.
///
/// **Plain atomics and a yield**, the same shape `subagent.Table`'s own `Lock`
/// takes, because `std.Io.Mutex` needs an `Io` and this waits on a thread of
/// the table's own. Nothing here measures a length of time: **the bound is a
/// count of yields**, and it exists only so that a build which never lets the
/// child out fails rather than hangs.
const ChildGate = struct {
    open: std.atomic.Value(bool) = .init(false),

    const give_up_yields: usize = 10_000_000;

    fn release(self: *ChildGate) void {
        self.open.store(true, .release);
    }

    fn wait(self: *ChildGate) void {
        var yields: usize = 0;
        while (yields < give_up_yields) : (yields += 1) {
            if (self.open.load(.acquire)) return;
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }
};

/// The one gate the tests below drive. File scope values, because
/// `FakeTurn.before` is a plain function pointer with no context of its own,
/// the same shape `RecordingSleeper.on_wait` already uses.
var carry_on_gate = ChildGate{};
/// The table the child of the moment runs on, when a test wants the child
/// finished before the turn goes on. Null leaves the child running.
var carry_on_table: ?*subagent.Table = null;

/// Let the child out, and, when a test asked for it, do not come back until the
/// child has ended and its completion is recorded.
///
/// **The wait is a join and never a pause.** A test that let the child out and
/// carried on would be racing the child's own thread: measured, that race is
/// lost about as often as it is won, and it was lost first on a Darwin box. A
/// join has no such margin.
///
/// **It does not weaken what the test pins, it sharpens it.** The child being
/// finished changes nothing about the log, because a finished child appends
/// nothing: only the drain at the top of the next turn does. So a completion
/// that still lands after this turn's own tool call is the delivery point being
/// the top of a turn, proven against a child that was ready long before.
fn releaseCarryOnChild() void {
    carry_on_gate.release();
    if (carry_on_table) |table| table.waitAll();
}

/// A `subagent.Spawner` whose child does not end until `carry_on_gate` is
/// opened. Everything else about it is `FakeSpawner`'s behaviour.
const GatedSpawner = struct {
    child_session: []const u8 = "01CHILDAA",
    result: []const u8 = "the tests pass",

    fn spawner(self: *GatedSpawner) subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
    ) subagent.Error!subagent.Prepared {
        _ = io;
        _ = request;
        const self: *GatedSpawner = @ptrCast(@alignCast(ptr));
        return .{
            .child_session = try allocator.dupe(u8, self.child_session),
            .log_path = try allocator.dupe(u8, "/tmp/chock/01CHILDAA.jsonl"),
            .scratchpad_path = try allocator.dupe(u8, "/tmp/chock/scratch/01CHILDAA"),
        };
    }

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
        prepared: subagent.Prepared,
    ) subagent.Error!subagent.Report {
        _ = io;
        _ = request;
        _ = prepared;
        const self: *GatedSpawner = @ptrCast(@alignCast(ptr));
        carry_on_gate.wait();
        return .{ .outcome = .finished, .result = try allocator.dupe(u8, self.result) };
    }
};

test "a spawn that carries on lets the parent work between the spawn and the answer" {
    // **The fact that makes a tree worth having.** Six children waited on one
    // at a time is a sequence with extra processes, so what has to be pinned is
    // not that a spawn and a completion both happened, which a waiting spawn
    // does too. It is that **work of the parent's own landed in the parent's
    // log between them**: a `tool.call` the parent made and a `tool.result` it
    // read, both after `session.spawn` and both before `agent.complete`.
    //
    // The order is driven and never timed. The child is held inside its own
    // `run` until the parent's second turn starts, and the completion is
    // delivered at the top of a turn, so the parent's tool call cannot land on
    // either side of the two events by luck. See `ChildGate`.
    const allocator = testing.allocator;
    const io = testing.io;

    carry_on_gate = .{};

    var backing = try chock_proto.storage.Memory.init(allocator, "01ASYNC");
    const store = backing.storage();
    defer store.close(io);

    var gated = GatedSpawner{};
    var table = subagent.Table{ .gpa = allocator, .spawner = gated.spawner() };
    defer table.deinit();
    // The child is finished before the parent's own tool call runs, and the
    // completion still lands after it: see `releaseCarryOnChild`.
    carry_on_table = &table;
    defer carry_on_table = null;

    var fake_client = FakeClient{
        .turns = &.{
            // Turn one: start the child and do not wait for it.
            .{ .deltas = &.{.{ .tool_call = .{
                .index = 0,
                .id = "spawn1",
                .name = spawn_tool_name,
                .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"run the tests\",\"background\":true}",
            } }} },
            // Turn two: the parent's own work. The child is let out, and finishes,
            // as this turn begins, which is after the drain at the top of it. So
            // its answer cannot reach the log before this turn's own tool call
            // however quickly the child ends.
            .{
                .deltas = &.{.{ .tool_call = .{
                    .index = 0,
                    .id = "own-work",
                    .name = "read_file",
                    .arguments = "{\"path\":\"README.md\"}",
                } }},
                .before = releaseCarryOnChild,
            },
            // Turn three: the top of it is where the child's answer arrives.
            .{ .deltas = &.{.{ .text = "the child says the tests pass and I read the file" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "the first line of the readme" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.spawner = gated.spawner();
    deps.children = &table;
    try run(allocator, io, deps);

    var spawn_id: ?u64 = null;
    var own_call_id: ?u64 = null;
    var own_result_id: ?u64 = null;
    var complete_id: ?u64 = null;
    var told_id: ?u64 = null;
    var spawn_result: []u8 = &.{};
    defer allocator.free(spawn_result);
    var spawn_was_error = true;

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_spawn => |spawn| {
                try testing.expectEqualStrings("01CHILDAA", spawn.child_session);
                spawn_id = parsed.value.id;
            },
            .tool_call => |call| {
                if (std.mem.eql(u8, call.tool, "read_file")) own_call_id = parsed.value.id;
            },
            .tool_result => |result| {
                if (std.mem.eql(u8, result.call_id, "own-work")) own_result_id = parsed.value.id;
                if (std.mem.eql(u8, result.call_id, "spawn1")) {
                    spawn_result = try allocator.dupe(u8, result.output);
                    spawn_was_error = result.is_error;
                }
            },
            .agent_complete => |done| {
                try testing.expectEqualStrings("01CHILDAA", done.child_session);
                try testing.expectEqual(event.AgentOutcome.finished, done.outcome);
                try testing.expectEqualStrings("the tests pass", done.result);
                try testing.expectEqualStrings("/tmp/chock/scratch/01CHILDAA", done.scratchpad_path);
                complete_id = parsed.value.id;
            },
            .message => |written| {
                if (written.role != .user) continue;
                if (std.mem.indexOf(u8, written.content[0].text, "01CHILDAA") == null) continue;
                told_id = parsed.value.id;
            },
            else => {},
        }
    }

    try testing.expect(spawn_id != null);
    try testing.expect(own_call_id != null);
    try testing.expect(own_result_id != null);
    try testing.expect(complete_id != null);
    try testing.expect(told_id != null);

    // **The whole test.** The parent asked for the child, then did a piece of
    // its own work and read the answer to it, and only then was told what the
    // child said. A waiting spawn puts `agent.complete` immediately after
    // `session.spawn` with nothing of the parent's between them, so this order
    // is what the two shapes differ by.
    try testing.expect(spawn_id.? < own_call_id.?);
    try testing.expect(own_call_id.? < own_result_id.?);
    try testing.expect(own_result_id.? < complete_id.?);
    // And the record is written before the parent is told, so a replay never
    // shows an agent hearing about a child that is not yet recorded as ended.
    try testing.expect(complete_id.? < told_id.?);

    // The call that started it came straight back, said there was no answer
    // yet, and was not an error: a spawn that did what it was asked to do.
    try testing.expect(!spawn_was_error);
    try testing.expect(std.mem.indexOf(u8, spawn_result, "01CHILDAA") != null);
    try testing.expect(std.mem.indexOf(u8, spawn_result, "has not answered yet") != null);

    // Drained once. A loop that polled at every safe point and did not clear
    // the table would tell the parent about the same child on every turn.
    const again = try table.take(allocator);
    defer subagent.freeCompletions(allocator, again);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "a spawn that waits still answers in its own call, and nothing is drained afterwards" {
    // The other shape, unchanged. **Both are needed and the spawn says which**:
    // "review this and tell me" has nothing for the parent to do meanwhile, and
    // an answer that arrived a turn later would be a parent that had to be told
    // to wait for it.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01WAITS");
    const store = backing.storage();
    defer store.close(io);

    var spawner = FakeSpawner{ .result = "the diff is fine" };
    var table = subagent.Table{ .gpa = allocator, .spawner = spawner.spawner() };
    defer table.deinit();

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "spawn1",
            .name = spawn_tool_name,
            .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"read the diff\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "understood" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.spawner = spawner.spawner();
    // The table is there and is simply not used, so this cannot pass for want
    // of one: a spawn that said nothing about carrying on waits.
    deps.children = &table;
    try run(allocator, io, deps);

    var spawn_id: ?u64 = null;
    var complete_id: ?u64 = null;
    var result_id: ?u64 = null;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_spawn => spawn_id = parsed.value.id,
            .agent_complete => complete_id = parsed.value.id,
            .tool_result => |result| {
                if (std.mem.eql(u8, result.call_id, "spawn1")) {
                    result_id = parsed.value.id;
                    try testing.expect(std.mem.indexOf(u8, result.output, "the diff is fine") != null);
                }
            },
            else => {},
        }
    }

    try testing.expect(spawn_id != null);
    try testing.expect(complete_id != null);
    try testing.expect(result_id != null);
    // The completion is inside the call: nothing of the parent's own can land
    // between the two, which is exactly what the other shape allows.
    try testing.expect(spawn_id.? < complete_id.?);
    try testing.expect(complete_id.? < result_id.?);
    // And the table was never given a child, so the drain had nothing to find.
    try testing.expectEqual(@as(usize, 0), table.startedCount());
}

test "a spawn that asks to carry on with no table for it is refused, and names the other shape" {
    // **Never a quiet fall back to waiting.** A model that asked to carry on
    // and was silently made to wait planned its next step around a turn that
    // did not happen. The refusal says what to ask for instead, because the
    // work can still be done.
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    const attempt = try attemptSpawn(allocator, io, .{
        .spawner = spawner.spawner(),
        .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"read the diff\",\"background\":true}",
    });
    defer allocator.free(attempt.output);

    try testing.expect(attempt.is_error);
    try testing.expectEqualStrings(spawn_cannot_carry_on_detail, attempt.output);
    try testing.expect(attempt.reached_the_model);
    // Nothing was started and nothing was recorded: the refusal is before
    // `prepare`, so no child was ever named.
    try testing.expectEqual(@as(usize, 0), spawner.prepared);
    try testing.expectEqual(@as(usize, 0), spawner.ran);
    try testing.expectEqual(@as(usize, 0), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 0), attempt.complete_events);
}

test "a child still running when the session ends is waited for and recorded, not lost" {
    // **A `session.spawn` with no `agent.complete` after it would be a log that
    // lies**, because the child did answer. The wait has to happen in any case:
    // `subagent.Table.deinit` cannot let a child outlive the scratchpad it
    // writes into. So the loop waits before it stops, and the record costs
    // nothing on top of a wait that was already forced.
    //
    // **Every way a session stops reaches these same lines**: a final answer, a
    // turn limit, a budget that refused the next turn, and a user who canceled
    // all end at `recordAtTheEnd`. So one test covers all four rather than four
    // tests covering one path.
    const allocator = testing.allocator;
    const io = testing.io;

    carry_on_gate = .{};
    // Left running when the turn goes on, which is the case this pins: the
    // wait that records it is `recordAtTheEnd`'s own.
    carry_on_table = null;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LATE");
    const store = backing.storage();
    defer store.close(io);

    var gated = GatedSpawner{ .result = "finished after the last turn" };
    var table = subagent.Table{ .gpa = allocator, .spawner = gated.spawner() };
    defer table.deinit();

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{
                .index = 0,
                .id = "spawn1",
                .name = spawn_tool_name,
                .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"run the tests\",\"background\":true}",
            } }} },
            // The session ends here, with the child still held inside its own run.
            // It is let out as this last turn begins, so it can only be recorded
            // after the session has already decided to stop.
            .{ .deltas = &.{.{ .text = "I am done" }}, .before = releaseCarryOnChild },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.spawner = gated.spawner();
    deps.children = &table;
    try run(allocator, io, deps);

    var end_id: ?u64 = null;
    var complete_id: ?u64 = null;
    var told_after_the_end = false;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_end => end_id = parsed.value.id,
            .agent_complete => |done| {
                try testing.expectEqualStrings("finished after the last turn", done.result);
                complete_id = parsed.value.id;
            },
            .message => |written| {
                if (written.role != .user) continue;
                if (std.mem.indexOf(u8, written.content[0].text, "01CHILDAA") != null) {
                    told_after_the_end = true;
                }
            },
            else => {},
        }
    }

    try testing.expect(end_id != null);
    try testing.expect(complete_id != null);
    // Recorded, and recorded after the end, which is where the fact belongs: a
    // record written before `session.end` would say the child ended before the
    // session did, and it did not.
    try testing.expect(end_id.? < complete_id.?);
    try testing.expect(!told_after_the_end);
}

test "a session with no children table runs exactly as it did before a spawn could carry on" {
    // The default, and the one every caller before this took. `Deps.children`
    // is null, so nothing is drained and nothing is appended.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NOKIDS");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    const deps = testDeps(fake_client.client(), store, fake_tools.runner());
    try testing.expectEqual(@as(?*subagent.Table, null), deps.children);

    try run(allocator, io, deps);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try testing.expect(parsed.value.event != .agent_complete);
    }
}

test "an approval request names every parent of the agent that asked" {
    // "A subagent three levels down wants to raise its budget" is the fact the
    // user most needs before answering, so the request carries the whole chain,
    // root first, and not only the kind that asked.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01CHAIN");
    const store = backing.storage();
    defer store.close(io);

    // A session that has already spent its whole budget, so the next turn
    // raises the request. The same shape the budget tests below use.
    try seedEvent(allocator, io, store, .{ .usage = .{
        .model_alias = "main",
        .model = "test-model",
        .input_tokens = 1_000_000,
        .output_tokens = 0,
        .cost = .{ .known = .{ .value = 5.00, .currency = "USD" } },
    } });

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{.{ .text = "never sent" }} }} };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "split the work" },
        .{ .agent_kind = "planner", .reason = "read the tree" },
    };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.budget = .{ .max_cost = 5.00, .currency = "USD" };
    deps.spawn_chain = &chain;
    try run(allocator, io, deps);

    var found = false;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .approval_request) continue;
        const request = parsed.value.event.approval_request;
        found = true;
        try testing.expectEqual(@as(usize, 2), request.spawn_chain.len);
        try testing.expectEqualStrings("main", request.spawn_chain[0].agent_kind);
        try testing.expectEqualStrings("split the work", request.spawn_chain[0].reason);
        try testing.expectEqualStrings("planner", request.spawn_chain[1].agent_kind);
        // The agent that asked is not a link of its own: the request already
        // names it in `agent_kind`.
        try testing.expectEqualStrings("coder", request.agent_kind);
    }
    try testing.expect(found);
}

// See `lib/chock-core/notices.zig` for the notices themselves and for the
// tests of each trigger. What is pinned here is the wiring: what actually
// reaches the model, where in the request it lands, what it does to the system
// prompt, and what the log holds afterwards.

/// One model call's request, as much of it as a notice test needs.
const SeenRequest = struct {
    /// The system prompt, byte for byte. **The whole point of the test that
    /// reads it**: a notice must never change this.
    system: []u8,
    /// Every text part of the last message, joined. A notice is the last
    /// message when there is one.
    tail: []u8,
    /// How many messages the request carried.
    messages: usize,
};

/// Every request a `FakeClient` was given, kept in order.
const SeenRequests = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(SeenRequest) = .empty,

    fn deinit(self: *SeenRequests) void {
        for (self.items.items) |seen| {
            self.allocator.free(seen.system);
            self.allocator.free(seen.tail);
        }
        self.items.deinit(self.allocator);
    }

    fn record(self: *SeenRequests, request: message.Request) std.mem.Allocator.Error!void {
        var tail: std.ArrayList(u8) = .empty;
        errdefer tail.deinit(self.allocator);
        if (request.messages.len != 0) {
            for (request.messages[request.messages.len - 1].content) |part| {
                if (part == .text) try tail.appendSlice(self.allocator, part.text);
            }
        }
        const system = try self.allocator.dupe(u8, request.system);
        errdefer self.allocator.free(system);
        try self.items.append(self.allocator, .{
            .system = system,
            .tail = try tail.toOwnedSlice(self.allocator),
            .messages = request.messages.len,
        });
    }

    /// True when any request carried this text at the end of it.
    fn anyTailHolds(self: SeenRequests, needle: []const u8) bool {
        for (self.items.items) |seen| {
            if (std.mem.indexOf(u8, seen.tail, needle) != null) return true;
        }
        return false;
    }
};

/// A `ToolRunner` that answers with a different scripted output per call, so a
/// test can make a file change between two reads of it.
const ScriptedToolRunner = struct {
    outputs: []const []const u8,
    calls: usize = 0,

    fn dispatch(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        call: event.ToolCall,
    ) DispatchError!event.ToolResult {
        _ = io;
        const self: *ScriptedToolRunner = @ptrCast(@alignCast(ptr));
        const output = self.outputs[@min(self.calls, self.outputs.len - 1)];
        self.calls += 1;
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, output),
            .is_error = false,
            .truncated = false,
        };
    }

    fn runner(self: *ScriptedToolRunner) ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatch };
};

/// A `read_file` result for `content`, with the header that tool really
/// writes. Built through `tools.contentHash`, so a test never states a hash by
/// hand and the loop reads back exactly what the tool would have written.
fn readResult(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "[chock: {d} bytes, file_hash {s}]\n{s}", .{
        content.len,
        tools.contentHash(content),
        content,
    });
}

/// One turn of a model that asks to read `path`.
fn readCall(id: []const u8, arguments: []const u8) chock_provider.Client.Delta {
    return .{ .tool_call = .{
        .index = 0,
        .id = id,
        .name = @tagName(tools.Tool.read_file),
        .arguments = arguments,
    } };
}

test "the system prompt is byte identical on every turn, whatever the notices say" {
    // **The cache trap, pinned.** A provider's cache keys on a stable prefix,
    // so a fact that changes every turn belongs at the end of the context and
    // never at the front. A version that built the notice into the prompt
    // would pass every other test in this file: the words would all be there,
    // and only `cache_read_input_tokens` on a real provider would show it,
    // which is a number no test here can see.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const same = try readResult(allocator, "hello");
    defer allocator.free(same);
    var scripted = ScriptedToolRunner{ .outputs = &.{ same, same } };

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();

    const arguments = "{\"path\":\"a.zig\"}";
    var fake_client = FakeClient{
        .seen = &seen,
        .turns = &.{
            .{ .deltas = &.{readCall("c1", arguments)} },
            .{ .deltas = &.{readCall("c2", arguments)} },
            .{ .deltas = &.{.{ .text = "done" }} },
        },
    };

    var deps = testDeps(fake_client.client(), store, scripted.runner());
    // Two different notices across the run: the uncommitted files on the first
    // turn, and the unchanged re-read on the last one.
    deps.uncommitted_files = 5;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 3), seen.items.items.len);
    for (seen.items.items) |request| {
        try testing.expectEqualStrings(deps.system_prompt, request.system);
    }

    // And the notices really did differ, or the test above proves nothing.
    try testing.expect(std.mem.indexOf(u8, seen.items.items[0].tail, "5 files") != null);
    try testing.expect(std.mem.indexOf(u8, seen.items.items[2].tail, "did not change") != null);
    try testing.expect(!std.mem.eql(u8, seen.items.items[0].tail, seen.items.items[2].tail));
}

test "a notice reaches the model on the turn it applies and on no other turn" {
    // The failure this pins is the one that turns notices into a long prompt
    // by another route: a block on the end of every single request.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_tools = FakeToolRunner{ .output = "ok" };
    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();

    var fake_client = FakeClient{
        .seen = &seen,
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c1", .name = "run_command", .arguments = "{\"a\":1}" } }} },
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c2", .name = "run_command", .arguments = "{\"b\":2}" } }} },
            .{ .deltas = &.{.{ .text = "done" }} },
        },
    };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.uncommitted_files = 7;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 3), seen.items.items.len);
    // Said once, on the first turn.
    try testing.expect(std.mem.indexOf(u8, seen.items.items[0].tail, "7 files") != null);
    // And never again: the count did not change, so repeating it would be
    // noise a model learns to skip.
    for (seen.items.items[1..]) |request| {
        try testing.expect(std.mem.indexOf(u8, request.tail, notices.prefix) == null);
    }
}

test "a file read again unchanged is reported to the model" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const before = try readResult(allocator, "the same bytes\n");
    defer allocator.free(before);
    var scripted = ScriptedToolRunner{ .outputs = &.{ before, before } };

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();

    const arguments = "{\"path\":\"src/main.zig\"}";
    var fake_client = FakeClient{
        .seen = &seen,
        .turns = &.{
            .{ .deltas = &.{readCall("c1", arguments)} },
            .{ .deltas = &.{readCall("c2", arguments)} },
            .{ .deltas = &.{.{ .text = "done" }} },
        },
    };

    try run(allocator, io, testDeps(fake_client.client(), store, scripted.runner()));

    // Nothing on the turn after the first read: one read is not a re-read.
    try testing.expect(std.mem.indexOf(u8, seen.items.items[1].tail, notices.prefix) == null);
    // And the file, by name, on the turn after the second one.
    const told = seen.items.items[2].tail;
    try testing.expect(std.mem.indexOf(u8, told, "src/main.zig") != null);
    try testing.expect(std.mem.indexOf(u8, told, "did not change") != null);
}

test "a file that changed between two reads is never reported as unchanged" {
    // **This is the half that makes the notice trustworthy**, and it is the
    // reason the file is changed between the two reads rather than read twice.
    // A notice that said "unchanged" here would send the model on with a stale
    // copy, which is a worse fault than the re-read the notice exists to stop.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const before = try readResult(allocator, "the first bytes\n");
    defer allocator.free(before);
    const after = try readResult(allocator, "somebody edited it\n");
    defer allocator.free(after);
    var scripted = ScriptedToolRunner{ .outputs = &.{ before, after } };

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();

    const arguments = "{\"path\":\"src/main.zig\"}";
    var fake_client = FakeClient{
        .seen = &seen,
        .turns = &.{
            .{ .deltas = &.{readCall("c1", arguments)} },
            .{ .deltas = &.{readCall("c2", arguments)} },
            .{ .deltas = &.{.{ .text = "done" }} },
        },
    };

    try run(allocator, io, testDeps(fake_client.client(), store, scripted.runner()));

    try testing.expect(!seen.anyTailHolds("did not change"));
}

test "the repeated call notice names the tool and the arguments, and one call alone gets none" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_tools = FakeToolRunner{ .output = "/home/ross/chock" };
    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();

    // The red team run of 2026-08-21, in miniature: the same read of the same
    // path, over and over, with nothing telling the model.
    const repeated = "{\"command\":\"readlink -f .\"}";
    var fake_client = FakeClient{
        .seen = &seen,
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c1", .name = "run_command", .arguments = repeated } }} },
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c2", .name = "run_command", .arguments = repeated } }} },
            .{ .deltas = &.{.{ .text = "done" }} },
        },
    };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    // One call is ordinary work and gets nothing at all. The notice that fired
    // there would fire on every healthy session.
    try testing.expect(std.mem.indexOf(u8, seen.items.items[1].tail, notices.prefix) == null);

    // The second identical call is the last moment a notice can still prevent
    // a third, which is what `Loop.no_progress_repeats` stops the session on.
    const told = seen.items.items[2].tail;
    try testing.expect(std.mem.indexOf(u8, told, "run_command") != null);
    try testing.expect(std.mem.indexOf(u8, told, "readlink -f .") != null);
    try testing.expect(std.mem.indexOf(u8, told, "2 times") != null);
}

test "a notice is in no event in the log, so a replay never sees one" {
    // A notice says what the harness knows now. It is not a turn anybody took,
    // it is recomputed from the log every time, and a copy of it in the log
    // would grow the context by one message per turn forever. The same rule
    // `Observer.onNotice` already keeps: see its own doc comment.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_tools = FakeToolRunner{ .output = "ok" };
    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "c1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.uncommitted_files = 3;
    try run(allocator, io, deps);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .message) continue;
        for (parsed.value.event.message.content) |part| {
            if (part != .text) continue;
            try testing.expect(std.mem.indexOf(u8, part.text, "not committed") == null);
        }
    }
}

test "notices turned off leave the request exactly as the fold built it" {
    // The off side of the measurement, at the wiring. Every fact this session
    // holds would produce a line with notices on.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const same = try readResult(allocator, "hello");
    defer allocator.free(same);
    var scripted = ScriptedToolRunner{ .outputs = &.{ same, same } };

    var on_seen = SeenRequests{ .allocator = allocator };
    defer on_seen.deinit();
    var off_seen = SeenRequests{ .allocator = allocator };
    defer off_seen.deinit();

    const arguments = "{\"path\":\"a.zig\"}";
    const script = [_]FakeTurn{
        .{ .deltas = &.{readCall("c1", arguments)} },
        .{ .deltas = &.{readCall("c2", arguments)} },
        .{ .deltas = &.{.{ .text = "done" }} },
    };

    var off_client = FakeClient{ .seen = &off_seen, .turns = &script };
    var deps = testDeps(off_client.client(), store, scripted.runner());
    deps.uncommitted_files = 5;
    deps.notices = .{ .enabled = false };
    try run(allocator, io, deps);

    for (off_seen.items.items) |request| {
        try testing.expect(std.mem.indexOf(u8, request.tail, notices.prefix) == null);
    }

    // The same session with notices on, so the difference is the switch and
    // not the script.
    var other_backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const other_store = other_backing.storage();
    defer other_store.close(io);

    var on_tools = ScriptedToolRunner{ .outputs = &.{ same, same } };
    var on_client = FakeClient{ .seen = &on_seen, .turns = &script };
    var on_deps = testDeps(on_client.client(), other_store, on_tools.runner());
    on_deps.uncommitted_files = 5;
    try run(allocator, io, on_deps);

    try testing.expect(on_seen.anyTailHolds(notices.prefix));

    // And the message counts differ by exactly the notices, which is the only
    // thing the switch changes.
    try testing.expectEqual(off_seen.items.items.len, on_seen.items.items.len);
    for (off_seen.items.items, on_seen.items.items) |off, on| {
        try testing.expect(on.messages == off.messages or on.messages == off.messages + 1);
    }
}

test "the notice the model is given is the notice a watching person is shown" {
    // A user who cannot see what the harness put in front of the model cannot
    // judge whether it helped, which is the whole of the measurement. See
    // `Observer.onNotice`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();
    var fake_client = FakeClient{ .seen = &seen, .turns = &.{.{ .deltas = &.{.{ .text = "done" }} }} };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var watcher = RecordingObserver{ .allocator = allocator };
    defer watcher.deinit();

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.uncommitted_files = 9;
    deps.observer = watcher.observer();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), watcher.notices.items.len);
    try testing.expectEqualStrings(seen.items.items[0].tail, watcher.notices.items[0]);
}

test "the budget notice reaches the model, and a spend Chock cannot measure is never given a percent" {
    // **The negative half is the one that matters.** A percentage of a total
    // with an unpriced turn in it is a made up number, and a model told a made
    // up number about its own money is worse off than one told nothing. The
    // same rule `refuseForBudget` already keeps, read from the other side: see
    // `spentPercent`.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    // Half the cap, spent on a turn that could be priced.
    try seedEvent(allocator, io, store, .{ .usage = .{
        .input_tokens = 1000,
        .output_tokens = 500,
        .cost = .{ .known = .{ .value = 0.50, .currency = "USD" } },
        .model = "test-model",
    } });

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();
    var fake_client = FakeClient{ .seen = &seen, .turns = &.{.{ .deltas = &.{.{ .text = "done" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.budget = .{ .max_cost = 1.00, .currency = "USD" };
    try run(allocator, io, deps);

    try testing.expect(seen.anyTailHolds("50 percent"));

    // The same session over a total that cannot be enforced: one turn whose
    // cost nobody knows, and the whole percentage goes away with it.
    var other_backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const other_store = other_backing.storage();
    defer other_store.close(io);

    try seedEvent(allocator, io, other_store, .{ .usage = .{
        .input_tokens = 1000,
        .output_tokens = 500,
        .cost = .{ .known = .{ .value = 0.50, .currency = "USD" } },
        .model = "test-model",
    } });
    try seedEvent(allocator, io, other_store, .{ .usage = .{
        .input_tokens = 10,
        .output_tokens = 5,
        .cost = .unknown,
        .model = "test-model",
    } });

    var quiet_seen = SeenRequests{ .allocator = allocator };
    defer quiet_seen.deinit();
    var quiet_client = FakeClient{
        .seen = &quiet_seen,
        .turns = &.{.{ .deltas = &.{.{ .text = "done" }} }},
    };
    var quiet_deps = testDeps(quiet_client.client(), other_store, fake_tools.runner());
    quiet_deps.budget = .{ .max_cost = 1.00, .currency = "USD" };
    try run(allocator, io, quiet_deps);

    try testing.expect(!quiet_seen.anyTailHolds("percent"));
}

test "a session with no cap at all is never told about a budget" {
    // A project that set no cap has no number to be a percentage of, and a
    // notice that appeared anyway would be the whole feature firing on a
    // session it does not apply to.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedEvent(allocator, io, store, .{ .usage = .{
        .input_tokens = 1000,
        .output_tokens = 500,
        .cost = .{ .known = .{ .value = 99.0, .currency = "USD" } },
        .model = "test-model",
    } });

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();
    var fake_client = FakeClient{ .seen = &seen, .turns = &.{.{ .deltas = &.{.{ .text = "done" }} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    // `budget` left null, which is what a project with no cap gets.
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    try testing.expect(!seen.anyTailHolds("percent"));
}

test "the task is put back in front of the agent in a long session, and not in a short one" {
    // A small model's attention decays across a long conversation, and the
    // first message is the one it can least afford to lose. It is also the one
    // that is already there on turn two, which is why this waits.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = "make the parser accept a trailing comma";
    const said = [_]event.ContentPart{.{ .text = task }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &said } });

    // Enough turns to pass `notices.Policy.goal_every_turns`, each one a tool
    // call so the session keeps going, and each with different arguments so
    // the no progress detector never fires.
    const turn_count = 12;
    var script: [turn_count]FakeTurn = undefined;
    var arguments: [turn_count][]u8 = undefined;
    var deltas: [turn_count][1]chock_provider.Client.Delta = undefined;
    for (0..turn_count) |i| {
        arguments[i] = try std.fmt.allocPrint(allocator, "{{\"step\":{d}}}", .{i});
        deltas[i] = .{.{ .tool_call = .{
            .index = 0,
            .id = "c",
            .name = "run_command",
            .arguments = arguments[i],
        } }};
        script[i] = .{ .deltas = &deltas[i] };
    }
    defer for (arguments) |owned| allocator.free(owned);

    var seen = SeenRequests{ .allocator = allocator };
    defer seen.deinit();
    var fake_client = FakeClient{ .seen = &seen, .turns = &script };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.max_turns = turn_count;
    try run(allocator, io, deps);

    // Not on any of the early turns: the task is the first message and it is
    // still close enough to read. Read from the mechanism itself, so a trigger
    // that changes changes this with it.
    const triggers = notices.Policy{};
    for (seen.items.items[0..triggers.goal_every_turns]) |request| {
        try testing.expect(std.mem.indexOf(u8, request.tail, notices.prefix) == null);
    }
    // And there once the session is long, in a line the harness signed. Not
    // merely "the task text appears somewhere": the very first request ends
    // with the user message itself, so that would have passed with the notice
    // never built at all.
    var restated = false;
    for (seen.items.items) |request| {
        if (std.mem.indexOf(u8, request.tail, notices.prefix) == null) continue;
        if (std.mem.indexOf(u8, request.tail, task) != null) restated = true;
    }
    try testing.expect(restated);
}

/// A `tasks.Runner` that runs nothing. The loop's job is to record and deliver
/// a completion, and neither of those needs a sandbox: see
/// `lib/chock-core/tasks.zig`'s own `Runner` for why that seam exists.
const FakeTaskRunner = struct {
    output: []const u8,

    fn runner(self: *FakeTaskRunner) task_table.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = task_table.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        loop_io: std.Io,
        request: *const task_table.Request,
    ) task_table.Outcome {
        _ = loop_io;
        _ = request;
        const self: *FakeTaskRunner = @ptrCast(@alignCast(ptr));
        return .{
            .status = .exited,
            .code = 2,
            .output = allocator.dupe(u8, self.output) catch "",
        };
    }
};

test "a finished background task is recorded as an event and delivered as a message" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buffer);
    const tasks_dir = try std.fmt.allocPrint(allocator, "{s}/tasks", .{path_buffer[0..path_len]});
    defer allocator.free(tasks_dir);
    try std.Io.Dir.createDirAbsolute(io, tasks_dir, .default_dir);

    var fake_task = FakeTaskRunner{ .output = "the build failed\n" };
    var table = task_table.Table{ .gpa = allocator, .dir = tasks_dir, .runner = fake_task.runner() };
    defer table.deinit();

    const argv = [_][]const u8{ "make", "-j8" };
    _ = try table.start(io, .{
        .config = .{ .root = "/root", .mounts = &.{}, .rules = &.{}, .cwd = "/project", .env = &.{} },
        .argv = &argv,
    });
    table.waitAll();

    var backing = try chock_proto.storage.Memory.init(allocator, "01TASK");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .text = "I read the output" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.tasks = &table;

    try run(allocator, io, deps);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();

    // Named from the directory the table really writes to, so this reads the
    // same fact on a build that moves a path and on one that does not: see
    // `chock_core.tasks.sandboxDirFor`.
    const output_path = try task_table.sandboxPathFor(allocator, tasks_dir, "task-01");
    defer allocator.free(output_path);

    var record_id: ?u64 = null;
    var delivery_id: ?u64 = null;
    var assistant_id: ?u64 = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .task_complete => |done| {
                try testing.expectEqualStrings("task-01", done.task_id);
                try testing.expectEqualStrings("make -j8", done.command);
                try testing.expectEqual(event.TaskStatus.exited, done.status);
                try testing.expectEqual(@as(i64, 2), done.code);
                try testing.expectEqualStrings(output_path, done.output_path);
                try testing.expectEqual(@as(u64, "the build failed\n".len), done.output_bytes);
                // The record names the file and never quotes it: a build
                // writes megabytes, and the log is the one file a session
                // cannot afford to bloat.
                record_id = parsed.value.id;
            },
            .message => |m| switch (m.role) {
                .user => {
                    try testing.expect(std.mem.indexOf(u8, m.content[0].text, "task-01") != null);
                    try testing.expect(std.mem.indexOf(u8, m.content[0].text, "exited with status 2") != null);
                    try testing.expect(std.mem.indexOf(u8, m.content[0].text, output_path) != null);
                    try testing.expect(std.mem.indexOf(u8, m.content[0].text, "the build failed") == null);
                    delivery_id = parsed.value.id;
                },
                .assistant => assistant_id = parsed.value.id,
                else => {},
            },
            else => {},
        }
    }

    try testing.expect(record_id != null);
    try testing.expect(delivery_id != null);
    // The record is written before the delivery, so a log a replay reads in
    // order never shows an agent being told about a task that has not been
    // recorded as finished.
    try testing.expect(record_id.? < delivery_id.?);
    // And both land before the model speaks, which is what "the agent acted on
    // a background result" has to mean: the turn that read it can be tied to
    // the turn it was told.
    try testing.expect(assistant_id != null);
    try testing.expect(delivery_id.? < assistant_id.?);

    // Drained once. A loop that polled at every safe point and did not clear
    // the table would tell the agent about one task on every turn.
    const again = try table.take(allocator);
    defer task_table.freeCompletions(allocator, again);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "a session with no task table runs exactly as it did before background tasks existed" {
    // The default, and the one every existing caller takes. `Deps.tasks` is
    // null, so nothing is drained, nothing is appended, and the log holds the
    // same events it always did.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NOTASK");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    const deps = testDeps(fake_client.client(), store, fake_tools.runner());
    try testing.expectEqual(@as(?*task_table.Table, null), deps.tasks);

    try run(allocator, io, deps);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try testing.expect(parsed.value.event != .task_complete);
    }
}

/// What one session's `update_plan` calls left behind. Every string is in the
/// arena the caller passed to `runPlanSession`.
const PlanRun = struct {
    /// One entry per `update_plan` call, in order: what the model read back.
    outputs: []const []const u8,
    /// One entry per call: whether that call was refused.
    refused: []const bool,
    /// How many `plan.update` events the log holds. **A call that changed
    /// nothing must add none.**
    events: usize,
    /// How many steps those events carry between them, so a test can see that
    /// only what changed was written down.
    written_steps: usize,
    /// How many times the tool runner was asked to run anything. Zero is the
    /// assertion: a task list is never a sandboxed tool call.
    runner_calls: usize,
};

/// Run one session that makes one `update_plan` call per entry of `calls`,
/// then answers. `session` is folded from a fresh replay of the log afterwards,
/// so what it holds came out of the file and not out of the running loop.
fn runPlanSession(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const []const u8,
    session: *chock_proto.state.Session,
) !PlanRun {
    var backing = try chock_proto.storage.Memory.init(allocator, "01PLANRUN");
    const store = backing.storage();
    defer store.close(io);

    const turns = try arena.alloc(FakeTurn, calls.len + 1);
    for (calls, 0..) |arguments, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "plan{d}", .{index}),
            .name = plan_tool_name,
            .arguments = arguments,
        } };
        turns[index] = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "that is the list" };
    turns[calls.len] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    const deps = testDeps(fake_client.client(), store, fake_tools.runner());
    try run(allocator, io, deps);

    var outputs = try arena.alloc([]const u8, calls.len);
    var refused = try arena.alloc(bool, calls.len);
    var found: usize = 0;
    var out = PlanRun{
        .outputs = outputs,
        .refused = refused,
        .events = 0,
        .written_steps = 0,
        .runner_calls = fake_tools.calls,
    };

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        switch (parsed.value.event) {
            .plan_update => |update| {
                out.events += 1;
                out.written_steps += update.steps.len;
            },
            .tool_result => |result| {
                if (!std.mem.startsWith(u8, result.call_id, "plan")) continue;
                outputs[found] = try arena.dupe(u8, result.output);
                refused[found] = result.is_error;
                found += 1;
            },
            else => {},
        }
    }
    if (found != calls.len) return error.MissingPlanResult;
    return out;
}

/// What one session's `restrict_self` calls left behind. Every string is in
/// the arena the caller passed to `runPromiseSession`.
const PromiseRun = struct {
    /// One entry per call, in order: what the model read back.
    outputs: []const []const u8,
    /// One entry per call: whether that call was refused.
    refused: []const bool,
    /// How many `policy.self` events the log holds. **A call that was refused,
    /// and a call that changed nothing, must add none.**
    events: usize,
    /// How many times the tool runner was asked to run anything. Zero is the
    /// assertion: a promise is never a sandboxed tool call.
    runner_calls: usize,
};

/// Run one session that makes one `restrict_self` call per entry of `calls`,
/// then answers. `session` is folded from a fresh replay of the log afterwards,
/// so what it holds came out of the file and not out of the running loop.
/// An `Arbiter` a test drives. **It counts its calls**, because a test that
/// only read the outcome could not tell a widening that was weighed and refused
/// from one that was never asked about, and several facts below are exactly
/// about which of those happened.
const TestArbiter = struct {
    answer: arbiter_mod.Answer = .{ .permitted = false, .outcome = "refused_by_user" },
    calls: usize = 0,
    /// What the last call was asked about. **Copied and not kept**: `runWiden`
    /// builds the summary and the detail for the length of the call and frees
    /// them again, the same way `Broker.Request` borrows everything it is
    /// given, so a double that held the slices would be reading freed memory a
    /// moment later.
    saw_action: []const u8 = "",
    saw_tool: []const u8 = "",
    summary_buffer: [512]u8 = undefined,
    summary_len: usize = 0,
    detail_buffer: [1024]u8 = undefined,
    detail_len: usize = 0,

    fn sawSummary(self: *const TestArbiter) []const u8 {
        return self.summary_buffer[0..self.summary_len];
    }

    fn sawDetail(self: *const TestArbiter) []const u8 {
        return self.detail_buffer[0..self.detail_len];
    }

    fn arbiter(self: *TestArbiter) arbiter_mod.Arbiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = arbiter_mod.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *arbiter_mod.Locked,
        ask: arbiter_mod.Ask,
    ) arbiter_mod.Answer {
        _ = gpa;
        _ = io;
        _ = locked;
        const self: *TestArbiter = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        // The action name and the tool name are static text a caller does not
        // build, so those are safe to keep as they are.
        self.saw_action = ask.action;
        self.saw_tool = ask.tool;
        self.summary_len = @min(ask.summary.len, self.summary_buffer.len);
        @memcpy(self.summary_buffer[0..self.summary_len], ask.summary[0..self.summary_len]);
        self.detail_len = @min(ask.detail.len, self.detail_buffer.len);
        @memcpy(self.detail_buffer[0..self.detail_len], ask.detail[0..self.detail_len]);
        return self.answer;
    }
};

fn runPromiseSession(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const []const u8,
    session: *chock_proto.state.Session,
) !PromiseRun {
    return runPromiseSessionWith(allocator, arena, io, calls, session, null);
}

/// Same, for a session that can ask somebody about a widening.
fn runPromiseSessionWith(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const []const u8,
    session: *chock_proto.state.Session,
    arbiter: ?arbiter_mod.Arbiter,
) !PromiseRun {
    var backing = try chock_proto.storage.Memory.init(allocator, "01PROMISERUN");
    const store = backing.storage();
    defer store.close(io);

    const turns = try arena.alloc(FakeTurn, calls.len + 1);
    for (calls, 0..) |arguments, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "promise{d}", .{index}),
            .name = restrict_tool_name,
            .arguments = arguments,
        } };
        turns[index] = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "that is what I will not do" };
    turns[calls.len] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = arbiter;
    try run(allocator, io, deps);

    var outputs = try arena.alloc([]const u8, calls.len);
    var refused = try arena.alloc(bool, calls.len);
    var found: usize = 0;
    var out = PromiseRun{
        .outputs = outputs,
        .refused = refused,
        .events = 0,
        .runner_calls = fake_tools.calls,
    };

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        switch (parsed.value.event) {
            .policy_self => out.events += 1,
            .tool_result => |result| {
                if (!std.mem.startsWith(u8, result.call_id, "promise")) continue;
                outputs[found] = try arena.dupe(u8, result.output);
                refused[found] = result.is_error;
                found += 1;
            },
            else => {},
        }
    }
    if (found != calls.len) return error.MissingPromiseResult;
    return out;
}

test "an agent cannot lift a promise it made, and the refusal writes nothing" {
    // A self imposed constraint the self can relax is not a constraint, so
    // this drives the whole shape: the agent binds itself, forgets, and asks
    // for the permission back. The request is refused, no event is written, and
    // the promise the session holds afterwards is exactly the one it made.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPromiseSession(allocator, arena, io, &.{
        \\{"action":"net.fetch","ceiling":"deny","reason":"this task reads local files only"}
        ,
        // The same act, asked for back. This is the call the whole design
        // exists to refuse.
        \\{"action":"net.fetch","ceiling":"allow","reason":"I have changed my mind"}
        ,
        // And the smaller version of it: not all the way back to `allow`, only
        // one step up. A ratchet that only caught the obvious case would pass
        // the line above and fail this one.
        \\{"action":"net.fetch","ceiling":"ask","reason":"a person could decide"}
        ,
    }, &session);

    // A promise is never a sandboxed tool call: it is an event in a log the
    // loop holds the only lock on.
    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);

    // One promise written, and neither request to lift it wrote anything.
    try testing.expectEqual(@as(usize, 1), outcome.events);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expect(outcome.refused[2]);

    // The model is told what it holds, that it cannot take it back, and what
    // to do instead. A bare no costs the next five turns.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "cannot take it back") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "net.fetch at most deny") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "nothing was lifted") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "authorised by somebody other than you") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "stop and say what is left") != null);

    // And the session, folded out of its own file, still holds the promise it
    // made. This is the fact the broker reads: see
    // `lib/chock-broker/Broker.zig`.
    try testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "net.fetch"));
    // A table that allowed the act outright still ends at `deny` once the
    // promise is folded in, which is what makes the promise worth making.
    try testing.expectEqual(
        chock_policy.table.Decision.deny,
        ratchet.narrow(.allow, held, "net.fetch"),
    );
}

test "a widening proposal is put to somebody, and the refusal says it was weighed" {
    // The ratchet, and `chock_policy.ratchet.widen_action`. Before this, a
    // widening was refused with nobody asked, and the refusal had to say so.
    // Now there is somebody to ask, so two facts: the request really does reach
    // them, under the action name given to it, and the answer that comes back
    // is what the model is told.
    //
    // **The call count is what separates weighed from never asked**, which a
    // test reading only the outcome could not tell apart, and those are the two
    // facts an approval keeps separate.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var judge = TestArbiter{ .answer = .{
        .permitted = false,
        .outcome = "refused_by_review",
        .review_text = "A reviewer read this request and did not allow it.",
    } };

    const outcome = try runPromiseSessionWith(allocator, arena, io, &.{
        \\{"action":"net.fetch","ceiling":"deny","reason":"this task reads local files only"}
        ,
        \\{"action":"net.fetch","ceiling":"ask","reason":"the task turned out to need one fetch"}
        ,
    }, &session, judge.arbiter());

    try testing.expectEqual(@as(usize, 1), judge.calls);
    // The key it was measured against, which is what a project writes a rule
    // for in `chock.zon`.
    try testing.expectEqualStrings(ratchet.widen_action, judge.saw_action);
    try testing.expectEqualStrings(restrict_tool_name, judge.saw_tool);
    // The effect, and never a command string. Both ceilings are in it, because
    // "from deny to ask" is what somebody is deciding about.
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "net.fetch") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "deny") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "ask") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "the task turned out to need one fetch") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawSummary(), "net.fetch") != null);

    // Refused, so nothing was written and the promise still stands.
    try testing.expect(outcome.refused[1]);
    try testing.expectEqual(@as(usize, 1), outcome.events);
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "net.fetch"));

    // And the model is told which answer it got, not a generic no. This is the
    // production caller `chock_broker.review.requesterText` did not have.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "refused_by_review") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "A reviewer read this request") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "nothing was lifted") != null);
}

test "a widening somebody authorised is the one thing that lifts a promise" {
    // The release valve actually opening. An agent binds itself, the task turns
    // out to need the thing it gave up, somebody who is not the agent says yes,
    // and **the ceiling the broker reads afterwards has really moved**. Without
    // this the whole path is a question with no consequence.
    //
    // The check is over a session folded from a fresh replay of its own log, so
    // what is read came out of the file: an authorised lift that only lived in
    // the running loop would be lost to a resume, a compaction, or a handover.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var judge = TestArbiter{ .answer = .{ .permitted = true, .outcome = "approved_by_user" } };

    const outcome = try runPromiseSessionWith(allocator, arena, io, &.{
        \\{"action":"net.fetch","ceiling":"deny","reason":"this task reads local files only"}
        ,
        \\{"action":"net.fetch","ceiling":"ask","reason":"the task turned out to need one fetch"}
        ,
    }, &session, judge.arbiter());

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expect(!outcome.refused[1]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "Lifted") != null);
    // The words say who decided, because an agent that read "lifted" and
    // thought it had lifted it would have learned the wrong lesson.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "Somebody other than you") != null);

    // Two `policy.self` events: the promise and the lift. The lift is a record
    // like any other, so a person reading the log the next morning sees both
    // the promise and who let the session out of it.
    try testing.expectEqual(@as(usize, 2), outcome.events);

    // **One promise left, at the new ceiling.** The fold replaced by exact name
    // rather than adding one more term to the minimum: see
    // `chock_proto.state.SelfPolicy.apply`.
    try testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.ask, ratchet.ceilingFor(held, "net.fetch"));
    // And the promise still binds: a lift to `ask` is not a lift to `allow`, so
    // a table that would have allowed the act outright still ends at `ask`.
    try testing.expectEqual(
        chock_policy.table.Decision.ask,
        ratchet.narrow(.allow, held, "net.fetch"),
    );
}

test "a lift that names a wider pattern than the promise is refused before anybody is asked" {
    // A session that promised `git.*` and asks to be let out of `git.push` is
    // asking about something it never promised under that name.
    // `ratchet.ceilingFor` would still hold `git.*` against it afterwards, so an
    // authorised yes would be recorded and would change nothing, which is the
    // worst of the three outcomes: a person spends a decision and the agent
    // believes a wall came down that is still there.
    //
    // **Nobody is asked at all**, which the call count is what proves: paying
    // for a review, or waking a person, for an answer that cannot take effect
    // is the same waste `Broker.reviewed` already refuses to spend.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var judge = TestArbiter{ .answer = .{ .permitted = true, .outcome = "approved_by_user" } };

    const outcome = try runPromiseSessionWith(allocator, arena, io, &.{
        \\{"action":"git.*","ceiling":"deny","reason":"this task changes no history"}
        ,
        \\{"action":"git.push","ceiling":"ask","reason":"I would like to publish it"}
        ,
    }, &session, judge.arbiter());

    try testing.expectEqual(@as(usize, 0), judge.calls);
    try testing.expect(outcome.refused[1]);
    try testing.expectEqual(@as(usize, 1), outcome.events);
    // The message names what to write instead, which is the whole difference
    // between a refusal a model can act on and one that costs five turns.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "under a different name") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "git.*") != null);

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "git.push"));
}

test "a promise applies at once when it narrows, and a session may narrow twice" {
    // Narrowing is free: no reviewer, no person, no question in the log. And
    // free more than once, because an agent that learns more about the task
    // should be able to give up more.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPromiseSession(allocator, arena, io, &.{
        \\{"action":"git.*","ceiling":"ask","reason":"no git without a person"}
        ,
        // Narrower than the class above, and about one act inside it.
        \\{"action":"git.push","ceiling":"deny","reason":"and nothing leaves this machine"}
        ,
        // Already covered by the class: the same ceiling it already holds.
        \\{"action":"git.commit","ceiling":"ask","reason":"saying it again"}
        ,
    }, &session);

    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);
    // Two written, and the third changed nothing so it wrote nothing.
    try testing.expectEqual(@as(usize, 2), outcome.events);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(!outcome.refused[1]);
    // A call that changed nothing is not a failure: what it asked for is
    // already true of this session.
    try testing.expect(!outcome.refused[2]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "Nothing changed") != null);

    // No approval was ever asked for, which is what "narrowing is free" means
    // in the log.
    try testing.expectEqual(@as(usize, 2), session.self_policy.restrictions.items.len);

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    // The narrowest promise that covers the act answers, so the class binds
    // every act under it and the one named act is narrower still.
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "git.push"));
    try testing.expectEqual(chock_policy.table.Decision.ask, ratchet.ceilingFor(held, "git.commit"));
    // And an act nobody promised anything about is untouched.
    try testing.expectEqual(chock_policy.table.Decision.allow, ratchet.ceilingFor(held, "net.fetch"));
}

test "a promise cannot be lifted by naming a wider pattern than the one it was made about" {
    // The near miss the classification has to get right. An agent that
    // promised `git.push` and then asks about `git.*` is asking about a class
    // this session promised nothing about **as a class**, so nothing it says
    // about that class can reach the narrower promise inside it. Without this
    // the ratchet has a way round it that reads like an ordinary call.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPromiseSession(allocator, arena, io, &.{
        \\{"action":"git.push","ceiling":"deny","reason":"nothing leaves this machine"}
        ,
        // The wider pattern, at the widest ceiling. This is the call that would
        // be a way out if a class could answer for the acts inside it.
        \\{"action":"git.*","ceiling":"allow","reason":"git should be fine after all"}
        ,
    }, &session);

    try testing.expect(!outcome.refused[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expectEqual(@as(usize, 1), outcome.events);

    // The refusal says what a ceiling of "allow" is worth and what lifting a
    // promise would actually take, so the model is not left guessing at a
    // wording.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "gives up nothing") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "name exactly the action") != null);
    // And it prints what is still held, which is the promise that was not
    // lifted.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "git.push at most deny") != null);

    // The act itself is still denied, folded out of the log.
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "git.push"));
    // And nothing under that class was quietly promised either, so the refusal
    // wrote nothing at all rather than writing something narrower.
    try testing.expectEqual(chock_policy.table.Decision.allow, ratchet.ceilingFor(held, "git.commit"));
}

test "a promise that binds nothing is refused, and nothing reaches the log" {
    // Every way a proposal can be one a reader could not act on. The bounds
    // live in `chock_policy.ratchet` and the loop is what applies them, so
    // this is the proof that a refused proposal writes no event at all: a
    // promise in the log that nobody can measure would be a wall the agent
    // believes in and the broker cannot find.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPromiseSession(allocator, arena, io, &.{
        "not json at all",
        \\{"action":"net.fetch","ceiling":"denny","reason":"a misspelled ceiling"}
        ,
        \\{"action":"","ceiling":"deny","reason":"a promise about nothing"}
        ,
        \\{"action":"*","ceiling":"deny","reason":"a promise about everything"}
        ,
        \\{"action":"net.fetch","ceiling":"deny","reason":""}
        ,
        \\{"action":"net.\nfetch","ceiling":"deny","reason":"a name on two lines"}
        ,
    }, &session);

    for (outcome.refused) |one| try testing.expect(one);
    try testing.expectEqual(@as(usize, 0), outcome.events);
    try testing.expectEqual(@as(usize, 0), session.self_policy.restrictions.items.len);

    // Each refusal says which of them it was, so the model can fix the call
    // rather than guess at it.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "JSON object") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "is not a ceiling") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "name the action") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[3], "name the one you mean") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[4], "say why") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[5], "one to a line") != null);

    // A misspelled ceiling is refused rather than read as the nearest one this
    // build knows. The five names are in the message, so the next call can be
    // right.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"deny\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"allow\"") != null);
}

test "a session that never calls restrict_self promises nothing at all" {
    // **Never pushed, proven at the log.** Nearly every session has no use for
    // a promise, and nothing in this loop writes one on the agent's behalf, so
    // a session that made none holds none. The same rule the task list keeps.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NOPROMISE");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "read_file",
            .arguments = "{\"path\":\"build.zig\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "the file" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        try testing.expect(parsed.value.event != .policy_self);
    }
    try testing.expectEqual(@as(usize, 0), session.self_policy.restrictions.items.len);

    // And a session that promised nothing narrows nothing, so the policy
    // table answers exactly as it would for a session with no promises in it.
    const held = try self_policy.restrictionsFrom(allocator, session.self_policy.restrictions.items);
    defer allocator.free(held);
    try testing.expectEqual(chock_policy.table.Decision.allow, ratchet.narrow(.allow, held, "git.push"));
}

// **The loop decides nothing about a fetch**, so these prove the two things
// only the loop can be wrong about: that the call reaches the seam at all, and
// that the promises of this session travel across it. What the seam then does
// with them is `lib/chock-broker/fetch.zig`'s question, and
// `test/broker/fetch.zig` answers it against a real HTTP server.

/// A `fetch_mod.Fetcher` that answers a fixed page and keeps what it was asked.
const FakeFetcher = struct {
    allocator: std.mem.Allocator,
    page: []const u8 = "the page",
    calls: usize = 0,
    /// The URL of the last call, owned by `allocator`.
    url: []u8 = &.{},
    /// What the last call was told this session had promised about `net.fetch`.
    /// **The fact these tests are about**: a loop that folded no promises would
    /// hand over an empty list and every refusal downstream would vanish.
    ceiling: chock_policy.table.Decision = .allow,
    promises: usize = 0,

    fn deinit(self: *FakeFetcher) void {
        self.allocator.free(self.url);
    }

    fn fetcher(self: *FakeFetcher) fetch_mod.Fetcher {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = fetch_mod.Fetcher.VTable{ .fetch = fetchFn };

    fn fetchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        ask: fetch_mod.Ask,
    ) fetch_mod.Error!fetch_mod.Answer {
        _ = io;
        const self: *FakeFetcher = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.allocator.free(self.url);
        self.url = try self.allocator.dupe(u8, ask.url);
        self.promises = ask.self_policy.len;
        self.ceiling = ratchet.ceilingFor(ask.self_policy, "net.fetch");
        return .{ .text = try gpa.dupe(u8, self.page), .is_error = false };
    }
};

/// Run one session whose turns are the tool calls in `calls`, each of them a
/// `fetch_url` or a `restrict_self`, and give back what each one read.
const FetchRun = struct {
    outputs: []const []const u8,
    refused: []const bool,
};

fn runFetchSession(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const struct { tool: []const u8, arguments: []const u8 },
    fetcher: ?fetch_mod.Fetcher,
) !FetchRun {
    var backing = try chock_proto.storage.Memory.init(allocator, "01FETCHRUN");
    const store = backing.storage();
    defer store.close(io);

    const turns = try arena.alloc(FakeTurn, calls.len + 1);
    for (calls, 0..) |one, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "fetch{d}", .{index}),
            .name = one.tool,
            .arguments = one.arguments,
        } };
        turns[index] = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "that is what the page said" };
    turns[calls.len] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.fetcher = fetcher;
    try run(allocator, io, deps);

    // **A fetch must never reach the tool runner.** The loop answers it, the
    // same way it answers a spawn and a promise, so a runner that saw one would
    // mean the seam had been bypassed.
    if (fake_tools.calls != 0) return error.FetchReachedTheToolRunner;

    const outputs = try arena.alloc([]const u8, calls.len);
    const refused = try arena.alloc(bool, calls.len);
    var found: usize = 0;

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .tool_result => |result| {
                if (!std.mem.startsWith(u8, result.call_id, "fetch")) continue;
                outputs[found] = try arena.dupe(u8, result.output);
                refused[found] = result.is_error;
                found += 1;
            },
            else => {},
        }
    }
    if (found != calls.len) return error.MissingFetchResult;
    return .{ .outputs = outputs, .refused = refused };
}

test "a fetch_url call reaches the fetcher and the page comes back as the tool result" {
    // The one thing a unit test of the broker cannot prove: that the name in
    // `tools.Tool` is really wired to the seam, so a model that calls it gets a
    // page rather than "unknown tool".
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeFetcher{ .allocator = allocator, .page = "the manual says so" };
    defer fake.deinit();

    const outcome = try runFetchSession(allocator, arena, io, &.{
        .{ .tool = fetch_tool_name, .arguments =
        \\{"url":"https://example.com/manual"}
        },
    }, fake.fetcher());

    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings("https://example.com/manual", fake.url);
    try testing.expect(!outcome.refused[0]);
    try testing.expectEqualStrings("the manual says so", outcome.outputs[0]);
}

test "a promise made earlier in the session reaches the fetcher" {
    // **The reason this call is answered by the loop at all.** The promises of
    // a session live in the fold of its log, a tool runner holds no log, and
    // `restrict_self` offers "net.fetch" at "deny" in its own description. A
    // loop that handed over an empty list would leave that promise binding
    // nothing.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeFetcher{ .allocator = allocator };
    defer fake.deinit();

    const outcome = try runFetchSession(allocator, arena, io, &.{
        .{ .tool = restrict_tool_name, .arguments =
        \\{"action":"net.fetch","ceiling":"deny","reason":"this task reads local files"}
        },
        .{ .tool = fetch_tool_name, .arguments =
        \\{"url":"https://example.com/manual"}
        },
    }, fake.fetcher());

    try testing.expect(!outcome.refused[0]);
    try testing.expectEqual(@as(usize, 1), fake.promises);
    // Mutation check: hand `&.{}` to `fetcher.fetch` in `runFetch` instead of
    // `held`, and this line is what fails.
    try testing.expectEqual(chock_policy.table.Decision.deny, fake.ceiling);
}

test "a session with no fetcher reads nothing and says so" {
    // A session started without one is the ordinary case for a caller that has
    // no policy table, and every test above this line runs as one. The model
    // must be told, or it reasons about a page nobody read.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runFetchSession(allocator, arena, io, &.{
        .{ .tool = fetch_tool_name, .arguments =
        \\{"url":"https://example.com/manual"}
        },
        // And a call this cannot even read is a refusal of its own, not a
        // fetch of an empty URL.
        .{ .tool = fetch_tool_name, .arguments = "not json at all" },
    }, null);

    try testing.expect(outcome.refused[0]);
    try testing.expectEqualStrings(fetch_mod.has_no_fetcher, outcome.outputs[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"url\"") != null);
}

// **The loop decides nothing about a question**, so these prove the three
// things only the loop can be wrong about: that the call reaches the seam at
// all, that the person's own answer travels back as the tool result, and that a
// session with nobody to ask comes straight back rather than waiting. What a
// person actually reads and types is `lib/chock-core/ask.zig`'s question, and
// its own tests answer it.

/// An `ask_mod.Asker` that answers a scripted answer and keeps what it was
/// asked.
const FakeAsker = struct {
    allocator: std.mem.Allocator,
    /// Which way the question ends. **The tag and not an `Answer`**, because the
    /// answered case owns memory the caller frees, so it has to be built fresh
    /// on every call.
    kind: std.meta.Tag(ask_mod.Answer) = .answered,
    /// What the person "types", for the answered case.
    said: []const u8 = "use the staging database",
    calls: usize = 0,
    /// The question of the last call, owned by `allocator`. **The fact these
    /// tests are about**: a loop that dropped the model's words would ask a
    /// person an empty question.
    question: []u8 = &.{},
    options: usize = 0,

    fn deinit(self: *FakeAsker) void {
        self.allocator.free(self.question);
    }

    fn asker(self: *FakeAsker) ask_mod.Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ask_mod.Asker.VTable{ .ask = askFn };

    fn askFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: ask_mod.Question,
    ) ask_mod.Error!ask_mod.Answer {
        _ = io;
        const self: *FakeAsker = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.allocator.free(self.question);
        self.question = try self.allocator.dupe(u8, question.text);
        self.options = question.options.len;
        // No `else`: a way for a question to end that is added to `Answer` and
        // forgotten here fails the build rather than being untested.
        return switch (self.kind) {
            .answered => .{ .answered = try gpa.dupe(u8, self.said) },
            .declined => .declined,
            .nobody => .nobody,
            .timed_out => .timed_out,
            .stopped => .stopped,
        };
    }
};

const AskRun = struct {
    outputs: []const []const u8,
    refused: []const bool,
    /// How many `approval.request` events the session wrote. **Always zero for
    /// an ask**: see `lib/chock-core/ask.zig`'s own top comment.
    approvals: usize,
};

fn runAskSession(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const []const u8,
    asker: ?ask_mod.Asker,
) !AskRun {
    var backing = try chock_proto.storage.Memory.init(allocator, "01ASKRUN");
    const store = backing.storage();
    defer store.close(io);

    const turns = try arena.alloc(FakeTurn, calls.len + 1);
    for (calls, 0..) |arguments, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "ask{d}", .{index}),
            .name = ask_tool_name,
            .arguments = arguments,
        } };
        turns[index] = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "that is what the user said" };
    turns[calls.len] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.asker = asker;
    try run(allocator, io, deps);

    // **A question must never reach the tool runner.** A `Registry` runs inside
    // a sandbox that holds no terminal, so a runner that saw one would mean the
    // seam had been bypassed.
    if (fake_tools.calls != 0) return error.AskReachedTheToolRunner;

    const outputs = try arena.alloc([]const u8, calls.len);
    const refused = try arena.alloc(bool, calls.len);
    var found: usize = 0;
    var approvals: usize = 0;

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => approvals += 1,
            .tool_result => |result| {
                if (!std.mem.startsWith(u8, result.call_id, "ask")) continue;
                outputs[found] = try arena.dupe(u8, result.output);
                refused[found] = result.is_error;
                found += 1;
            },
            else => {},
        }
    }
    if (found != calls.len) return error.MissingAskResult;
    return .{ .outputs = outputs, .refused = refused, .approvals = approvals };
}

test "an ask_user call reaches the person and the answer comes back as the tool result" {
    // The one thing a unit test of `ask.zig` cannot prove: that the name in
    // `tools.Tool` is really wired to the seam, so a model that calls it reaches
    // a person rather than "unknown tool". This is the fault this project has
    // shipped at least eight times.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeAsker{ .allocator = allocator, .said = "use the staging database" };
    defer fake.deinit();

    const outcome = try runAskSession(allocator, arena, io, &.{
        \\{"question":"which database should I write to?","options":["staging","production"]}
    }, fake.asker());

    // The model's own words reached the seam, and so did its options.
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings("which database should I write to?", fake.question);
    try testing.expectEqual(@as(usize, 2), fake.options);

    // And the person's own words reached the model, marked as theirs.
    try testing.expect(!outcome.refused[0]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "use the staging database") != null);
    try testing.expect(std.mem.startsWith(u8, outcome.outputs[0], "[chock: the user answered.]"));

    // **And no approval was asked for.** An ask grants nothing, so it writes no
    // `approval.request` and there is nothing for anybody to have permitted.
    try testing.expectEqual(@as(usize, 0), outcome.approvals);

    // Mutation check: send `&.{}` instead of `question.options` in
    // `runAskUser`, and the `fake.options` line fails. Drop the `ask_tool_name`
    // branch in `runTool` and `runAskSession` fails with
    // `AskReachedTheToolRunner`.
}

test "a session with nobody to ask says so at once and does not stall" {
    // **The refusal path at the loop.** A subagent and a daemon session both run
    // as this, and every other test of this loop runs as one too. A hang here
    // holds the session lock for good, so what is pinned is that the call comes
    // back and that the words tell the model to carry on by itself.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runAskSession(allocator, arena, io, &.{
        \\{"question":"which database should I write to?"}
        ,
        // A call this cannot even read is a refusal of its own, and never a
        // question with an empty body put in front of somebody.
        "not json at all",
        // So is one with nothing in it. `ask.check` is what stops it, before
        // any seam is reached.
        \\{"question":"   "}
        ,
    }, null);

    try testing.expect(outcome.refused[0]);
    try testing.expectEqualStrings(ask_mod.has_no_asker, outcome.outputs[0]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "Do not ask again") != null);

    try testing.expect(outcome.refused[1]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"question\"") != null);

    try testing.expect(outcome.refused[2]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "was empty") != null);

    try testing.expectEqual(@as(usize, 0), outcome.approvals);
}

test "an ask that nobody answered is an error result the model can act on" {
    // The three ways a question ends with no answer are kept apart from a person
    // who answered, because a model told "no answer" and a model told "they said
    // nothing" go different ways. What is pinned here is that each one arrives
    // as an error result carrying its own words, so the model never mistakes one
    // for a person's reply.
    const allocator = testing.allocator;
    const io = testing.io;

    const cases = [_]struct { kind: std.meta.Tag(ask_mod.Answer), says: []const u8 }{
        .{ .kind = .declined, .says = "chose to say nothing" },
        .{ .kind = .timed_out, .says = "nobody answered it in time" },
        .{ .kind = .stopped, .says = "session is stopping" },
    };

    for (cases) |case| {
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var fake = FakeAsker{ .allocator = allocator, .kind = case.kind };
        defer fake.deinit();

        const outcome = try runAskSession(allocator, arena, io, &.{
            \\{"question":"which database?"}
        }, fake.asker());

        try testing.expectEqual(@as(usize, 1), fake.calls);
        try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], case.says) != null);
        // A person who deliberately said nothing has answered the question, so
        // that one alone is not an error.
        try testing.expectEqual(case.kind != .declined, outcome.refused[0]);
    }
}

// **The title travels a road no unit test can check on its own**: the model
// names a tool, the loop answers it in place of the tool runner, and the name
// ends up as an event in the session log that `chock sessions` folds. These
// drive the whole of that road, because every part of it has been built and left
// unwired at least eight times in this project.

const TitleRun = struct {
    outputs: []const []const u8,
    refused: []const bool,
    /// Every title the log holds, in the order they were written. **The fact
    /// these tests are about**: a title that never reached the log is a title no
    /// listing will ever show.
    written: []const []const u8,
};

fn runTitleSession(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const []const u8,
) !TitleRun {
    var backing = try chock_proto.storage.Memory.init(allocator, "01TITLERUN");
    const store = backing.storage();
    defer store.close(io);

    const turns = try arena.alloc(FakeTurn, calls.len + 1);
    for (calls, 0..) |arguments, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "title{d}", .{index}),
            .name = title_tool_name,
            .arguments = arguments,
        } };
        turns[index] = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "the session is named" };
    turns[calls.len] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    const deps = testDeps(fake_client.client(), store, fake_tools.runner());
    try run(allocator, io, deps);

    // **A title must never reach the tool runner.** A `Registry` runs inside a
    // sandbox and holds no log, so a runner that saw one would mean the loop had
    // handed the session's own record to something that cannot write it.
    if (fake_tools.calls != 0) return error.TitleReachedTheToolRunner;

    const outputs = try arena.alloc([]const u8, calls.len);
    const refused = try arena.alloc(bool, calls.len);
    var found: usize = 0;
    var written: std.ArrayList([]const u8) = .empty;

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_title => |named| try written.append(arena, try arena.dupe(u8, named.title)),
            .tool_result => |result| {
                if (!std.mem.startsWith(u8, result.call_id, "title")) continue;
                outputs[found] = try arena.dupe(u8, result.output);
                refused[found] = result.is_error;
                found += 1;
            },
            else => {},
        }
    }
    if (found != calls.len) return error.MissingTitleResult;
    return .{
        .outputs = outputs,
        .refused = refused,
        .written = try written.toOwnedSlice(arena),
    };
}

test "a set_title call names the session, and the name is in the log the listing folds" {
    // The one thing a unit test cannot prove: that `set_title` in `tools.Tool` is
    // really wired to a loop that writes the event, so a model that calls it
    // names the session rather than reading "unknown tool".
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runTitleSession(allocator, arena, io, &.{
        \\{"title":"port the parser to the new lexer"}
    });

    try testing.expect(!outcome.refused[0]);
    // The name reached the log, which is the only place a listing reads it from.
    try testing.expectEqual(@as(usize, 1), outcome.written.len);
    try testing.expectEqualStrings("port the parser to the new lexer", outcome.written[0]);
    // And the model is told the name it gave, so it can see which of its
    // attempts is the one a person will read.
    try testing.expect(std.mem.indexOf(
        u8,
        outcome.outputs[0],
        "This session is now called: port the parser to the new lexer",
    ) != null);

    // A title with a space at either end is the same title as the one without,
    // so a retitle that only added whitespace does not read as a rename.
    const trimmed = try runTitleSession(allocator, arena, io, &.{
        \\{"title":"  port the parser to the new lexer \t"}
    });
    try testing.expectEqualStrings("port the parser to the new lexer", trimmed.written[0]);

    // Mutation check: drop the `title_tool_name` branch in `runTool`, and
    // `runTitleSession` fails with `TitleReachedTheToolRunner`. Drop the
    // `appendAndApply` call in `runSetTitle` and the `outcome.written` lines
    // fail. Drop the `std.mem.trim` and the last line fails.
}

test "a later title supersedes an earlier one, and the log still holds both" {
    // **The log is append only, so a rename cannot be a rewrite.** This is what
    // makes "name the session early and correct it later" safe advice: an agent
    // that finds out halfway through what the task really is says so, the fold
    // takes the last, and the name the session went by first is still on record.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runTitleSession(allocator, arena, io, &.{
        \\{"title":"read the parser tests"}
        ,
        \\{"title":"port the parser to the new lexer"}
    });

    try testing.expect(!outcome.refused[0] and !outcome.refused[1]);
    try testing.expectEqual(@as(usize, 2), outcome.written.len);
    try testing.expectEqualStrings("read the parser tests", outcome.written[0]);
    try testing.expectEqualStrings("port the parser to the new lexer", outcome.written[1]);
    // And the answer says a later call is allowed, so a model that learns
    // something is not left believing the first name is final.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "again") != null);

    // Mutation check: keep only the first title, by returning early in
    // `runSetTitle` when the log already holds one, and the second
    // `expectEqualStrings` fails on a list of one.
}

test "a title that is not one short line of plain text is refused and nothing is written" {
    // Every one of these is the model's own to fix, so it is told what to send
    // instead and no bad title reaches the log at all. **The hostile ones matter
    // most**: a title is printed in a list on somebody's terminal, so an escape
    // sequence in one would drive it.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const long = "e" ** (max_title_bytes + 1);
    const too_long = try std.fmt.allocPrint(arena, "{{\"title\":\"{s}\"}}", .{long});

    const cases = [_][]const u8{
        // Nothing at all, and whitespace, which is the same fact.
        \\{"title":""}
        ,
        \\{"title":"   "}
        ,
        // Not the shape the tool takes.
        \\{"steps":[]}
        ,
        too_long,
        // Two lines, the second of which would reach column zero in a listing
        // and read as a row of the table.
        \\{"title":"read the tests\n01M0TMATKB6M4H3GY35KYA68QR  finished"}
        ,
        // An escape sequence that clears the screen, and a bell. Written as
        // JSON escapes, so the real bytes reach the check and this source file
        // stays plain text.
        \\{"title":"read \u001b[2J the tests \u0007"}
        ,
    };
    const outcome = try runTitleSession(allocator, arena, io, &cases);

    // **Not one of them reached the log.** This is the line that matters: a
    // refusal that still wrote the title would defend nothing.
    try testing.expectEqual(@as(usize, 0), outcome.written.len);
    for (outcome.refused) |one| try testing.expect(one);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "was empty") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "was empty") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "\"title\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[3], "longer than") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[4], "one line") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[5], "control character") != null);

    // A title exactly at the bound is allowed: the bound is what is allowed, and
    // the one past it is what is refused.
    const at_bound = "e" ** max_title_bytes;
    const allowed = try std.fmt.allocPrint(arena, "{{\"title\":\"{s}\"}}", .{at_bound});
    const kept = try runTitleSession(allocator, arena, io, &.{allowed});
    try testing.expect(!kept.refused[0]);
    try testing.expectEqual(@as(usize, 1), kept.written.len);

    // Bytes that are not text never get as far as a JSON document, so that one
    // is answered at the check itself. A log line whose title is not a string is
    // a line no replay of this build can read back.
    try testing.expect(titleRefusalText("\xff\xfe name") != null);
    try testing.expect(titleRefusalText("an ordinary name") == null);

    // Mutation check: change `>` to `>=` on the length test in
    // `titleRefusalText` and the `at_bound` case fails. Drop the control
    // character loop and the last two outputs stop being refused, so the
    // `outcome.written.len` line fails with a list of two.
}

test "a compaction puts the task list back in front of the model, and only when there is one" {
    // The task list's own known gap, closed at the loop. The list survives a
    // compaction for the reader, because `chock plan` folds the log, and it
    // does not survive one for the model: the only place the model ever saw its
    // list was the tool result of its own `update_plan` call, and that is
    // exactly what a fold can take away.
    //
    // **Both halves in one test**, because the trigger never firing for a
    // session that keeps no list is what makes this notice acceptable at all.
    const allocator = testing.allocator;
    const io = testing.io;

    const plan_arguments =
        "{\"steps\":[" ++
        "{\"id\":\"read\",\"subject\":\"read the fold\",\"status\":\"in_progress\"}," ++
        "{\"id\":\"fix\",\"subject\":\"fix the width count\",\"status\":\"pending\"}," ++
        "{\"id\":\"old\",\"subject\":\"work that is finished\",\"status\":\"done\"}]}";

    // A session that kept a list and then compacted.
    {
        var backing = try chock_proto.storage.Memory.init(allocator, "01PLANFOLD");
        const store = backing.storage();
        defer store.close(io);

        const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
        try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
        try seedMessages(allocator, io, store, "MIDDLE", 5);
        try seedMessages(allocator, io, store, "RECENT", 6);

        var seen = SeenRequests{ .allocator = allocator };
        defer seen.deinit();

        var fake_client = FakeClient{
            .seen = &seen,
            .turns = &.{
                .{ .deltas = &.{.{ .tool_call = .{
                    .index = 0,
                    .id = "plan1",
                    .name = plan_tool_name,
                    .arguments = plan_arguments,
                } }} },
                // Now past three quarters of 65536, which is 49152.
                .{ .deltas = &.{
                    .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                    .{ .usage = .{ .input_tokens = 60000 } },
                } },
                // The summary the compaction asks for, before the turn after it.
                .{ .deltas = &.{.{ .text = "SUMMARY" }} },
                .{ .deltas = &.{.{ .text = "all done" }} },
            },
        };
        var fake_tools = FakeToolRunner{ .output = "ok" };

        var deps = testDeps(fake_client.client(), store, fake_tools.runner());
        deps.compaction = .{ .context_limit_tokens = 65536 };
        try run(allocator, io, deps);

        // The compaction really happened, so what follows is about a folded
        // session and not about a session that never reached the threshold.
        var found = (try firstCompaction(allocator, io, store)).?;
        defer found.deinit(allocator);

        // The two steps that are left, by name, because a reminder that a list
        // exists is not the list: an agent that lost its plan cannot fetch one.
        try testing.expect(seen.anyTailHolds("folded into a summary"));
        try testing.expect(seen.anyTailHolds("read the fold"));
        try testing.expect(seen.anyTailHolds("fix the width count"));
        // And the step that is finished is not put back, because it is not
        // work that is left.
        try testing.expect(!seen.anyTailHolds("work that is finished"));

        // Nothing about the notice reaches the log, the same as every other
        // notice: a replay of this session never sees one.
        var replay = try store.replay(allocator, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            const line = try std.json.Stringify.valueAlloc(allocator, parsed.value.event, .{});
            defer allocator.free(line);
            try testing.expect(std.mem.indexOf(u8, line, "folded into a summary") == null);
        }
    }

    // The same compaction on a session whose agent never wrote a list. Nothing
    // is said, which is the property that keeps this notice worth reading.
    {
        var backing = try chock_proto.storage.Memory.init(allocator, "01NOPLANFOLD");
        const store = backing.storage();
        defer store.close(io);

        const task = [_]event.ContentPart{.{ .text = "TASK: one thing" }};
        try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &task } });
        try seedMessages(allocator, io, store, "MIDDLE", 5);
        try seedMessages(allocator, io, store, "RECENT", 6);

        var seen = SeenRequests{ .allocator = allocator };
        defer seen.deinit();

        var fake_client = FakeClient{ .seen = &seen, .turns = &.{
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 60000 } },
            } },
            .{ .deltas = &.{.{ .text = "SUMMARY" }} },
            .{ .deltas = &.{.{ .text = "all done" }} },
        } };
        var fake_tools = FakeToolRunner{ .output = "ok" };

        var deps = testDeps(fake_client.client(), store, fake_tools.runner());
        deps.compaction = .{ .context_limit_tokens = 65536 };
        try run(allocator, io, deps);

        var found = (try firstCompaction(allocator, io, store)).?;
        defer found.deinit(allocator);
        try testing.expect(!seen.anyTailHolds("folded into a summary"));
    }
}

test "an arbitrator runs no tool at all, and the three the loop answers itself are not exceptions" {
    // `chock_core.tools` keeps an arbitrator out of the tool list and out of
    // the dispatch, and **this file is the third place, because three tool
    // calls never reach the tool runner**: `spawn_agent`, `update_plan` and
    // `restrict_self` are answered here. A gate that lived only in the dispatch
    // would leave an arbitrator able to start a subagent, which is the one
    // thing that would give it a way to act.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01ARBITER");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "one",
            .name = "run_command",
            .arguments = "{\"argv\":[\"/bin/echo\",\"hi\"]}",
        } }} },
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "two",
            .name = spawn_tool_name,
            .arguments = "{\"agent_kind\":\"worker\",\"task\":\"do the act for me\"}",
        } }} },
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "three",
            .name = plan_tool_name,
            .arguments = "{\"steps\":[{\"id\":\"a\",\"subject\":\"weigh the case\",\"status\":\"pending\"}]}",
        } }} },
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "four",
            .name = restrict_tool_name,
            .arguments = "{\"action\":\"git.push\",\"ceiling\":\"deny\",\"reason\":\"this task reaches no other machine\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "{\"verdict\":\"refuse\",\"why\":\"the diff rewrites chock.zon\"}" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    // With a spawner, so nothing here passes for want of one. A real way to
    // start a child is right there and the role is what refuses.
    var spawner = FakeSpawner{};

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.role = .arbitrator;
    deps.spawner = spawner.spawner();
    deps.subagents = .{ .max_depth = 6, .max_width = 6 };
    try run(allocator, io, deps);

    // Nothing ran, nothing was started, and nothing about the session changed.
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);
    try testing.expectEqual(@as(usize, 0), spawner.prepared);
    try testing.expectEqual(@as(usize, 0), spawner.ran);

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var refusals: usize = 0;
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        switch (parsed.value.event) {
            // Not one of the three the loop answers itself reached the log as
            // a thing that happened.
            .session_spawn,
            .plan_update,
            .policy_self,
            .session_title,
            => return error.TheArbitratorActed,
            .tool_result => |result| {
                try testing.expect(result.is_error);
                try testing.expectEqualStrings(tools.arbitrator_holds_no_tool, result.output);
                refusals += 1;
            },
            else => {},
        }
    }
    // Every one of the four calls was refused, and the calls are still in the
    // log: a reviewer that tried is a thing the record shows.
    try testing.expectEqual(@as(usize, 4), refusals);
    try testing.expect(session.plan.isEmpty());
    try testing.expectEqual(@as(usize, 0), session.self_policy.restrictions.items.len);
    try testing.expectEqual(@as(usize, 0), session.children.items.len);
}

test "a worker with the same session runs every one of those four calls" {
    // The other side of the test above, so each of its lines is a fact about
    // the role and not about a loop that refuses these calls for everyone.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01WORKER");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "one",
            .name = "run_command",
            .arguments = "{\"argv\":[\"/bin/echo\",\"hi\"]}",
        } }} },
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "two",
            .name = spawn_tool_name,
            .arguments = "{\"agent_kind\":\"worker\",\"task\":\"do the act for me\"}",
        } }} },
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "three",
            .name = plan_tool_name,
            .arguments = "{\"steps\":[{\"id\":\"a\",\"subject\":\"weigh the case\",\"status\":\"pending\"}]}",
        } }} },
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "four",
            .name = restrict_tool_name,
            .arguments = "{\"action\":\"git.push\",\"ceiling\":\"deny\",\"reason\":\"this task reaches no other machine\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    var spawner = FakeSpawner{};

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.spawner = spawner.spawner();
    deps.subagents = .{ .max_depth = 6, .max_width = 6 };
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
    try testing.expectEqual(@as(usize, 1), spawner.ran);

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
    }
    try testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
    try testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);
    try testing.expectEqual(@as(usize, 1), session.children.items.len);
}

test "a session that never calls update_plan appends no plan.update at all" {
    // **Not mandatory, proven at the log.** A one step task with a task list
    // is noise, and this project has already learned that a notice which
    // always fires stops being read. Nothing in the loop writes one of these
    // on the agent's behalf, so a session that had no use for a list is a
    // session whose log holds none.
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NOPLAN");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "read_file",
            .arguments = "{\"path\":\"build.zig\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "all done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "the file" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        try testing.expect(parsed.value.event != .plan_update);
    }
    try testing.expect(session.plan.isEmpty());
}

test "the task list a session ends with is folded out of its own log, never held beside it" {
    // The list is written as events, so a fresh replay of the file rebuilds
    // exactly what the running session had. That is what makes it survive a
    // compaction, a handover to the daemon, and a phone attaching partway.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPlanSession(allocator, arena, io, &.{
        \\{"steps":[
        \\{"id":"s1","subject":"read the fold","status":"in_progress"},
        \\{"id":"s2","subject":"write the command","status":"pending"},
        \\{"id":"s3","subject":"measure it on Darwin","status":"pending","blocked_by":"s2"}]}
        ,
        \\{"steps":[{"id":"s1","subject":"read the fold","status":"done"},
        \\{"id":"s2","subject":"write the command","status":"in_progress"}]}
        ,
    }, &session);

    // A task list is never a sandboxed tool call: it is an event in a log the
    // loop holds the only lock on.
    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);
    try testing.expectEqual(@as(usize, 2), outcome.events);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(!outcome.refused[1]);

    // Three steps first, then only the two that moved: the second call
    // repeated s3 nowhere, and the event carries only what changed.
    try testing.expectEqual(@as(usize, 5), outcome.written_steps);

    try testing.expectEqual(@as(usize, 3), session.plan.steps.items.len);
    try testing.expectEqual(event.PlanStatus.done, std.meta.activeTag(session.plan.find("s1").?.status));
    try testing.expectEqual(event.PlanStatus.in_progress, std.meta.activeTag(session.plan.find("s2").?.status));
    try testing.expectEqual(event.PlanStatus.pending, std.meta.activeTag(session.plan.find("s3").?.status));
    try testing.expectEqualStrings("s2", session.plan.find("s3").?.blocked_by);

    // The model reads the whole list back, so it never has to hold the list
    // in its attention to know what is left.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "measure it on Darwin") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "2 of 3 left to do") != null);
}

test "a step the agent stops naming stays on the list, and only abandoned takes it off" {
    // **The fault the whole design exists to stop.** An agent that drops a
    // step leaves a list that reads as finished work, and the person reading
    // the night's work in the morning cannot tell. The fold keeps every
    // identifier, so the honest answer is the only one available.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPlanSession(allocator, arena, io, &.{
        \\{"steps":[{"id":"s1","subject":"port the driver","status":"pending"},
        \\{"id":"s2","subject":"write the escape test","status":"pending"},
        \\{"id":"s3","subject":"rewrite the build script","status":"pending"}]}
        ,
        // The agent finishes one, gives one up, and simply stops mentioning
        // the third.
        \\{"steps":[{"id":"s1","subject":"port the driver","status":"done"},
        \\{"id":"s3","subject":"rewrite the build script","status":"abandoned"}]}
        ,
    }, &session);
    try testing.expectEqual(@as(usize, 2), outcome.events);

    try testing.expectEqual(@as(usize, 3), session.plan.steps.items.len);
    // Given up, and visible as given up. Not gone, and not done.
    const dropped = session.plan.find("s3").?;
    try testing.expectEqual(event.PlanStatus.abandoned, std.meta.activeTag(dropped.status));
    try testing.expect(dropped.status != .done);
    // And the one nobody mentioned again is still waiting, which is the truth
    // about it.
    try testing.expectEqual(event.PlanStatus.pending, std.meta.activeTag(session.plan.find("s2").?.status));

    const counts = session.plan.counts();
    try testing.expectEqual(@as(usize, 1), counts.done);
    try testing.expectEqual(@as(usize, 1), counts.abandoned);
    try testing.expectEqual(@as(usize, 1), counts.left());
}

test "a call that repeats the list unchanged appends nothing, and is not an error" {
    // A model that resends its whole list every turn is doing the ordinary
    // thing. The log must not fill with copies of a list that did not move,
    // and the model must not read a refusal for a call that was correct.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    // Twice, and not three times: the third identical call in a row is what
    // `no_progress_repeats` stops a session at, whatever tool it names, and
    // this tool is not an exception to that.
    const same = "{\"steps\":[{\"id\":\"s1\",\"subject\":\"read the fold\",\"status\":\"pending\"}]}";
    const outcome = try runPlanSession(allocator, arena, io, &.{ same, same }, &session);

    try testing.expectEqual(@as(usize, 1), outcome.events);
    try testing.expectEqual(@as(usize, 1), outcome.written_steps);
    for (outcome.refused) |one| try testing.expect(!one);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "already this") != null);
    try testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
}

test "a call this loop cannot record changes nothing, and says so as an error" {
    // Four refusals, one test, because they share the one rule: a call that
    // was not written down must never read as one that was. A model told its
    // list was kept would believe the user could watch a list nobody has.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPlanSession(allocator, arena, io, &.{
        // A status nobody wrote. It must not reach the log as a fourth one:
        // `PlanStatus.unknown` is for a name a later Chock wrote, and a typo
        // taking that path would be relayed onward as real.
        "{\"steps\":[{\"id\":\"s1\",\"subject\":\"ship it\",\"status\":\"dnoe\"}]}",
        // A step nothing can ever name again, so nothing could ever cross it
        // off.
        "{\"steps\":[{\"id\":\"\",\"subject\":\"ship it\",\"status\":\"pending\"}]}",
        // An empty list says nothing at all.
        "{\"steps\":[]}",
        // Arguments that are not the shape the tool takes.
        "{\"steps\":\"read the fold\"}",
        // A step that would take two lines on the terminal, so the next line
        // would read as a step of its own.
        "{\"steps\":[{\"id\":\"s1\",\"subject\":\"read the fold\\nand the log\",\"status\":\"pending\"}]}",
    }, &session);

    for (outcome.refused) |one| try testing.expect(one);
    try testing.expectEqual(@as(usize, 0), outcome.events);
    try testing.expect(session.plan.isEmpty());
    // Refused or not, a task list never reaches a sandbox: it is an event in a
    // log the loop holds the only lock on.
    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);

    // Each refusal names what to do instead, rather than only saying no.
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "\"pending\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "dnoe") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"id\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[3], "\"steps\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[4], "one to a line") != null);
}

test "a plan longer than the bound is refused whole, and leaves the list it had" {
    // The bound exists because the list is read by a person, one step to a
    // line. A call that passed it used to have two honest answers: keep the
    // front of a list the agent did not write, or keep none of it. It keeps
    // none of it and says the number.
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var too_many: std.ArrayList(u8) = .empty;
    try too_many.appendSlice(arena, "{\"steps\":[");
    for (0..max_plan_steps + 1) |index| {
        if (index != 0) try too_many.append(arena, ',');
        try too_many.print(arena, "{{\"id\":\"s{d}\",\"subject\":\"a step\",\"status\":\"pending\"}}", .{index});
    }
    try too_many.appendSlice(arena, "]}");

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPlanSession(allocator, arena, io, &.{
        "{\"steps\":[{\"id\":\"s1\",\"subject\":\"the one real step\",\"status\":\"pending\"}]}",
        too_many.items,
    }, &session);

    try testing.expect(!outcome.refused[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expectEqual(@as(usize, 1), outcome.events);
    // The list the agent really wrote is untouched, not half replaced.
    try testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
    try testing.expectEqualStrings("the one real step", session.plan.steps.items[0].subject);
}
