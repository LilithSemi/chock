//! The agent loop: it joins a model client, a session log, and a tool runner
//! into a session that goes back and forth. The log is the truth, and the
//! context the model sees is a fold of it that each turn rebuilds.

const std = @import("std");
const chock_cost = @import("chock-cost");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");
const sandbox = @import("chock-sandbox");
const tools = @import("tools.zig");
const nix_action = @import("nix.zig");
const context = @import("context.zig");
const compaction = @import("compaction.zig");
const notices = @import("notices.zig");
const task_table = @import("tasks.zig");
const subagent = @import("subagent.zig");
const self_policy = @import("self_policy.zig");
const arbiter_mod = @import("arbiter.zig");
const fetch_mod = @import("fetch.zig");
const ask_mod = @import("ask.zig");
const handback_mod = @import("handback.zig");
const redact = @import("redact.zig");

const event = chock_proto.event;
const message = chock_provider.message;
const retry = chock_provider.retry;
const subagents = chock_policy.subagents;
const ratchet = chock_policy.ratchet;

/// What `ToolRunner.dispatch` can fail with. A command that exited 1, or a
/// tool name that does not exist, is an `is_error` `ToolResult` and not this.
pub const DispatchError = tools.Error;

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

pub const SandboxToolRunner = struct {
    env: *const std.process.Environ.Map,
    sandbox_config: sandbox.Config,
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

/// Hands over the session's own locked handle, once, right after `run` takes
/// it. The caller that stores the pointer must never call `unlock` on it.
pub const GiveLocked = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        give: *const fn (ptr: *anyopaque, locked: *arbiter_mod.Locked) void,
    };

    pub fn give(self: GiveLocked, locked: *arbiter_mod.Locked) void {
        self.vtable.give(self.ptr, locked);
    }
};

/// Told about each event as `Loop.run` appends it, and about each piece of a
/// reply as it arrives. An observer watches and never decides.
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

    pub fn onNotice(self: Observer, text: []const u8) void {
        self.vtable.onNotice(self.ptr, text);
    }

    /// What this shows is not yet in the log. A turn the provider cuts off part
    /// way is never appended, so a person can see words that no replay produces.
    pub fn onPiece(self: Observer, piece: Piece) void {
        self.vtable.onPiece(self.ptr, piece);
    }
};

pub const Piece = union(enum) {
    text: []const u8,
    reasoning: []const u8,
};

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
/// arguments, before the session ends with `no_progress`. Three, because a
/// tool call can fail for a reason that is gone a moment later.
pub const no_progress_repeats: usize = 3;

/// How many of the most recent tool calls `Progress` weighs. Five, the
/// smallest window an A B A B A cycle fits in.
pub const no_progress_window: usize = 5;

/// How many different calls the window may hold and still count as a loop.
/// Two, because build, edit, build, edit, build is three identical builds
/// inside five and is healthy work. A longer cycle still gets through.
pub const no_progress_distinct: usize = 2;

pub const InFlight = struct {
    tasks: usize = 0,
    children: usize = 0,
};

pub const Deps = struct {
    client: chock_provider.Client.Client,
    storage: chock_proto.storage.Storage,
    tool_runner: ToolRunner,
    give_locked: ?GiveLocked = null,
    tool_definitions: []const message.ToolDefinition,
    model: []const u8,
    model_alias: []const u8,
    /// The agent kind that selects the policy. This loop never evaluates the
    /// policy table, which stays the broker's job.
    agent_kind: []const u8,
    /// What kind of agent this is. The loop reads it because some tool calls never
    /// reach the tool runner, so a gate in `tools.Registry.dispatchWith` alone
    /// would leave an arbitrator able to start a subagent.
    role: tools.Role = .worker,
    /// Every parent between the root of the spawn tree and this agent. Every
    /// parent, and not the nearest one: one link would report depth 2 at every
    /// depth and `max_depth` would bound nothing.
    spawn_chain: []const event.SpawnLink = &.{},
    /// What a person put on the command line, and the hash of the file the
    /// policy came from. Written once, beside `session_start`, so a session
    /// that resumes does not write it twice. Null for a caller that records
    /// nothing, which is every test that does not ask about it.
    config: ?event.SessionConfig = null,
    parent_session: []const u8 = "",
    spawner: ?subagent.Spawner = null,
    /// The children this session started and did not wait for. Null is the wait
    /// shape, and a spawn that asks to carry on is then refused and says so.
    children: ?*subagent.Table = null,
    subagents: subagents.Limits = .{},
    system_prompt: []const u8,
    max_turns: ?usize = null,
    observer: ?Observer = null,
    /// Asked at every safe point whether this session should stop now. It must be
    /// safe to call from anywhere and must not fail: it is read while `run` holds
    /// the exclusive lock, so a call that takes a lock of its own can deadlock.
    canceled: ?*const fn () bool = null,
    /// Asked at every turn boundary, and nowhere else, whether another process
    /// should take this session. The turn boundary alone, because a session
    /// stopped between two tool calls leaves an assistant message whose `tool_use`
    /// parts have no result, which a provider refuses.
    handover: ?*const fn (io: std.Io, in_flight: InFlight) bool = null,
    tasks: ?*task_table.Table = null,
    /// What this session may spend, read from `chock.zon` by the caller. That
    /// file stays beyond the agent's reach, so the model cannot raise its own cap.
    budget: ?chock_cost.budget.Budget = null,
    billing: chock_cost.prices.Billing = .billed,
    compaction: compaction.Policy = .{},
    retry: retry.Policy = .{},
    /// What the harness tells the agent that the agent cannot work out for
    /// itself. This never touches `system_prompt`: a value that changes every
    /// turn, put at the front of a request, loses the provider's cache.
    notices: notices.Policy = .{},
    uncommitted_files: usize = 0,
    sleeper: ?retry.Sleeper = null,
    /// Who decides an act this loop may not decide for itself. Null answers
    /// `arbiter.not_asked`, so a session with no arbiter runs no sandboxed tool,
    /// and the model is told nobody could be asked.
    arbiter: ?arbiter_mod.Arbiter = null,
    /// The workspace's own absolute root, handed to `tools.Tool.actionInto`.
    /// Empty is safe: the path is then read as written, which still names a real
    /// if less specific action, and nothing falls back to `allow`.
    project_root: []const u8 = "",
    /// The store paths this session mounted when it started, and never the list as
    /// it stands now, so a program the session put in the store keeps asking.
    /// Empty is safe: every store path then names `exec.nix.store.*`, which is `ask`.
    store_closure: []const []const u8 = &.{},
    /// What reads a URL for the agent. Null refuses and says so, because a tool
    /// that answered with an empty page would have a model reason about it.
    fetcher: ?fetch_mod.Fetcher = null,
    /// What puts a question to the person. This is not the arbiter and must never
    /// become it: it asks for a fact and grants nothing, whatever the person types.
    asker: ?ask_mod.Asker = null,
    /// What carries the session's own work back into the user's repository. One
    /// act reaches it, `handback.apply_action`, and the tool refuses every other name.
    handback: ?handback_mod.Handback = null,
    /// What must not reach the provider. Read `lib/chock-core/redact.zig` first:
    /// it is protection against an accident and it is not a boundary. The default
    /// is inert, so a project that declared nothing sends the same bytes as before.
    redact: redact.Policy = .{},
};

pub const budget_detail_prefix = "the session budget was reached";

pub const budget_action = "budget.raise";

pub const Error =
    std.mem.Allocator.Error ||
    chock_provider.Client.SendError ||
    // ReplayError and not StorageError alone: `foldExisting` reads the log back
    // before the first append, where a line that does not parse is a real fault.
    chock_proto.storage.ReplayError;

/// Run a session to completion: repeat a turn until the model answers with no
/// tool call.
///
/// Appends `session.start` only when the fold found none, and `session.end`
/// before returning in every case. A signal runs no deferred append, which is
/// why `deps.canceled` is read at the top of each turn and between two tool
/// calls of one turn.
pub fn run(allocator: std.mem.Allocator, io: std.Io, deps: Deps) Error!void {
    var locked = try deps.storage.lock(io);
    defer locked.unlock(io) catch {};

    if (deps.give_locked) |give| give.give(&locked);

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    var telling = notices.State{};
    defer telling.deinit(allocator);

    try foldExisting(allocator, io, deps.storage, &session, &telling);
    if (telling.started_ms == null) telling.started_ms = nowMs(io, deps);

    // `session_start` is the only event that sets `agent_kind`, so an empty one
    // here means the fold found no start.
    if (session.agent_kind.len == 0) {
        _ = try appendAndApply(allocator, io, &locked, &session, deps, .{
            .session_start = .{
                .agent_kind = deps.agent_kind,
                .model_alias = deps.model_alias,
                .parent_session = deps.parent_session,
                .spawn_chain = deps.spawn_chain,
            },
        });
    }

    // On every run and not only the first, because a session that resumes can
    // be given different flags, and those decide what it may do for the rest
    // of it. The same reason `sandbox.open` is written every run.
    if (deps.config) |config| {
        _ = try appendAndApply(allocator, io, &locked, &session, deps, .{
            .session_config = config,
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
    try recordAtTheEnd(allocator, io, &locked, &session, deps);
}

/// The last thing a session writes, whichever way the session stopped. A child
/// is waited for and a background command is not: `subagent.Table.deinit` has
/// to wait in any case, because a child writes into a directory the caller is
/// about to remove.
fn recordAtTheEnd(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
) Error!void {
    try recordFinishedTasks(allocator, io, locked, session, deps, .record_only);
    if (deps.children) |table| table.waitAll();
    try recordFinishedChildren(allocator, io, locked, session, deps, .record_only);
}

const ContextWatch = struct {
    warned: bool = false,
};

const Observation = struct {
    seen: usize,
    repeats: usize,
    distinct: usize,

    fn isLoop(self: Observation) bool {
        return self.repeats >= no_progress_repeats and self.distinct <= no_progress_distinct;
    }
};

const Progress = struct {
    calls: [no_progress_window]?[]u8 = @splat(null),
    next: usize = 0,

    fn deinit(self: *Progress, allocator: std.mem.Allocator) void {
        for (self.calls) |entry| {
            if (entry) |owned| allocator.free(owned);
        }
        self.* = undefined;
    }

    fn observe(
        self: *Progress,
        allocator: std.mem.Allocator,
        tool: []const u8,
        arguments: []const u8,
    ) std.mem.Allocator.Error!Observation {
        // Joined with a byte no tool name holds, so "read" with arguments "x" and
        // "read x" with no arguments cannot be mistaken for each other.
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

    if (try endIfCanceled(allocator, io, locked, session, deps)) return true;

    // At the top of a turn, and never between two tool calls of one: a provider
    // requires an exact shape between an assistant turn and its own tool results.
    try recordFinishedTasks(allocator, io, locked, session, deps, .tell_the_agent);

    try recordFinishedChildren(allocator, io, locked, session, deps, .tell_the_agent);

    // After both drains, so work that already finished refuses no handover, and
    // before the request, so a session about to change hands pays for no turn.
    if (try endIfHandedOver(allocator, io, locked, session, deps)) return true;

    // Before the request, because money cannot be un-spent.
    if (try refuseForBudget(allocator, io, locked, session, deps)) return true;

    try watchContext(allocator, io, locked, session, deps, watch, telling);

    const messages = try context.build(arena, session);
    const request = message.Request{
        .model = deps.model,
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

            if (class == .context_overflow) {
                if (try compactNow(allocator, io, locked, session, deps, telling)) {
                    watch.warned = false;
                    return false;
                }
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

            _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
                .role = .assistant,
                .content = reply_message.content,
                .model_alias = deps.model_alias,
            } });
            telling.observeEvent(nowMs(io, deps), true);

            // Before the empty check: a refusal and an absence arrive looking alike, and
            // the advice is opposite. Nothing retries, switches model, or rewords this.
            if (reply.stop().isRefusal()) {
                const detail = try refusalDetail(allocator, reply.stop(), whichTurn(turn_index));
                defer allocator.free(detail);
                _ = try appendAndApply(allocator, io, locked, session, deps, .{
                    .session_end = .{ .reason = .refused_by_model, .detail = detail },
                });
                return true;
            }

            if (!saidSomething(reply_message)) {
                const detail = try emptyReplyDetail(allocator, reply.stop(), turn_index);
                defer allocator.free(detail);
                _ = try appendAndApply(allocator, io, locked, session, deps, .{
                    .session_end = .{ .reason = .empty_response, .detail = detail },
                });
                return true;
            }

            var ran_a_tool = false;
            for (reply_message.content) |part| {
                if (part != .tool_use) continue;
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
                try telling.observeCall(
                    allocator,
                    part.tool_use.tool,
                    part.tool_use.arguments,
                    observed.repeats,
                );
                ran_a_tool = true;
                try runTool(allocator, io, locked, session, deps, telling, part.tool_use);
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

/// Whether one model turn carried anything the session can use. A reply of
/// reasoning alone, or of whitespace alone, carries nothing.
fn saidSomething(reply: chock_provider.message.Message) bool {
    for (reply.content) |part| switch (part) {
        .tool_use => return true,
        .text => |text| if (std.mem.trim(u8, text, &std.ascii.whitespace).len != 0) return true,
        else => {},
    };
    return false;
}

fn whichTurn(turn_index: usize) []const u8 {
    return if (turn_index == 0) "the first turn of the session" else "a turn of the session";
}

fn stopWords(
    allocator: std.mem.Allocator,
    stop: chock_provider.Client.Stop,
) std.mem.Allocator.Error![]u8 {
    if (stop.category.len != 0 and stop.explanation.len != 0) {
        return std.fmt.allocPrint(
            allocator,
            ", in the category {s}: {s}",
            .{ stop.category, stop.explanation },
        );
    }
    if (stop.category.len != 0) {
        return std.fmt.allocPrint(allocator, ", in the category {s}", .{stop.category});
    }
    if (stop.explanation.len != 0) {
        return std.fmt.allocPrint(allocator, ": {s}", .{stop.explanation});
    }
    return allocator.dupe(u8, "");
}

/// What the log says about something the provider refused. Caller owns the
/// result. Nothing here or anywhere else works around the refusal.
fn refusalDetail(
    allocator: std.mem.Allocator,
    stop: chock_provider.Client.Stop,
    what: []const u8,
) std.mem.Allocator.Error![]u8 {
    const words = try stopWords(allocator, stop);
    defer allocator.free(words);
    if (words.len == 0) {
        return std.fmt.allocPrint(
            allocator,
            "the model backend refused {s}, and gave no reason for the refusal",
            .{what},
        );
    }
    return std.fmt.allocPrint(allocator, "the model backend refused {s}{s}", .{ what, words });
}

fn emptyReplyDetail(
    allocator: std.mem.Allocator,
    stop: chock_provider.Client.Stop,
    turn_index: usize,
) std.mem.Allocator.Error![]u8 {
    const which = whichTurn(turn_index);
    const opening = "the model backend answered {s} with no text and no tool call";
    if (stop.reason.len == 0) {
        return std.fmt.allocPrint(allocator, opening ++ ", and gave no stop reason", .{which});
    }
    const words = try stopWords(allocator, stop);
    defer allocator.free(words);
    return std.fmt.allocPrint(
        allocator,
        opening ++ ", and said it stopped because of {s}{s}",
        .{ which, stop.reason, words },
    );
}

/// Hand one request to the provider, once. The only place in `chock-core` that
/// calls a `chock_provider.Client`, which makes it the only place redaction
/// has to be: a second call to `Client.sendAndAssemble` in this library would
/// be a way past `deps.redact`.
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
        // This iteration owns `answer` until it hands it back or frees it. The flag
        // keeps a fault in between from leaking a refusal body of several kilobytes.
        var held = true;
        errdefer if (held) freeReply(allocator, answer);

        try appendUsage(allocator, io, locked, session, deps, answer.usage);

        const refusal = switch (answer.outcome) {
            .status_error => |status_error| status_error,
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
                .not_retryable => return answer,
                .attempts_spent, .wait_too_long => {
                    const detail = try givingUpDetail(allocator, why, attempts, refusal);
                    defer allocator.free(detail);
                    held = false;
                    freeReply(allocator, answer);
                    _ = try appendAndApply(allocator, io, locked, session, deps, .{
                        .session_end = .{ .reason = endReasonFor(class), .detail = detail },
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
                held = false;
                freeReply(allocator, answer);

                sleeper.sleep(io, wait_ms);

                if (try endIfCanceled(allocator, io, locked, session, deps)) return null;
            },
        }
    }
}

fn freeReply(allocator: std.mem.Allocator, reply: chock_provider.Client.AssembledReply) void {
    chock_provider.Client.freeUsage(allocator, reply.usage);
    switch (reply.outcome) {
        .status_error => |status_error| allocator.free(status_error.body),
        .message => |said| chock_provider.Client.freeAssembledMessage(allocator, said),
        .failed => |failed| chock_provider.Client.freeAssembledMessage(allocator, failed.partial),
    }
}

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
        // The caller answers this class itself, so `decide` never reaches here with
        // a wait or a give up of its own.
        .not_retryable => unreachable,
    };
}

fn endReasonFor(class: chock_provider.failure.Class) chock_proto.event.SessionEndReason {
    return switch (class) {
        .rate_limited => .rate_limited,
        .transient, .permanent, .context_overflow => .errored,
    };
}

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

/// Give this session to another process. The reason on the event is what makes
/// this a handover and not a stop: `canceled_by_user` would tell the next
/// reader that a person said no.
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

const TaskDelivery = enum {
    tell_the_agent,
    record_only,
};

/// Record every background task that finished since the last turn. Two events,
/// because only a `message` re-enters the model's context. Neither carries the
/// output, because a build writes megabytes.
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
/// about it. The parent appends both events, because the child cannot write
/// the parent's log.
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

/// Append the `usage` event for one turn. A provider that reported nothing at
/// all still gets one, with every count zero, which is the log saying the
/// session cannot be priced rather than saying it was free.
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
    // Stamped only on a number this table produced. A cost the provider reported
    // is the provider's.
    if (cost == .known and reported.cost == .unknown) {
        usage.price_table_version = chock_cost.prices.version;
    }
    usage.cost = cost;

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .usage = usage });
}

/// Check the cap before a request goes out, and stop the session when this turn
/// would pass it. Nothing answers the `approval.request` this writes, and an
/// unanswered request is a refusal, which is the safe direction for a budget.
fn refuseForBudget(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
) Error!bool {
    const cap = deps.budget orelse return false;
    const spend = session.spend;
    if (!spend.enforceable()) return false;
    if (spend.turns == 0) return false;
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, cap.currency)) return false;

    // The mean of the turns so far. A turn's cost grows with the context it
    // carries, so the mean under estimates the next turn and the cap can be passed
    // by that much.
    const projected = spend.amount / @as(f64, @floatFromInt(spend.turns));
    if (spend.amount + projected <= cap.max_cost) return false;

    const summary = try std.fmt.allocPrint(
        allocator,
        "the session has spent {d:.4} {s} of a {d:.4} {s} budget, and the next turn is " ++
            "projected to cost about {d:.4} {s}",
        .{ spend.amount, spend.currency, cap.max_cost, cap.currency, projected, spend.currency },
    );
    defer allocator.free(summary);

    const request_id = try appendAndApply(allocator, io, locked, session, deps, .{
        .approval_request = .{
            .action = budget_action,
            .summary = summary,
            .detail = summary,
            .reason = "the next turn would take the session past the budget in chock.zon",
            .agent_kind = deps.agent_kind,
            .spawn_chain = deps.spawn_chain,
            .timeout_at_ms = std.Io.Timestamp.now(io, .real).toMilliseconds(),
            .tool_call_id = "",
        },
    });
    // An `Envelope.id` of zero means an event not yet written, so a zero here
    // would leave the answer naming no question.
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .approval_response = .{
        .request_id = request_id,
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
/// coming or do one. Does nothing when the context limit is unknown, because a
/// guessed limit would compact a session that had room.
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
    // Zero is "nobody has counted this yet", never "the context is empty".
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

    const parts = [_]event.ContentPart{.{ .text = text }};
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
        .role = .system,
        .content = &parts,
    } });
    watch.warned = true;
}

/// Whether this session offers the tool that writes a note. A tool that is not
/// offered is never named: naming one costs the agent a turn to find out.
fn offersMemory(deps: Deps) bool {
    for (deps.tool_definitions) |definition| {
        if (std.mem.eql(u8, definition.name, @tagName(tools.Tool.write_memory))) return true;
    }
    return false;
}

/// Fold the middle of the context into one summary and append the `compaction`
/// event. The log loses nothing, and `model_alias` is empty when the harness
/// wrote the summary instead of the model.
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

    // `folding.folded` borrows `session.context`, so both texts are built from it
    // before anything appends an event that would fold the context again.
    const folding = try compaction.plan(arena, session, deps.compaction) orelse return false;
    const rendered = try compaction.transcript(arena, folding.folded, deps.compaction);

    const asked = try askForSummary(allocator, arena, io, locked, session, deps, rendered);
    var summary: []const u8 = undefined;
    var wrote_it: []const u8 = "";
    if (asked.text.len != 0) {
        summary = asked.text;
        wrote_it = deps.model_alias;
    } else {
        summary = try compaction.harnessSummary(arena, folding.folded, deps.compaction);
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{
        .compaction = .{
            .summary = summary,
            .from_id = folding.from_id,
            .through_id = folding.through_id,
            .kept_ranges = folding.kept_ranges,
            .model_alias = wrote_it,
            .stand_in_reason = asked.stand_in_reason,
        },
    });

    telling.observeCompaction();
    return true;
}

/// What one compaction call came back with. Exactly one of the two is ever set.
const CompactionAnswer = struct {
    text: []const u8 = "",
    stand_in_reason: []const u8 = "",
};

/// Ask the model for the summary. The request carries one user message and no
/// tools: the folded span cannot be replayed as real messages, because a `tool`
/// role message needs the `tool_use` part it answers beside it and a span cut
/// anywhere breaks that pairing.
fn askForSummary(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    rendered: []const u8,
) Error!CompactionAnswer {
    const asked = try compaction.summaryPrompt(arena, rendered);
    const parts = [_]message.ContentPart{.{ .text = asked }};
    const messages = [_]message.Message{.{ .role = .user, .content = &parts }};
    const request = message.Request{
        .model = deps.model,
        .system = compaction.summary_system,
        .messages = &messages,
    };

    // Through `sendOnce`, and never through `Client.sendAndAssemble`: a compaction
    // sends the context itself, so a second road out would be past the redactor.
    const reply = sendOnce(allocator, arena, deps, request, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .stand_in_reason = try std.fmt.allocPrint(
            arena,
            "the compaction call did not reach the model backend: {s}",
            .{@errorName(err)},
        ) },
    };
    defer chock_provider.Client.freeUsage(allocator, reply.usage);
    try appendUsage(allocator, io, locked, session, deps, reply.usage);

    switch (reply.outcome) {
        .status_error => |status_error| {
            defer allocator.free(status_error.body);
            return .{ .stand_in_reason = try std.fmt.allocPrint(
                arena,
                "the model backend answered the compaction call with status {d}: {s}",
                .{ @intFromEnum(status_error.status), status_error.body },
            ) };
        },
        .failed => |failed| {
            chock_provider.Client.freeAssembledMessage(allocator, failed.partial);
            return .{ .stand_in_reason = try std.fmt.allocPrint(
                arena,
                "the reply to the compaction call did not complete: {s}",
                .{@errorName(failed.err)},
            ) };
        },
        .message => |reply_message| {
            defer chock_provider.Client.freeAssembledMessage(allocator, reply_message);
            // Before the text is read: a classifier fires part way through, so a refused
            // call can carry half a summary.
            if (reply.stop().isRefusal()) {
                const said = try refusalDetail(arena, reply.stop(), "the compaction call");
                return .{ .stand_in_reason = said };
            }
            var out: std.ArrayList(u8) = .empty;
            for (reply_message.content) |part| {
                if (part == .text) try out.appendSlice(arena, part.text);
            }
            const joined = try out.toOwnedSlice(arena);
            if (std.mem.trim(u8, joined, " \t\r\n").len == 0) {
                return .{ .stand_in_reason = try arena.dupe(
                    u8,
                    "the model backend answered the compaction call with no summary text",
                ) };
            }
            return .{ .text = joined };
        },
    }
}

/// The policy gate a call bound for `deps.tool_runner` passes through. Null
/// means the call may run. A session with no arbiter can run none of these,
/// because null answers `arbiter_mod.not_asked`. A name this enum cannot spell
/// is gated at its own door instead, in `chock_core.mcp.Session.dispatch`.
fn gateToolCall(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    deps: Deps,
    call: event.ToolCall,
) Error!?event.ToolResult {
    const tool = std.meta.stringToEnum(tools.Tool, call.tool) orelse return null;

    // The seven names `runTool` answers itself already carry their own gate,
    // scoped to the privileged act. Gating the coarse name here as well would ask
    // twice, and for `restrict_self` a null arbiter must refuse only a widening.
    switch (tool) {
        .spawn_agent,
        .update_plan,
        .restrict_self,
        .fetch_url,
        .ask_user,
        .set_title,
        .request_action,
        => return null,
        else => {},
    }

    var argv0_owned: ?[]u8 = null;
    defer if (argv0_owned) |owned| allocator.free(owned);
    if (tool == .run_command) argv0_owned = try tools.firstArgvIn(allocator, call.arguments);

    var action_buffer: [gate_action_bytes]u8 = undefined;

    // The one call named after what it asks for, and the one that can ask twice.
    // Both questions must pass, so a rule a project wrote for its own attribute
    // does not authorise the same attribute of anybody else's flake.
    if (tool == .nix_build) {
        var flake_buffer: [gate_action_bytes]u8 = undefined;
        const actions = try nix_action.buildActionsFor(
            allocator,
            &action_buffer,
            &flake_buffer,
            call.arguments,
        ) orelse
            return try gateRefusal(allocator, call, try allocator.dupe(u8, nix_action.unnamed_detail));

        const on_attribute = try decideAction(allocator, io, locked, deps, call, actions.attribute);
        if (!on_attribute.permitted) return try gateRefusal(
            allocator,
            call,
            try arbiter_mod.refusalText(allocator, call.tool, on_attribute),
        );

        const flake_action = actions.flake orelse return null;
        const on_flake = try decideAction(allocator, io, locked, deps, call, flake_action);
        if (on_flake.permitted) return null;
        return try gateRefusal(
            allocator,
            call,
            try arbiter_mod.refusalText(allocator, call.tool, on_flake),
        );
    }

    const action = tool.actionInto(
        &action_buffer,
        argv0_owned,
        deps.project_root,
        deps.store_closure,
    ) orelse
        return try gateRefusal(allocator, call, try allocator.dupe(u8, gate_unnamed_detail));

    const answer = try decideAction(allocator, io, locked, deps, call, action);
    if (answer.permitted) return null;

    // The refusal carries the rule and the alternative and never the reason: a
    // model told why a wall exists is a model handed a map.
    return try gateRefusal(allocator, call, try arbiter_mod.refusalText(allocator, call.tool, answer));
}

fn decideAction(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    deps: Deps,
    call: event.ToolCall,
    action: []const u8,
) std.mem.Allocator.Error!arbiter_mod.Answer {
    const arbiter = deps.arbiter orelse return arbiter_mod.not_asked;
    const summary = try std.fmt.allocPrint(allocator, "run the tool \"{s}\"", .{call.tool});
    defer allocator.free(summary);
    return arbiter.decide(allocator, io, locked, .{
        .action = action,
        .summary = summary,
        .detail = action,
        .reason = "",
        .tool = call.tool,
        .tool_call_id = call.call_id,
    });
}

const gate_action_bytes = @max(tools.Tool.max_action_bytes, nix_action.max_action_bytes);

/// What `gateToolCall` answers when `Tool.actionInto` could not name the call.
/// The sized buffers make this unreachable, so a caller that shrinks one fails
/// safely.
const gate_unnamed_detail = "nothing ran: this call could not be named for a policy check, " ++
    "so it was not run. Try something else.";

fn gateRefusal(
    allocator: std.mem.Allocator,
    call: event.ToolCall,
    detail: []u8,
) std.mem.Allocator.Error!event.ToolResult {
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = detail,
        .is_error = true,
        .truncated = false,
    };
}

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
    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .tool_call = call });

    // An arbitrator holds no tools, enforced here for the calls the tool runner
    // never sees. The policy gate comes second, once an arbitrator is ruled out,
    // so no `approval.response` is spent on a call that cannot run either way.
    const dispatched = if (!deps.role.holdsTools())
        event.ToolResult{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try allocator.dupe(u8, tools.arbitrator_holds_no_tool),
            .is_error = true,
            .truncated = false,
        }
    else if (try gateToolCall(allocator, io, locked, deps, call)) |refusal|
        refusal
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
    else if (std.mem.eql(u8, call.tool, request_tool_name))
        try runRequestAction(allocator, io, locked, deps, call)
    else
        deps.tool_runner.dispatch(allocator, io, call) catch |err| event.ToolResult{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try std.fmt.allocPrint(allocator, "tool dispatch failed: {s}", .{@errorName(err)}),
            .is_error = true,
            .truncated = false,
        };
    defer allocator.free(dispatched.call_id);
    defer allocator.free(dispatched.output);
    defer if (dispatched.note.len != 0) allocator.free(dispatched.note);
    defer if (dispatched.image) |image| {
        allocator.free(image.media_type);
        allocator.free(image.content_hash);
        allocator.free(image.data);
    };

    // Bytes that are not valid UTF-8 serialize as a JSON array and not a JSON
    // string, which ends the session with a provider 400 and cannot be parsed back
    // by a replay. After the runner, because `ToolRunner` is an interface.
    const note = try tools.outputForModel(allocator, dispatched.output);
    defer if (note) |owned| allocator.free(owned);
    var result = dispatched;
    if (note) |owned| result.output = owned;

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .tool_result = result });

    try noteRead(allocator, telling, result, call);

    // Only these three fields become a content part, so `result.note`, which is
    // written for the person, never reaches the model.
    var feedback: [2]event.ContentPart = undefined;
    var parts: usize = 1;
    feedback[0] = .{ .tool_result = .{
        .call_id = result.call_id,
        .output = result.output,
        .is_error = result.is_error,
    } };

    // The one copy of the picture the log keeps: the fold reads `message` events
    // alone. After the tool result and never before it, because the Anthropic wire
    // refuses a `tool_result` block that follows anything else in the same turn.
    if (result.image) |image| {
        feedback[parts] = .{ .image = .{
            .call_id = result.call_id,
            .media_type = image.media_type,
            .data = image.data,
        } };
        parts += 1;
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{ .message = .{
        .role = .tool,
        .content = feedback[0..parts],
    } });
}

pub const spawn_tool_name = @tagName(tools.Tool.spawn_agent);

pub const spawn_has_no_spawner_detail = "no subagent was started: the limits in chock.zon allow " ++
    "one, and this session was started with no way to run a child process. Do the work yourself.";

pub const spawn_cannot_carry_on_detail = "no subagent was started: this session cannot run a " ++
    "subagent while it works. Ask again without \"background\", and the subagent's answer comes " ++
    "back in that call.";

pub const spawn_no_budget_detail = "no subagent was started: this session has spent or promised " ++
    "the whole budget in chock.zon, so there is nothing left to give a subagent. Do the work " ++
    "yourself, or stop and say what is left.";

/// Answer a `spawn_agent` call, in place of the tool runner. The width comes
/// from the folded log and never from a counter of this call's own, so a
/// resumed session counts the children it really has.
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

    // A caller with no table cannot run a child beside the parent's own work, and
    // a spawn that asked to carry on is told so rather than quietly waiting.
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

    // No `agent.complete` now: the child has not finished, and the log never
    // writes an event for an act that has not happened.
    if (mode == .carry_on) {
        try deps.children.?.start(io, request, prepared);
        return .{
            .call_id = try allocator.dupe(u8, call.call_id),
            .output = try spawnStartedText(allocator, prepared, request),
            .is_error = false,
            .truncated = false,
        };
    }

    const report = spawner.run(allocator, io, request, prepared) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
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
        .is_error = report.outcome != .finished,
        .truncated = false,
    };
}

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

pub const plan_tool_name = @tagName(tools.Tool.update_plan);

pub const max_plan_steps: usize = 64;

pub const max_plan_id_bytes: usize = 32;
pub const max_plan_subject_bytes: usize = 200;
pub const max_plan_blocked_by_bytes: usize = 200;

/// Answer an `update_plan` call, in place of the tool runner. Nothing here is
/// enforced against the agent: the list is its own statement of intent, so this
/// refuses a call it cannot record and never a plan it disagrees with.
fn runPlanUpdate(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
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

    // Every step is checked before any is written: a call half applied would
    // leave a list the agent did not ask for.
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
        .output = try planText(allocator, session.plan, "The task list is now:"),
        .is_error = false,
        .truncated = false,
    };
}

/// Why this step cannot be recorded, or null when it can. The bounds are here
/// and not in the fold, because the fold reads logs that are already written.
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
    // A step is read one to a line, so a line break in one would make the next
    // reader take the second half for a step of its own.
    if (hasALineBreak(step.id) or hasALineBreak(step.subject) or hasALineBreak(blocked_by)) {
        return "the task list was not changed: a step is read one to a line, so no part of one " ++
            "may hold a line break. Say the detail in your answer instead.";
    }
    return null;
}

fn hasALineBreak(text: []const u8) bool {
    return std.mem.indexOfAny(u8, text, "\n\r") != null;
}

/// Whether this step says anything the folded plan does not hold. An empty
/// subject is not a change: `Plan.apply` reads it as "keep the words you have".
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

pub const restrict_tool_name = @tagName(tools.Tool.restrict_self);

/// Answer a `restrict_self` call, in place of the tool runner. Narrowing is
/// free and widening needs authorisation. This never reads the policy table and
/// enforces no promise: the record binds and the broker reads it. A widening
/// nobody permits writes no `policy.self` event at all.
fn runRestrictSelf(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
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
        // A ceiling of `allow` promises nothing, so a call that reaches here with one
        // was asking to be let out rather than to give something up.
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

/// A `restrict_self` call that asks to be let out of a promise it made. The
/// proposal has to name exactly a promise this session holds, or
/// `ratchet.ceilingFor` would hold a wider one against it afterwards and an
/// authorised yes would change nothing. An authorised widening writes the one
/// `policy.self` event with `authorised` set, which alone can lift a promise.
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
            // The one place this flag is ever set.
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

/// Whether this session holds a promise written under exactly this name. Exact
/// and never a pattern, the rule `ratchet.ceilingFor` and `SelfPolicy.apply`
/// also keep. The three have to agree, or a lift is recorded and changes nothing.
fn promisedExactly(session: *const chock_proto.state.Session, action: []const u8) bool {
    for (session.self_policy.restrictions.items) |one| {
        if (std.mem.eql(u8, one.action, action)) return true;
    }
    return false;
}

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

pub const fetch_tool_name = @tagName(tools.Tool.fetch_url);

/// Answer a `fetch_url` call, in place of the tool runner. Answered here
/// because a promise binds it, and the promises of a session live in the fold
/// of its log. This loop still decides nothing: `deps.fetcher` does.
fn runFetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
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
        .note = answer.note,
    };
}

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

pub const ask_tool_name = @tagName(tools.Tool.ask_user);

/// Answer an `ask_user` call, in place of the tool runner. This is not an
/// approval and writes no `approval.request`: it grants nothing, whatever the
/// person types.
fn runAskUser(
    allocator: std.mem.Allocator,
    io: std.Io,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
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

pub const title_tool_name = @tagName(tools.Tool.set_title);

pub const max_title_bytes: usize = 120;

/// Answer a `set_title` call, in place of the tool runner. The log is append
/// only, so a second call appends a second event and the fold takes the last.
/// A reader must not rely on what this refuses: a log is a file a person with
/// an editor can write, so `src/sessions.zig` filters what it prints as well.
fn runSetTitle(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    session: *chock_proto.state.Session,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
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

    const title = std.mem.trim(u8, parsed.value.title, " \t");
    if (titleRefusalText(title)) |why| {
        return titleRefusal(allocator, call, try allocator.dupe(u8, why));
    }

    _ = try appendAndApply(allocator, io, locked, session, deps, .{
        .session_title = .{ .title = title },
    });

    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
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

pub fn titleRefusalText(title: []const u8) ?[]const u8 {
    if (title.len == 0) return "this session was not named: \"title\" was empty. Write what the " ++
        "session is about, in a few words.";
    if (title.len > max_title_bytes) return "this session was not named: a title is longer than " ++
        max_title_text ++ " bytes. It is read at the end of a row beside the session's " ++
        "identifier and its time, so name the work in a few words and say the detail in your " ++
        "answer.";
    // A title is shown on a terminal, so an escape sequence in one would drive
    // the terminal of whoever ran `chock sessions`.
    for (title) |byte| {
        // Checking ASCII control characters byte by byte is safe over UTF-8: every
        // byte of a multi byte character is 0x80 or above.
        if (byte == '\n' or byte == '\r') return "this session was not named: a title is one " ++
            "line, and this one has a line break in it. Put the whole name on one line.";
        if (byte < 0x20 or byte == 0x7F) return "this session was not named: a title is plain " ++
            "text, and this one has a control character in it. Send the words alone.";
    }
    // Bytes that are not valid UTF-8 serialize as an array of integers and not a
    // string, which is a log line no replay of this build can read back.
    if (!std.unicode.utf8ValidateSlice(title)) return "this session was not named: a title has " ++
        "to be text, and these bytes are not valid UTF-8. Send the words alone.";
    return null;
}

const max_title_text = std.fmt.comptimePrint("{d}", .{max_title_bytes});

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

pub const request_tool_name = @tagName(tools.Tool.request_action);

/// Answer a `request_action` call, in place of the tool runner. One action name
/// is offered and every other is refused before anybody is asked. Nothing here
/// decides: a reason is an argument rather than an answer.
fn runRequestAction(
    allocator: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    deps: Deps,
    call: event.ToolCall,
) Error!event.ToolResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const parsed = std.json.parseFromSlice(
        tools.RequestActionArgs,
        arena_state.allocator(),
        call.arguments,
        .{ .ignore_unknown_fields = true },
    ) catch return requestRefusal(allocator, call, try allocator.dupe(
        u8,
        "nothing was asked for: " ++ request_tool_name ++ " needs a JSON object with two " ++
            "fields, \"action\" and \"reason\".",
    ));

    if (!std.mem.eql(u8, parsed.value.action, handback_mod.apply_action)) {
        return requestRefusal(allocator, call, try std.fmt.allocPrint(
            allocator,
            "nothing was asked for: \"{s}\" is not an act you can request. The only one is " ++
                "\"{s}\", which carries your commit back into the user's repository. Nothing " ++
                "else was put to anybody.",
            .{ parsed.value.action, handback_mod.apply_action },
        ));
    }

    if (std.mem.trim(u8, parsed.value.reason, " \t\r\n").len == 0) {
        return requestRefusal(allocator, call, try allocator.dupe(
            u8,
            "nothing was asked for: say why the work is ready. A person reads your reason " ++
                "beside the diff, and a request with none is one they cannot weigh.",
        ));
    }

    const handback = deps.handback orelse return requestRefusal(
        allocator,
        call,
        try allocator.dupe(u8, handback_mod.not_offered),
    );

    const result = try handback.apply(allocator, io, locked, .{
        .reason = parsed.value.reason,
        .tool_call_id = call.call_id,
    });
    return .{
        .call_id = try allocator.dupe(u8, call.call_id),
        .output = result.output,
        .is_error = !result.carried,
        .truncated = false,
    };
}

fn requestRefusal(
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

fn nowMs(io: std.Io, deps: Deps) i64 {
    const clock = deps.notices.clock orelse
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    return clock.now();
}

/// The messages this turn sends, with this turn's notice on the end so the
/// provider's cache keeps the prefix it had. The role is `user` and not
/// `system` because `chock_provider.anthropic.buildRequest` folds a `system`
/// role message into the top level `system` field.
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

/// The steps of the agent's own task list that are neither done nor abandoned.
/// An unrecognized status counts as unfinished, so a step a newer writer named
/// something else does not vanish in silence.
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

/// How much of the budget is spent, in whole percent, or null wherever
/// `refuseForBudget` also refuses to enforce: a percentage of a number Chock
/// cannot price is a made up number.
fn spentPercent(session: *const chock_proto.state.Session, deps: Deps) ?u8 {
    const cap = deps.budget orelse return null;
    if (cap.max_cost <= 0) return null;
    const spend = session.spend;
    if (!spend.enforceable()) return null;
    if (spend.turns == 0) return null;
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, cap.currency)) return null;

    const fraction = spend.amount / cap.max_cost * 100;
    // A total that is not a number is one Chock cannot price, and it is the value
    // `@intFromFloat` below has no defined answer for.
    if (std.math.isNan(fraction)) return null;
    if (fraction <= 0) return 0;
    if (fraction >= 100) return 100;
    return @intFromFloat(fraction);
}

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

/// Append `ev` to the log through `locked`, then fold it into `session`.
/// `locked` is `anytype` because `chock_proto.storage.Locked` is not `pub`, and
/// a runtime generation check is what proves a caller holds a real lock. The
/// redaction happens before `Locked.append`, so the chain runs over the bytes
/// the file holds and a credential cannot be taken out later.
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
    const clean = try redact.event(scratch.allocator(), deps.redact, ev);

    const time_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();
    const offset = try locked.append(allocator, io, clean, time_ms);
    try session.apply(.{ .id = offset, .session = "", .time_ms = time_ms, .event = clean });
    if (deps.observer) |watching| watching.onEvent(offset, clean);
    return offset;
}

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
        const spoke = parsed.value.event == .message and
            std.meta.activeTag(parsed.value.event.message.role) == .assistant;
        telling.observeEvent(parsed.value.time_ms, spoke);
    }
}

// Zig 0.16 refuses a relative `@import` outside a module's own root, so the one
// test that needs `test/core/fake_provider.zig` lives in `test/core/loop.zig`.

const testing = std.testing;

const FakeTurn = struct {
    deltas: []const chock_provider.Client.Delta = &.{},
    refusal: ?Refusal = null,
    before: ?*const fn () void = null,

    const Refusal = struct {
        status: std.http.Status = .bad_request,
        body: []const u8,
        retry_after_s: ?u64 = null,
    };
};

/// The refusal a llama.cpp server really sent, word for word.
const measured_overflow_body =
    \\{"error":{"code":400,"message":"request (77857 tokens) exceeds the available context size (65536 tokens)","type":"exceed_context_size_error"}}
;

const FakeClient = struct {
    turns: []const FakeTurn,
    calls: usize = 0,
    /// When true, `send` keeps the serialized bytes of the last request. The
    /// bytes, and not the `message.Request` value: a `[]const u8` that is valid
    /// UTF-8 and one that is not are the same Zig type.
    record_requests: bool = false,
    last_request_json: ?[]u8 = null,
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

const RecordingSleeper = struct {
    allocator: std.mem.Allocator,
    waits: std.ArrayList(u64) = .empty,
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

const FakeToolRunner = struct {
    output: []const u8,
    is_error: bool = false,
    note: []const u8 = "",
    storage_to_check: ?chock_proto.storage.Storage = null,
    saw_call_in_log: bool = false,
    calls: usize = 0,
    image: ?event.ImageRef = null,

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
            .note = if (self.note.len == 0) "" else try allocator.dupe(u8, self.note),
            .image = if (self.image) |image| .{
                .media_type = try allocator.dupe(u8, image.media_type),
                .byte_count = image.byte_count,
                .content_hash = try allocator.dupe(u8, image.content_hash),
                .data = try allocator.dupe(u8, image.data),
            } else null,
        };
    }

    fn runner(self: *FakeToolRunner) ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ToolRunner.VTable{ .dispatch = dispatch };
};

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

const AlwaysPermitArbiter = struct {
    var anchor: u8 = 0;

    fn arbiter() arbiter_mod.Arbiter {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = arbiter_mod.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *arbiter_mod.Locked,
        ask: arbiter_mod.Ask,
    ) arbiter_mod.Answer {
        _ = ptr;
        _ = gpa;
        _ = io;
        _ = locked;
        _ = ask;
        return .{ .permitted = true, .outcome = "allowed_by_policy" };
    }
};

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
        .arbiter = AlwaysPermitArbiter.arbiter(),
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

    try testing.expect(call_id != null);
    try testing.expect(result_id != null);
    try testing.expect(call_id.? < result_id.?);
}

test "a tool call whose row the policy allows runs, with no reviewer weighed in" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01GATEALLOW");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = TestArbiter{ .answer = .{ .permitted = true, .outcome = "allowed_by_policy" } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .tool_result) {
            try testing.expect(!parsed.value.event.tool_result.is_error);
            try testing.expectEqualStrings("ok", parsed.value.event.tool_result.output);
            saw_result = true;
        }
    }
    try testing.expect(saw_result);
}

test "a tool call whose row asks, with an arbiter that permits, runs" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01GATEASKYES");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "done" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = TestArbiter{ .answer = .{ .permitted = true, .outcome = "approved_by_user" } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
}

test "a tool call whose row asks, with an arbiter that refuses, does not run, and the model is told" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01GATEASKNO");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "that is what I will not do" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = TestArbiter{ .answer = .{
        .permitted = false,
        .outcome = "refused_by_user",
        .review_text = "a reviewer weighed this and said no",
    } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_error_result = false;
    var saw_tool_message = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .tool_result => |r| {
                try testing.expect(r.is_error);
                try testing.expect(std.mem.indexOf(u8, r.output, "refused_by_user") != null);
                try testing.expect(
                    std.mem.indexOf(u8, r.output, "a reviewer weighed this and said no") != null,
                );
                saw_error_result = true;
            },
            .message => |m| if (m.role == .tool) {
                try testing.expect(m.content[0].tool_result.is_error);
                saw_tool_message = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_error_result);
    try testing.expect(saw_tool_message);
}

test "a build is decided under the attribute path it named, and not under the call" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NIXBUILDNAME");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "nix_build",
            .arguments = "{\"attribute\":[\"packages\",\"x86_64-linux\",\"default\"]}",
        } }} },
        .{ .deltas = &.{.{ .text = "built" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = TestArbiter{ .answer = .{ .permitted = true, .outcome = "approved_by_user" } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", judge.sawDetail());
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
}

const foreign_flake_turns = [_]FakeTurn{
    .{ .deltas = &.{.{ .tool_call = .{
        .index = 0,
        .id = "call1",
        .name = "nix_build",
        .arguments =
        \\{"attribute":["packages","x86_64-linux","default"],"flake":"github:evil/repo"}
        ,
    } }} },
    .{ .deltas = &.{.{ .text = "done with that" }} },
};

test "a build that names a flake asks about the attribute path and about the reference" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NIXBUILDFLAKE");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &foreign_flake_turns };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = ActionArbiter{};

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 2), judge.calls);
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", judge.sawAt(0));
    try testing.expectEqualStrings("nix.build.flake.github.evil.repo", judge.sawAt(1));
    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
}

test "a rule that allows the attribute does not authorise a foreign flake" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NIXBUILDFOREIGN");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &foreign_flake_turns };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = ActionArbiter{ .refuse_prefix = "nix.build.flake" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 2), judge.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_error_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .tool_result) {
            try testing.expect(parsed.value.event.tool_result.is_error);
            saw_error_result = true;
        }
    }
    try testing.expect(saw_error_result);
}

test "a rule that allows the reference does not authorise an attribute the project denied" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NIXBUILDATTRDENY");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &foreign_flake_turns };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = ActionArbiter{ .refuse_prefix = "nix.build.packages" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", judge.sawAt(0));
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);
}

test "a build whose action is denied does not run, and the model is told" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NIXBUILDDENY");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "nix_build",
            .arguments = "{\"attribute\":[\"packages\",\"x86_64-linux\",\"default\"]}",
        } }} },
        .{ .deltas = &.{.{ .text = "then I will not build it" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = TestArbiter{ .answer = .{ .permitted = false, .outcome = "refused_by_policy" } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), judge.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_error_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .tool_result) {
            try testing.expect(parsed.value.event.tool_result.is_error);
            saw_error_result = true;
        }
    }
    try testing.expect(saw_error_result);
}

test "a build whose attribute path cannot be named is refused, and nobody is asked" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01NIXBUILDUNNAMED");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{
            .index = 0,
            .id = "call1",
            .name = "nix_build",
            .arguments = "{\"attribute\":\"packages.x86_64-linux.default\"}",
        } }} },
        .{ .deltas = &.{.{ .text = "I will send a list" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };
    var judge = TestArbiter{ .answer = .{ .permitted = true, .outcome = "allowed_by_policy" } };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = judge.arbiter();
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 0), judge.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);
}

test "a session with no arbiter refuses every ordinary tool call and does not run it" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01GATENOARBITER");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } }} },
        .{ .deltas = &.{.{ .text = "that is what I will not do" }} },
    } };
    var fake_tools = FakeToolRunner{ .output = "ok" };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.arbiter = null;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var saw_error_result = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event == .tool_result) {
            try testing.expect(parsed.value.event.tool_result.is_error);
            try testing.expect(
                std.mem.indexOf(u8, parsed.value.event.tool_result.output, arbiter_mod.not_asked.outcome) != null,
            );
            saw_error_result = true;
        }
    }
    try testing.expect(saw_error_result);
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

    var first = try foldFromStart(allocator, io, store);
    defer first.deinit();
    var second = try foldFromStart(allocator, io, store);
    defer second.deinit();

    try testing.expectEqual(first.context.items.len, second.context.items.len);
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
            .image => |at| {
                try testing.expectEqualStrings(at.call_id, bp.image.call_id);
                try testing.expectEqualStrings(at.media_type, bp.image.media_type);
                try testing.expectEqualStrings(at.data, bp.image.data);
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
    try testing.expectEqual(@as(usize, 1), starts);
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

    try testing.expect(fake_tools.saw_call_in_log);
}

test "the API key is in no event in the log" {
    comptime {
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
        found = switch (parsed.value.event.session_end.reason) {
            .unknown => .{ .unknown = "" },
            inline else => |_, tag| @unionInit(event.SessionEndReason, @tagName(tag), {}),
        };
    }
    return found orelse error.NoSessionEnd;
}

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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{.{ .deltas = &.{} }} };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));

    try testing.expect(std.meta.activeTag(reason) != event.SessionEndReason.finished);

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.indexOf(u8, detail, "the first turn") != null);
    try testing.expect(std.mem.indexOf(u8, detail, "gave no stop reason") != null);
}

test "an empty turn carries the provider's own stop reason into the log" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{.{ .stop_reason = .{ .reason = "end_turn" } }} }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.empty_response, std.meta.activeTag(reason));

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.endsWith(u8, detail, "because of end_turn"));
}

test "a refusal that came with text ends the session and keeps the text" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{
            .{ .text = "Here is how the exploit works" },
            .{ .stop_reason = .{
                .reason = "refusal",
                .category = "cyber",
                .explanation = "This request was declined because it could enable cyber harm.",
            } },
        } }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.refused_by_model, std.meta.activeTag(reason));

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expectEqualStrings(
        "the model backend refused the first turn of the session, in the category cyber: This " ++
            "request was declined because it could enable cyber harm.",
        detail,
    );

    const said = try lastAssistantText(allocator, io, store);
    defer allocator.free(said);
    try testing.expectEqualStrings("Here is how the exploit works", said);

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expectEqual(@as(usize, 0), fake_tools.calls);
}

test "a refusal with no text ends refused_by_model and never empty_response" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{.{ .stop_reason = .{
            .reason = "refusal",
            .explanation = "This request was declined.",
        } }} }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.refused_by_model, std.meta.activeTag(reason));
    try testing.expect(std.meta.activeTag(reason) != event.SessionEndReason.empty_response);

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expectEqualStrings(
        "the model backend refused the first turn of the session: This request was declined.",
        detail,
    );
}

test "a refusal with no category and no explanation still ends, and invents nothing" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{.{ .deltas = &.{.{ .stop_reason = .{ .reason = "refusal" } }} }},
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.refused_by_model, std.meta.activeTag(reason));

    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expectEqualStrings(
        "the model backend refused the first turn of the session, and gave no reason for the " ++
            "refusal",
        detail,
    );
    try testing.expect(std.mem.indexOf(u8, detail, "category") == null);
    try testing.expectEqual(@as(usize, 1), fake_client.calls);
}

test "every shape of a refusal gets its own sentence" {
    const allocator = testing.allocator;
    const opening = "the model backend refused a turn of the session";

    const cases = [_]struct { stop: chock_provider.Client.Stop, want: []const u8 }{
        .{
            .stop = .{ .reason = "refusal" },
            .want = opening ++ ", and gave no reason for the refusal",
        },
        .{
            .stop = .{ .reason = "refusal", .category = "cyber" },
            .want = opening ++ ", in the category cyber",
        },
        .{
            .stop = .{ .reason = "refusal", .explanation = "This request was declined." },
            .want = opening ++ ": This request was declined.",
        },
        .{
            .stop = .{
                .reason = "refusal",
                .category = "cyber",
                .explanation = "This request was declined.",
            },
            .want = opening ++ ", in the category cyber: This request was declined.",
        },
    };

    for (cases) |case| {
        const detail = try refusalDetail(allocator, case.stop, whichTurn(3));
        defer allocator.free(detail);
        try testing.expectEqualStrings(case.want, detail);
    }

    const first = try refusalDetail(allocator, .{ .reason = "refusal" }, whichTurn(0));
    defer allocator.free(first);
    try testing.expectEqualStrings(
        "the model backend refused the first turn of the session, and gave no reason for the " ++
            "refusal",
        first,
    );
}

test "an empty turn reports the word the provider sent, or that it sent none" {
    const allocator = testing.allocator;
    const opening = "the model backend answered a turn of the session with no text and no tool call";

    const said_nothing = try emptyReplyDetail(allocator, .{ .reason = "" }, 3);
    defer allocator.free(said_nothing);
    try testing.expectEqualStrings(opening ++ ", and gave no stop reason", said_nothing);

    const said_a_word = try emptyReplyDetail(allocator, .{ .reason = "end_turn" }, 3);
    defer allocator.free(said_a_word);
    try testing.expectEqualStrings(opening ++ ", and said it stopped because of end_turn", said_a_word);

    const first = try emptyReplyDetail(allocator, .{ .reason = "end_turn" }, 0);
    defer allocator.free(first);
    try testing.expectEqualStrings(
        "the model backend answered the first turn of the session with no text and no tool " ++
            "call, and said it stopped because of end_turn",
        first,
    );

    const with_words = try emptyReplyDetail(
        allocator,
        .{ .reason = "max_tokens", .explanation = "The answer was cut short." },
        3,
    );
    defer allocator.free(with_words);
    try testing.expectEqualStrings(
        opening ++ ", and said it stopped because of max_tokens: The answer was cut short.",
        with_words,
    );
}

test "a turn that carries only reasoning is empty, because nothing runs and nobody reads it" {
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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{ .turns = &.{
        .{ .deltas = &.{ .{ .text = "the build is green" }, .{ .stop_reason = .{ .reason = "end_turn" } } } },
    } };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.finished, std.meta.activeTag(reason));
}

test "the same tool with the same arguments, three times in a row, ends the session no_progress" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

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

    try testing.expectEqual(@as(usize, 3), fake_client.calls);
    try testing.expectEqual(@as(usize, 2), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.no_progress, std.meta.activeTag(reason));
}

test "a legitimate retry does not trip the no progress detector" {
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

    try testing.expectEqual(@as(usize, 5), fake_client.calls);
    try testing.expectEqual(@as(usize, 4), fake_tools.calls);

    const reason = try endReasonOf(allocator, io, store);
    try testing.expectEqual(event.SessionEndReason.no_progress, std.meta.activeTag(reason));
}

test "build, edit, build, edit, build is work and is not stopped" {
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
    const allocator = testing.allocator;

    var progress = Progress{};
    defer progress.deinit(allocator);

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
    try testing.expect(!fourth.isLoop());
    const fifth = try cycle.observe(allocator, "run_command", a);
    try testing.expectEqual(@as(usize, 3), fifth.repeats);
    try testing.expectEqual(@as(usize, 2), fifth.distinct);
    try testing.expect(fifth.isLoop());
}

test "a session of more than fifty turns runs to completion" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const working_turns = 60;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

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

const RecordingObserver = struct {
    allocator: std.mem.Allocator,
    ids: std.ArrayList(u64) = .empty,
    kinds: std.ArrayList(event.Kind) = .empty,
    log_lengths: std.ArrayList(usize) = .empty,
    log_to_measure: ?*const chock_proto.storage.Memory = null,
    trace: std.ArrayList(Step) = .empty,
    notices: std.ArrayList([]u8) = .empty,

    const Step = union(enum) {
        event: event.Kind,
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

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        const owned = self.allocator.dupe(u8, text) catch return;
        self.notices.append(self.allocator, owned) catch {
            self.allocator.free(owned);
            return;
        };
    }

    fn firstPiece(self: *const RecordingObserver) ?usize {
        for (self.trace.items, 0..) |step, index| {
            if (step == .piece) return index;
        }
        return null;
    }

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
    try testing.expectEqual(index, watcher.ids.items.len);
    try testing.expectEqual(@as(usize, 9), index);

    for (watcher.ids.items, watcher.log_lengths.items) |id, length| {
        try testing.expect(length > id);
    }
}

test "a piece of the model's answer reaches the observer before the turn that holds it is over" {
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

    var pieces_before: usize = 0;
    for (watcher.trace.items[0..message_event]) |step| {
        if (step == .piece) pieces_before += 1;
    }
    try testing.expectEqual(@as(usize, 3), pieces_before);

    const expected = [_][]const u8{ "I will ", "read the file ", "first." };
    var seen: usize = 0;
    for (watcher.trace.items[0..message_event]) |step| {
        if (step != .piece) continue;
        try testing.expectEqualStrings(expected[seen], step.piece);
        seen += 1;
    }
}

test "streaming the pieces changes nothing about the log, which still gains one message event per turn" {
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

    try testing.expectEqual(@as(usize, 1), messages);
    try testing.expectEqualStrings("one two three", answer);
}

test "the model's reasoning reaches the observer as reasoning, and never as answer text" {
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

var test_cancel_asked: bool = false;

fn testCanceled() bool {
    return test_cancel_asked;
}

fn askForCancelDuringWait() void {
    test_cancel_asked = true;
}

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

var test_handover_agree: bool = false;
var test_handover_asks: usize = 0;
var test_handover_seen: InFlight = .{};

fn testHandover(io: std.Io, in_flight: InFlight) bool {
    _ = io;
    test_handover_asks += 1;
    test_handover_seen = in_flight;
    return test_handover_agree;
}

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
    var tasks = task_table.Table{ .gpa = allocator, .dir = "/tmp", .runner = undefined };
    var children = subagent.Table{ .gpa = allocator, .spawner = undefined };
    deps.tasks = &tasks;
    deps.children = &children;
    deps.handover = testHandover;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 0), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), test_handover_asks);

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
            .{ .deltas = &.{.{ .text = "unreachable" }} },
        },
    };
    var fake_tools = HandingOverToolRunner{ .after = 1 };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.handover = testHandover;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 2), fake_tools.calls);
    try testing.expectEqual(@as(usize, 1), fake_client.calls);

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
    const allocator = testing.allocator;
    const io = testing.io;

    test_cancel_asked = false;
    defer test_cancel_asked = false;

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
            .{ .deltas = &.{.{ .text = "unreachable" }} },
        },
    };
    var fake_tools = CancelingToolRunner{ .after = 1 };

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.canceled = testCanceled;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_tools.calls);
    try testing.expectEqual(@as(usize, 1), fake_client.calls);

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
    try testing.expectEqual(
        event.SessionEndReason.canceled_by_user,
        std.meta.activeTag(reason.?),
    );
}

test "a session stopped before its first turn spends nothing at all" {
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
    try testing.expectEqual(@as(usize, 4), events);
}

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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

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
    var request_id: u64 = 0;
    var end_detail: []const u8 = "";
    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => |request| {
                saw_request = true;
                request_id = parsed.value.id;
                try testing.expectEqualStrings(budget_action, request.action);
            },
            .approval_response => |response| {
                saw_response = true;
                try testing.expectEqual(
                    event.ApprovalDecision.expired,
                    std.meta.activeTag(response.decision),
                );
                try testing.expect(request_id != 0);
                try testing.expectEqual(request_id, response.request_id);
            },
            .session_end => |ended| {
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
    try testing.expectEqual(@as(u64, 1), spend.unpriced_turns);
    try testing.expect(!spend.enforceable());
}

test "a provider that reports no usage still gets a usage event, saying the cost is unknown" {
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
        try testing.expectEqualStrings("", usage.price_table_version);
    }
    try testing.expect(saw_usage);
}

test "a free provider under a cap runs to completion, because free is not unknown" {
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

    try testing.expectEqual(@as(usize, 2), fake_client.calls);

    const spend = try foldSpend(allocator, io, store);
    try testing.expectEqual(@as(u64, 2), spend.turns);
    try testing.expectEqual(@as(u64, 0), spend.unpriced_turns);
    try testing.expect(spend.enforceable());
    try testing.expectEqual(@as(f64, 0), spend.amount);
}

test "the cost of a session survives a replay: two folds of one log agree" {
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
    try testing.expectEqual(@as(u64, 2), first.turns);
    try testing.expectEqual(@as(u64, 3000), first.input_tokens);
    try testing.expectEqual(@as(u64, 130), first.output_tokens);
}

test "a cap in one currency and turns billed in another is not enforced" {
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

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
}

test "an image answer puts the bytes in the message event and the description in the tool result" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const data = "iVBORw0KGgoAAAANSUhEUg==";
    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{ .index = 0, .id = "call1", .name = "read_image", .arguments = "{}" } }} },
            .{ .deltas = &.{.{ .text = "a red square" }} },
        },
        .record_requests = true,
    };
    var fake_tools = FakeToolRunner{
        .output = "[chock: image/png, 69 bytes, image_hash 0123456789abcdef] shot.png",
        .image = .{
            .media_type = "image/png",
            .byte_count = 69,
            .content_hash = "0123456789abcdef",
            .data = data,
        },
    };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    try testing.expectEqual(@as(usize, 2), fake_client.calls);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, data) != null);

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    var image_parts: usize = 0;
    var results_with_bytes: usize = 0;
    var described: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .message => |m| for (m.content) |part| {
                if (part != .image) continue;
                image_parts += 1;
                try testing.expectEqualStrings("call1", part.image.call_id);
                try testing.expectEqualStrings("image/png", part.image.media_type);
                try testing.expectEqualStrings(data, part.image.data);
            },
            .tool_result => |r| {
                if (std.mem.indexOf(u8, replay.line(), data) != null) results_with_bytes += 1;
                const image = r.image orelse continue;
                described += 1;
                try testing.expectEqualStrings("image/png", image.media_type);
                try testing.expectEqual(@as(u64, 69), image.byte_count);
                try testing.expectEqualStrings("0123456789abcdef", image.content_hash);
                try testing.expectEqualStrings("", image.data);
            },
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, 1), image_parts);
    try testing.expectEqual(@as(usize, 1), described);
    try testing.expectEqual(@as(usize, 0), results_with_bytes);
}

test "a tool that answers with bytes that are not UTF-8 leaves a JSON string in the request, never an array" {
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

    try testing.expectEqual(@as(usize, 2), fake_client.calls);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, "\"content\":\"[chock: binary output, 10 bytes, not shown]\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "[120,156,75,202,201,255,254,128,129,0]") == null);

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

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, "SOCK_RAW") != null);
    try testing.expect(std.mem.indexOf(u8, json, "no network at all") == null);

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

const fake_key = "sk-loop-test-000000000000000000";

fn logBytes(backing: *const chock_proto.storage.Memory) []const u8 {
    return backing.bytes.items;
}

test "a credential in a tool result is in none of the log's own bytes" {
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

    try testing.expect(std.mem.indexOf(u8, logBytes(&backing), fake_key) == null);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, fake_key) == null);
    try testing.expectEqual(
        @as(usize, 2),
        std.mem.count(u8, json, redact.Source.credential.marker()),
    );
    try testing.expect(std.mem.indexOf(u8, json, "401 for key ") != null);
    try testing.expect(std.mem.indexOf(u8, json, ", check it") != null);

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

    const report = try chock_proto.storage.verify(store, allocator, io);
    try testing.expectEqual(chock_proto.chain.Verdict.intact, report.verdict);
    try testing.expect(report.events > 0);
    try testing.expectEqual(report.events, report.chained);

    const marker_at = std.mem.indexOf(u8, logBytes(&backing), redact.Source.credential.marker()).?;
    backing.bytes.items[marker_at + 1] = 'X';
    const forged = try chock_proto.storage.verify(store, allocator, io);
    try testing.expectEqual(chock_proto.chain.Verdict.broken, forged.verdict);
}

test "the funnel is the append, so a kind nobody listed is covered too" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

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

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    defer if (fake_client.last_request_json) |json| allocator.free(json);

    const json = fake_client.last_request_json.?;
    try testing.expect(std.mem.indexOf(u8, json, shaped) != null);
    try testing.expect(std.mem.indexOf(u8, json, "[chock: redacted") == null);
}

test "the compaction call is redacted too, so the second road out is not a way past" {
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

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);

    var saw_summary_call = false;
    for (seen.items.items) |one| {
        try testing.expect(std.mem.indexOf(u8, one.system, fake_key) == null);
        try testing.expect(std.mem.indexOf(u8, one.tail, fake_key) == null);
        if (!std.mem.eql(u8, one.system, compaction.summary_system)) continue;
        saw_summary_call = true;
        try testing.expect(std.mem.indexOf(u8, one.tail, redact.Source.credential.marker()) != null);
    }
    try testing.expect(saw_summary_call);
}

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

const FoundCompaction = struct {
    id: u64,
    summary: []u8,
    from_id: u64,
    through_id: u64,
    kept_ranges: []event.EventRange,
    model_alias: []u8,
    stand_in_reason: []u8,

    fn deinit(self: *FoundCompaction, allocator: std.mem.Allocator) void {
        allocator.free(self.summary);
        allocator.free(self.kept_ranges);
        allocator.free(self.model_alias);
        allocator.free(self.stand_in_reason);
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
            .stand_in_reason = try allocator.dupe(u8, found.stand_in_reason),
        };
    }
    return null;
}

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
            .{ .refusal = .{ .body = measured_overflow_body } },
            .{ .deltas = &.{.{ .text = "the parser work is half done and the tab case is open" }} },
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    try testing.expectEqual(@as(usize, 3), fake_client.calls);

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expectEqualStrings("the parser work is half done and the tab case is open", found.summary);
    try testing.expectEqualStrings("main", found.model_alias);
    try testing.expectEqual(@as(usize, 1), found.kept_ranges.len);
}

test "a compaction folds the middle and leaves the task and the recent turns word for word" {
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

    // Nothing writes to the terminal on a pass: `zig build` reads a run step that
    // wrote to standard error as a failure.
    const task_at = std.mem.indexOf(u8, text, "TASK: make the parser accept tabs") orelse {
        try testing.expectEqualStrings("TASK: make the parser accept tabs", text);
        return error.TheUsersOwnTaskWasFoldedAway;
    };
    const summary_at = std.mem.indexOf(u8, text, "SUMMARY OF THE MIDDLE") orelse {
        try testing.expectEqualStrings("SUMMARY OF THE MIDDLE", text);
        return error.TheCompactionLeftNoSummary;
    };
    try testing.expect(task_at < summary_at);

    for (0..6) |i| {
        const recent = try std.fmt.allocPrint(allocator, "RECENT-{d}", .{i});
        defer allocator.free(recent);
        const at = std.mem.indexOf(u8, text, recent) orelse {
            try testing.expectEqualStrings(recent, text);
            return error.AKeptTurnDidNotSurviveTheCompaction;
        };
        try testing.expect(summary_at < at);
    }

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

    try testing.expect(first.context.items.len < 12);
}

test "a rate limit ends the session and never compacts, however much its body says about tokens" {
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
    deps.retry.max_attempts = 1;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), fake_client.calls);
    try testing.expect(try firstCompaction(allocator, io, store) == null);
    try testing.expectEqual(
        event.SessionEndReason.rate_limited,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

const measured_rate_limit_body =
    \\{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your rate limit of 500,000 input tokens per minute"}}
;

test "a rate limit is waited out, and the reply after the wait is the session's real answer" {
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

    try testing.expectEqual(@as(usize, 2), fake_client.calls);
    try testing.expectEqual(@as(usize, 1), sleeper.waits.items.len);
    try testing.expect(sleeper.waits.items[0] > 0);

    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    const said = try lastAssistantText(allocator, io, store);
    defer allocator.free(said);
    try testing.expectEqualStrings("the answer the session was for", said);

    try testing.expectEqual(@as(usize, 1), watching.notices.items.len);
    try testing.expect(std.mem.indexOf(u8, watching.notices.items[0], "rate_limited") != null);
}

test "the wait is exactly what the provider's Retry-After asked for" {
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
    deps.retry.retry_after_spread_ms = 0;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 1), sleeper.waits.items.len);
    try testing.expectEqual(@as(u64, 37_000), sleeper.waits.items[0]);

    try testing.expect(sleeper.waits.items[0] != retry.waitMs(deps.retry, 1, null, 0));
}

test "the attempts run out, and the session says how many were made and what the provider last said" {
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

    try testing.expectEqual(@as(usize, 3), fake_client.calls);
    try testing.expectEqual(@as(usize, 2), sleeper.waits.items.len);
    try testing.expect(sleeper.waits.items[1] > sleeper.waits.items[0]);

    try testing.expectEqual(
        event.SessionEndReason.rate_limited,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    const detail = try endDetailOf(allocator, io, store);
    defer allocator.free(detail);
    try testing.expect(std.mem.indexOf(u8, detail, "3 attempts") != null);
    try testing.expect(std.mem.indexOf(u8, detail, "500,000 input tokens per minute") != null);
}

test "a Retry-After longer than the session waits ends it at once instead of retrying blind" {
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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    try seedMessages(allocator, io, store, "MIDDLE", 12);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .refusal = .{ .body = measured_overflow_body } },
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

    var folded = (try firstCompaction(allocator, io, store)).?;
    defer folded.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), sleeper.waits.items.len);
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "a session canceled during a wait ends as canceled, and never sends the request the wait was for" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    var fake_client = FakeClient{
        .turns = &.{
            .{ .refusal = .{ .status = .too_many_requests, .body = measured_rate_limit_body } },
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
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 60000, .output_tokens = 10 } },
            } },
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
            .{ .deltas = &.{
                .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                .{ .usage = .{ .input_tokens = 40000 } },
            } },
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
            try testing.expect(std.mem.indexOf(u8, part.text, "49152") != null);
            try testing.expect(std.mem.indexOf(u8, part.text, "65536") != null);
            try testing.expect(std.mem.indexOf(u8, part.text, "write_memory") != null);
            try testing.expect(std.mem.indexOf(u8, part.text, "dead ends") != null);
            warnings += 1;
            if (notice_id == null) notice_id = parsed.value.id;
        }
    }
    try testing.expectEqual(@as(usize, 1), warnings);

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expect(notice_id.? < found.id);
}

test "a session with no write_memory is never told to call it as a compaction approaches" {
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
    try testing.expectEqualStrings(
        "the model backend answered the compaction call with status 500: the summariser fell over",
        found.stand_in_reason,
    );
    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
}

test "a refused compaction call is written into the log, and the session carries on" {
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
            .{ .deltas = &.{
                .{ .text = "The session was about" },
                .{ .stop_reason = .{
                    .reason = "refusal",
                    .category = "cyber",
                    .explanation = "This request was declined because it could enable cyber harm.",
                } },
            } },
            .{ .deltas = &.{.{ .text = "all done" }} },
        },
    };
    var fake_tools = FakeToolRunner{ .output = "unused" };
    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));

    var found = (try firstCompaction(allocator, io, store)).?;
    defer found.deinit(allocator);
    try testing.expectEqualStrings(
        "the model backend refused the compaction call, in the category cyber: This request was " ++
            "declined because it could enable cyber harm.",
        found.stand_in_reason,
    );

    try testing.expectEqualStrings("", found.model_alias);
    try testing.expect(std.mem.startsWith(u8, found.summary, compaction.harness_summary_first_line));
    try testing.expect(std.mem.indexOf(u8, found.summary, "The session was about") == null);

    try testing.expectEqual(
        event.SessionEndReason.finished,
        std.meta.activeTag(try endReasonOf(allocator, io, store)),
    );
    const said = try lastAssistantText(allocator, io, store);
    defer allocator.free(said);
    try testing.expectEqualStrings("all done", said);
}

const FakeSpawner = struct {
    child_session: []const u8 = "01CHILDAA",
    scratchpad_path: []const u8 = "/tmp/chock/01SPAWN/agents/01CHILDAA/scratch",
    outcome: event.AgentOutcome = .finished,
    result: []const u8 = "the diff is safe to apply",
    prepare_fails: bool = false,
    run_fails: bool = false,

    prepared: usize = 0,
    ran: usize = 0,
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

const SpawnAttempt = struct {
    output: []u8,
    is_error: bool,
    runner_calls: usize,
    spawn_events: usize,
    complete_events: usize,
    child_budget: f64,
    child_budget_named_currency: bool,
    reached_the_model: bool,
    assistant_turns: usize,
};

const SpawnCase = struct {
    limits: subagents.Limits = .{},
    chain: []const event.SpawnLink = &.{},
    already_started: usize = 0,
    committed_each: f64 = 0,
    spawner: ?subagent.Spawner = null,
    arguments: []const u8 = "{\"agent_kind\":\"reviewer\",\"task\":\"read the diff\"}",
    budget: ?chock_cost.budget.Budget = null,
    spent: f64 = 0,
};

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
            .message => |written| {
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
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    const attempt = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 0 },
        .spawner = spawner.spawner(),
    });
    defer allocator.free(attempt.output);

    try testing.expect(std.mem.indexOf(u8, attempt.output, "max_width to 0") != null);
    try testing.expect(std.mem.indexOf(u8, attempt.output, "chock.zon") != null);
    try testing.expect(attempt.is_error);
    try testing.expect(attempt.reached_the_model);

    try testing.expectEqual(@as(usize, 0), attempt.runner_calls);
    try testing.expectEqual(@as(usize, 0), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 0), attempt.complete_events);
    try testing.expectEqual(@as(usize, 0), spawner.prepared);
    try testing.expectEqual(@as(usize, 0), spawner.ran);

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
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{};
    const first = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 1 },
        .spawner = spawner.spawner(),
    });
    defer allocator.free(first.output);
    try testing.expectEqual(@as(usize, 1), spawner.ran);
    try testing.expectEqual(@as(usize, 1), first.spawn_events);
    try testing.expectEqual(@as(usize, 1), first.complete_events);
    try testing.expect(!first.is_error);
    try testing.expectEqual(@as(usize, 0), first.runner_calls);

    const second = try attemptSpawn(allocator, io, .{
        .limits = .{ .max_depth = 6, .max_width = 1 },
        .already_started = 1,
        .spawner = spawner.spawner(),
    });
    defer allocator.free(second.output);
    try testing.expect(std.mem.indexOf(u8, second.output, "max_width to 1") != null);
    try testing.expect(std.mem.indexOf(u8, second.output, "already started 1 subagent") != null);
    try testing.expectEqual(@as(usize, 1), second.spawn_events);
    try testing.expectEqual(@as(usize, 0), second.complete_events);
    try testing.expectEqual(@as(usize, 1), spawner.ran);
}

test "the width the loop measures is the number of session.spawn events in the log" {
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
            try testing.expectEqual(already_started + 1, attempt.spawn_events);
            try testing.expectEqual(@as(usize, 1), attempt.complete_events);
        } else {
            try testing.expect(std.mem.indexOf(u8, attempt.output, "max_width to 6") != null);
            try testing.expectEqual(already_started, attempt.spawn_events);
            try testing.expectEqual(@as(usize, 0), attempt.complete_events);
        }
        try testing.expectEqual(@as(usize, 0), attempt.runner_calls);
    }
}

test "the depth the loop measures is the length of the spawn chain" {
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
                try testing.expectEqualStrings("read the diff", spawn.reason);
            },
            .agent_complete => |done| {
                try order.append(allocator, .agent_complete);
                try testing.expectEqualStrings("01CHILDAA", done.child_session);
                try testing.expectEqual(event.AgentOutcome.finished, done.outcome);
                try testing.expectEqualStrings("the diff is safe to apply", done.result);
                try testing.expectEqualStrings(spawner.scratchpad_path, done.scratchpad_path);
            },
            else => {},
        }
    }

    try testing.expectEqual(@as(usize, 2), order.items.len);
    try testing.expectEqual(event.Kind.session_spawn, order.items[0]);
    try testing.expectEqual(event.Kind.agent_complete, order.items[1]);

    try testing.expectEqual(@as(usize, 1), spawner.prepared);
    try testing.expectEqual(@as(usize, 1), spawner.ran);
    try testing.expectEqualStrings("reviewer", spawner.kind());
    try testing.expectEqualStrings("read the diff\nand say what is wrong", spawner.task());
}

test "a subagent's turns are not in its parent's log, whatever the child said" {
    const allocator = testing.allocator;
    const io = testing.io;

    var spawner = FakeSpawner{ .result = "the parser refuses an empty file" };
    const attempt = try attemptSpawn(allocator, io, .{ .spawner = spawner.spawner() });
    defer allocator.free(attempt.output);

    try testing.expectEqual(@as(usize, 2), attempt.assistant_turns);
    try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 1), attempt.complete_events);

    try testing.expect(std.mem.indexOf(u8, attempt.output, "the parser refuses an empty file") != null);
    try testing.expect(std.mem.indexOf(u8, attempt.output, spawner.scratchpad_path) != null);
    try testing.expect(attempt.reached_the_model);
    try testing.expect(!attempt.is_error);
}

test "a child that did not finish is an error result, and the reason reaches the model" {
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
        try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
        try testing.expectEqual(@as(usize, 1), attempt.complete_events);
    }

    var broken = FakeSpawner{ .run_fails = true };
    const attempt = try attemptSpawn(allocator, io, .{ .spawner = broken.spawner() });
    defer allocator.free(attempt.output);
    try testing.expect(attempt.is_error);
    try testing.expect(std.mem.indexOf(u8, attempt.output, "died") != null);
    try testing.expectEqual(@as(usize, 1), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 1), attempt.complete_events);
}

test "the child is given a slice of the budget, and the slice is in the parent's own log" {
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

    try testing.expectEqual(@as(f64, 1.0), spawner.seen_budget.?);
    try testing.expectEqual(@as(f64, 1.0), first.child_budget);
    try testing.expect(first.child_budget_named_currency);

    var uncapped = FakeSpawner{};
    const no_cap = try attemptSpawn(allocator, io, .{ .spawner = uncapped.spawner() });
    defer allocator.free(no_cap.output);
    try testing.expectEqual(@as(?f64, null), uncapped.seen_budget);
    try testing.expectEqual(@as(f64, 0), no_cap.child_budget);
    try testing.expect(!no_cap.child_budget_named_currency);

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
    try testing.expectEqual(@as(usize, 3), nothing_left.spawn_events);
    try testing.expectEqual(@as(usize, 0), nothing_left.complete_events);
}

test "the shape the spawn asked for is what the child is told to produce" {
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

    var plain = FakeSpawner{};
    const prose = try attemptSpawn(allocator, io, .{ .spawner = plain.spawner() });
    defer allocator.free(prose.output);
    try testing.expectEqualStrings("read the diff", plain.task());
}

test "a spawn with no spawner, and one with arguments that say nothing, both start nothing" {
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

    const broken = try attemptSpawn(allocator, io, .{
        .spawner = spawner.spawner(),
        .arguments = "not json",
    });
    defer allocator.free(broken.output);
    try testing.expect(std.mem.indexOf(u8, broken.output, "agent_kind") != null);
    try testing.expectEqual(@as(usize, 0), spawner.prepared);

    var unbuildable = FakeSpawner{ .prepare_fails = true };
    const failed = try attemptSpawn(allocator, io, .{ .spawner = unbuildable.spawner() });
    defer allocator.free(failed.output);
    try testing.expect(failed.is_error);
    try testing.expectEqual(@as(usize, 0), failed.spawn_events);
    try testing.expectEqual(@as(usize, 0), failed.complete_events);
}

test "the child's session.start names the parent, and the kinds above it" {
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

/// Holds a subagent inside its own `run` until a test lets it out. Plain
/// atomics and a yield, because `std.Io.Mutex` needs an `Io`. The bound is a
/// count of yields, so a build that never lets the child out fails, not hangs.
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

var carry_on_gate = ChildGate{};
var carry_on_table: ?*subagent.Table = null;

fn releaseCarryOnChild() void {
    carry_on_gate.release();
    if (carry_on_table) |table| table.waitAll();
}

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
    const allocator = testing.allocator;
    const io = testing.io;

    carry_on_gate = .{};

    var backing = try chock_proto.storage.Memory.init(allocator, "01ASYNC");
    const store = backing.storage();
    defer store.close(io);

    var gated = GatedSpawner{};
    var table = subagent.Table{ .gpa = allocator, .spawner = gated.spawner() };
    defer table.deinit();
    carry_on_table = &table;
    defer carry_on_table = null;

    var fake_client = FakeClient{
        .turns = &.{
            .{ .deltas = &.{.{ .tool_call = .{
                .index = 0,
                .id = "spawn1",
                .name = spawn_tool_name,
                .arguments = "{\"agent_kind\":\"reviewer\",\"task\":\"run the tests\",\"background\":true}",
            } }} },
            .{
                .deltas = &.{.{ .tool_call = .{
                    .index = 0,
                    .id = "own-work",
                    .name = "read_file",
                    .arguments = "{\"path\":\"README.md\"}",
                } }},
                .before = releaseCarryOnChild,
            },
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

    try testing.expect(spawn_id.? < own_call_id.?);
    try testing.expect(own_call_id.? < own_result_id.?);
    try testing.expect(own_result_id.? < complete_id.?);
    try testing.expect(complete_id.? < told_id.?);

    try testing.expect(!spawn_was_error);
    try testing.expect(std.mem.indexOf(u8, spawn_result, "01CHILDAA") != null);
    try testing.expect(std.mem.indexOf(u8, spawn_result, "has not answered yet") != null);

    const again = try table.take(allocator);
    defer subagent.freeCompletions(allocator, again);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "a spawn that waits still answers in its own call, and nothing is drained afterwards" {
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
    try testing.expect(spawn_id.? < complete_id.?);
    try testing.expect(complete_id.? < result_id.?);
    try testing.expectEqual(@as(usize, 0), table.startedCount());
}

test "a spawn that asks to carry on with no table for it is refused, and names the other shape" {
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
    try testing.expectEqual(@as(usize, 0), spawner.prepared);
    try testing.expectEqual(@as(usize, 0), spawner.ran);
    try testing.expectEqual(@as(usize, 0), attempt.spawn_events);
    try testing.expectEqual(@as(usize, 0), attempt.complete_events);
}

test "a child still running when the session ends is waited for and recorded, not lost" {
    const allocator = testing.allocator;
    const io = testing.io;

    carry_on_gate = .{};
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
    try testing.expect(end_id.? < complete_id.?);
    try testing.expect(!told_after_the_end);
}

test "a session with no children table runs exactly as it did before a spawn could carry on" {
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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01CHAIN");
    const store = backing.storage();
    defer store.close(io);

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
        try testing.expectEqualStrings("coder", request.agent_kind);
    }
    try testing.expect(found);
}

const SeenRequest = struct {
    system: []u8,
    tail: []u8,
    messages: usize,
};

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

    fn anyTailHolds(self: SeenRequests, needle: []const u8) bool {
        for (self.items.items) |seen| {
            if (std.mem.indexOf(u8, seen.tail, needle) != null) return true;
        }
        return false;
    }
};

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

fn readResult(allocator: std.mem.Allocator, content: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "[chock: {d} bytes, file_hash {s}]\n{s}", .{
        content.len,
        tools.contentHash(content),
        content,
    });
}

fn readCall(id: []const u8, arguments: []const u8) chock_provider.Client.Delta {
    return .{ .tool_call = .{
        .index = 0,
        .id = id,
        .name = @tagName(tools.Tool.read_file),
        .arguments = arguments,
    } };
}

test "the system prompt is byte identical on every turn, whatever the notices say" {
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
    deps.uncommitted_files = 5;
    try run(allocator, io, deps);

    try testing.expectEqual(@as(usize, 3), seen.items.items.len);
    for (seen.items.items) |request| {
        try testing.expectEqualStrings(deps.system_prompt, request.system);
    }

    try testing.expect(std.mem.indexOf(u8, seen.items.items[0].tail, "5 files") != null);
    try testing.expect(std.mem.indexOf(u8, seen.items.items[2].tail, "did not change") != null);
    try testing.expect(!std.mem.eql(u8, seen.items.items[0].tail, seen.items.items[2].tail));
}

test "a notice reaches the model on the turn it applies and on no other turn" {
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
    try testing.expect(std.mem.indexOf(u8, seen.items.items[0].tail, "7 files") != null);
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

    try testing.expect(std.mem.indexOf(u8, seen.items.items[1].tail, notices.prefix) == null);
    const told = seen.items.items[2].tail;
    try testing.expect(std.mem.indexOf(u8, told, "src/main.zig") != null);
    try testing.expect(std.mem.indexOf(u8, told, "did not change") != null);
}

test "a file that changed between two reads is never reported as unchanged" {
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

    try testing.expect(std.mem.indexOf(u8, seen.items.items[1].tail, notices.prefix) == null);

    const told = seen.items.items[2].tail;
    try testing.expect(std.mem.indexOf(u8, told, "run_command") != null);
    try testing.expect(std.mem.indexOf(u8, told, "readlink -f .") != null);
    try testing.expect(std.mem.indexOf(u8, told, "2 times") != null);
}

test "a notice is in no event in the log, so a replay never sees one" {
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

    var other_backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const other_store = other_backing.storage();
    defer other_store.close(io);

    var on_tools = ScriptedToolRunner{ .outputs = &.{ same, same } };
    var on_client = FakeClient{ .seen = &on_seen, .turns = &script };
    var on_deps = testDeps(on_client.client(), other_store, on_tools.runner());
    on_deps.uncommitted_files = 5;
    try run(allocator, io, on_deps);

    try testing.expect(on_seen.anyTailHolds(notices.prefix));

    try testing.expectEqual(off_seen.items.items.len, on_seen.items.items.len);
    for (off_seen.items.items, on_seen.items.items) |off, on| {
        try testing.expect(on.messages == off.messages or on.messages == off.messages + 1);
    }
}

test "the notice the model is given is the notice a watching person is shown" {
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
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

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

    try run(allocator, io, testDeps(fake_client.client(), store, fake_tools.runner()));
    try testing.expect(!seen.anyTailHolds("percent"));
}

test "the task is put back in front of the agent in a long session, and not in a short one" {
    const allocator = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(allocator, "01LOOP");
    const store = backing.storage();
    defer store.close(io);

    const task = "make the parser accept a trailing comma";
    const said = [_]event.ContentPart{.{ .text = task }};
    try seedEvent(allocator, io, store, .{ .message = .{ .role = .user, .content = &said } });

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

    const triggers = notices.Policy{};
    for (seen.items.items[0..triggers.goal_every_turns]) |request| {
        try testing.expect(std.mem.indexOf(u8, request.tail, notices.prefix) == null);
    }
    var restated = false;
    for (seen.items.items) |request| {
        if (std.mem.indexOf(u8, request.tail, notices.prefix) == null) continue;
        if (std.mem.indexOf(u8, request.tail, task) != null) restated = true;
    }
    try testing.expect(restated);
}

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
    try testing.expect(record_id.? < delivery_id.?);
    try testing.expect(assistant_id != null);
    try testing.expect(delivery_id.? < assistant_id.?);

    const again = try table.take(allocator);
    defer task_table.freeCompletions(allocator, again);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "a session with no task table runs exactly as it did before background tasks existed" {
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

const PlanRun = struct {
    outputs: []const []const u8,
    refused: []const bool,
    events: usize,
    written_steps: usize,
    runner_calls: usize,
};

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

const PromiseRun = struct {
    outputs: []const []const u8,
    refused: []const bool,
    events: usize,
    runner_calls: usize,
};

const ActionArbiter = struct {
    refuse_prefix: []const u8 = "",
    calls: usize = 0,
    seen: [4][256]u8 = undefined,
    seen_len: [4]usize = .{0} ** 4,

    fn sawAt(self: *const ActionArbiter, index: usize) []const u8 {
        return self.seen[index][0..self.seen_len[index]];
    }

    fn arbiter(self: *ActionArbiter) arbiter_mod.Arbiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = arbiter_mod.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        _: *arbiter_mod.Locked,
        ask: arbiter_mod.Ask,
    ) arbiter_mod.Answer {
        const self: *ActionArbiter = @ptrCast(@alignCast(ptr));
        if (self.calls < self.seen.len) {
            const length = @min(ask.action.len, self.seen[self.calls].len);
            @memcpy(self.seen[self.calls][0..length], ask.action[0..length]);
            self.seen_len[self.calls] = length;
        }
        self.calls += 1;

        if (self.refuse_prefix.len != 0 and std.mem.startsWith(u8, ask.action, self.refuse_prefix)) {
            return .{ .permitted = false, .outcome = "refused_by_policy" };
        }
        return .{ .permitted = true, .outcome = "allowed_by_policy" };
    }
};

const TestArbiter = struct {
    answer: arbiter_mod.Answer = .{ .permitted = false, .outcome = "refused_by_user" },
    calls: usize = 0,
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
        \\{"action":"net.fetch","ceiling":"allow","reason":"I have changed my mind"}
        ,
        \\{"action":"net.fetch","ceiling":"ask","reason":"a person could decide"}
        ,
    }, &session);

    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);

    try testing.expectEqual(@as(usize, 1), outcome.events);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expect(outcome.refused[2]);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "cannot take it back") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "net.fetch at most deny") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "nothing was lifted") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "authorised by somebody other than you") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "stop and say what is left") != null);

    try testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "net.fetch"));
    try testing.expectEqual(
        chock_policy.table.Decision.deny,
        ratchet.narrow(.allow, held, "net.fetch"),
    );
}

test "a widening proposal is put to somebody, and the refusal says it was weighed" {
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
    try testing.expectEqualStrings(ratchet.widen_action, judge.saw_action);
    try testing.expectEqualStrings(restrict_tool_name, judge.saw_tool);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "net.fetch") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "deny") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "ask") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawDetail(), "the task turned out to need one fetch") != null);
    try testing.expect(std.mem.indexOf(u8, judge.sawSummary(), "net.fetch") != null);

    try testing.expect(outcome.refused[1]);
    try testing.expectEqual(@as(usize, 1), outcome.events);
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "net.fetch"));

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "refused_by_review") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "A reviewer read this request") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "nothing was lifted") != null);
}

test "a widening somebody authorised is the one thing that lifts a promise" {
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
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "Somebody other than you") != null);

    try testing.expectEqual(@as(usize, 2), outcome.events);

    try testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);
    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.ask, ratchet.ceilingFor(held, "net.fetch"));
    try testing.expectEqual(
        chock_policy.table.Decision.ask,
        ratchet.narrow(.allow, held, "net.fetch"),
    );
}

test "a lift that names a wider pattern than the promise is refused before anybody is asked" {
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
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "under a different name") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "git.*") != null);

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "git.push"));
}

test "a promise applies at once when it narrows, and a session may narrow twice" {
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
        \\{"action":"git.push","ceiling":"deny","reason":"and nothing leaves this machine"}
        ,
        \\{"action":"git.commit","ceiling":"ask","reason":"saying it again"}
        ,
    }, &session);

    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);
    try testing.expectEqual(@as(usize, 2), outcome.events);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(!outcome.refused[1]);
    try testing.expect(!outcome.refused[2]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "Nothing changed") != null);

    try testing.expectEqual(@as(usize, 2), session.self_policy.restrictions.items.len);

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "git.push"));
    try testing.expectEqual(chock_policy.table.Decision.ask, ratchet.ceilingFor(held, "git.commit"));
    try testing.expectEqual(chock_policy.table.Decision.allow, ratchet.ceilingFor(held, "net.fetch"));
}

test "a promise cannot be lifted by naming a wider pattern than the one it was made about" {
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
        \\{"action":"git.*","ceiling":"allow","reason":"git should be fine after all"}
        ,
    }, &session);

    try testing.expect(!outcome.refused[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expectEqual(@as(usize, 1), outcome.events);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "gives up nothing") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "name exactly the action") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "git.push at most deny") != null);

    const held = try self_policy.restrictionsFrom(arena, session.self_policy.restrictions.items);
    try testing.expectEqual(chock_policy.table.Decision.deny, ratchet.ceilingFor(held, "git.push"));
    try testing.expectEqual(chock_policy.table.Decision.allow, ratchet.ceilingFor(held, "git.commit"));
}

test "a promise that binds nothing is refused, and nothing reaches the log" {
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

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "JSON object") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "is not a ceiling") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "name the action") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[3], "name the one you mean") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[4], "say why") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[5], "one to a line") != null);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"deny\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"allow\"") != null);
}

test "a session that never calls restrict_self promises nothing at all" {
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

    const held = try self_policy.restrictionsFrom(allocator, session.self_policy.restrictions.items);
    defer allocator.free(held);
    try testing.expectEqual(chock_policy.table.Decision.allow, ratchet.narrow(.allow, held, "git.push"));
}

const FakeFetcher = struct {
    allocator: std.mem.Allocator,
    page: []const u8 = "the page",
    calls: usize = 0,
    url: []u8 = &.{},
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
    try testing.expectEqual(chock_policy.table.Decision.deny, fake.ceiling);
}

test "a session with no fetcher reads nothing and says so" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runFetchSession(allocator, arena, io, &.{
        .{ .tool = fetch_tool_name, .arguments =
        \\{"url":"https://example.com/manual"}
        },
        .{ .tool = fetch_tool_name, .arguments = "not json at all" },
    }, null);

    try testing.expect(outcome.refused[0]);
    try testing.expectEqualStrings(fetch_mod.has_no_fetcher, outcome.outputs[0]);
    try testing.expect(outcome.refused[1]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"url\"") != null);
}

const FakeHandback = struct {
    allocator: std.mem.Allocator,
    result: handback_mod.Result = .{ .carried = false, .output = &.{} },
    text: []const u8 = "nothing was carried back",
    carried: bool = false,
    calls: usize = 0,
    reason: []u8 = &.{},
    call_id: []u8 = &.{},

    fn deinit(self: *FakeHandback) void {
        self.allocator.free(self.reason);
        self.allocator.free(self.call_id);
    }

    fn handback(self: *FakeHandback) handback_mod.Handback {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = handback_mod.Handback.VTable{ .apply = applyFn };

    fn applyFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *handback_mod.Locked,
        ask: handback_mod.Ask,
    ) std.mem.Allocator.Error!handback_mod.Result {
        _ = io;
        _ = locked;
        const self: *FakeHandback = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.allocator.free(self.reason);
        self.reason = try self.allocator.dupe(u8, ask.reason);
        self.allocator.free(self.call_id);
        self.call_id = try self.allocator.dupe(u8, ask.tool_call_id);
        return .{ .carried = self.carried, .output = try gpa.dupe(u8, self.text) };
    }
};

fn runRequestSession(
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    calls: []const struct { tool: []const u8, arguments: []const u8 },
    seam: ?handback_mod.Handback,
) !FetchRun {
    var backing = try chock_proto.storage.Memory.init(allocator, "01ASKEDRUN");
    const store = backing.storage();
    defer store.close(io);

    const turns = try arena.alloc(FakeTurn, calls.len + 1);
    for (calls, 0..) |one, index| {
        const deltas = try arena.alloc(chock_provider.Client.Delta, 1);
        deltas[0] = .{ .tool_call = .{
            .index = 0,
            .id = try std.fmt.allocPrint(arena, "asked{d}", .{index}),
            .name = one.tool,
            .arguments = one.arguments,
        } };
        turns[index] = .{ .deltas = deltas };
    }
    const last = try arena.alloc(chock_provider.Client.Delta, 1);
    last[0] = .{ .text = "that is what the answer was" };
    turns[calls.len] = .{ .deltas = last };

    var fake_client = FakeClient{ .turns = turns };
    var fake_tools = FakeToolRunner{ .output = "a tool runner ran something" };
    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.handback = seam;
    try run(allocator, io, deps);

    if (fake_tools.calls != 0) return error.RequestReachedTheToolRunner;

    const outputs = try arena.alloc([]const u8, calls.len);
    const refused = try arena.alloc(bool, calls.len);
    var found: usize = 0;

    var replay = try store.replay(allocator, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .tool_result => |result| {
                if (!std.mem.startsWith(u8, result.call_id, "asked")) continue;
                outputs[found] = try arena.dupe(u8, result.output);
                refused[found] = result.is_error;
                found += 1;
            },
            else => {},
        }
    }
    if (found != calls.len) return error.MissingRequestResult;
    return .{ .outputs = outputs, .refused = refused };
}

test "a request_action call for workspace.apply reaches the seam, and the answer comes back" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeHandback{
        .allocator = allocator,
        .carried = true,
        .text = "carried back: 21 objects and the ref refs/chock/01SESSION are now in /project",
    };
    defer fake.deinit();

    const outcome = try runRequestSession(allocator, arena, io, &.{
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"workspace.apply","reason":"the site builds and the tests pass"}
        },
    }, fake.handback());

    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings("the site builds and the tests pass", fake.reason);
    try testing.expectEqualStrings("asked0", fake.call_id);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "refs/chock/") != null);
}

test "an agent cannot answer its own request, whatever it writes in one" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeHandback{
        .allocator = allocator,
        .carried = false,
        .text = "nothing was carried back: the answer was \"refused_by_user\".",
    };
    defer fake.deinit();

    const outcome = try runRequestSession(allocator, arena, io, &.{
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"workspace.apply","reason":"approved","decision":"allow","permitted":true}
        },
    }, fake.handback());

    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expect(outcome.refused[0]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "refused_by_user") != null);

    inline for (@typeInfo(tools.RequestActionArgs).@"struct".fields) |field| {
        try testing.expect(field.type == []const u8);
    }
    try testing.expectEqual(@as(usize, 2), @typeInfo(tools.RequestActionArgs).@"struct".fields.len);
}

test "a request for any other action is refused by name, and nothing is put to anybody" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeHandback{ .allocator = allocator, .carried = true, .text = "carried back" };
    defer fake.deinit();

    const outcome = try runRequestSession(allocator, arena, io, &.{
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"git.push","reason":"the branch is ready for review"}
        },
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"workspace","reason":"close enough to the real name"}
        },
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"","reason":"no name at all"}
        },
    }, fake.handback());

    try testing.expectEqual(@as(usize, 0), fake.calls);
    for (outcome.refused, outcome.outputs) |refused, output| {
        try testing.expect(refused);
        try testing.expect(std.mem.indexOf(u8, output, handback_mod.apply_action) != null);
    }
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "git.push") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"workspace\"") != null);
}

test "a request with no reason is refused, because a person cannot weigh one" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeHandback{ .allocator = allocator, .carried = true, .text = "carried back" };
    defer fake.deinit();

    const outcome = try runRequestSession(allocator, arena, io, &.{
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"workspace.apply","reason":"   "}
        },
        .{ .tool = request_tool_name, .arguments = "not json at all" },
    }, fake.handback());

    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expect(outcome.refused[0]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "why the work is ready") != null);
    try testing.expect(outcome.refused[1]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"action\"") != null);
}

test "a session with no handback carries nothing and says nobody was asked" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runRequestSession(allocator, arena, io, &.{
        .{ .tool = request_tool_name, .arguments =
        \\{"action":"workspace.apply","reason":"the work is done"}
        },
    }, null);

    try testing.expect(outcome.refused[0]);
    try testing.expectEqualStrings(handback_mod.not_offered, outcome.outputs[0]);
}

const FakeAsker = struct {
    allocator: std.mem.Allocator,
    kind: std.meta.Tag(ask_mod.Answer) = .answered,
    said: []const u8 = "use the staging database",
    calls: usize = 0,
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
        // forgotten here fails the build rather than going untested.
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

    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings("which database should I write to?", fake.question);
    try testing.expectEqual(@as(usize, 2), fake.options);

    try testing.expect(!outcome.refused[0]);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "use the staging database") != null);
    try testing.expect(std.mem.startsWith(u8, outcome.outputs[0], "[chock: the user answered.]"));

    try testing.expectEqual(@as(usize, 0), outcome.approvals);
}

test "a session with nobody to ask says so at once and does not stall" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runAskSession(allocator, arena, io, &.{
        \\{"question":"which database should I write to?"}
        ,
        "not json at all",
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
        try testing.expectEqual(case.kind != .declined, outcome.refused[0]);
    }
}

const TitleRun = struct {
    outputs: []const []const u8,
    refused: []const bool,
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
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try runTitleSession(allocator, arena, io, &.{
        \\{"title":"port the parser to the new lexer"}
    });

    try testing.expect(!outcome.refused[0]);
    try testing.expectEqual(@as(usize, 1), outcome.written.len);
    try testing.expectEqualStrings("port the parser to the new lexer", outcome.written[0]);
    try testing.expect(std.mem.indexOf(
        u8,
        outcome.outputs[0],
        "This session is now called: port the parser to the new lexer",
    ) != null);

    const trimmed = try runTitleSession(allocator, arena, io, &.{
        \\{"title":"  port the parser to the new lexer \t"}
    });
    try testing.expectEqualStrings("port the parser to the new lexer", trimmed.written[0]);
}

test "a later title supersedes an earlier one, and the log still holds both" {
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
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "again") != null);
}

test "a title that is not one short line of plain text is refused and nothing is written" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const long = "e" ** (max_title_bytes + 1);
    const too_long = try std.fmt.allocPrint(arena, "{{\"title\":\"{s}\"}}", .{long});

    const cases = [_][]const u8{
        \\{"title":""}
        ,
        \\{"title":"   "}
        ,
        \\{"steps":[]}
        ,
        too_long,
        \\{"title":"read the tests\n01M0TMATKB6M4H3GY35KYA68QR  finished"}
        ,
        // Written as JSON escapes, so the real bytes reach the check and this source
        // file stays plain text.
        \\{"title":"read \u001b[2J the tests \u0007"}
        ,
    };
    const outcome = try runTitleSession(allocator, arena, io, &cases);

    try testing.expectEqual(@as(usize, 0), outcome.written.len);
    for (outcome.refused) |one| try testing.expect(one);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "was empty") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "was empty") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[2], "\"title\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[3], "longer than") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[4], "one line") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[5], "control character") != null);

    const at_bound = "e" ** max_title_bytes;
    const allowed = try std.fmt.allocPrint(arena, "{{\"title\":\"{s}\"}}", .{at_bound});
    const kept = try runTitleSession(allocator, arena, io, &.{allowed});
    try testing.expect(!kept.refused[0]);
    try testing.expectEqual(@as(usize, 1), kept.written.len);

    try testing.expect(titleRefusalText("\xff\xfe name") != null);
    try testing.expect(titleRefusalText("an ordinary name") == null);
}

test "a compaction puts the task list back in front of the model, and only when there is one" {
    const allocator = testing.allocator;
    const io = testing.io;

    const plan_arguments =
        "{\"steps\":[" ++
        "{\"id\":\"read\",\"subject\":\"read the fold\",\"status\":\"in_progress\"}," ++
        "{\"id\":\"fix\",\"subject\":\"fix the width count\",\"status\":\"pending\"}," ++
        "{\"id\":\"old\",\"subject\":\"work that is finished\",\"status\":\"done\"}]}";

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
                .{ .deltas = &.{
                    .{ .tool_call = .{ .index = 0, .id = "call1", .name = "run_command", .arguments = "{}" } },
                    .{ .usage = .{ .input_tokens = 60000 } },
                } },
                .{ .deltas = &.{.{ .text = "SUMMARY" }} },
                .{ .deltas = &.{.{ .text = "all done" }} },
            },
        };
        var fake_tools = FakeToolRunner{ .output = "ok" };

        var deps = testDeps(fake_client.client(), store, fake_tools.runner());
        deps.compaction = .{ .context_limit_tokens = 65536 };
        try run(allocator, io, deps);

        var found = (try firstCompaction(allocator, io, store)).?;
        defer found.deinit(allocator);

        try testing.expect(seen.anyTailHolds("folded into a summary"));
        try testing.expect(seen.anyTailHolds("read the fold"));
        try testing.expect(seen.anyTailHolds("fix the width count"));
        try testing.expect(!seen.anyTailHolds("work that is finished"));

        var replay = try store.replay(allocator, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            const line = try std.json.Stringify.valueAlloc(allocator, parsed.value.event, .{});
            defer allocator.free(line);
            try testing.expect(std.mem.indexOf(u8, line, "folded into a summary") == null);
        }
    }

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
    var spawner = FakeSpawner{};

    var deps = testDeps(fake_client.client(), store, fake_tools.runner());
    deps.role = .arbitrator;
    deps.spawner = spawner.spawner();
    deps.subagents = .{ .max_depth = 6, .max_width = 6 };
    try run(allocator, io, deps);

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
    try testing.expectEqual(@as(usize, 4), refusals);
    try testing.expect(session.plan.isEmpty());
    try testing.expectEqual(@as(usize, 0), session.self_policy.restrictions.items.len);
    try testing.expectEqual(@as(usize, 0), session.children.items.len);
}

test "a worker with the same session runs every one of those four calls" {
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

    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);
    try testing.expectEqual(@as(usize, 2), outcome.events);
    try testing.expect(!outcome.refused[0]);
    try testing.expect(!outcome.refused[1]);

    try testing.expectEqual(@as(usize, 5), outcome.written_steps);

    try testing.expectEqual(@as(usize, 3), session.plan.steps.items.len);
    try testing.expectEqual(event.PlanStatus.done, std.meta.activeTag(session.plan.find("s1").?.status));
    try testing.expectEqual(event.PlanStatus.in_progress, std.meta.activeTag(session.plan.find("s2").?.status));
    try testing.expectEqual(event.PlanStatus.pending, std.meta.activeTag(session.plan.find("s3").?.status));
    try testing.expectEqualStrings("s2", session.plan.find("s3").?.blocked_by);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "measure it on Darwin") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "2 of 3 left to do") != null);
}

test "a step the agent stops naming stays on the list, and only abandoned takes it off" {
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
        \\{"steps":[{"id":"s1","subject":"port the driver","status":"done"},
        \\{"id":"s3","subject":"rewrite the build script","status":"abandoned"}]}
        ,
    }, &session);
    try testing.expectEqual(@as(usize, 2), outcome.events);

    try testing.expectEqual(@as(usize, 3), session.plan.steps.items.len);
    const dropped = session.plan.find("s3").?;
    try testing.expectEqual(event.PlanStatus.abandoned, std.meta.activeTag(dropped.status));
    try testing.expect(dropped.status != .done);
    try testing.expectEqual(event.PlanStatus.pending, std.meta.activeTag(session.plan.find("s2").?.status));

    const counts = session.plan.counts();
    try testing.expectEqual(@as(usize, 1), counts.done);
    try testing.expectEqual(@as(usize, 1), counts.abandoned);
    try testing.expectEqual(@as(usize, 1), counts.left());
}

test "a call that repeats the list unchanged appends nothing, and is not an error" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const same = "{\"steps\":[{\"id\":\"s1\",\"subject\":\"read the fold\",\"status\":\"pending\"}]}";
    const outcome = try runPlanSession(allocator, arena, io, &.{ same, same }, &session);

    try testing.expectEqual(@as(usize, 1), outcome.events);
    try testing.expectEqual(@as(usize, 1), outcome.written_steps);
    for (outcome.refused) |one| try testing.expect(!one);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "already this") != null);
    try testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
}

test "a call this loop cannot record changes nothing, and says so as an error" {
    const allocator = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = chock_proto.state.Session.init(allocator);
    defer session.deinit();

    const outcome = try runPlanSession(allocator, arena, io, &.{
        "{\"steps\":[{\"id\":\"s1\",\"subject\":\"ship it\",\"status\":\"dnoe\"}]}",
        "{\"steps\":[{\"id\":\"\",\"subject\":\"ship it\",\"status\":\"pending\"}]}",
        "{\"steps\":[]}",
        "{\"steps\":\"read the fold\"}",
        "{\"steps\":[{\"id\":\"s1\",\"subject\":\"read the fold\\nand the log\",\"status\":\"pending\"}]}",
    }, &session);

    for (outcome.refused) |one| try testing.expect(one);
    try testing.expectEqual(@as(usize, 0), outcome.events);
    try testing.expect(session.plan.isEmpty());
    try testing.expectEqual(@as(usize, 0), outcome.runner_calls);

    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "\"pending\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[0], "dnoe") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[1], "\"id\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[3], "\"steps\"") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.outputs[4], "one to a line") != null);
}

test "a plan longer than the bound is refused whole, and leaves the list it had" {
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
    try testing.expectEqual(@as(usize, 1), session.plan.steps.items.len);
    try testing.expectEqualStrings("the one real step", session.plan.steps.items[0].subject);
}
