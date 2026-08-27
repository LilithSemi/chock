//! What the harness knows and the model cannot: the facts the loop computes
//! exactly and a model can only estimate. See `chock-plan-14-guidance`, the
//! section "the part a prompt cannot do".
//!
//! The rule that decides what belongs here is one question with two halves:
//! **can the loop know this for certain, and would the model have to guess?**
//! If both, it belongs. If the loop is also guessing, it does not, and a
//! notice built on a guess is worse than no notice at all, because it fires on
//! a session that was working.
//!
//! ## Why this is not in the system prompt, and what it costs to get wrong
//!
//! **A provider's cache keys on a stable prefix.** A value that changes every
//! turn, put at the front, invalidates that cache every turn, and the bill
//! lands on exactly the long sessions these notices exist to help.
//! `chock_proto.event.Usage.cache_read_input_tokens` is the number that would
//! go to zero.
//!
//! So a notice goes at the **end** of the context, as one message that stands
//! in place of the previous one, and the system prompt is not touched at all.
//! `Loop.zig` pins that with a test: the system prompt is byte identical
//! across two turns that carry different notices.
//!
//! ## A notice that fires always is noise, and one that never fires is dead
//!
//! Every notice below has a trigger, and the trigger is the whole design. The
//! block is built new each turn from the facts that apply now, and a turn with
//! no applicable fact gets no message at all. See `State`, which holds what
//! each notice has already said, so that a notice says it once and not on
//! every turn after.
//!
//! ## The clock is injected and is never read here
//!
//! `Policy.clock` is a seam, the same one `chock_provider.retry.Sleeper` and
//! `chock_broker.Broker.Waiter` are, and for the same reason: **no test in
//! this file reads a wall clock.** Every duration and every stamp in the tests
//! below comes from a number the test itself chose, so a test that passes on a
//! fast machine passes on a slow one and passes in a year.

const std = @import("std");

pub const Error = std.mem.Allocator.Error;

/// Reads the real world clock. See this file's own top comment: injected, so
/// that a test names the time it wants rather than measuring the one it got.
pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowMs: *const fn (ctx: ?*anyopaque) i64,
    /// Minutes east of UTC where the person running this session is. Zero is
    /// UTC itself, and it is also the honest answer when the offset could not
    /// be read: a wrong offset is worse than none, because the question a
    /// local time answers is whether somebody is awake.
    ///
    /// **Both times are carried in one string.** Whether a person is asleep is
    /// a local question and correlating with a log is a UTC one, and a model
    /// that has to subtract two numbers to get the second one gets it wrong
    /// silently.
    utc_offset_minutes: i32 = 0,

    pub fn now(self: Clock) i64 {
        return self.nowMs(self.ctx);
    }
};

/// When each notice fires. Every number here is a trigger, and a trigger is
/// what keeps this from becoming a long prompt by another route.
pub const Policy = struct {
    /// Whether the loop injects any notice at all. **A real switch, and it is
    /// what the measurement needs**: the claim that guidance makes a small
    /// model better is a claim to measure, and a measurement needs the off
    /// side as well as the on side. `chock run --no-notices` sets this false.
    enabled: bool = true,

    /// How many times one identical call must have been made before the agent
    /// is told about it.
    ///
    /// **Two, and not three, because a notice that arrives with the stop has
    /// already failed.** `Loop.no_progress_repeats` ends a session at the
    /// third identical call. The red team run of 2026-08-21 called `readlink
    /// -f` on the same four paths sixteen times and nothing told it. This is
    /// the cheaper intervention that might prevent that stop, and it can only
    /// prevent a third call by arriving before one.
    repeat_at: usize = 2,

    /// How many turns pass before the task is put in front of the agent
    /// again. **Not on the first turns**: the task is the first message and it
    /// is right there. A small model's attention decays across a long
    /// conversation, and the first message is the one it can least afford to
    /// lose.
    goal_every_turns: usize = 8,

    /// How long before the time is stated again. Fifteen minutes: a model that
    /// was told the time two minutes ago can still reason with it, and a
    /// session that restated it every turn would be the every turn tail this
    /// design exists to avoid.
    restate_time_after_ms: i64 = 15 * 60 * 1000,

    /// The size of one budget step, in percent. The spend is reported when it
    /// crosses a new step and never again inside the same one, so a session
    /// hears about its money four times rather than on every turn.
    budget_step_percent: u8 = 25,

    /// Reads the clock, and says which offset a local time is stated in.
    ///
    /// **Null leaves the time notice out entirely.** A caller that cannot read
    /// a clock, or a test that does not want one, says nothing about the time
    /// rather than guessing at it. Every other notice still fires: none of
    /// them is about the time.
    clock: ?Clock = null,
};

/// The largest amount of the task that is repeated back. A task longer than
/// this is cut, and the cut is said out loud, so a model never acts on half a
/// sentence believing it read the whole one.
pub const goal_max_bytes: usize = 400;

/// How many steps of the task list are named after a compaction. A list longer
/// than this is cut and the number left out is said, so the notice stays one
/// short block rather than becoming the whole plan again.
pub const plan_steps_shown: usize = 12;

/// One step of the agent's own task list that is not finished.
///
/// **A shape of this file's own, and not `chock_proto.state.Plan.Step`.** This
/// file imports nothing but `std`, which is what lets every test below build
/// the exact facts it wants with no log, no fold and no event. `Loop.zig` is
/// what reads a `Plan` and fills these in.
pub const Step = struct {
    /// The identifier the agent gave the step and reuses to change it.
    id: []const u8,
    /// The subject, in the imperative, in the agent's own words.
    subject: []const u8,
    /// The status word, from `chock_proto.event.PlanStatus.wireName`. Carried
    /// as text so this file needs no copy of that union.
    status: []const u8,
};

/// The prefix on every notice line. The same one
/// `lib/chock-core/compaction.zig` already uses for the compaction warning:
/// **the harness is speaking, not the user**, and one mark for that across the
/// whole product is one thing for a model to learn instead of two.
pub const prefix = "[chock] ";

/// One call the agent made, kept until the next turn can be told about it.
const Call = struct {
    tool: []u8,
    arguments: []u8,
    repeats: usize,

    fn deinit(self: Call, allocator: std.mem.Allocator) void {
        allocator.free(self.tool);
        allocator.free(self.arguments);
    }
};

/// What the notices remember between turns. One per session, held by
/// `Loop.run` beside `Progress` and freed with it.
///
/// **Two different kinds of memory live here, and they are not the same
/// thing.** The `..._shown` fields are what has already been said, and they
/// are what stops a notice from firing on every turn. `last_call` and
/// `unchanged_read` are facts waiting for the turn that can use them: a fact
/// found while a turn was running is only useful to the turn after it, and
/// `render` consumes it there.
pub const State = struct {
    /// When the session's first event was written, in real time milliseconds.
    /// Null until an event has been seen, which is only true of a log with
    /// nothing in it at all.
    started_ms: ?i64 = null,
    /// When the agent last produced a message of its own.
    last_spoke_ms: ?i64 = null,

    /// When the time was last stated. Null when it never has been.
    time_shown_ms: ?i64 = null,
    /// The turn on which the task was last restated.
    goal_shown_turn: ?usize = null,
    /// The highest budget step already reported. Zero before any.
    budget_step_shown: u8 = 0,
    /// Whether the uncommitted files have been named. That count does not
    /// change during a session, so it is said once.
    uncommitted_shown: bool = false,

    /// A compaction happened and the turn after it has not been told yet.
    ///
    /// **A fact waiting for a turn, like `last_call` below, and not a record of
    /// something already said.** The compaction is what arms this; whether
    /// anything is said depends on the plan the turn carries, and `render`
    /// consumes it either way. See `renderCompactedPlan`.
    compacted: bool = false,

    /// The last tool call of the turn just finished, and how many of the last
    /// few calls were the same one. Owned.
    last_call: ?Call = null,
    /// The path of a file the turn just finished read again with no change in
    /// it. Owned.
    unchanged_read: ?[]u8 = null,
    /// How many such files that turn had. **One turn can ask for many reads**,
    /// and a real session against `glm4.7-flash:A3B` re-read six files in one
    /// turn: a notice naming only the last of them would understate what
    /// happened by a factor of six.
    unchanged_count: usize = 0,

    /// Every file read so far, and the `file_hash` its last read reported.
    /// Both key and value are owned.
    ///
    /// **The hash is what makes the notice trustworthy, and the negative case
    /// is why.** Saying "unchanged" about a file that did change would send a
    /// model on with a stale copy, which is a worse fault than the re-read
    /// this notice exists to stop. `read_file` already prints the hash for
    /// `edit_file` to anchor on, so this costs no extra work at all.
    reads: std.StringHashMapUnmanaged([]u8) = .empty,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        if (self.last_call) |call| call.deinit(allocator);
        if (self.unchanged_read) |path| allocator.free(path);
        var it = self.reads.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.reads.deinit(allocator);
        self.* = undefined;
    }

    /// Record one event's time. Called for every event, both the ones a replay
    /// folds in at the start of a session and the ones the loop appends as it
    /// goes, so a resumed session knows when it really started rather than
    /// when it was picked up again.
    pub fn observeEvent(self: *State, time_ms: i64, is_agent_message: bool) void {
        if (self.started_ms == null) self.started_ms = time_ms;
        if (is_agent_message) self.last_spoke_ms = time_ms;
    }

    /// Record that the context was just folded into a summary. See
    /// `renderCompactedPlan`.
    pub fn observeCompaction(self: *State) void {
        self.compacted = true;
    }

    /// Record one tool call the agent just made, with how many of the last few
    /// calls were this same one. `repeats` is `Loop.Observation.repeats`, the
    /// number the no progress detector already computes.
    pub fn observeCall(
        self: *State,
        allocator: std.mem.Allocator,
        tool: []const u8,
        arguments: []const u8,
        repeats: usize,
    ) Error!void {
        const owned_tool = try allocator.dupe(u8, tool);
        errdefer allocator.free(owned_tool);
        const owned_arguments = try allocator.dupe(u8, arguments);
        errdefer allocator.free(owned_arguments);

        if (self.last_call) |old| old.deinit(allocator);
        self.last_call = .{ .tool = owned_tool, .arguments = owned_arguments, .repeats = repeats };
    }

    /// Record one `read_file` result: which path was read and what hash it
    /// reported.
    ///
    /// **The whole notice is decided here, and the negative case is half of
    /// it.** A path read for the first time records its hash and says nothing.
    /// A path read again with the same hash arms the notice. A path read again
    /// with a different hash records the new hash and arms nothing, because
    /// the file did change and the model is right to have read it.
    pub fn observeRead(
        self: *State,
        allocator: std.mem.Allocator,
        path: []const u8,
        hash: []const u8,
    ) Error!void {
        const found = try self.reads.getOrPut(allocator, path);
        if (!found.found_existing) {
            found.key_ptr.* = allocator.dupe(u8, path) catch |err| {
                _ = self.reads.remove(path);
                return err;
            };
            found.value_ptr.* = allocator.dupe(u8, hash) catch |err| {
                allocator.free(found.key_ptr.*);
                _ = self.reads.remove(path);
                return err;
            };
            return;
        }

        const same = std.mem.eql(u8, found.value_ptr.*, hash);
        if (!same) {
            const fresh = try allocator.dupe(u8, hash);
            allocator.free(found.value_ptr.*);
            found.value_ptr.* = fresh;
            return;
        }

        const owned = try allocator.dupe(u8, path);
        if (self.unchanged_read) |old| allocator.free(old);
        self.unchanged_read = owned;
        self.unchanged_count += 1;
    }

    /// Drop every fact waiting for a turn that will not use it. Called when
    /// notices are off, so that a session with them off never grows a queue of
    /// things nobody reads.
    fn dropPending(self: *State, allocator: std.mem.Allocator) void {
        self.compacted = false;
        if (self.last_call) |call| {
            call.deinit(allocator);
            self.last_call = null;
        }
        if (self.unchanged_read) |path| {
            allocator.free(path);
            self.unchanged_read = null;
            self.unchanged_count = 0;
        }
    }
};

/// Everything about one turn the notices read that `State` does not already
/// hold. Built by `Loop.runTurn` from the fold and from `Deps`.
pub const Turn = struct {
    /// How many turns have already run in this call to `Loop.run`. Zero on the
    /// first one.
    index: usize = 0,
    /// The real world time now, from the injected clock.
    now_ms: i64 = 0,
    /// The task, word for word: the first `user` message of the fold. Empty
    /// when the session has none, which is true of a log that starts with
    /// something else.
    goal: []const u8 = "",
    /// How much of the budget is spent, in whole percent. Null when there is
    /// no cap, or when the total cannot be enforced at all: see
    /// `chock_proto.state.Spend.enforceable`. A percentage of a number Chock
    /// cannot measure is a made up number.
    spent_percent: ?u8 = null,
    /// How many files in the user's own project are not committed, and so are
    /// not in the agent's copy. Zero for a clean tree, and zero for an overlay
    /// workspace, which copies the whole directory and hides nothing.
    uncommitted_files: usize = 0,
    /// The steps of the agent's own task list that are neither done nor
    /// abandoned, in the order the fold holds them. **Empty for every session
    /// whose agent never wrote a list**, which is what keeps the notice that
    /// reads it from firing on a session that has nothing to be reminded of.
    /// See `renderCompactedPlan`.
    unfinished_plan: []const Step = &.{},
};

/// Build this turn's notice, or null when no fact applies to this turn.
///
/// The caller owns the result and frees it with `allocator.free`. It is one
/// message, and it goes at the **end** of the context: see this file's own top
/// comment on the cache.
///
/// **`allocator` must be the one `state` was built with.** This call frees the
/// facts it consumes, and a turn arena passed here would free nothing and leak
/// every one of them.
pub fn render(
    allocator: std.mem.Allocator,
    policy: Policy,
    state: *State,
    turn: Turn,
) Error!?[]u8 {
    if (!policy.enabled) {
        state.dropPending(allocator);
        return null;
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try renderTime(allocator, &out, policy, state, turn);
    try renderGoal(allocator, &out, policy, state, turn);
    try renderCompactedPlan(allocator, &out, state, turn);
    try renderBudget(allocator, &out, policy, state, turn);
    try renderUncommitted(allocator, &out, state, turn);
    try renderUnchangedRead(allocator, &out, state);
    try renderRepeat(allocator, &out, policy, state);

    if (out.items.len == 0) {
        out.deinit(allocator);
        return null;
    }
    return try out.toOwnedSlice(allocator);
}

fn renderTime(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    policy: Policy,
    state: *State,
    turn: Turn,
) Error!void {
    const clock = policy.clock orelse return;
    if (state.time_shown_ms) |shown| {
        if (turn.now_ms - shown < policy.restate_time_after_ms) return;
    }

    var stamp_buf: [stamp_bytes]u8 = undefined;
    var utc_buf: [stamp_bytes]u8 = undefined;
    const local = writeStamp(&stamp_buf, turn.now_ms, clock.utc_offset_minutes);

    try out.appendSlice(allocator, prefix ++ "The time is now ");
    try out.appendSlice(allocator, local);
    if (clock.utc_offset_minutes != 0) {
        try out.appendSlice(allocator, ", which is ");
        try out.appendSlice(allocator, writeUtcStamp(&utc_buf, turn.now_ms, clock.utc_offset_minutes));
    }
    try out.append(allocator, '.');

    if (state.started_ms) |started| {
        const age_ms = turn.now_ms - started;
        if (age_ms >= min_session_age_ms) {
            var age_buf: [duration_bytes]u8 = undefined;
            try out.appendSlice(allocator, " This session started ");
            try out.appendSlice(allocator, writeDuration(&age_buf, age_ms));
            try out.appendSlice(allocator, " ago.");
        }
    }
    if (state.last_spoke_ms) |spoke| {
        var gap_buf: [duration_bytes]u8 = undefined;
        try out.appendSlice(allocator, " You last spoke ");
        try out.appendSlice(allocator, writeDuration(&gap_buf, turn.now_ms - spoke));
        try out.appendSlice(allocator, " ago.");
    }
    try out.append(allocator, '\n');

    state.time_shown_ms = turn.now_ms;
}

fn renderGoal(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    policy: Policy,
    state: *State,
    turn: Turn,
) Error!void {
    if (turn.goal.len == 0) return;
    if (policy.goal_every_turns == 0) return;
    const since = if (state.goal_shown_turn) |shown| turn.index -| shown else turn.index;
    if (since < policy.goal_every_turns) return;

    const kept = cutToCharacter(turn.goal, goal_max_bytes);
    try out.appendSlice(allocator, prefix ++ "The task you were given at the start of this session: ");
    try out.appendSlice(allocator, kept);
    if (kept.len != turn.goal.len) try out.appendSlice(allocator, " [chock: the task is longer than this]");
    try out.append(allocator, '\n');

    state.goal_shown_turn = turn.index;
}

/// Put the agent's own task list back in front of it after a compaction folded
/// it away.
///
/// **The list survives a compaction for the reader and not for the model**, and
/// that asymmetry is what this closes. `chock_proto.state.Plan` is a fold over
/// the log, so `chock plan` and the terminal are right whatever is folded. The
/// only place the model ever saw its list was the tool result of its own
/// `update_plan` call, and a compaction can fold exactly that away. An agent
/// then carries on with no idea what it had planned, which is the failure the
/// task list was built to prevent.
///
/// **The trigger never fires for a session that keeps no list.** A session
/// whose agent never called `update_plan` has an empty plan, and one whose
/// steps are all done or abandoned has nothing unfinished, so both read the
/// compaction and say nothing. That is the property this notice needs to earn
/// its place: this project has learned twice that a notice which always fires
/// stops being read.
///
/// **The compaction is consumed whether or not anything is said**, the same way
/// `renderRepeat` consumes its call. The fact is about the fold that just
/// happened, and a fold nobody had a use for is not a fold saved up for later.
fn renderCompactedPlan(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    state: *State,
    turn: Turn,
) Error!void {
    if (!state.compacted) return;
    state.compacted = false;
    if (turn.unfinished_plan.len == 0) return;

    try out.appendSlice(
        allocator,
        prefix ++ "The conversation so far was folded into a summary, so the task list you kept " ++
            "is no longer in front of you. These steps of it are not finished:\n",
    );
    const shown = @min(turn.unfinished_plan.len, plan_steps_shown);
    for (turn.unfinished_plan[0..shown]) |step| {
        try out.print(allocator, prefix ++ "  {s} ({s}): {s}\n", .{ step.id, step.status, step.subject });
    }
    if (turn.unfinished_plan.len > shown) {
        try out.print(
            allocator,
            prefix ++ "  and {d} more, which update_plan still holds.\n",
            .{turn.unfinished_plan.len - shown},
        );
    }
    try out.appendSlice(
        allocator,
        prefix ++ "Carry on from these. Call update_plan when one starts or finishes, and mark a " ++
            "step \"abandoned\" if you decided against it.\n",
    );
}

/// The front of `text`, at most `limit` bytes, cut on a character and never
/// in the middle of one.
///
/// **A cut in the middle of a character is not text.** A task written in
/// Japanese, or one with an emoji in it, is three bytes per character, and half
/// of one serializes as a JSON array rather than a JSON string, which is the
/// exact fault `chock_core.tools.outputForModel` exists to catch one level
/// down. See its own doc comment.
///
/// **Public because `lib/chock-core/lsp.zig` bounds a diagnostic message with
/// the same rule.** A second copy of this is how two cuts quietly stop agreeing
/// about where a character begins.
pub fn cutToCharacter(text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;
    var at = limit;
    // A continuation byte is 0b10xxxxxx, so walking back over them lands on
    // the first byte of the character the cut fell inside.
    while (at > 0 and text[at] & 0xC0 == 0x80) at -= 1;
    return text[0..at];
}

fn renderBudget(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    policy: Policy,
    state: *State,
    turn: Turn,
) Error!void {
    const percent = turn.spent_percent orelse return;
    if (policy.budget_step_percent == 0) return;
    const step: u8 = @intCast(@min(@as(usize, 255), percent / policy.budget_step_percent));
    if (step == 0 or step <= state.budget_step_shown) return;

    try out.print(
        allocator,
        prefix ++ "You have spent {d} percent of the money this session may cost.\n",
        .{percent},
    );
    state.budget_step_shown = step;
}

fn renderUncommitted(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    state: *State,
    turn: Turn,
) Error!void {
    if (turn.uncommitted_files == 0 or state.uncommitted_shown) return;
    try out.print(
        allocator,
        prefix ++ "{d} files in the user's own project are not committed, so your copy does not " ++
            "hold them. Do not look for that work, and do not write it again.\n",
        .{turn.uncommitted_files},
    );
    state.uncommitted_shown = true;
}

fn renderUnchangedRead(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    state: *State,
) Error!void {
    const path = state.unchanged_read orelse return;
    const count = state.unchanged_count;
    defer {
        allocator.free(path);
        state.unchanged_read = null;
        state.unchanged_count = 0;
    }

    if (count <= 1) {
        try out.print(
            allocator,
            prefix ++ "You read {s} again and the file did not change between the two reads. Use " ++
                "the copy you already have.\n",
            .{path},
        );
        return;
    }
    try out.print(
        allocator,
        prefix ++ "You read {d} files again and not one of them changed, the last of them {s}. " ++
            "Use the copies you already have.\n",
        .{ count, path },
    );
}

fn renderRepeat(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    policy: Policy,
    state: *State,
) Error!void {
    const call = state.last_call orelse return;
    defer {
        call.deinit(allocator);
        state.last_call = null;
    }
    if (call.repeats < policy.repeat_at) return;

    try out.print(
        allocator,
        prefix ++ "You have already called {s} with these exact arguments {d} times: {s}. The " ++
            "answer will not change. Use what it gave you, or do something different.\n",
        .{ call.tool, call.repeats, call.arguments },
    );
}

/// The room one timestamp needs, for example "2026-08-21 14:03:57 +02:00".
/// Exact, because both numbers in it are bounded: see `last_second` and
/// `max_offset_minutes`.
pub const stamp_bytes: usize = 26;

/// The last moment this writes, 9999-12-31 23:59:59 UTC.
///
/// **A bound, and not a formality.** `std.time.epoch.EpochDay` counts years up
/// from 1970 one at a time, in a `u16`, so a clock reporting a number far past
/// any real date does not print a strange year: it runs until that counter
/// wraps. A clock is a runtime fault and never a programmer error, so this is
/// clamped rather than asserted.
const last_second: u64 = 253402300799;

/// The largest offset from UTC this states, in minutes. A real zone is inside
/// one day of UTC. The value is read from the machine's own zone database, so
/// it is input like any other and it is bounded like any other.
const max_offset_minutes: i32 = 24 * 60;

/// The shortest session age this notice states.
///
/// **"This session started less than a second ago" is true and useless.** It
/// was the first line of the first turn of every session Chock ran. The model
/// already knows it is on the first turn, because the conversation in front of
/// it holds one message. A number nobody can act on is what teaches a reader to
/// skip the line, and the lines under it are the ones that matter.
///
/// The gap since the agent last spoke keeps no such floor. That gap is how long
/// the tool call it just made took, which is a fact the model has no other way
/// to get.
const min_session_age_ms: i64 = 60 * 1000;

/// The offset held inside the range this file states, in minutes.
fn boundedOffset(offset_minutes: i32) i32 {
    return std.math.clamp(offset_minutes, -max_offset_minutes, max_offset_minutes);
}

/// The second this moment falls on in the zone `offset_minutes` names.
///
/// A moment before 1970 is not a session Chock ran, it is a clock that is
/// wrong. Clamping at both ends keeps the arithmetic that follows inside the
/// range its own types hold rather than making a wrong clock a crash.
fn secondsAt(epoch_ms: i64, offset_minutes: i32) u64 {
    const shifted = @divFloor(epoch_ms, 1000) + @as(i64, boundedOffset(offset_minutes)) * 60;
    if (shifted < 0) return 0;
    return @min(@as(u64, @intCast(shifted)), last_second);
}

/// Write one moment as a date, a time, and the offset it is stated in.
///
/// **The offset is part of the value and is never left off.** A time with no
/// offset is two different moments, and the whole reason to give a model the
/// local time is that it says something the UTC one does not.
pub fn writeStamp(buf: *[stamp_bytes]u8, epoch_ms: i64, offset_minutes: i32) []const u8 {
    const bounded = boundedOffset(offset_minutes);
    const seconds = secondsAt(epoch_ms, bounded);

    const stamp = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = stamp.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = stamp.getDaySeconds();

    const sign: u8 = if (bounded < 0) '-' else '+';
    const away: u32 = @abs(bounded);

    return std.fmt.bufPrint(
        buf,
        "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} {c}{d:0>2}:{d:0>2}",
        .{
            year_day.year,
            month_day.month.numeric(),
            @as(u32, month_day.day_index) + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
            sign,
            away / 60,
            away % 60,
        },
    ) catch unreachable;
}

/// Write the same moment as UTC, for the second half of a line whose first half
/// already gave the local reading.
///
/// **It says "UTC" and it never says "+00:00".** The two mean one thing, and
/// the line said both: `2026-08-22 18:09:25 +00:00 UTC`. The model quietly
/// corrected that when it answered, which is how it read as correct for as long
/// as it did. `writeStamp` still writes the offset for every other caller,
/// because a local time with no offset is two different moments.
///
/// **The date comes back only when the two readings fall on different days.**
/// A session mostly runs on one day in both zones, and repeating the date makes
/// a reader compare two long strings to find the one field that moved. The two
/// readings do fall on different days near midnight, and then the date is the
/// whole point, so it is there.
pub fn writeUtcStamp(buf: *[stamp_bytes]u8, epoch_ms: i64, local_offset_minutes: i32) []const u8 {
    const utc_seconds = secondsAt(epoch_ms, 0);
    const local_seconds = secondsAt(epoch_ms, local_offset_minutes);

    const stamp = std.time.epoch.EpochSeconds{ .secs = utc_seconds };
    const day_seconds = stamp.getDaySeconds();
    const same_day = utc_seconds / std.time.epoch.secs_per_day ==
        local_seconds / std.time.epoch.secs_per_day;

    if (same_day) {
        return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}:{d:0>2} UTC", .{
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        }) catch unreachable;
    }

    const year_day = stamp.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable;
}

/// The room one duration needs, for example "4 hours 12 minutes".
pub const duration_bytes: usize = 48;

/// Write one length of time in words.
///
/// **The duration is given as well as the timestamp, and this is the reason.**
/// A model reasons well about "4 hours 12 minutes ago" and badly about
/// subtracting two timestamps, and it gets that arithmetic wrong silently.
///
/// Two units at most. "4 hours 12 minutes" is a fact somebody can act on;
/// "4 hours 12 minutes 6 seconds" is the same fact with a number in it that
/// nobody uses.
pub fn writeDuration(buf: *[duration_bytes]u8, ms: i64) []const u8 {
    if (ms < 1000) return "less than a second";
    const total: u64 = @intCast(@divFloor(ms, 1000));

    const days = total / (24 * 60 * 60);
    const hours = (total % (24 * 60 * 60)) / (60 * 60);
    const minutes = (total % (60 * 60)) / 60;
    const seconds = total % 60;

    if (days != 0) return writePair(buf, days, "day", hours, "hour");
    if (hours != 0) return writePair(buf, hours, "hour", minutes, "minute");
    if (minutes != 0) return writePair(buf, minutes, "minute", seconds, "second");
    return writePair(buf, seconds, "second", 0, "");
}

fn writePair(
    buf: *[duration_bytes]u8,
    big: u64,
    big_unit: []const u8,
    small: u64,
    small_unit: []const u8,
) []const u8 {
    if (small == 0) {
        return std.fmt.bufPrint(buf, "{d} {s}{s}", .{
            big,
            big_unit,
            plural(big),
        }) catch unreachable;
    }
    return std.fmt.bufPrint(buf, "{d} {s}{s} {d} {s}{s}", .{
        big,
        big_unit,
        plural(big),
        small,
        small_unit,
        plural(small),
    }) catch unreachable;
}

fn plural(count: u64) []const u8 {
    return if (count == 1) "" else "s";
}

const testing = std.testing;

fn fixedNow(ctx: ?*anyopaque) i64 {
    const at: *const i64 = @ptrCast(@alignCast(ctx.?));
    return at.*;
}

/// A clock that answers with whatever `at` currently holds.
fn clockAt(at: *const i64, offset_minutes: i32) Clock {
    return .{ .ctx = @constCast(at), .nowMs = fixedNow, .utc_offset_minutes = offset_minutes };
}

test "a duration is written in words, with two units at most and the plural right" {
    var buf: [duration_bytes]u8 = undefined;

    try testing.expectEqualStrings("less than a second", writeDuration(&buf, 999));
    try testing.expectEqualStrings("1 second", writeDuration(&buf, 1_000));
    try testing.expectEqualStrings("42 seconds", writeDuration(&buf, 42_000));
    try testing.expectEqualStrings("1 minute", writeDuration(&buf, 60_000));
    try testing.expectEqualStrings("3 minutes 5 seconds", writeDuration(&buf, 185_000));
    try testing.expectEqualStrings("1 hour", writeDuration(&buf, 3_600_000));
    // The case the plan names word for word: a model reasons about this and
    // cannot subtract two timestamps to get it.
    try testing.expectEqualStrings("4 hours 12 minutes", writeDuration(&buf, (4 * 3600 + 12 * 60) * 1000));
    try testing.expectEqualStrings("2 days 3 hours", writeDuration(&buf, (2 * 86400 + 3 * 3600) * 1000));
    // Two units and no more: the seconds of a long session are noise.
    try testing.expectEqualStrings("2 days 3 hours", writeDuration(&buf, (2 * 86400 + 3 * 3600 + 59) * 1000));
}

test "a stamp carries the offset it is stated in, and the local and UTC readings differ by it" {
    var local_buf: [stamp_bytes]u8 = undefined;
    var utc_buf: [stamp_bytes]u8 = undefined;

    // 2026-08-21 12:03:57 UTC.
    const at_ms: i64 = 1787313837 * 1000;
    try testing.expectEqualStrings("2026-08-21 12:03:57 +00:00", writeStamp(&utc_buf, at_ms, 0));
    try testing.expectEqualStrings("2026-08-21 14:03:57 +02:00", writeStamp(&local_buf, at_ms, 120));
    // West of UTC, and an offset that is not a whole hour, because both exist
    // and a formatter that only handles the easy one is a formatter that is
    // wrong for somebody.
    try testing.expectEqualStrings("2026-08-21 07:03:57 -05:00", writeStamp(&local_buf, at_ms, -300));
    try testing.expectEqualStrings("2026-08-21 17:48:57 +05:45", writeStamp(&local_buf, at_ms, 345));
}

test "the UTC reading says UTC and never +00:00" {
    // The measured defect: the line read `2026-08-22 18:09:25 +00:00 UTC`,
    // which states the zone twice. Mutation check: give `writeUtcStamp` the
    // body of `writeStamp` and both halves of this fail.
    var buf: [stamp_bytes]u8 = undefined;
    // 2026-08-22 18:09:25 UTC, which is 11:09:25 at an offset of -7 hours.
    const at_ms: i64 = 1787422165 * 1000;
    const written = writeUtcStamp(&buf, at_ms, -7 * 60);
    try testing.expect(std.mem.indexOf(u8, written, "UTC") != null);
    try testing.expect(std.mem.indexOf(u8, written, "+00:00") == null);
}

test "the UTC reading drops the date on a shared day and keeps it across midnight" {
    var buf: [stamp_bytes]u8 = undefined;
    const at_ms: i64 = 1787422165 * 1000;

    // Both readings fall on 2026-08-22, so the date is stated once, by the
    // local reading, and this half gives only what differs.
    try testing.expectEqualStrings("18:09:25 UTC", writeUtcStamp(&buf, at_ms, -7 * 60));

    // An offset that carries the local reading over midnight into the next day.
    // Now the date is the whole point of the second reading, so it is there.
    try testing.expectEqualStrings("2026-08-22 18:09:25 UTC", writeUtcStamp(&buf, at_ms, 7 * 60));

    // And the other side of midnight, west rather than east.
    // 2026-08-23 02:30:00 UTC is 2026-08-22 in every zone west of -3 hours.
    const past_midnight: i64 = 1787452200 * 1000;
    try testing.expectEqualStrings("2026-08-23 02:30:00 UTC", writeUtcStamp(&buf, past_midnight, -7 * 60));
    try testing.expectEqualStrings("02:30:00 UTC", writeUtcStamp(&buf, past_midnight, 60));
}

test "a clock that is plainly wrong is clamped and never runs away" {
    // Both numbers come from outside: the operating system's clock and the
    // machine's own zone database. A moment far past any real date makes
    // `std.time.epoch` count years in a `u16` until it wraps, and an offset of
    // millions of minutes does not fit the room a stamp has. Neither is a
    // programmer error, so both are bounded rather than asserted.
    var buf: [stamp_bytes]u8 = undefined;

    try testing.expectEqualStrings("1970-01-01 00:00:00 +00:00", writeStamp(&buf, 0, 0));
    // Before the epoch, which is a clock that is wrong and not a session.
    try testing.expectEqualStrings("1970-01-01 00:00:00 +00:00", writeStamp(&buf, -1_000_000_000, 0));
    // Past the last date this writes.
    try testing.expectEqualStrings("9999-12-31 23:59:59 +00:00", writeStamp(&buf, std.math.maxInt(i64), 0));
    // An offset no zone has. The stamp still fits the room it is given, which
    // is what `stamp_bytes` being exact depends on.
    const wild = writeStamp(&buf, 0, std.math.minInt(i32));
    try testing.expectEqual(stamp_bytes, wild.len);
    try testing.expect(std.mem.endsWith(u8, wild, "-24:00"));
}

test "a turn with no applicable fact gets no notice at all" {
    // The failure this pins is the one that turns notices into a long prompt
    // by another route: a block that is built on every turn whether or not
    // anything in it applies.
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    const notice = try render(allocator, .{}, &state, .{ .index = 1, .goal = "do the thing" });
    try testing.expect(notice == null);
}

test "a compaction puts the unfinished steps back, and says nothing to a session with no list" {
    // The task list's own known gap. The list survives a compaction for the
    // reader, because the fold reads the log, and it does not survive one for
    // the model: the only place the model saw its list was its own tool result,
    // which a fold can take away.
    //
    // **The trigger never firing for a session that keeps no list is what makes
    // this acceptable.** This project has learned twice that a notice which
    // always fires stops being read, so both halves are pinned here.
    const allocator = testing.allocator;

    const steps = [_]Step{
        .{ .id = "read", .subject = "read the fold", .status = "in_progress" },
        .{ .id = "fix", .subject = "fix the width count", .status = "pending" },
    };

    // A session that kept a list, compacted, and has unfinished work.
    {
        var state = State{};
        defer state.deinit(allocator);
        state.observeCompaction();

        const notice = (try render(allocator, .{}, &state, .{
            .index = 1,
            .unfinished_plan = &steps,
        })).?;
        defer allocator.free(notice);

        try testing.expect(std.mem.indexOf(u8, notice, "folded into a summary") != null);
        // The steps themselves, because a reminder that a list exists is not
        // the list: an agent that has lost its plan cannot fetch one.
        try testing.expect(std.mem.indexOf(u8, notice, "read the fold") != null);
        try testing.expect(std.mem.indexOf(u8, notice, "fix the width count") != null);
        try testing.expect(std.mem.indexOf(u8, notice, "in_progress") != null);
        try testing.expect(std.mem.indexOf(u8, notice, "abandoned") != null);

        // Said once. The compaction is consumed, so the turn after this one
        // hears nothing, which is what stops the whole list riding on every
        // later turn.
        try testing.expect(try render(allocator, .{}, &state, .{
            .index = 2,
            .unfinished_plan = &steps,
        }) == null);
    }

    // A session whose agent never wrote a list. The same compaction, and
    // nothing at all is said.
    {
        var state = State{};
        defer state.deinit(allocator);
        state.observeCompaction();
        try testing.expect(try render(allocator, .{}, &state, .{ .index = 1 }) == null);
    }

    // A session whose every step is finished or given up. The caller leaves
    // those out, so this is the same silence for a different reason, and it is
    // the reason a session that finished its plan is not nagged about it.
    {
        var state = State{};
        defer state.deinit(allocator);
        state.observeCompaction();
        try testing.expect(try render(allocator, .{}, &state, .{
            .index = 1,
            .unfinished_plan = &.{},
        }) == null);
    }

    // And a session with a list and no compaction hears nothing either, so the
    // notice is about the fold and not about having a plan.
    {
        var state = State{};
        defer state.deinit(allocator);
        try testing.expect(try render(allocator, .{}, &state, .{
            .index = 1,
            .unfinished_plan = &steps,
        }) == null);
    }
}

test "a task list longer than the notice carries is cut, and the cut is said out loud" {
    // The bound that keeps this one notice from becoming the whole plan again.
    // A list this long is already past what a person reads at a glance, and the
    // count is said so the model knows the rest is still there.
    const allocator = testing.allocator;

    var many: [plan_steps_shown + 3]Step = undefined;
    var subjects: [plan_steps_shown + 3][16]u8 = undefined;
    for (&many, &subjects, 0..) |*step, *subject, index| {
        step.* = .{
            .id = try std.fmt.bufPrint(subject, "step-{d}", .{index}),
            .subject = "do the thing",
            .status = "pending",
        };
    }

    var state = State{};
    defer state.deinit(allocator);
    state.observeCompaction();

    const notice = (try render(allocator, .{}, &state, .{ .index = 1, .unfinished_plan = &many })).?;
    defer allocator.free(notice);

    try testing.expect(std.mem.indexOf(u8, notice, "step-0") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "step-11") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "step-12") == null);
    try testing.expect(std.mem.indexOf(u8, notice, "and 3 more") != null);
}

test "notices turned off drop a compaction the same way they drop every other waiting fact" {
    // A session with notices off must not grow a queue of things nobody reads.
    // `dropPending` is what empties it, and a fact added to `State` and left
    // out of that function is a fact that fires on the turn somebody turns
    // notices back on.
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    state.observeCompaction();
    try testing.expect(try render(allocator, .{ .enabled = false }, &state, .{}) == null);
    try testing.expect(!state.compacted);
}

test "the time is stated once, and not again until enough time has passed" {
    const allocator = testing.allocator;
    var now: i64 = 1787313837 * 1000;
    const policy = Policy{ .clock = clockAt(&now, 0) };

    var state = State{};
    defer state.deinit(allocator);
    state.observeEvent(now - 60_000, false);

    const first = (try render(allocator, policy, &state, .{ .now_ms = now })).?;
    defer allocator.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "2026-08-21 12:03:57 +00:00") != null);
    try testing.expect(std.mem.indexOf(u8, first, "1 minute ago") != null);

    // One minute later is not enough, and the whole notice is empty because
    // nothing else applies either.
    now += 60_000;
    try testing.expect(try render(allocator, policy, &state, .{ .now_ms = now }) == null);

    now += policy.restate_time_after_ms;
    const later = (try render(allocator, policy, &state, .{ .now_ms = now })).?;
    defer allocator.free(later);
    try testing.expect(std.mem.indexOf(u8, later, "The time is now") != null);
    try testing.expect(std.mem.indexOf(u8, later, "2026-08-21 12:03:57 +00:00") == null);
}

test "a local time away from UTC carries both readings, and one at UTC carries one" {
    const allocator = testing.allocator;
    const now: i64 = 1787313837 * 1000;

    var away = State{};
    defer away.deinit(allocator);
    const with_offset = (try render(
        allocator,
        .{ .clock = clockAt(&now, 120) },
        &away,
        .{ .now_ms = now },
    )).?;
    defer allocator.free(with_offset);
    try testing.expect(std.mem.indexOf(u8, with_offset, "14:03:57 +02:00") != null);
    // The UTC reading names the zone in words and never as an offset, and it
    // does not repeat a date the local reading already gave.
    try testing.expect(std.mem.indexOf(u8, with_offset, "which is 12:03:57 UTC.") != null);
    try testing.expect(std.mem.indexOf(u8, with_offset, "+00:00") == null);

    // At UTC the second reading would be the first one again, so it is left
    // out rather than printed twice.
    var here = State{};
    defer here.deinit(allocator);
    const without = (try render(
        allocator,
        .{ .clock = clockAt(&now, 0) },
        &here,
        .{ .now_ms = now },
    )).?;
    defer allocator.free(without);
    try testing.expect(std.mem.indexOf(u8, without, "UTC") == null);
}

test "the task is restated in a long session and not in a short one" {
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    const goal = "add a test for the parser";
    const policy = Policy{};

    // The first turns say nothing: the task is the first message and it is
    // still right there.
    var turn: usize = 0;
    while (turn < policy.goal_every_turns) : (turn += 1) {
        try testing.expect(try render(allocator, policy, &state, .{ .index = turn, .goal = goal }) == null);
    }

    const restated = (try render(allocator, policy, &state, .{ .index = turn, .goal = goal })).?;
    defer allocator.free(restated);
    try testing.expect(std.mem.indexOf(u8, restated, goal) != null);

    // And not again on the very next turn.
    try testing.expect(try render(allocator, policy, &state, .{ .index = turn + 1, .goal = goal }) == null);
}

test "a task longer than the bound is cut and the cut is said out loud" {
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    const goal = "x" ** (goal_max_bytes + 100);
    const notice = (try render(allocator, .{}, &state, .{ .index = 8, .goal = goal })).?;
    defer allocator.free(notice);

    try testing.expect(std.mem.indexOf(u8, notice, "the task is longer than this") != null);
    try testing.expect(std.mem.indexOf(u8, notice, goal) == null);
}

test "a task cut at the bound is still valid text, whatever alphabet it is written in" {
    // The cut lands inside a three byte character here, and a notice that
    // carried half of one would serialize as a JSON array rather than a JSON
    // string, which is the fault `tools.outputForModel` catches one level down.
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    // Three bytes each, so no multiple of the character length is the bound.
    const goal = "パーサのテストを書いて" ** 40;
    try testing.expect(goal.len > goal_max_bytes);

    const notice = (try render(allocator, .{}, &state, .{ .index = 8, .goal = goal })).?;
    defer allocator.free(notice);

    try testing.expect(std.unicode.utf8ValidateSlice(notice));
    try testing.expect(std.mem.indexOf(u8, notice, "the task is longer than this") != null);
}

test "a task exactly at the bound is not cut, and one byte past it is" {
    const allocator = testing.allocator;

    const exact = "x" ** goal_max_bytes;
    try testing.expectEqualStrings(exact, cutToCharacter(exact, goal_max_bytes));

    const over = "x" ** (goal_max_bytes + 1);
    try testing.expectEqual(goal_max_bytes, cutToCharacter(over, goal_max_bytes).len);

    var state = State{};
    defer state.deinit(allocator);
    const notice = (try render(allocator, .{}, &state, .{ .index = 8, .goal = exact })).?;
    defer allocator.free(notice);
    try testing.expect(std.mem.indexOf(u8, notice, "the task is longer than this") == null);
}

test "a repeated call is named with its tool and its arguments, and one call alone is not" {
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    // One call, which is ordinary work.
    try state.observeCall(allocator, "run_command", "{\"command\":\"readlink -f a\"}", 1);
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);

    // The same call a second time, which is the turn a notice can still
    // prevent a third.
    try state.observeCall(allocator, "run_command", "{\"command\":\"readlink -f a\"}", 2);
    const notice = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(notice);
    try testing.expect(std.mem.indexOf(u8, notice, "run_command") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "readlink -f a") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "2 times") != null);

    // The fact is consumed: a turn that made no call hears nothing.
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
}

test "a file read again unchanged is reported, and one that changed is not" {
    // **This is the half that makes the notice trustworthy.** A notice that
    // said "unchanged" about a file that did change would send a model on with
    // a stale copy, which is worse than the re-read it exists to stop.
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    // First read: nothing to say.
    try state.observeRead(allocator, "src/main.zig", "0123456789abcdef");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);

    try state.observeRead(allocator, "src/main.zig", "0123456789abcdef");
    const unchanged = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(unchanged);
    try testing.expect(std.mem.indexOf(u8, unchanged, "src/main.zig") != null);
    try testing.expect(std.mem.indexOf(u8, unchanged, "did not change") != null);

    // Read again after the file changed: no notice, and the new hash is what
    // the next read is measured against.
    try state.observeRead(allocator, "src/main.zig", "fedcba9876543210");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
    try state.observeRead(allocator, "src/main.zig", "fedcba9876543210");
    const again = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(again);
    try testing.expect(std.mem.indexOf(u8, again, "did not change") != null);

    // A different file read once is not the same file read twice.
    try state.observeRead(allocator, "src/other.zig", "0123456789abcdef");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
}

test "a turn that read many files again says how many, not only the last one" {
    // Measured against `glm4.7-flash:A3B` on 2026-08-22: asked to check its
    // reading, it re-read six files inside one turn. A notice naming the last
    // of them alone would have understated that by a factor of six.
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    const files = [_][]const u8{ "mod1.py", "mod2.py", "mod3.py", "mod4.py", "mod5.py", "mod6.py" };
    for (files) |path| try state.observeRead(allocator, path, "0123456789abcdef");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
    for (files) |path| try state.observeRead(allocator, path, "0123456789abcdef");

    const notice = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(notice);
    try testing.expect(std.mem.indexOf(u8, notice, "6 files") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "mod6.py") != null);

    // And the count starts again with the next turn, so one re-read after this
    // is one re-read and not seven.
    try state.observeRead(allocator, "mod1.py", "0123456789abcdef");
    const one = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(one);
    try testing.expect(std.mem.indexOf(u8, one, "You read mod1.py again") != null);
    try testing.expect(std.mem.indexOf(u8, one, "files again") == null);
}

test "the budget is reported once per step and never twice inside one" {
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);
    const policy = Policy{};

    // Under the first step: nothing.
    try testing.expect(try render(allocator, policy, &state, .{ .spent_percent = 24 }) == null);

    const quarter = (try render(allocator, policy, &state, .{ .spent_percent = 25 })).?;
    defer allocator.free(quarter);
    try testing.expect(std.mem.indexOf(u8, quarter, "25 percent") != null);

    // Still inside the same step, so nothing is said again.
    try testing.expect(try render(allocator, policy, &state, .{ .spent_percent = 40 }) == null);

    const half = (try render(allocator, policy, &state, .{ .spent_percent = 51 })).?;
    defer allocator.free(half);
    try testing.expect(std.mem.indexOf(u8, half, "51 percent") != null);
}

test "the uncommitted files are named once, and a clean tree is never named" {
    const allocator = testing.allocator;

    var dirty = State{};
    defer dirty.deinit(allocator);
    const said = (try render(allocator, .{}, &dirty, .{ .uncommitted_files = 12 })).?;
    defer allocator.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "12 files") != null);
    // The count does not change during a session, so it is said once.
    try testing.expect(try render(allocator, .{}, &dirty, .{ .uncommitted_files = 12 }) == null);

    var clean = State{};
    defer clean.deinit(allocator);
    try testing.expect(try render(allocator, .{}, &clean, .{ .uncommitted_files = 0 }) == null);
}

test "notices turned off produce nothing, whatever facts are waiting" {
    // The off side of the measurement. Every fact below would produce a line
    // with notices on, and the switch is what makes the claim testable.
    const allocator = testing.allocator;
    const now: i64 = 1787313837 * 1000;
    var state = State{};
    defer state.deinit(allocator);

    try state.observeCall(allocator, "run_command", "{}", 9);
    try state.observeRead(allocator, "a.zig", "0123456789abcdef");
    try state.observeRead(allocator, "a.zig", "0123456789abcdef");

    const off = Policy{ .enabled = false, .clock = clockAt(&now, 0) };
    try testing.expect(try render(allocator, off, &state, .{
        .index = 99,
        .now_ms = now,
        .goal = "do the thing",
        .spent_percent = 90,
        .uncommitted_files = 4,
    }) == null);

    // And nothing is left waiting to be said on some later turn.
    try testing.expect(state.last_call == null);
    try testing.expect(state.unchanged_read == null);
}

test "the session age is measured from the first event and not from the call to render" {
    const allocator = testing.allocator;
    var now: i64 = 1787313837 * 1000;
    const policy = Policy{ .clock = clockAt(&now, 0) };

    var state = State{};
    defer state.deinit(allocator);
    // A resumed session: the log's own first event is hours old, and that is
    // when the session started, not when this process picked it up.
    state.observeEvent(now - 4 * 60 * 60 * 1000, false);
    state.observeEvent(now - 30_000, true);

    const notice = (try render(allocator, policy, &state, .{ .now_ms = now })).?;
    defer allocator.free(notice);
    try testing.expect(std.mem.indexOf(u8, notice, "started 4 hours ago") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "last spoke 30 seconds ago") != null);
}

test "a session that has just started does not say how long ago that was" {
    // The measured defect: "This session started less than a second ago" was
    // the first line of the first turn of every session. Mutation check: remove
    // the floor in `renderTime` and the first half of this fails.
    const allocator = testing.allocator;
    const now: i64 = 1787313837 * 1000;
    const policy = Policy{ .clock = clockAt(&now, 0) };

    var fresh = State{};
    defer fresh.deinit(allocator);
    fresh.observeEvent(now, false);
    const first = (try render(allocator, policy, &fresh, .{ .now_ms = now })).?;
    defer allocator.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "This session started") == null);
    // The time itself is still there. The floor drops one clause, never the
    // notice.
    try testing.expect(std.mem.indexOf(u8, first, "The time is now") != null);

    // And an age worth stating is stated. A session at the floor is old enough.
    var older = State{};
    defer older.deinit(allocator);
    older.observeEvent(now - min_session_age_ms, false);
    const later = (try render(allocator, policy, &older, .{ .now_ms = now })).?;
    defer allocator.free(later);
    try testing.expect(std.mem.indexOf(u8, later, "This session started 1 minute ago") != null);
}

test "every notice line says the harness is speaking" {
    const allocator = testing.allocator;
    const now: i64 = 1787313837 * 1000;
    var state = State{};
    defer state.deinit(allocator);
    state.observeEvent(now, false);
    try state.observeCall(allocator, "grep", "{}", 3);
    try state.observeRead(allocator, "a.zig", "0123456789abcdef");
    try state.observeRead(allocator, "a.zig", "0123456789abcdef");

    const notice = (try render(allocator, .{ .clock = clockAt(&now, 0) }, &state, .{
        .index = 40,
        .now_ms = now,
        .goal = "do the thing",
        .spent_percent = 80,
        .uncommitted_files = 3,
    })).?;
    defer allocator.free(notice);

    var lines = std.mem.splitScalar(u8, notice, '\n');
    var counted: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        counted += 1;
        try testing.expect(std.mem.startsWith(u8, line, prefix));
    }
    // Six facts applied, so six lines: the model is never left guessing which
    // of them it just read.
    try testing.expectEqual(@as(usize, 6), counted);
}
