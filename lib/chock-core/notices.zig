//! What the harness knows and the model cannot: facts the loop computes
//! exactly, told to the agent on the turn they matter.

const std = @import("std");

pub const Error = std.mem.Allocator.Error;

pub const Clock = struct {
    ctx: ?*anyopaque = null,
    nowMs: *const fn (ctx: ?*anyopaque) i64,
    utc_offset_minutes: i32 = 0,

    pub fn now(self: Clock) i64 {
        return self.nowMs(self.ctx);
    }
};

pub const Policy = struct {
    enabled: bool = true,

    repeat_at: usize = 2,

    goal_every_turns: usize = 8,

    restate_time_after_ms: i64 = 15 * 60 * 1000,

    budget_step_percent: u8 = 25,

    clock: ?Clock = null,
};

pub const goal_max_bytes: usize = 400;

pub const plan_steps_shown: usize = 12;

pub const Step = struct {
    id: []const u8,
    subject: []const u8,
    status: []const u8,
};

pub const prefix = "[chock] ";

const Call = struct {
    tool: []u8,
    arguments: []u8,
    repeats: usize,

    fn deinit(self: Call, allocator: std.mem.Allocator) void {
        allocator.free(self.tool);
        allocator.free(self.arguments);
    }
};

pub const State = struct {
    started_ms: ?i64 = null,
    last_spoke_ms: ?i64 = null,

    time_shown_ms: ?i64 = null,
    goal_shown_turn: ?usize = null,
    budget_step_shown: u8 = 0,
    uncommitted_shown: bool = false,

    compacted: bool = false,

    last_call: ?Call = null,
    unchanged_read: ?[]u8 = null,
    unchanged_count: usize = 0,

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

    pub fn observeEvent(self: *State, time_ms: i64, is_agent_message: bool) void {
        if (self.started_ms == null) self.started_ms = time_ms;
        if (is_agent_message) self.last_spoke_ms = time_ms;
    }

    pub fn observeCompaction(self: *State) void {
        self.compacted = true;
    }

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

pub const Turn = struct {
    index: usize = 0,
    now_ms: i64 = 0,
    goal: []const u8 = "",
    spent_percent: ?u8 = null,
    uncommitted_files: usize = 0,
    unfinished_plan: []const Step = &.{},
};

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

pub fn cutToCharacter(text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;
    var at = limit;
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

pub const stamp_bytes: usize = 26;

const last_second: u64 = 253402300799;

const max_offset_minutes: i32 = 24 * 60;

const min_session_age_ms: i64 = 60 * 1000;

fn boundedOffset(offset_minutes: i32) i32 {
    return std.math.clamp(offset_minutes, -max_offset_minutes, max_offset_minutes);
}

fn secondsAt(epoch_ms: i64, offset_minutes: i32) u64 {
    const shifted = @divFloor(epoch_ms, 1000) + @as(i64, boundedOffset(offset_minutes)) * 60;
    if (shifted < 0) return 0;
    return @min(@as(u64, @intCast(shifted)), last_second);
}

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

pub const duration_bytes: usize = 48;

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
    try testing.expectEqualStrings("4 hours 12 minutes", writeDuration(&buf, (4 * 3600 + 12 * 60) * 1000));
    try testing.expectEqualStrings("2 days 3 hours", writeDuration(&buf, (2 * 86400 + 3 * 3600) * 1000));
    try testing.expectEqualStrings("2 days 3 hours", writeDuration(&buf, (2 * 86400 + 3 * 3600 + 59) * 1000));
}

test "a stamp carries the offset it is stated in, and the local and UTC readings differ by it" {
    var local_buf: [stamp_bytes]u8 = undefined;
    var utc_buf: [stamp_bytes]u8 = undefined;

    const at_ms: i64 = 1787313837 * 1000;
    try testing.expectEqualStrings("2026-08-21 12:03:57 +00:00", writeStamp(&utc_buf, at_ms, 0));
    try testing.expectEqualStrings("2026-08-21 14:03:57 +02:00", writeStamp(&local_buf, at_ms, 120));
    try testing.expectEqualStrings("2026-08-21 07:03:57 -05:00", writeStamp(&local_buf, at_ms, -300));
    try testing.expectEqualStrings("2026-08-21 17:48:57 +05:45", writeStamp(&local_buf, at_ms, 345));
}

test "the UTC reading says UTC and never +00:00" {
    var buf: [stamp_bytes]u8 = undefined;
    const at_ms: i64 = 1787422165 * 1000;
    const written = writeUtcStamp(&buf, at_ms, -7 * 60);
    try testing.expect(std.mem.indexOf(u8, written, "UTC") != null);
    try testing.expect(std.mem.indexOf(u8, written, "+00:00") == null);
}

test "the UTC reading drops the date on a shared day and keeps it across midnight" {
    var buf: [stamp_bytes]u8 = undefined;
    const at_ms: i64 = 1787422165 * 1000;

    try testing.expectEqualStrings("18:09:25 UTC", writeUtcStamp(&buf, at_ms, -7 * 60));

    try testing.expectEqualStrings("2026-08-22 18:09:25 UTC", writeUtcStamp(&buf, at_ms, 7 * 60));

    const past_midnight: i64 = 1787452200 * 1000;
    try testing.expectEqualStrings("2026-08-23 02:30:00 UTC", writeUtcStamp(&buf, past_midnight, -7 * 60));
    try testing.expectEqualStrings("02:30:00 UTC", writeUtcStamp(&buf, past_midnight, 60));
}

test "a clock that is plainly wrong is clamped and never runs away" {
    var buf: [stamp_bytes]u8 = undefined;

    try testing.expectEqualStrings("1970-01-01 00:00:00 +00:00", writeStamp(&buf, 0, 0));
    try testing.expectEqualStrings("1970-01-01 00:00:00 +00:00", writeStamp(&buf, -1_000_000_000, 0));
    try testing.expectEqualStrings("9999-12-31 23:59:59 +00:00", writeStamp(&buf, std.math.maxInt(i64), 0));
    const wild = writeStamp(&buf, 0, std.math.minInt(i32));
    try testing.expectEqual(stamp_bytes, wild.len);
    try testing.expect(std.mem.endsWith(u8, wild, "-24:00"));
}

test "a turn with no applicable fact gets no notice at all" {
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    const notice = try render(allocator, .{}, &state, .{ .index = 1, .goal = "do the thing" });
    try testing.expect(notice == null);
}

test "a compaction puts the unfinished steps back, and says nothing to a session with no list" {
    const allocator = testing.allocator;

    const steps = [_]Step{
        .{ .id = "read", .subject = "read the fold", .status = "in_progress" },
        .{ .id = "fix", .subject = "fix the width count", .status = "pending" },
    };

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
        try testing.expect(std.mem.indexOf(u8, notice, "read the fold") != null);
        try testing.expect(std.mem.indexOf(u8, notice, "fix the width count") != null);
        try testing.expect(std.mem.indexOf(u8, notice, "in_progress") != null);
        try testing.expect(std.mem.indexOf(u8, notice, "abandoned") != null);

        try testing.expect(try render(allocator, .{}, &state, .{
            .index = 2,
            .unfinished_plan = &steps,
        }) == null);
    }

    {
        var state = State{};
        defer state.deinit(allocator);
        state.observeCompaction();
        try testing.expect(try render(allocator, .{}, &state, .{ .index = 1 }) == null);
    }

    {
        var state = State{};
        defer state.deinit(allocator);
        state.observeCompaction();
        try testing.expect(try render(allocator, .{}, &state, .{
            .index = 1,
            .unfinished_plan = &.{},
        }) == null);
    }

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
    try testing.expect(std.mem.indexOf(u8, with_offset, "which is 12:03:57 UTC.") != null);
    try testing.expect(std.mem.indexOf(u8, with_offset, "+00:00") == null);

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

    var turn: usize = 0;
    while (turn < policy.goal_every_turns) : (turn += 1) {
        try testing.expect(try render(allocator, policy, &state, .{ .index = turn, .goal = goal }) == null);
    }

    const restated = (try render(allocator, policy, &state, .{ .index = turn, .goal = goal })).?;
    defer allocator.free(restated);
    try testing.expect(std.mem.indexOf(u8, restated, goal) != null);

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
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

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

    try state.observeCall(allocator, "run_command", "{\"command\":\"readlink -f a\"}", 1);
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);

    try state.observeCall(allocator, "run_command", "{\"command\":\"readlink -f a\"}", 2);
    const notice = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(notice);
    try testing.expect(std.mem.indexOf(u8, notice, "run_command") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "readlink -f a") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "2 times") != null);

    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
}

test "a file read again unchanged is reported, and one that changed is not" {
    const allocator = testing.allocator;
    var state = State{};
    defer state.deinit(allocator);

    try state.observeRead(allocator, "src/main.zig", "0123456789abcdef");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);

    try state.observeRead(allocator, "src/main.zig", "0123456789abcdef");
    const unchanged = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(unchanged);
    try testing.expect(std.mem.indexOf(u8, unchanged, "src/main.zig") != null);
    try testing.expect(std.mem.indexOf(u8, unchanged, "did not change") != null);

    try state.observeRead(allocator, "src/main.zig", "fedcba9876543210");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
    try state.observeRead(allocator, "src/main.zig", "fedcba9876543210");
    const again = (try render(allocator, .{}, &state, .{})).?;
    defer allocator.free(again);
    try testing.expect(std.mem.indexOf(u8, again, "did not change") != null);

    try state.observeRead(allocator, "src/other.zig", "0123456789abcdef");
    try testing.expect(try render(allocator, .{}, &state, .{}) == null);
}

test "a turn that read many files again says how many, not only the last one" {
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

    try testing.expect(try render(allocator, policy, &state, .{ .spent_percent = 24 }) == null);

    const quarter = (try render(allocator, policy, &state, .{ .spent_percent = 25 })).?;
    defer allocator.free(quarter);
    try testing.expect(std.mem.indexOf(u8, quarter, "25 percent") != null);

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
    try testing.expect(try render(allocator, .{}, &dirty, .{ .uncommitted_files = 12 }) == null);

    var clean = State{};
    defer clean.deinit(allocator);
    try testing.expect(try render(allocator, .{}, &clean, .{ .uncommitted_files = 0 }) == null);
}

test "notices turned off produce nothing, whatever facts are waiting" {
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

    try testing.expect(state.last_call == null);
    try testing.expect(state.unchanged_read == null);
}

test "the session age is measured from the first event and not from the call to render" {
    const allocator = testing.allocator;
    var now: i64 = 1787313837 * 1000;
    const policy = Policy{ .clock = clockAt(&now, 0) };

    var state = State{};
    defer state.deinit(allocator);
    state.observeEvent(now - 4 * 60 * 60 * 1000, false);
    state.observeEvent(now - 30_000, true);

    const notice = (try render(allocator, policy, &state, .{ .now_ms = now })).?;
    defer allocator.free(notice);
    try testing.expect(std.mem.indexOf(u8, notice, "started 4 hours ago") != null);
    try testing.expect(std.mem.indexOf(u8, notice, "last spoke 30 seconds ago") != null);
}

test "a session that has just started does not say how long ago that was" {
    const allocator = testing.allocator;
    const now: i64 = 1787313837 * 1000;
    const policy = Policy{ .clock = clockAt(&now, 0) };

    var fresh = State{};
    defer fresh.deinit(allocator);
    fresh.observeEvent(now, false);
    const first = (try render(allocator, policy, &fresh, .{ .now_ms = now })).?;
    defer allocator.free(first);
    try testing.expect(std.mem.indexOf(u8, first, "This session started") == null);
    try testing.expect(std.mem.indexOf(u8, first, "The time is now") != null);

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
    try testing.expectEqual(@as(usize, 6), counted);
}
