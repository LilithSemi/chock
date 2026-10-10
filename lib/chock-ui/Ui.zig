//! The interface Chock draws, whatever is drawing it.
//!
//! One widget tree over phantom's terminal, window and web backends. Everything
//! the machine underneath provides arrives through `Host`, so nothing here knows
//! which of the three it is running under.

const std = @import("std");
const phantom = @import("phantom");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const host_mod = @import("host.zig");
const layout = @import("layout.zig");
const model = @import("model.zig");
const text_mod = @import("text.zig");

const Host = host_mod.Host;

pub const approval_keys = " [y] approve  [n] refuse  [d] diff  [w] why";

pub const approval_keys_narrow = " [y] yes  [n] no  [d] diff  [w] why";

pub fn elsewhereText(
    arena: std.mem.Allocator,
    session: []const u8,
    room: layout.Room,
) []const u8 {
    const short = " answer it with: chock approve";
    if (session.len == 0) return short;
    const whole = std.fmt.allocPrint(arena, "{s} {s}", .{ short, session }) catch return short;
    return if (room.holds(whole)) whole else short;
}

fn safeText(
    arena: std.mem.Allocator,
    raw: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < raw.len) {
        const one = layout.drawnAt(raw, index);
        if (one.whole) {
            try out.appendSlice(arena, raw[index..][0..one.length]);
        } else {
            try out.append(arena, @intCast(one.point));
        }
        index += one.length;
    }
    return out.items;
}

pub const Answer = union(enum) {
    nothing,
    command: model.Command,
    message: []const u8,
};

pub fn approvalKeys(room: layout.Room) []const u8 {
    return if (room.isNarrow()) approval_keys_narrow else approval_keys;
}

fn escapeLength(text: []const u8) usize {
    if (text.len < 2) return text.len;
    switch (text[1]) {
        '[' => {
            var at: usize = 2;
            while (at < text.len) : (at += 1) {
                if (text[at] >= 0x40 and text[at] <= 0x7e) return at + 1;
            }
            return text.len;
        },
        ']' => {
            var at: usize = 2;
            while (at < text.len) : (at += 1) {
                if (text[at] == 0x07) return at + 1;
                if (text[at] == 0x1b and at + 1 < text.len and text[at + 1] == '\\') return at + 2;
            }
            return text.len;
        },
        else => return 2,
    }
}

pub fn answerFor(line: []const u8) Answer {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return .nothing;
    if (model.commandOf(trimmed)) |command| return .{ .command = command };
    return .{ .message = trimmed };
}

pub fn backOne(text: []const u8) usize {
    if (text.len == 0) return 0;
    var at = text.len - 1;
    while (at != 0 and text[at] & 0b1100_0000 == 0b1000_0000) at -= 1;
    return at;
}

pub fn completions(line: []const u8, into: []model.Command) []const model.Command {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return into[0..0];
    if (std.mem.indexOfScalar(u8, trimmed, ' ') != null) return into[0..0];

    var found: usize = 0;
    for (model.Command.all) |one| {
        if (found == into.len) break;
        if (!std.mem.startsWith(u8, one.typed(), trimmed)) continue;
        into[found] = one;
        found += 1;
    }
    return into[0..found];
}

pub fn countLines(text: []const u8) usize {
    return 1 + std.mem.count(u8, text, "\n");
}

pub fn countdownText(arena: std.mem.Allocator, left_ms: i64) std.mem.Allocator.Error![]const u8 {
    if (left_ms <= 0) return "0:00";
    const seconds: u64 = @intCast(@divFloor(left_ms + 999, 1000));
    return std.fmt.allocPrint(arena, "{d}:{d:0>2}", .{ seconds / 60, seconds % 60 });
}

fn dupeOptions(arena: std.mem.Allocator, options: []const []const u8) []const []const u8 {
    var kept: std.ArrayList([]const u8) = .empty;
    for (options) |option| {
        const one = arena.dupe(u8, option) catch continue;
        kept.append(arena, one) catch return kept.items;
    }
    return kept.items;
}

pub fn keepText(gpa: std.mem.Allocator, into: *std.ArrayList(u8), text: []const u8) void {
    var at: usize = 0;
    while (at < text.len) {
        // A whole escape sequence goes, and never its first byte alone: keeping the rest turns a colour code into a literal [0m.
        if (text[at] == 0x1b) {
            at += escapeLength(text[at..]);
            continue;
        }
        const length = std.unicode.utf8ByteSequenceLength(text[at]) catch {
            at += 1;
            continue;
        };
        if (at + length > text.len) return;
        const scalar = text[at..][0..length];
        _ = std.unicode.utf8Decode(scalar) catch {
            at += 1;
            continue;
        };
        at += length;
        if (length == 1) {
            const byte = scalar[0];
            if (byte < 0x20 and byte != '\n' and byte != '\t') continue;
            if (byte == 0x7f) continue;
        }
        into.appendSlice(gpa, scalar) catch return;
    }
}

pub fn markFor(point: u21) ?Mark {
    return switch (point) {
        '\u{2713}' => .{ .id = .check, .label = "ok" },
        '\u{2717}' => .{ .id = .cross, .label = "not ok" },
        '\u{2502}' => .{ .id = .rule_vertical, .label = null },
        '\u{2500}' => .{ .id = .rule_horizontal, .label = null },
        '\u{25b8}' => .{ .id = .chevron_right, .label = null },
        '\u{25be}' => .{ .id = .chevron_down, .label = null },
        '\u{22ef}' => .{ .id = .ellipsis, .label = "running" },
        else => null,
    };
}

pub const readable_columns: u16 = 80;

pub const settle_looks: u8 = 3;

pub fn wrapText(
    arena: std.mem.Allocator,
    raw: []const u8,
    room: layout.Room,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (!(room.width > 0)) {
        try out.append(arena, "");
        return out.items;
    }

    const safe = try safeText(arena, raw);
    const broken = phantom.text.layout.layoutParagraph(
        arena,
        room.measure.font,
        safe,
        room.measure.size,
        room.measure.logicalMetrics(),
        room.width,
    ) catch {
        try out.append(arena, safe);
        return out.items;
    };

    for (broken.lines) |line| {
        var words: std.ArrayList(u8) = .empty;
        for (line.glyphs) |one| {
            var bytes: [4]u8 = undefined;
            const length = std.unicode.utf8Encode(one.cp, &bytes) catch continue;
            try words.appendSlice(arena, bytes[0..length]);
        }
        try out.append(arena, words.items);
    }
    if (out.items.len == 0) try out.append(arena, "");
    return out.items;
}

pub const Ask = union(enum) {
    done,
    message: []const u8,
    take_up: []const u8,
};

const Mark = struct {
    id: phantom.icon.Id,
    label: ?[]const u8,
};

pub const Rows = struct {
    into: std.ArrayList(phantom.Widget) = .empty,
    left: u16,

    pub fn add(self: *Rows, arena: std.mem.Allocator, one: phantom.Widget) void {
        if (self.left == 0) return;
        self.left -= 1;
        self.into.append(arena, one) catch {};
    }

    pub fn items(self: Rows) []const phantom.Widget {
        return self.into.items;
    }
};

/// What `markdown.wrapSpans` needs to fit one logical line.
///
/// Every style measures the same in a terminal and not in a window, where a
/// bold face is wider, so the measure is asked for per style rather than taken
/// once. Row zero is narrower wherever something is pinned to its right.
const SpanRoom = struct {
    measure: layout.Measure,
    rest: f32,
    first: f32,

    fn wrap(self: *const SpanRoom) phantom.text.markdown.Wrap {
        return .{ .ctx = @constCast(self), .measure_for = measureFor, .width_of = widthOf };
    }

    fn measureFor(ctx: ?*anyopaque, _: phantom.text.markdown.Style) phantom.text.fit.Measure {
        const self: *const SpanRoom = @ptrCast(@alignCast(ctx.?));
        return .{
            .font = self.measure.font,
            .size = self.measure.size,
            .metrics = self.measure.logicalMetrics(),
        };
    }

    fn widthOf(ctx: ?*anyopaque, at: usize) f32 {
        const self: *const SpanRoom = @ptrCast(@alignCast(ctx.?));
        return if (at == 0) self.first else self.rest;
    }
};

const Shown = struct {
    voice: model.Voice,
    text: []const u8,
    /// The runs this row is made of. Empty for a row that carries no style,
    /// which is drawn as plain text.
    spans: []const phantom.text.markdown.Span = &.{},
    pinned: []const u8 = "",
    fold_at: ?usize = null,
    open: bool = false,
    gap: bool = false,
};

const Screen = struct {
    ui: *Ui,

    pub const State = struct {
        base: phantom.StateBase = .{},
        ui: ?*Ui = null,

        pub fn initState(self: *State, config: *const Screen) !void {
            self.ui = config.ui;
            config.ui.screen = self;
        }

        pub fn build(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            const ui = self.ui orelse return ctx.new(phantom.Text{ .text = "" }).widget();
            return ui.view(ctx);
        }
    };
};

pub const answer_prompt = " > ";

pub const question_unanswerable = " nobody can answer here. The agent is told so when the time runs out.";

pub const Ui = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    inner: ?chock_core.Loop.Observer = null,
    transcript: std.ArrayList(u8) = .empty,

    phase: Phase = .message,
    typed: std.ArrayList(u8) = .empty,
    submitted: bool = false,
    primed: ?[]const u8 = null,

    scroll_back: usize = 0,
    completion_selected: usize = 0,

    picker: ?[]const model.Resumable = null,
    picked: usize = 0,
    /// What a tap on a picker row carries. One per row and a field rather than
    /// a local, because a tap arrives after the frame that drew it is gone and
    /// the gesture holds this address.
    picker_taps: [max_picker_taps]Tap = @splat(.{}),
    sessions_dir: []const u8 = "",
    current_session: []const u8 = "",
    taken: ?[]const u8 = null,

    tasks: ?*chock_core.tasks.Table = null,
    tasks_shown_early: usize = 0,

    tokens_in: u64 = 0,
    tokens_out: u64 = 0,
    spent: f64 = 0,
    spent_currency: []const u8 = "",

    transcript_focused: bool = false,

    approval: ?model.Approval = null,
    approval_focused: bool = false,
    approval_settle: u8 = 0,
    approval_answer: ?model.Answered = null,
    approval_arena: std.heap.ArenaAllocator,

    question: ?model.Question = null,
    question_focused: bool = false,
    question_settle: u8 = 0,
    question_typed: [chock_core.ask.max_answer_bytes]u8 = undefined,
    question_filled: usize = 0,
    question_said: ?enum { answered, declined } = null,
    question_arena: std.heap.ArenaAllocator,
    /// What this interface needs from the machine under it. Quiet by default so
    /// a test draws without a terminal; `start` puts the real one in.
    host: Host = host_mod.quiet,
    lines: std.ArrayList(model.Line) = .empty,
    pending: std.ArrayList(u8) = .empty,
    pending_voice: model.Voice = .chock,

    cursor: ?usize = null,

    pane: ?model.Pane = null,

    sidebar: model.Sidebar = .none,

    fixed_size: bool = false,

    running_call: ?Running = null,
    running_row: ?usize = null,

    reasoning: std.ArrayList(u8) = .empty,
    turn_open: bool = false,

    /// Reads the agent's markdown. Kept because a fenced block spans lines, so
    /// the reader of one line needs what the line before it opened.
    markdown: phantom.text.markdown.Parser = .{},

    clock: chock_core.notices.Clock = .{ .nowMs = noClock },

    replaying: bool = false,

    rows: u16 = 0,
    width: f32 = 0,
    measure: layout.Measure = layout.grid_measure,

    arena: std.heap.ArenaAllocator,
    plan: chock_proto.state.Plan = .{},

    facts: model.Facts = .{},

    seen_scrolls: u32 = 0,
    running: bool = true,
    said_stopping: bool = false,
    stopped: bool = false,
    screen: ?*Screen.State = null,

    const status_bytes = 256;

    pub const Phase = enum { message, session };

    /// The most picker rows a tap can reach. A longer list still draws and still
    /// answers the arrow keys; only the rows past this are keyboard only.
    const max_picker_taps = 256;

    const Tap = struct {
        ui: ?*Ui = null,
        index: usize = 0,
    };

    fn onPickerTap(ctx: *anyopaque) void {
        const tap: *Tap = @ptrCast(@alignCast(ctx));
        const self = tap.ui orelse return;
        self.picked = tap.index;
        self.takePicked();
        self.host.invalidate();
    }

    const Running = struct {
        tool: []const u8,
        argument: []const u8,
        at_ms: i64,
    };

    fn noClock(ctx: ?*anyopaque) i64 {
        _ = ctx;
        return 0;
    }

    pub fn realNowMs(ctx: ?*anyopaque) i64 {
        const self: *const Ui = @ptrCast(@alignCast(ctx.?));
        return std.Io.Timestamp.now(self.io, .real).toMilliseconds();
    }

    pub fn askForMessage(self: *Ui, arena: std.mem.Allocator) !Ask {
        defer self.endInput();

        if (self.primed) |message| {
            self.primed = null;
            self.saidByUser(message);
            return .{ .message = try arena.dupe(u8, message) };
        }

        while (true) {
            self.beginInput();

            while (!self.submitted) {
                if (!self.paintWaiting(look_ms)) return .done;

                if (!self.host.hasFocus()) self.host.focusLast();
                _ = self.host.pumpKeys();

                self.pollFinishedTasks();
            }

            if (self.taken) |id| {
                self.taken = null;
                return .{ .take_up = try arena.dupe(u8, id) };
            }

            switch (answerFor(self.typed.items)) {
                .nothing => return .done,
                .message => |words| {
                    self.saidByUser(words);
                    return .{ .message = try arena.dupe(u8, words) };
                },
                .command => |command| {
                    self.runCommand(command);
                    self.phase = .session;
                    _ = self.paint();
                    continue;
                },
            }
        }
    }

    pub fn pollFinishedTasks(self: *Ui) void {
        const table = self.tasks orelse return;
        const finished = table.peek(self.gpa) catch return;
        defer chock_core.tasks.freeCompletions(self.gpa, finished);

        if (finished.len <= self.tasks_shown_early) return;
        for (finished[self.tasks_shown_early..]) |one| {
            self.sayFmt(.chock, "the background task {s} finished, {s} {d}", .{
                one.id,
                one.status.wireName(),
                one.code,
            });
        }
        self.tasks_shown_early = finished.len;
        self.draw();
    }

    pub const said_by_user = "you";

    pub fn saidByUser(self: *Ui, text: []const u8) void {
        self.startBlock();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const at = text_mod.clockText(arena, self.clock.now(), self.clock.utc_offset_minutes) catch "";
        self.sayPinned(.chock, said_by_user, at);

        self.say(.chock, text);
        self.endLine();
        self.draw();
    }

    pub fn runCommand(self: *Ui, command: model.Command) void {
        switch (command) {
            .help => self.openHelp(),
            .plan => self.togglePlan(),
            .usage => self.sayUsage(),
            .@"resume" => self.openPicker(),
        }
    }

    pub fn openHelp(self: *Ui) void {
        self.pane = .{ .kind = .keys };
    }

    pub fn helpRows(
        arena: std.mem.Allocator,
    ) std.mem.Allocator.Error![]const []const u8 {
        var rows: std.ArrayList([]const u8) = .empty;
        try rows.append(arena, "keys");
        for ([_][2][]const u8{
            .{ "Enter", "send what you typed" },
            .{ "Ctrl-C", "once stops the turn, twice leaves" },
            .{ "Tab", "move the focus between the transcript and the input" },
            .{ "up down", "scroll the transcript, and step between the rows that open" },
            .{ "Space", "open or close the focused row, with the transcript focused" },
            .{ "g", "go to the newest row, with the transcript focused" },
            .{ "p", "open the plan beside the transcript, or close it" },
            .{ "?", "this" },
        }) |pair| {
            try rows.append(arena, try std.fmt.allocPrint(arena, "  {s: <8} {s}", .{
                pair[0],
                pair[1],
            }));
        }

        try rows.append(arena, "");
        try rows.append(arena, "in this pane");
        for ([_][2][]const u8{
            .{ "up down", "read the rest of it" },
            .{ "Esc", "close it" },
            .{ "?", "close it" },
        }) |pair| {
            try rows.append(arena, try std.fmt.allocPrint(arena, "  {s: <8} {s}", .{
                pair[0],
                pair[1],
            }));
        }

        try rows.append(arena, "");
        try rows.append(arena, "commands");
        for (model.Command.all) |one| {
            try rows.append(arena, try std.fmt.allocPrint(arena, "  {s: <8} {s}", .{
                one.typed(),
                one.does(),
            }));
        }
        try rows.append(arena, "");
        try rows.append(arena, "a line whose first word is not one of those is a message");
        return rows.items;
    }

    fn sayPlan(self: *Ui) void {
        if (self.plan.isEmpty()) {
            self.sayFmt(.chock, "the agent has written no plan", .{});
            return;
        }
        const counts = self.plan.counts();
        self.sayFmt(.chock, "plan: {d} done, {d} left", .{ counts.done, counts.left() });
        for (self.plan.steps.items) |step| {
            self.sayFmt(.chock, "  {s: <12} {s}", .{ step.status.wireName(), step.subject });
        }
    }

    pub fn togglePlan(self: *Ui) void {
        if (self.sidebar == .plan) {
            self.sidebar = .none;
            return;
        }
        if (!self.fitsSidebar()) {
            self.sayFmt(
                .chock,
                "there is no room beside the transcript. A wider display keeps the plan there.",
                .{},
            );
            self.sayPlan();
            return;
        }
        self.sidebar = .plan;
    }

    /// Keep the other sessions beside the transcript, rather than over it.
    ///
    /// The same list the picker shows, in the band instead of the middle, so a
    /// person reads one session and still sees the rest.
    pub fn toggleSessions(self: *Ui) void {
        if (self.sidebar == .sessions) {
            self.sidebar = .none;
            self.picker = null;
            return;
        }
        if (!self.fitsSidebar()) {
            self.openPicker();
            return;
        }
        self.sidebar = .sessions;
        self.refreshSessions();
    }

    /// Read the session list again, keeping whatever row was chosen.
    pub fn refreshSessions(self: *Ui) void {
        const was = self.picked;
        const offered = self.host.resumables(self.arena.allocator(), self.current_session) orelse return;
        self.picker = offered;
        self.picked = if (offered.len == 0) 0 else @min(was, offered.len - 1);
    }

    fn foldPlan(self: *Ui, update: chock_proto.event.PlanUpdate) void {
        var gave_up: [max_said_steps]usize = undefined;
        var count: usize = 0;
        for (update.steps, 0..) |step, at| {
            if (!model.isStatus(step.status, .abandoned)) continue;
            if (self.plan.find(step.id)) |had| {
                if (model.isStatus(had.status, .abandoned)) continue;
            }
            if (count == gave_up.len) break;
            gave_up[count] = at;
            count += 1;
        }

        self.plan.apply(self.arena.allocator(), update) catch {};

        if (self.sidebar != .plan) {
            for (update.steps) |step| {
                self.sayFmt(.chock, "plan step {s} is now {s}", .{
                    step.id,
                    step.status.wireName(),
                });
            }
            return;
        }

        for (gave_up[0..count]) |at| {
            self.sayFmt(.chock, "plan step {s} was given up: {s}", .{
                update.steps[at].id,
                update.steps[at].subject,
            });
        }

        const counts = self.plan.counts();
        const now = self.stepInProgress();
        if (now) |one| {
            self.sayFmt(.chock, "plan: {d} of {d} done, now on \"{s}\"", .{
                counts.done,
                counts.total(),
                one.subject,
            });
        } else {
            self.sayFmt(.chock, "plan: {d} of {d} done", .{ counts.done, counts.total() });
        }
    }

    const max_said_steps = 64;

    fn stepInProgress(self: *const Ui) ?chock_proto.state.Plan.Step {
        for (self.plan.steps.items) |step| {
            if (model.isStatus(step.status, .in_progress)) return step;
        }
        return null;
    }

    pub fn sayProbe(self: *Ui, caps: anytype, mode: phantom.tui.Mode, asked: bool) void {
        if (!self.host.verbose()) return;

        if (!asked) {
            self.sayFmt(.chock, "the terminal was not asked what it can do: it took no raw mode", .{});
            return;
        }

        self.sayFmt(.chock, "the terminal drawing mode is {s}", .{@tagName(mode)});
        self.sayFmt(
            .chock,
            "  it answered: graphics {s}, keyboard {s}, truecolor {s}",
            .{ model.yesNo(caps.kitty_graphics), model.yesNo(caps.kitty_keyboard), model.yesNo(caps.truecolor) },
        );
        self.sayFmt(
            .chock,
            "  and: sync {s}, inband resize {s}, pixel mouse {s}",
            .{ model.yesNo(caps.sync_output), model.yesNo(caps.inband_resize), model.yesNo(caps.sgr_pixel_mouse) },
        );

        const anything = caps.kitty_keyboard or caps.sync_output or
            caps.inband_resize or caps.sgr_pixel_mouse;
        if (!anything) {
            self.sayFmt(
                .chock,
                "  nothing came back at all, so the reply did not arrive rather than not matching",
                .{},
            );
        } else if (!caps.kitty_graphics) {
            self.sayFmt(
                .chock,
                "  a reply did arrive and its graphics answer did not match, which is phantom's matcher",
                .{},
            );
        }
    }

    pub fn resumable(self: *Ui, sessions_dir: []const u8, current: []const u8) void {
        self.sessions_dir = sessions_dir;
        self.current_session = current;
    }

    pub fn openPicker(self: *Ui) void {
        const arena = self.arena.allocator();
        const offered = self.host.resumables(arena, self.current_session) orelse {
            self.sayFmt(.chock, "the sessions of this project could not be read", .{});
            return;
        };
        if (offered.len == 0) {
            self.sayFmt(.chock, "this project has no other session to take up", .{});
            return;
        }
        self.picker = offered;
        self.picked = 0;
    }

    pub fn takePicked(self: *Ui) void {
        const offered = self.picker orelse return;
        if (offered.len == 0) return;
        const chosen = offered[@min(self.picked, offered.len - 1)];

        if (chosen.refusal.len != 0) {
            self.sayFmt(.chock, "{s} cannot be taken up: {s}", .{ chosen.id, chosen.refusal });
            return;
        }

        self.taken = chosen.id;
        // The band keeps the list: a person reading one session still sees the
        // rest. A picker drawn over the transcript goes away once it is used.
        if (self.sidebar != .sessions) self.picker = null;
        self.submitted = true;
    }

    fn sayUsage(self: *Ui) void {
        self.sayFmt(.chock, "usage: {d} tokens in, {d} tokens out", .{
            self.tokens_in,
            self.tokens_out,
        });
        if (self.spent_currency.len == 0) {
            self.sayFmt(.chock, "  the cost is not known for this provider", .{});
            return;
        }
        self.sayFmt(.chock, "  {d:.4} {s}", .{ self.spent, self.spent_currency });
    }

    pub fn beginInput(self: *Ui) void {
        self.host.takeKeys(.flush);
        self.typed.clearRetainingCapacity();
        self.submitted = false;
        self.phase = .message;
    }

    pub fn endInput(self: *Ui) void {
        self.host.giveKeys(.flush);
        self.phase = .session;
    }

    pub fn showApproval(self: *Ui, one: model.Approval) void {
        _ = self.approval_arena.reset(.free_all);
        const arena = self.approval_arena.allocator();

        var copy = one;
        copy.view = .question;
        for ([_]*[]const u8{
            &copy.action,
            &copy.summary,
            &copy.reason,
            &copy.chain,
            &copy.detail,
            &copy.review,
        }) |field| {
            field.* = arena.dupe(u8, field.*) catch "";
        }

        self.approval = copy;
        self.approval_answer = null;
        self.approval_settle = settle_looks;
        self.host.takeKeys(.flush);
        _ = self.paint();
        self.host.focusLast();
    }

    pub fn clearApproval(self: *Ui) void {
        if (self.approval == null) return;
        self.approval = null;
        self.approval_answer = null;
        self.approval_settle = 0;
        self.approval_focused = false;
        _ = self.approval_arena.reset(.free_all);
        self.host.giveKeys(.flush);
        _ = self.paint();
    }

    pub fn approvalLeft(self: *Ui, left_ms: i64) void {
        if (self.approval) |*one| one.left_ms = left_ms;
    }

    pub fn awaitAnswer(self: *Ui, budget_ms: u64) model.Look {
        if (self.approval == null) return .waiting;

        if (!self.approval_focused) self.host.focusLast();

        if (!self.paintWaiting(lookWait(budget_ms))) {
            self.running = false;
            self.host.requestStop();
            return .canceled;
        }

        if (self.approval_answer) |said| {
            self.approval_answer = null;
            return .{ .answered = said };
        }

        if (self.host.answersKeys()) {
            const presses = self.host.pumpKeys();
            if (presses != 0) {
                // The device goes back before the signal is raised.
                self.host.giveKeys(.flush);
                self.host.interrupt(presses);
                return .canceled;
            }
        }

        if (self.approval_settle > 0) self.approval_settle -= 1;

        if (self.approval_answer) |said| {
            self.approval_answer = null;
            return .{ .answered = said };
        }
        return .waiting;
    }

    pub fn pumpStep(self: *Ui) void {
        if (self.replaying) return;
        if (!self.running) return;
        if (self.approval != null or self.question != null) return;
        if (self.phase != .session) return;

        self.noteStopping();

        self.host.takeKeys(.now);
        defer self.host.giveKeys(.now);

        if (self.host.answersKeys() and self.host.keysWaiting()) {
            const presses = self.host.pumpKeys();
            if (presses != 0) {
                self.host.giveKeys(.now);
                self.host.interrupt(presses);
                return;
            }
        }

        if (self.paint()) return;

        self.running = false;
        self.host.requestStop();
    }

    pub fn showQuestion(self: *Ui, one: model.Question) void {
        _ = self.question_arena.reset(.free_all);
        const arena = self.question_arena.allocator();

        var copy = one;
        copy.agent_kind = arena.dupe(u8, one.agent_kind) catch "";
        copy.text = arena.dupe(u8, one.text) catch "";
        copy.options = dupeOptions(arena, one.options);

        self.question = copy;
        self.question_filled = 0;
        self.question_said = null;
        self.question_settle = settle_looks;
        self.host.takeKeys(.flush);
        _ = self.paint();
        self.host.focusLast();
    }

    pub fn clearQuestion(self: *Ui) void {
        if (self.question == null) return;
        std.crypto.secureZero(u8, self.question_typed[0..self.question_filled]);
        self.question = null;
        self.question_said = null;
        self.question_filled = 0;
        self.question_settle = 0;
        self.question_focused = false;
        _ = self.question_arena.reset(.free_all);
        self.host.giveKeys(.flush);
        _ = self.paint();
    }

    pub fn questionLeft(self: *Ui, left_ms: i64) void {
        if (self.question) |*one| one.left_ms = left_ms;
    }

    pub fn awaitText(self: *Ui, budget_ms: u64) model.Text {
        if (self.question == null) return .waiting;

        if (!self.question_focused) self.host.focusLast();

        if (!self.paintWaiting(lookWait(budget_ms))) {
            self.running = false;
            self.host.requestStop();
            return .canceled;
        }

        if (self.takeSaid()) |said| return said;

        if (self.host.answersKeys()) {
            const presses = self.host.pumpKeys();
            if (presses != 0) {
                self.host.giveKeys(.flush);
                self.host.interrupt(presses);
                return .canceled;
            }
        }

        if (self.question_settle > 0) self.question_settle -= 1;

        if (self.takeSaid()) |said| return said;
        return .waiting;
    }

    fn takeSaid(self: *Ui) ?model.Text {
        const said = self.question_said orelse return null;
        self.question_said = null;
        return switch (said) {
            .declined => .declined,
            .answered => .{ .answered = self.question_typed[0..self.question_filled] },
        };
    }

    pub fn questionRows(self: *const Ui) u16 {
        const one = self.question orelse return 0;
        var wanted: usize = 3 + countLines(one.text) + one.options.len;
        if (one.options.len != 0) wanted += 1; // the blank row before the list
        const half: u16 = @max(question_rows_min, self.rows / 2);
        const asked: u16 = @intCast(@min(wanted, std.math.maxInt(u16)));
        return @min(@max(question_rows_min, asked), half);
    }

    const question_rows_min: u16 = 4;

    pub fn panelRows(self: *const Ui) u16 {
        if (self.approval != null) return self.approvalRows();
        return self.questionRows();
    }

    pub fn approvalRows(self: *const Ui) u16 {
        const one = self.approval orelse return 0;
        return switch (one.view) {
            .question => question_rows,
            .diff, .why => @max(question_rows, self.rows / 2),
        };
    }

    const question_rows: u16 = 6;

    pub fn wrap(self: *Ui, inner: chock_core.Loop.Observer) void {
        self.inner = inner;
    }

    pub fn describe(self: *Ui, facts: model.Facts) void {
        self.facts = facts;
    }

    pub fn prime(self: *Ui, message: []const u8) void {
        self.primed = message;
    }

    pub fn note(self: *Ui, comptime fmt: []const u8, args: anytype) void {
        self.sayFmt(.chock, fmt, args);
    }

    pub fn stop(self: *Ui) void {
        if (self.stopped) return;
        self.stopped = true;
        self.endInput();
        self.host.dropKeys();

        self.host.finish();
        self.host.flushOut();

        self.host.writeOut(self.transcript.items);
        self.host.flushOut();
    }

    /// An interface with nothing in it yet. The caller gives it a host and a
    /// clock, then feeds it events.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, on: Host) !*Ui {
        const self = try gpa.create(Ui);
        self.* = .{
            .gpa = gpa,
            .io = io,
            .host = on,
            .rows = 0,
            .width = 0,
            .measure = layout.grid_measure,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .approval_arena = std.heap.ArenaAllocator.init(gpa),
            .question_arena = std.heap.ArenaAllocator.init(gpa),
            .seen_scrolls = 0,
        };
        return self;
    }

    /// Say where the time comes from. A browser has no system clock this code
    /// can reach, so its page gives one that reads the daemon's own times.
    pub fn setClock(
        self: *Ui,
        ctx: ?*anyopaque,
        nowMs: *const fn (?*anyopaque) i64,
        offset_minutes: i32,
    ) void {
        self.clock = .{ .ctx = ctx, .nowMs = nowMs, .utc_offset_minutes = offset_minutes };
    }

    pub fn deinit(self: *Ui) void {
        const gpa = self.gpa;
        self.stop();
        self.arena.deinit();
        self.approval_arena.deinit();
        self.question_arena.deinit();
        self.transcript.deinit(gpa);
        self.typed.deinit(gpa);
        self.pending.deinit(gpa);
        self.reasoning.deinit(gpa);
        self.dropRunning();
        for (self.lines.items) |line| self.freeLine(line);
        self.lines.deinit(gpa);
        self.host.release();
        gpa.destroy(self);
    }

    pub fn observer(self: *Ui) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        const self: *Ui = @ptrCast(@alignCast(ptr));
        if (self.inner) |one| one.onEvent(id, ev);
        self.foldEvent(id, ev);
    }

    fn foldEvent(self: *Ui, id: u64, ev: chock_proto.event.Event) void {
        _ = id;
        switch (ev) {
            .plan_update => |update| self.foldPlan(update),
            .message => |m| switch (m.role) {
                .assistant => {
                    self.foldReasoning();
                    self.endLine();
                    self.turn_open = false;
                },
                .system => for (m.content) |part| {
                    if (part == .text) self.say(.chock, part.text);
                },
                else => {},
            },
            .tool_call => |call| self.beginCall(call),
            .tool_result => |result| self.finishCall(result),
            .compaction => |folded| {
                var buffer: [128]u8 = undefined;
                const said = std.fmt.bufPrint(
                    &buffer,
                    "\u{2500}\u{2500} events {d} to {d} folded. The log keeps them.",
                    .{ folded.from_id, folded.through_id },
                ) catch "\u{2500}\u{2500} the context was folded. The log keeps it.";
                self.sayFolded(.chock, said, .compaction, folded.summary);
            },
            .session_spawn => |spawn| {
                var buffer: [256]u8 = undefined;
                const said = std.fmt.bufPrint(&buffer, "started a subagent, {s}", .{
                    spawn.child_agent_kind,
                }) catch "started a subagent";
                self.sayFolded(.chock, said, .subagent, spawn.reason);
            },
            .agent_complete => |done| {
                var buffer: [256]u8 = undefined;
                const said = std.fmt.bufPrint(&buffer, "the subagent {s} came back, {s}", .{
                    done.child_agent_kind,
                    done.outcome.wireName(),
                }) catch "a subagent came back";
                self.sayFolded(.chock, said, .subagent, done.result);
            },
            .task_complete => |done| if (self.tasks_shown_early > 0) {
                self.tasks_shown_early -= 1;
            } else self.sayFmt(.chock, "the background task {s} finished, {s} {d}", .{
                done.task_id,
                done.status.wireName(),
                done.code,
            }),
            .policy_self => |update| for (update.restrictions) |one| {
                self.sayFmt(.chock, "the agent promised {s} at most {s}", .{
                    one.action,
                    one.ceiling.wireName(),
                });
            },
            .workspace_integrate => |landed| if (landed.branch.len != 0) self.sayFmt(
                .chock,
                "your branch {s} moved to {s}, because this project asks for {s}",
                .{ landed.branch, landed.branch_to, landed.mode },
            ) else self.sayFmt(
                .chock,
                "no branch of yours moved, and the reason recorded is {s}. The work is at {s}",
                .{ landed.parked, landed.ref },
            ),
            .sandbox_open => |opened| switch (opened.write_execute) {
                .strict => {},
                .relaxed, .unknown => self.sayFmt(
                    .chock,
                    "the write and execute rule is off for this session, because the policy " ++
                        "answers {s} for sandbox.jit",
                    .{opened.decision},
                ),
            },
            .session_end => |ended| if (ended.detail.len == 0)
                self.sayFmt(.chock, "session ended, {s}", .{ended.reason.wireName()})
            else
                self.sayFmt(.chock, "session ended, {s}: {s}", .{
                    ended.reason.wireName(),
                    ended.detail[0..@min(ended.detail.len, shown_detail_bytes)],
                }),
            .usage => |spent| {
                self.tokens_in += spent.input_tokens +
                    spent.cache_creation_input_tokens +
                    spent.cache_read_input_tokens;
                self.tokens_out += spent.output_tokens;
                switch (spent.cost) {
                    .known => |amount| {
                        self.spent += amount.value;
                        self.spent_currency = amount.currency;
                    },
                    .free, .unknown, .unrecognized => {},
                }
            },
            else => {},
        }
        self.draw();
    }

    pub fn replay(self: *Ui, id: u64, ev: chock_proto.event.Event) void {
        self.replaying = true;
        defer self.replaying = false;
        switch (ev) {
            .message => |m| switch (m.role) {
                .assistant => {
                    self.openTurn();
                    for (m.content) |part| {
                        if (part == .text) self.say(.agent, part.text);
                    }
                    self.endLine();
                    self.turn_open = false;
                },
                .user => for (m.content) |part| {
                    if (part == .text) self.saidByUser(part.text);
                },
                else => self.foldEvent(id, ev),
            },
            else => self.foldEvent(id, ev),
        }
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Ui = @ptrCast(@alignCast(ptr));
        if (self.inner) |one| one.onPiece(piece);
        switch (piece) {
            .text => |text| {
                self.openTurn();
                self.foldReasoning();
                self.say(.agent, text);
            },
            .reasoning => |text| {
                self.openTurn();
                self.reasoning.appendSlice(self.gpa, text) catch {};
            },
        }
        self.draw();
    }

    pub fn openTurn(self: *Ui) void {
        if (self.turn_open) return;
        self.turn_open = true;
        self.startBlock();
        if (self.facts.model.len == 0) return;

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const at = text_mod.clockText(arena, self.clock.now(), self.clock.utc_offset_minutes) catch return;
        const who = if (self.facts.provider.len == 0)
            self.facts.model
        else
            std.fmt.allocPrint(arena, "{s} \u{b7} {s}", .{
                self.facts.model,
                self.facts.provider,
            }) catch self.facts.model;
        self.sayPinned(.agent, who, at);
    }

    fn foldReasoning(self: *Ui) void {
        if (self.reasoning.items.len == 0) return;
        var buffer: [64]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&buffer);
        const size = text_mod.sizeText(fixed.allocator(), self.reasoning.items.len) catch "some";

        var said: [96]u8 = undefined;
        const text = std.fmt.bufPrint(&said, "{s} of reasoning", .{size}) catch "reasoning";
        self.sayFolded(.agent, text, .reasoning, self.reasoning.items);
        self.reasoning.clearRetainingCapacity();
    }

    fn beginCall(self: *Ui, call: chock_proto.event.ToolCall) void {
        self.dropRunning();
        self.startBlock();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const argument = if (std.mem.eql(u8, call.tool, chock_core.Loop.ask_tool_name))
            text_mod.askArgumentText(arena, call.arguments) catch call.arguments
        else
            text_mod.argumentText(arena, call.arguments) catch call.arguments;
        const tool = self.gpa.dupe(u8, call.tool) catch return;
        const kept = self.gpa.dupe(u8, argument) catch {
            self.gpa.free(tool);
            return;
        };
        self.running_call = .{ .tool = tool, .argument = kept, .at_ms = self.clock.now() };

        self.sayPinned(.agent, callText(arena, "\u{22ef}", tool, kept) catch "", "");
        self.running_row = if (self.lines.items.len == 0) null else self.lines.items.len - 1;
    }

    fn callText(
        arena: std.mem.Allocator,
        glyph: []const u8,
        tool: []const u8,
        argument: []const u8,
    ) std.mem.Allocator.Error![]const u8 {
        return std.fmt.allocPrint(arena, "{s} {s}  {s}", .{ glyph, tool, argument });
    }

    fn finishCall(self: *Ui, result: chock_proto.event.ToolResult) void {
        self.endLine();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const glyph = if (result.is_error) "\u{2717}" else "\u{2713}";
        if (self.running_call) |call| {
            const took = text_mod.durationText(arena, self.clock.now() - call.at_ms) catch "";
            const said = callText(arena, glyph, call.tool, call.argument) catch "";
            self.rewriteRunningRow(said, took);
        }
        self.dropRunning();

        if (result.note.len != 0) {
            self.say(.chock, result.note);
            self.endLine();
        }

        const summary = text_mod.summaryText(
            arena,
            result.output,
            result.is_error,
            result.truncated,
        ) catch "no output";
        self.sayFolded(.agent, summary, .result, result.output);
    }

    fn rewriteRunningRow(self: *Ui, text: []const u8, right: []const u8) void {
        const at = self.running_row orelse return;
        if (at >= self.lines.items.len) return;
        const kept = self.gpa.dupe(u8, text) catch return;
        const held = self.gpa.dupe(u8, right) catch {
            self.gpa.free(kept);
            return;
        };
        self.gpa.free(self.lines.items[at].text);
        self.gpa.free(self.lines.items[at].pinned);
        self.lines.items[at].text = kept;
        self.lines.items[at].pinned = held;
    }

    fn dropRunning(self: *Ui) void {
        if (self.running_call) |call| {
            self.gpa.free(call.tool);
            self.gpa.free(call.argument);
        }
        self.running_call = null;
        self.running_row = null;
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *Ui = @ptrCast(@alignCast(ptr));
        if (self.inner) |one| one.onNotice(text);
        self.startBlock();
        self.say(.chock, text);
        self.endLine();
        self.draw();
    }

    const shown_line_bytes = 400;

    const shown_detail_bytes = 240;

    pub const kept_lines = 512;

    pub fn say(self: *Ui, voice: model.Voice, text: []const u8) void {
        if (voice != self.pending_voice) self.endLine();
        self.pending_voice = voice;

        var rest = text;
        while (std.mem.indexOfScalar(u8, rest, '\n')) |at| {
            self.pending.appendSlice(self.gpa, rest[0..at]) catch {};
            self.endRow();
            self.pending_voice = voice;
            rest = rest[at + 1 ..];
        }
        self.pending.appendSlice(self.gpa, rest) catch {};
    }

    fn sayFmt(self: *Ui, voice: model.Voice, comptime fmt: []const u8, args: anytype) void {
        var buffer: [shown_line_bytes + 128]u8 = undefined;
        const said = std.fmt.bufPrint(&buffer, fmt, args) catch said: {
            @memset(buffer[buffer.len - 3 ..], '.');
            break :said buffer[0..];
        };
        self.say(voice, said);
        self.endLine();
    }

    const kept_body_bytes = 16 * 1024;

    const open_body_rows = 200;

    pub fn screenRoom(self: *const Ui) layout.Room {
        return .{ .measure = self.measure, .width = self.width };
    }

    pub fn transcriptRoom(self: *const Ui) layout.Room {
        return self.transcriptBandRoom().upTo(@as(f32, readable_columns) * self.measure.step());
    }

    pub fn sidebarWidth(self: *const Ui) f32 {
        if (self.sidebar == .none) return 0;
        if (!self.fitsSidebar()) return 0;
        return @as(f32, self.sidebar.columns()) * self.measure.step();
    }

    pub fn fitsSidebar(self: *const Ui) bool {
        return self.width >= @as(f32, model.sidebar_needs_columns) * self.measure.step();
    }

    pub fn transcriptBandRoom(self: *const Ui) layout.Room {
        const room = self.screenRoom();
        const side = self.sidebarWidth();
        return .{
            .measure = room.measure,
            .width = if (room.width > side) room.width - side else 0,
        };
    }

    fn sidebarRoom(self: *const Ui) layout.Room {
        return .{ .measure = self.measure, .width = self.sidebarWidth() };
    }

    pub fn roomFor(self: *const Ui, voice: model.Voice) layout.Room {
        return self.transcriptRoom().less(voice.prefix());
    }

    pub fn agentRoom(self: *const Ui) layout.Room {
        return self.roomFor(.agent);
    }

    pub fn endLine(self: *Ui) void {
        if (self.pending.items.len == 0) return;
        self.endRow();
    }

    pub fn endRow(self: *Ui) void {
        defer self.pending.clearRetainingCapacity();
        self.addLine(self.lineOf(self.pending_voice, self.pending.items) orelse return);
    }

    /// One stored line, with the markdown markers taken off and the runs they
    /// marked kept beside the words.
    ///
    /// The spans the parser answers borrow the text given to it, which is about
    /// to go away, so each is pointed at the copy this keeps instead. Both are
    /// freed together in `freeLine`.
    fn lineOf(self: *Ui, voice: model.Voice, raw: []const u8) ?model.Line {
        var room = std.heap.ArenaAllocator.init(self.gpa);
        defer room.deinit();

        const read = self.markdown.line(room.allocator(), raw) catch
            return self.plainLine(voice, raw);

        var plain: std.ArrayList(u8) = .empty;
        for (read.spans) |one| plain.appendSlice(room.allocator(), one.text) catch
            return self.plainLine(voice, raw);

        const kept = self.gpa.dupe(u8, plain.items) catch return null;
        const spans = self.gpa.alloc(phantom.text.markdown.Span, read.spans.len) catch {
            self.gpa.free(kept);
            return null;
        };

        var at: usize = 0;
        for (read.spans, spans) |one, *into| {
            into.* = .{ .text = kept[at..][0..one.text.len], .style = one.style };
            at += one.text.len;
        }
        return .{ .voice = voice, .text = kept, .spans = spans, .block = read.block };
    }

    /// The words as they came, for a line the reader could not take.
    fn plainLine(self: *Ui, voice: model.Voice, raw: []const u8) ?model.Line {
        const kept = self.gpa.dupe(u8, raw) catch return null;
        return .{ .voice = voice, .text = kept };
    }

    fn startBlock(self: *Ui) void {
        self.endLine();
        if (self.lines.items.len == 0) return;
        if (self.lines.items[self.lines.items.len - 1].gap) return;
        self.addLine(.{ .voice = .chock, .text = "", .gap = true });
    }

    fn sayFolded(
        self: *Ui,
        voice: model.Voice,
        text: []const u8,
        kind: model.Fold.Kind,
        body: []const u8,
    ) void {
        self.endLine();
        if (body.len == 0) {
            self.say(voice, text);
            self.endLine();
            return;
        }
        const kept = self.gpa.dupe(u8, text) catch return;
        const held = self.gpa.dupe(u8, body[0..@min(body.len, kept_body_bytes)]) catch {
            self.gpa.free(kept);
            return;
        };
        self.addLine(.{
            .voice = voice,
            .text = kept,
            .fold = .{ .kind = kind, .body = held, .dropped = body.len - held.len },
        });
    }

    fn addLine(self: *Ui, line: model.Line) void {
        if (self.lines.items.len >= kept_lines) {
            self.freeLine(self.lines.orderedRemove(0));
            if (self.running_row) |at| self.running_row = if (at == 0) null else at - 1;
            if (self.cursor) |at| self.cursor = if (at == 0) null else at - 1;
        }
        self.lines.append(self.gpa, line) catch self.freeLine(line);
    }

    fn freeLine(self: *Ui, line: model.Line) void {
        self.gpa.free(line.text);
        self.gpa.free(line.spans);
        self.gpa.free(line.pinned);
        if (line.fold) |one| self.gpa.free(one.body);
    }

    fn sayPinned(self: *Ui, voice: model.Voice, text: []const u8, right: []const u8) void {
        self.endLine();
        const kept = self.gpa.dupe(u8, text) catch return;
        const held = self.gpa.dupe(u8, right) catch {
            self.gpa.free(kept);
            return;
        };
        self.addLine(.{ .voice = voice, .text = kept, .pinned = held });
    }

    pub const stopping_text = "stopping at the next safe point, and writing the session end. " ++
        "Press Ctrl-C again to stop now.";

    fn noteStopping(self: *Ui) void {
        if (self.said_stopping) return;
        if (!self.host.stopRequested()) return;
        self.said_stopping = true;
        self.startBlock();
        self.say(.chock, stopping_text);
        self.endLine();
    }

    fn draw(self: *Ui) void {
        if (self.replaying) return;
        if (!self.running) return;
        self.noteStopping();
        if (self.paint()) return;

        self.running = false;
        self.host.requestStop();
    }

    fn followSize(self: *Ui) void {
        if (self.fixed_size) return;
        self.host.followSize();
    }

    pub fn paint(self: *Ui) bool {
        return self.paintWaiting(0);
    }

    pub const look_ms: u32 = @intCast(chock_core.idle.slice_ms);

    pub fn lookWait(budget_ms: u64) u32 {
        return @intCast(@min(budget_ms, @as(u64, look_ms)));
    }

    pub fn paintWaiting(self: *Ui, wait_ms: u32) bool {
        const scrolls: u32 = @intCast(self.host.scrollCount());
        if (scrolls != self.seen_scrolls) {
            self.seen_scrolls = scrolls;
            self.host.invalidate();
        }

        self.followSize();

        if (self.screen) |one| phantom.markNeedsBuild(one);
        const carry_on = self.host.step(wait_ms);
        self.host.flushOut();
        return carry_on;
    }

    fn view(self: *Ui, ctx: *phantom.BuildContext) phantom.Widget {
        const colors = phantom.ColorScheme.tokyoNight();
        const measure = self.resize(ctx);
        const parts = layout.split(self.rows, self.panelRows());

        var regions: std.ArrayList(phantom.Widget) = .empty;
        regions.append(ctx.arena, band(
            ctx,
            measure,
            parts.header,
            colors.bg_dark,
            self.headerRows(ctx, colors),
        )) catch {};
        regions.append(ctx.arena, self.middleRegions(
            ctx,
            measure,
            parts.transcript,
            colors,
        )) catch {};
        if (parts.approval != 0) {
            const approving = self.approval != null;
            regions.append(ctx.arena, ctx.new(phantom.Focus{
                .child = band(
                    ctx,
                    measure,
                    parts.approval,
                    colors.bg_medium,
                    if (approving)
                        self.approvalRegion(ctx, parts.approval, colors)
                    else
                        self.questionRegion(ctx, parts.approval, colors),
                ),
                .on_key = if (approving) onApprovalKey else onQuestionKey,
                .on_focus_change = if (approving) onApprovalFocus else onQuestionFocus,
                .ctx = self,
            }).widget()) catch {};
        }
        regions.append(ctx.arena, band(
            ctx,
            measure,
            parts.input,
            colors.bg_dark,
            self.inputRows(ctx, colors),
        )) catch {};

        const screen = ctx.new(phantom.Column(.{ .children = regions.items })).widget();
        return ctx.new(phantom.KeyboardListener{
            .child = screen,
            .on_key = onSessionKey,
            .ctx = self,
        }).widget();
    }

    fn resize(self: *Ui, ctx: *phantom.BuildContext) layout.Measure {
        const measure = layout.Measure.of(ctx);
        self.measure = measure;
        const view_now = ctx.owner.activeView() orelse return measure;
        self.rows = measure.rowsIn(view_now.metrics.size.height);
        self.width = view_now.metrics.size.width;
        return measure;
    }

    fn band(
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        rows: u16,
        color: phantom.Color,
        contents: []const phantom.Widget,
    ) phantom.Widget {
        const inside = ctx.new(phantom.Column(.{ .children = contents })).widget();
        const painted = ctx.new(phantom.DecoratedBox{ .color = color, .child = inside }).widget();
        return ctx.new(phantom.SizedBox{
            .height = bandHeight(measure, rows),
            .child = painted,
        }).widget();
    }

    fn bandHeight(measure: layout.Measure, rows: u16) f32 {
        return @as(f32, @floatFromInt(rows)) * measure.height();
    }

    fn middleRegions(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const focused = ctx.new(phantom.Focus{
            .child = self.transcriptBand(ctx, measure, rows, colors),
            .on_key = onTranscriptKey,
            .on_focus_change = onTranscriptFocus,
            .ctx = self,
        }).widget();

        const side = self.sidebarWidth();
        const beside = if (side > 0) band(
            ctx,
            measure,
            rows,
            colors.bg_dark,
            self.sidebarRows(ctx, rows, colors),
        ) else plainRow(ctx, "", colors.fg);

        const both = ctx.newSlice(phantom.Widget, &.{
            ctx.new(phantom.Expanded(.{ .child = focused })).widget(),
            ctx.new(phantom.SizedBox{ .width = side, .child = beside }).widget(),
        });
        return ctx.new(phantom.SizedBox{
            .height = bandHeight(measure, rows),
            .child = ctx.new(phantom.Row(.{ .children = both })).widget(),
        }).widget();
    }

    fn sidebarRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        if (self.sidebar == .sessions) return self.sessionRows(ctx, rows, colors);

        var lines = Rows{ .left = rows };
        const said = model.planRows(ctx.arena, self.plan, rows) catch return &.{};
        for (said) |one| {
            lines.add(ctx.arena, row(
                ctx,
                self.measure,
                layout.visibleLine(ctx.arena, one.text, self.sidebarRoom()) catch "",
                switch (one.tone) {
                    .title => colors.blue_light,
                    .now => colors.green,
                    .step => colors.fg,
                    .aside => colors.fg_muted,
                },
            ));
        }
        return lines.items();
    }

    /// The other sessions, in the band beside the transcript.
    ///
    /// One line each and the title alone, because a column this narrow has no
    /// room for an identifier a person does not read anyway.
    fn sessionRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var lines = Rows{ .left = rows };
        const offered = self.picker orelse &[_]model.Resumable{};

        var at: usize = 0;
        while (at < offered.len and lines.left > 0) : (at += 1) {
            const one = offered[at];
            if (self.opensGroup(at)) {
                lines.add(ctx.arena, row(
                    ctx,
                    self.measure,
                    layout.visibleLine(ctx.arena, one.group, self.sidebarRoom()) catch "",
                    colors.fg_muted,
                ));
                if (lines.left == 0) break;
            }
            lines.add(ctx.arena, self.sessionRow(ctx, one, at, colors));
        }
        return lines.items();
    }

    fn sessionRow(
        self: *Ui,
        ctx: *phantom.BuildContext,
        one: model.Resumable,
        at: usize,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const chosen = at == self.picked;
        const said = std.fmt.allocPrint(ctx.arena, "{s} {s}", .{
            if (chosen) "\u{25b8}" else " ",
            one.words,
        }) catch one.words;

        const drawn = row(
            ctx,
            self.measure,
            layout.visibleLine(ctx.arena, said, self.sidebarRoom()) catch "",
            if (one.refusal.len != 0)
                colors.fg_muted
            else if (chosen)
                colors.blue_light
            else
                colors.fg,
        );

        if (one.refusal.len != 0 or at >= max_picker_taps) return drawn;
        self.picker_taps[at] = .{ .ui = self, .index = at };
        return ctx.new(phantom.GestureDetector{
            .child = drawn,
            .on_tap = onPickerTap,
            .ctx = &self.picker_taps[at],
        }).widget();
    }

    fn transcriptBand(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const under = band(
            ctx,
            measure,
            rows,
            colors.bg,
            self.transcriptRows(ctx, measure, rows, colors),
        );
        const over = self.paneOver(ctx, rows, colors) orelse return under;
        return ctx.new(phantom.Stack{
            .children = ctx.newSlice(phantom.Widget, &.{ under, over }),
        }).widget();
    }

    fn paneOver(
        self: *Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) ?phantom.Widget {
        if (self.pane == null) return null;
        const contents = self.paneRows(ctx, rows, colors);
        const inside = ctx.new(phantom.Column(.{ .children = contents })).widget();
        const painted = ctx.new(phantom.DecoratedBox{
            .color = colors.bg_medium,
            .child = inside,
        }).widget();
        return ctx.new(phantom.Positioned{
            .top = 0,
            .right = 0,
            .bottom = 0,
            .left = 0,
            .child = painted,
        }).widget();
    }

    fn paneRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        if (self.pane == null) return &.{};
        const pane = &self.pane.?;
        const all = switch (pane.kind) {
            .keys => helpRows(ctx.arena) catch return &.{},
        };
        const total: u16 = @intCast(@min(all.len, std.math.maxInt(u16)));

        var lines = Rows{ .left = rows };
        const room = rows -| 2;
        pane.hold(room, total);

        lines.add(ctx.arena, self.bandRow(ctx, switch (pane.kind) {
            .keys => " keys",
        }, colors.blue_light));

        var index: u16 = pane.at;
        while (index < total and index < pane.at + room) : (index += 1) {
            lines.add(ctx.arena, self.bandRow(
                ctx,
                std.fmt.allocPrint(ctx.arena, " {s}", .{all[index]}) catch "",
                colors.fg,
            ));
        }

        const left = total -| (pane.at + room);
        lines.add(ctx.arena, self.bandRow(ctx, if (left == 0)
            " Esc closes this"
        else
            std.fmt.allocPrint(ctx.arena, " {d} rows below. Esc closes this.", .{
                left,
            }) catch " Esc closes this", colors.fg_muted));
        return lines.items();
    }

    fn headerRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var said: std.ArrayList(model.HeaderPiece) = .empty;
        model.headerPieces(ctx.arena, self.facts, self.screenRoom(), &said) catch {};

        var pieces: std.ArrayList(phantom.Widget) = .empty;
        for (said.items) |one| {
            pieces.append(ctx.arena, row(ctx, self.measure, one.text, switch (one.tone) {
                .name => colors.fg,
                .context => colors.fg_muted,
                .on => colors.green,
                .off => colors.red,
            })) catch {};
        }

        const line = ctx.new(phantom.Row(.{ .children = pieces.items })).widget();
        return ctx.newSlice(phantom.Widget, &.{line});
    }

    fn transcriptRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var lines = Rows{ .left = rows };
        var room = rows;

        var slots: [model.Command.all.len]model.Command = undefined;
        const all_listed = self.openCompletions(&slots);
        // The band beside this one has the list when it is open, so drawing it
        // here as well would show every session twice.
        const all_offered = if (self.sidebar == .sessions)
            &[_]model.Resumable{}
        else
            self.picker orelse &[_]model.Resumable{};
        const taken: u16 = @intCast(@min(all_listed.len + all_offered.len, room));
        const listed = all_listed[0..@min(all_listed.len, taken)];
        const seats: u16 = @intCast(taken - listed.len);
        const first = self.pickerFirst(seats);
        const offered = all_offered[@min(first, all_offered.len)..][0..self.pickerCount(first, seats)];
        room -= taken;

        if (self.showsRule() and room != 0) {
            lines.add(ctx.arena, self.ruleRow(ctx, colors));
            room -= 1;
        }

        const open: u16 = if (self.pending.items.len != 0 and self.scroll_back == 0) 1 else 0;
        const shown = self.visibleRows(ctx.arena, room -| open);

        var blank: u16 = room -| (@as(u16, @intCast(shown.len)) + open);
        while (blank > 0) : (blank -= 1) {
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
        }
        for (shown) |line| {
            lines.add(ctx.arena, self.voicedRow(ctx, measure, line, colors));
        }
        if (open != 0) {
            lines.add(ctx.arena, self.voicedRow(ctx, measure, .{
                .voice = self.pending_voice,
                .text = self.pending.items,
            }, colors));
        }
        for (self.completionRows(ctx, listed, colors)) |one| {
            lines.add(ctx.arena, one);
        }
        for (offered, 0..) |one, index| {
            const at = first + index;
            if (self.opensGroup(at)) {
                lines.add(ctx.arena, self.groupRow(ctx, one.group, colors));
            }
            lines.add(ctx.arena, self.pickerRow(ctx, one, at, colors));
        }
        return lines.items();
    }

    fn approvalRegion(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        const one = self.approval orelse return &.{};
        var lines = Rows{ .left = rows };

        if (rows == 0) return &.{};
        var room = rows - 1;

        if (room != 0) {
            room -= 1;
            const left = countdownText(ctx.arena, one.left_ms) catch "";
            lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                ctx.arena,
                " APPROVAL  {s}   {s}",
                .{ one.action, left },
            ) catch " APPROVAL", colors.blue_light));
        }
        switch (one.view) {
            .question => {
                const middle = [_][]const u8{
                    std.fmt.allocPrint(ctx.arena, " {s}  depth {d}", .{
                        one.chain,
                        one.depth,
                    }) catch " ",
                    std.fmt.allocPrint(ctx.arena, "   \"{s}\"", .{one.reason}) catch " ",
                    std.fmt.allocPrint(ctx.arena, "   {s}", .{one.summary}) catch " ",
                    if (one.review.len != 0)
                        std.fmt.allocPrint(ctx.arena, "   review: {s}", .{one.review}) catch " "
                    else
                        std.fmt.allocPrint(ctx.arena, "   {d} bytes of effect. [d] shows them.", .{
                            one.detail.len,
                        }) catch " ",
                };
                const tones = [middle.len]phantom.Color{
                    colors.fg_muted,
                    colors.fg,
                    colors.fg,
                    colors.fg_muted,
                };
                for (middle, tones) |text, tone| {
                    if (room == 0) break;
                    room -= 1;
                    lines.add(ctx.arena, self.regionRow(ctx, text, tone));
                }
            },
            .diff => {
                var rest = one.detail;
                while (room > 0) : (room -= 1) {
                    const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
                    lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                        ctx.arena,
                        "   {s}",
                        .{rest[0..at]},
                    ) catch " ", colors.fg));
                    if (at == rest.len) break;
                    rest = rest[at + 1 ..];
                }
            },
            .why => {
                const middle = [_][]const u8{
                    std.fmt.allocPrint(ctx.arena, " {s}  depth {d}", .{
                        one.chain,
                        one.depth,
                    }) catch " ",
                    std.fmt.allocPrint(ctx.arena, "   \"{s}\"", .{one.reason}) catch " ",
                };
                for (middle) |text| {
                    if (room == 0) break;
                    room -= 1;
                    lines.add(ctx.arena, self.regionRow(ctx, text, colors.fg));
                }
            },
        }

        while (lines.left > 1) {
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
        }
        lines.add(ctx.arena, self.regionRow(
            ctx,
            if (self.host.answersKeys())
                approvalKeys(self.screenRoom())
            else
                elsewhereText(ctx.arena, self.current_session, self.screenRoom()),
            colors.blue_light,
        ));
        return lines.items();
    }

    fn questionRegion(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        const one = self.question orelse return &.{};
        var lines = Rows{ .left = rows };

        if (rows == 0) return &.{};
        if (rows < 3) return &.{};
        var room = rows - 3;

        const left = countdownText(ctx.arena, one.left_ms) catch "";
        lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
            ctx.arena,
            " QUESTION from {s}   {s}",
            .{ if (one.agent_kind.len == 0) "the agent" else one.agent_kind, left },
        ) catch " QUESTION", colors.blue_light));

        var body = std.mem.splitScalar(u8, one.text, '\n');
        while (body.next()) |line| {
            if (room == 0) break;
            room -= 1;
            lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                ctx.arena,
                chock_core.ask.question_marker ++ "{s}",
                .{line},
            ) catch chock_core.ask.question_marker, colors.fg));
        }

        if (one.options.len != 0 and room != 0) {
            room -= 1;
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
            for (one.options, 1..) |option, number| {
                if (room == 0) break;
                room -= 1;
                lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
                    ctx.arena,
                    chock_core.ask.question_marker ++ "{d}) {s}",
                    .{ number, option },
                ) catch chock_core.ask.question_marker, colors.fg_muted));
            }
        }

        while (lines.left > 2) {
            lines.add(ctx.arena, plainRow(ctx, "", colors.fg));
        }

        const shown: []const u8 = switch (one.echo) {
            .on => self.question_typed[0..self.question_filled],
            .masked => marks: {
                const cells = ctx.arena.alloc(u8, self.question_filled) catch break :marks "";
                @memset(cells, '*');
                break :marks cells;
            },
        };
        lines.add(ctx.arena, self.regionRow(ctx, std.fmt.allocPrint(
            ctx.arena,
            answer_prompt ++ "{s}\u{2588}",
            .{shown},
        ) catch answer_prompt, colors.fg));

        lines.add(ctx.arena, self.regionRow(
            ctx,
            if (self.host.answersKeys())
                model.questionKeys(self.screenRoom(), one.options.len != 0)
            else
                question_unanswerable,
            colors.blue_light,
        ));
        return lines.items();
    }

    fn regionRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        return row(
            ctx,
            self.measure,
            layout.visibleLine(ctx.arena, text, self.screenRoom()) catch "",
            color,
        );
    }

    fn bandRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        return row(
            ctx,
            self.measure,
            layout.visibleLine(ctx.arena, text, self.transcriptBandRoom()) catch "",
            color,
        );
    }

    /// The first picker row to draw, so the chosen one stays in view and the
    /// heading it sits under fits beside it.
    ///
    /// Walks back from the chosen row, paying for a heading wherever the project
    /// changes, until the seats run out.
    fn pickerFirst(self: *const Ui, seats: u16) usize {
        const offered = self.picker orelse return 0;
        if (offered.len == 0 or seats == 0) return 0;

        const chosen = @min(self.picked, offered.len - 1);
        var at = chosen;
        var used: u16 = 0;
        while (true) {
            const cost: u16 = if (self.opensGroup(at)) 2 else 1;
            if (used + cost > seats) {
                at += 1;
                break;
            }
            used += cost;
            if (at == 0) break;
            at -= 1;
        }
        return @min(at, chosen);
    }

    /// How many picker rows fit from `first`, counting the headings they need.
    fn pickerCount(self: *const Ui, first: usize, seats: u16) usize {
        const offered = self.picker orelse return 0;
        var at = first;
        var used: u16 = 0;
        while (at < offered.len) : (at += 1) {
            const cost: u16 = if (self.opensGroup(at)) 2 else 1;
            if (used + cost > seats) break;
            used += cost;
        }
        return at - first;
    }

    /// Whether this row starts a run of rows from one project. The first row
    /// always does, and after that only a row whose project differs from the
    /// one above it.
    fn opensGroup(self: *const Ui, at: usize) bool {
        const offered = self.picker orelse return false;
        if (at >= offered.len) return false;
        if (offered[at].group.len == 0) return false;
        if (at == 0) return true;
        return !std.mem.eql(u8, offered[at].group, offered[at - 1].group);
    }

    fn groupRow(
        self: *Ui,
        ctx: *phantom.BuildContext,
        said: []const u8,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        return self.bandRow(ctx, said, colors.fg_dim);
    }

    fn pickerRow(
        self: *Ui,
        ctx: *phantom.BuildContext,
        one: model.Resumable,
        index: usize,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const chosen = index == self.picked;
        const words = if (one.refusal.len == 0)
            std.fmt.allocPrint(ctx.arena, "{s} {s}", .{
                if (chosen) "\u{25b8}" else " ",
                one.words,
            }) catch one.words
        else
            std.fmt.allocPrint(ctx.arena, "{s} {s}  {s}", .{
                if (chosen) "\u{25b8}" else " ",
                one.words,
                one.refusal,
            }) catch one.words;

        const drawn = self.bandRow(ctx, words, if (one.refusal.len != 0)
            colors.red
        else if (chosen)
            colors.blue_light
        else
            colors.fg_muted);

        // A row a refusal covers cannot be taken up, so it does not answer a
        // tap either. A gesture and not a `Button`: a button paints a filled
        // shape sized to its own text, which turns a list into ragged blocks.
        if (one.refusal.len != 0 or index >= max_picker_taps) return drawn;
        self.picker_taps[index] = .{ .ui = self, .index = index };
        return ctx.new(phantom.GestureDetector{
            .child = drawn,
            .on_tap = onPickerTap,
            .ctx = &self.picker_taps[index],
        }).widget();
    }

    fn ruleRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        const words = std.fmt.allocPrint(
            ctx.arena,
            "\u{2500}\u{2500} {d} rows above. The log keeps them. \u{2500}\u{2500}",
            .{self.scroll_back},
        ) catch "\u{2500}\u{2500}";
        return self.bandRow(ctx, words, if (self.transcript_focused)
            colors.blue_light
        else
            colors.fg_dim);
    }

    fn inputRows(
        self: *Ui,
        ctx: *phantom.BuildContext,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var pieces: std.ArrayList(phantom.Widget) = .empty;
        pieces.append(ctx.arena, plainRow(
            ctx,
            " > ",
            if (self.transcript_focused) colors.fg_dim else colors.blue_light,
        )) catch {};

        if (self.phase == .message) {
            const field = ctx.new(phantom.TextField{
                .color = colors.fg,
                .caret_color = colors.blue_light,
                .on_change = onTyped,
                .ctx = self,
            });
            pieces.append(ctx.arena, ctx.new(phantom.KeyboardListener{
                .child = field.widget(),
                .on_key = onMessageKey,
                .ctx = self,
            }).widget()) catch {};
        }

        const line = ctx.new(phantom.Row(.{ .children = pieces.items })).widget();
        return ctx.newSlice(phantom.Widget, &.{line});
    }

    pub fn openCompletions(self: *const Ui, into: []model.Command) []const model.Command {
        if (self.phase != .message) return into[0..0];
        return completions(self.typed.items, into);
    }

    fn completionRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        shown: []const model.Command,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var rows: std.ArrayList(phantom.Widget) = .empty;
        for (shown, 0..) |one, index| {
            const chosen = index == self.completion_selected;
            const words = std.fmt.allocPrint(ctx.arena, "{s} {s: <8}  {s}", .{
                if (chosen) "\u{25b8}" else " ",
                one.typed(),
                one.does(),
            }) catch one.typed();
            rows.append(ctx.arena, self.bandRow(
                ctx,
                words,
                if (chosen) colors.blue_light else colors.fg_muted,
            )) catch {};
        }
        return rows.items;
    }

    fn onTyped(context: *anyopaque, text: []const u8) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.completion_selected = 0;
        self.typed.clearRetainingCapacity();
        keepText(self.gpa, &self.typed, text);
    }

    fn onMessageKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        if (event.keysym != .enter) return false;
        const self: *Ui = @ptrCast(@alignCast(context));

        // Whoever drives this reads `submitted` on the next frame, and a host
        // that only draws when asked would never take one.
        defer self.host.invalidate();

        if (self.picker != null) {
            self.takePicked();
            return true;
        }

        var slots: [model.Command.all.len]model.Command = undefined;
        const listed = self.openCompletions(&slots);
        if (listed.len != 0) {
            const chosen = listed[@min(self.completion_selected, listed.len - 1)];
            self.typed.clearRetainingCapacity();
            self.typed.appendSlice(self.gpa, chosen.typed()) catch {};
        }

        self.submitted = true;
        return true;
    }

    /// Plain text wrapped into rows, in the shape the span path answers, so one
    /// loop builds the rows either way.
    fn plainRows(
        arena: std.mem.Allocator,
        text: []const u8,
        room: layout.Room,
    ) std.mem.Allocator.Error![]const []const phantom.text.markdown.Span {
        const broken = try wrapText(arena, text, room);
        const out = try arena.alloc([]const phantom.text.markdown.Span, broken.len);
        for (broken, out) |words, *into| {
            const one = try arena.alloc(phantom.text.markdown.Span, 1);
            one[0] = .{ .text = words };
            into.* = one;
        }
        return out;
    }

    /// The words of a row, for the parts of the interface that read text rather
    /// than draw it.
    fn joinSpans(
        arena: std.mem.Allocator,
        spans: []const phantom.text.markdown.Span,
    ) std.mem.Allocator.Error![]const u8 {
        if (spans.len == 1) return spans[0].text;
        var out: std.ArrayList(u8) = .empty;
        for (spans) |one| try out.appendSlice(arena, one.text);
        return out.items;
    }

    pub fn showRows(self: *const Ui, arena: std.mem.Allocator) []const Shown {
        var out: std.ArrayList(Shown) = .empty;
        for (self.lines.items, 0..) |line, at| {
            const fold = line.fold;
            if (line.gap) {
                out.append(arena, .{ .voice = line.voice, .text = "", .gap = true }) catch
                    return out.items;
                continue;
            }
            const room = self.roomFor(line.voice);
            // Row zero gives up the width of whatever sits to its right, so the
            // words and the pinned piece never land on top of one another.
            const right = if (fold != null) model.markerText(false, false) else line.pinned;
            const taken = if (right.len == 0) 0 else room.measure.widthOf(right) + room.measure.step();
            const styled = anyStyled(line.spans);
            const held: SpanRoom = .{
                .measure = room.measure,
                .rest = room.width,
                .first = if (styled and room.width > taken) room.width - taken else room.width,
            };

            // A line nothing parsed carries no runs, which is every line Chock
            // builds itself. Those wrap as plain text, where an empty span list
            // would wrap to one empty row and lose the words.
            const head: []const []const phantom.text.markdown.Span = if (line.spans.len == 0)
                plainRows(arena, line.text, room) catch return out.items
            else
                phantom.text.markdown.wrapSpans(arena, line.spans, held.wrap()) catch
                    return out.items;

            for (head, 0..) |spans, part| {
                out.append(arena, .{
                    .voice = line.voice,
                    .text = joinSpans(arena, spans) catch return out.items,
                    .spans = if (line.spans.len == 0) &.{} else spans,
                    .pinned = if (part == 0) line.pinned else "",
                    .fold_at = if (fold != null and part == 0) at else null,
                    .open = if (fold) |one| one.open else false,
                }) catch return out.items;
            }

            const one = fold orelse continue;
            if (!one.open) continue;

            var rest = one.body;
            var drawn: usize = 0;
            while (rest.len != 0 and drawn < open_body_rows) {
                const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
                const body = wrapText(arena, rest[0..end], self.roomFor(.agent)) catch
                    return out.items;
                for (body) |words| {
                    out.append(arena, .{ .voice = .agent, .text = words }) catch
                        return out.items;
                }
                drawn += 1;
                if (end == rest.len) {
                    rest = rest[end..];
                    break;
                }
                rest = rest[end + 1 ..];
            }
            if (rest.len + one.dropped != 0) {
                const more = std.fmt.allocPrint(
                    arena,
                    "\u{2026} {d} bytes more, in the log",
                    .{rest.len + one.dropped},
                ) catch "\u{2026} more, in the log";
                out.append(arena, .{ .voice = .agent, .text = more }) catch return out.items;
            }
        }
        return out.items;
    }

    fn shownCount(self: *const Ui) usize {
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        return self.showRows(arena_state.allocator()).len;
    }

    pub fn visibleRows(self: *const Ui, arena: std.mem.Allocator, count: u16) []const Shown {
        const all = self.showRows(arena);
        const back = @min(self.scroll_back, all.len -| count);
        const end = all.len - back;
        const from = end - @min(end, count);
        return all[from..end];
    }

    pub fn maxScrollBack(self: *const Ui) usize {
        const parts = layout.split(self.rows, self.panelRows());
        const room = parts.transcript -| 1;
        return self.shownCount() -| room;
    }

    pub fn showsRule(self: *const Ui) bool {
        return self.transcript_focused or self.scroll_back != 0;
    }

    /// How far one page key moves. One row short of the band, so a reader keeps
    /// a line of what they were looking at.
    fn pageRows(self: *const Ui) u16 {
        return @max(1, layout.split(self.rows, self.panelRows()).transcript -| 1);
    }

    pub fn scrollBy(self: *Ui, rows: i32) void {
        const most = self.maxScrollBack();
        const now: i64 = @intCast(self.scroll_back);
        const moved = std.math.clamp(now + rows, 0, @as(i64, @intCast(most)));
        self.scroll_back = @intCast(moved);
    }

    const Step = enum { older, newer };

    fn stepCursor(self: *Ui, step: Step) void {
        if (self.foldCount() == 0) {
            self.scrollBy(if (step == .older) 1 else -1);
            return;
        }

        const at = self.cursor orelse {
            self.cursor = self.nextFold(self.lines.items.len, .older);
            self.showCursor();
            return;
        };
        self.cursor = self.nextFold(at, step) orelse at;
        self.showCursor();
    }

    fn foldCount(self: *const Ui) usize {
        var found: usize = 0;
        for (self.lines.items) |line| {
            if (line.fold != null) found += 1;
        }
        return found;
    }

    fn nextFold(self: *const Ui, from: usize, step: Step) ?usize {
        if (step == .older) {
            var at = @min(from, self.lines.items.len);
            while (at > 0) {
                at -= 1;
                if (self.lines.items[at].fold != null) return at;
            }
            return null;
        }
        var at = from + 1;
        while (at < self.lines.items.len) : (at += 1) {
            if (self.lines.items[at].fold != null) return at;
        }
        return null;
    }

    fn showCursor(self: *Ui) void {
        const at = self.cursor orelse return;
        const parts = layout.split(self.rows, self.panelRows());
        const room: usize = parts.transcript -| 1;
        if (room == 0) return;

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const all = self.showRows(arena_state.allocator());
        var first: ?usize = null;
        for (all, 0..) |one, index| {
            if (one.fold_at != null and one.fold_at.? == at) {
                first = index;
                break;
            }
        }
        const below = all.len - (first orelse return);
        self.scroll_back = @min(below -| room, self.maxScrollBack());
    }

    fn toggleFocused(self: *Ui) void {
        const at = self.cursor orelse return;
        if (at >= self.lines.items.len) return;
        if (self.lines.items[at].fold == null) return;
        self.lines.items[at].fold.?.open = !self.lines.items[at].fold.?.open;
        self.showCursor();
    }

    fn onTranscriptKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));
        if (self.pane != null and self.onPaneKey(event)) return true;
        switch (event.keysym) {
            .up => {
                self.stepCursor(.older);
                return true;
            },
            .down => {
                self.stepCursor(.newer);
                return true;
            },
            else => {
                const typed = event.text orelse return false;
                if (std.mem.eql(u8, typed, " ")) {
                    self.toggleFocused();
                    return true;
                }
                if (std.mem.eql(u8, typed, "g")) {
                    self.scroll_back = 0;
                    self.cursor = null;
                    return true;
                }
                if (std.mem.eql(u8, typed, "p")) {
                    self.togglePlan();
                    return true;
                }
                if (std.mem.eql(u8, typed, "?")) {
                    self.openHelp();
                    return true;
                }
                return false;
            },
        }
    }

    pub fn onPaneKey(self: *Ui, event: phantom.input.KeyEvent) bool {
        if (self.pane == null) return false;
        const pane = &self.pane.?;
        const room = layout.split(self.rows, self.panelRows()).transcript -| 2;
        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const all = switch (pane.kind) {
            .keys => helpRows(arena_state.allocator()) catch return false,
        };
        const total: u16 = @intCast(@min(all.len, std.math.maxInt(u16)));

        switch (event.keysym) {
            .up => {
                pane.move(-1, room, total);
                return true;
            },
            .down => {
                pane.move(1, room, total);
                return true;
            },
            .escape => {
                self.pane = null;
                return true;
            },
            else => {
                const typed = event.text orelse return false;
                if (std.mem.eql(u8, typed, "?")) {
                    self.pane = null;
                    return true;
                }
                return false;
            },
        }
    }

    fn onTranscriptFocus(context: *anyopaque, focused: bool) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.transcript_focused = focused;
    }

    fn onApprovalKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));
        if (self.approval == null) return false;

        const typed = event.text orelse return false;
        if (std.mem.eql(u8, typed, "d")) {
            self.approval.?.view = if (self.approval.?.view == .diff) .question else .diff;
            return true;
        }
        if (std.mem.eql(u8, typed, "w")) {
            self.approval.?.view = if (self.approval.?.view == .why) .question else .why;
            return true;
        }
        if (self.approval_settle != 0) return false;
        if (std.mem.eql(u8, typed, "y")) {
            self.approval_answer = .approved;
            return true;
        }
        if (std.mem.eql(u8, typed, "n")) {
            self.approval_answer = .refused;
            return true;
        }
        return false;
    }

    fn onApprovalFocus(context: *anyopaque, focused: bool) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.approval_focused = focused;
    }

    fn onQuestionKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));
        const one = self.question orelse return false;

        switch (event.keysym) {
            .enter => {
                if (self.question_settle != 0) return false;
                self.question_said = if (self.question_filled == 0) .declined else .answered;
                return true;
            },
            .backspace => {
                self.question_filled = backOne(self.question_typed[0..self.question_filled]);
                return true;
            },
            else => {},
        }

        const typed = event.text orelse return false;
        if (typed.len == 0) return false;

        if (one.echo == .on and self.question_filled == 0 and one.options.len != 0 and typed.len == 1) {
            if (typed[0] >= '1' and typed[0] <= '9') {
                if (self.question_settle != 0) return false;
                const index: usize = typed[0] - '1';
                if (index < one.options.len) {
                    const chose = one.options[index];
                    if (chose.len <= self.question_typed.len) {
                        @memcpy(self.question_typed[0..chose.len], chose);
                        self.question_filled = chose.len;
                        self.question_said = .answered;
                        return true;
                    }
                }
            }
        }

        for (typed) |byte| {
            if (byte < 0x20 or byte == 0x7f) return false;
        }
        if (self.question_filled + typed.len > self.question_typed.len) return false;
        @memcpy(self.question_typed[self.question_filled..][0..typed.len], typed);
        self.question_filled += typed.len;
        return true;
    }

    fn onQuestionFocus(context: *anyopaque, focused: bool) void {
        const self: *Ui = @ptrCast(@alignCast(context));
        self.question_focused = focused;
    }

    fn onSessionKey(context: *anyopaque, event: phantom.input.KeyEvent) bool {
        if (event.action == .release) return false;
        const self: *Ui = @ptrCast(@alignCast(context));

        var slots: [model.Command.all.len]model.Command = undefined;
        const listed = self.openCompletions(&slots);
        const offered = self.picker orelse &[_]model.Resumable{};
        // A list drawn over the transcript owns the page keys, because it is
        // what a person is looking at. A list in the band beside it does not:
        // the transcript is still there and is what they are reading.
        const paging = if (self.sidebar == .sessions) &[_]model.Resumable{} else offered;

        switch (event.keysym) {
            .up => {
                if (offered.len != 0) {
                    self.picked -|= 1;
                } else if (listed.len != 0) {
                    self.completion_selected -|= 1;
                } else self.scrollBy(1);
                return true;
            },
            .down => {
                if (offered.len != 0) {
                    self.picked = @min(self.picked + 1, offered.len - 1);
                } else if (listed.len != 0) {
                    self.completion_selected = @min(self.completion_selected + 1, listed.len - 1);
                } else self.scrollBy(-1);
                return true;
            },
            // A text field takes the arrows for its own caret, so these are what
            // a person has to move with while typing. A picker moves its chosen
            // row, because that is what brings the rest of the list into view.
            .page_up => {
                if (paging.len != 0) {
                    self.picked -|= self.pageRows();
                } else self.scrollBy(@intCast(self.pageRows()));
                self.host.invalidate();
                return true;
            },
            .page_down => {
                if (paging.len != 0) {
                    self.picked = @min(self.picked + self.pageRows(), paging.len - 1);
                } else self.scrollBy(-@as(i32, @intCast(self.pageRows())));
                self.host.invalidate();
                return true;
            },
            else => return false,
        }
    }

    fn voicedRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        line: Shown,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        if (line.gap) return plainRow(ctx, "", colors.fg);

        const focused = line.fold_at != null and
            self.transcript_focused and
            self.cursor != null and
            self.cursor.? == line.fold_at.?;
        const marker = if (line.fold_at == null) "" else model.markerText(line.open, focused);
        const right = if (marker.len != 0) marker else line.pinned;

        const tone = switch (line.voice) {
            .chock => colors.blue_light,
            .agent => colors.fg,
        };

        if (isStyled(line)) {
            // Row zero already gave up the room beside `right` when it wrapped,
            // so nothing is cut back off here.
            const rich = self.voicedText(ctx, measure, line, tone);
            if (right.len == 0) return rich;
            return pinnedRow(ctx, measure, self.transcriptRoom().width, rich, row(ctx, measure, right, tone));
        }

        const words = layout.spread(ctx.arena, line.text, right, self.roomFor(line.voice)) catch "";
        const cut = std.mem.trimEnd(u8, words, " ");
        const pinned = right.len != 0 and std.mem.endsWith(u8, cut, right);
        const left = if (!pinned)
            cut
        else
            std.mem.trimEnd(u8, cut[0 .. cut.len - right.len], " ");

        const said = self.voicedText(ctx, measure, .{
            .voice = line.voice,
            .text = left,
        }, tone);
        if (!pinned) return said;
        return pinnedRow(
            ctx,
            measure,
            self.transcriptRoom().width,
            said,
            row(ctx, measure, right, tone),
        );
    }

    fn voicedText(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        line: Shown,
        tone: phantom.Color,
    ) phantom.Widget {
        _ = self;
        // Nothing styled, so this is the plain path: one text widget, the same
        // one every row used before any of this could carry a style.
        if (!isStyled(line)) {
            return switch (line.voice) {
                .chock => row(ctx, measure, std.fmt.allocPrint(ctx.arena, "{s}{s}", .{
                    model.Voice.chock.prefix(),
                    line.text,
                }) catch model.Voice.chock.prefix(), tone),
                .agent => ctx.new(phantom.Padding{
                    .insets = .{ .left = measure.widthOf(model.Voice.agent.prefix()) },
                    .child = row(ctx, measure, line.text, tone),
                }).widget(),
            };
        }

        const said = styledRow(ctx, measure, line, tone);
        return ctx.new(phantom.Padding{
            .insets = .{ .left = measure.widthOf(line.voice.prefix()) },
            .child = said,
        }).widget();
    }

    /// Whether any run carries emphasis. Most lines carry none, and those keep
    /// the plain path, cut back by `spread` at draw the way they always were.
    fn anyStyled(spans: []const phantom.text.markdown.Span) bool {
        for (spans) |one| {
            if (one.style.strong or one.style.em or one.style.code) return true;
        }
        return false;
    }

    fn isStyled(line: Shown) bool {
        return anyStyled(line.spans);
    }

    /// One row of words, with the emphasis the agent wrote still on it.
    fn styledRow(
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        line: Shown,
        tone: phantom.Color,
    ) phantom.Widget {
        const out = ctx.arena.alloc(phantom.RichText.Span, line.spans.len) catch
            return row(ctx, measure, line.text, tone);
        for (line.spans, out) |one, *into| {
            into.* = .{
                .text = one.text,
                .style = .{ .strong = one.style.strong, .em = one.style.em, .code = one.style.code },
                .color = tone,
            };
        }
        return ctx.new(phantom.RichText{
            .spans = out,
            .size = measure.size,
            // Already wrapped into rows, so this draws exactly what it is given.
            .wrap = false,
        }).widget();
    }

    fn pinnedRow(
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        across: f32,
        left: phantom.Widget,
        right: phantom.Widget,
    ) phantom.Widget {
        const both = ctx.newSlice(phantom.Widget, &.{
            ctx.new(phantom.Align{ .alignment = .top_left, .child = left }).widget(),
            ctx.new(phantom.Align{ .alignment = .top_right, .child = right }).widget(),
        });
        return ctx.new(phantom.SizedBox{
            .width = across,
            .height = measure.height(),
            .child = ctx.new(phantom.Stack{ .children = both }).widget(),
        }).widget();
    }

    fn row(
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        if (marked(ctx, measure, text, color)) |made| return made;
        return plainRow(ctx, text, color);
    }

    fn plainRow(
        ctx: *phantom.BuildContext,
        text: []const u8,
        color: phantom.Color,
    ) phantom.Widget {
        return ctx.new(phantom.Text{
            .text = text,
            .color = color,
        }).widget();
    }

    fn marked(
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        text: []const u8,
        color: phantom.Color,
    ) ?phantom.Widget {
        var pieces: std.ArrayList(phantom.Widget) = .empty;
        var index: usize = 0;
        var kept: usize = 0;
        while (index < text.len) {
            const one = layout.drawnAt(text, index);
            const mark = if (one.whole) markFor(one.point) else null;
            const width = if (mark == null) 0 else measure.advanceOf(one.point);
            if (mark == null or !(width > 0)) {
                index += one.length;
                continue;
            }
            if (index > kept) pieces.append(ctx.arena, plainRow(
                ctx,
                text[kept..index],
                color,
            )) catch return null;
            pieces.append(
                ctx.arena,
                markBox(ctx, measure, mark.?, width, color),
            ) catch return null;
            index += one.length;
            kept = index;
        }
        if (pieces.items.len == 0) return null;
        if (kept < text.len) pieces.append(ctx.arena, plainRow(
            ctx,
            text[kept..],
            color,
        )) catch return null;
        return ctx.new(phantom.SizedBox{
            .width = measure.widthOf(text),
            .height = measure.height(),
            .child = ctx.new(phantom.Row(.{ .children = pieces.items })).widget(),
        }).widget();
    }

    fn markBox(
        ctx: *phantom.BuildContext,
        measure: layout.Measure,
        mark: Mark,
        across: f32,
        color: phantom.Color,
    ) phantom.Widget {
        const icon = ctx.new(phantom.Icon{
            .id = mark.id,
            .size = across,
            .fit = if (isRule(mark.id)) .fill else .square,
            .color = color,
            .label = mark.label,
        }).widget();
        return ctx.new(phantom.SizedBox{
            .width = across,
            .height = measure.height(),
            .child = if (isRule(mark.id)) icon else ctx.new(phantom.Align{
                .alignment = .center,
                .child = icon,
            }).widget(),
        }).widget();
    }

    fn isRule(id: phantom.icon.Id) bool {
        const cell = phantom.icon.cellMarkFor(id) orelse return false;
        return cell.tile;
    }

    pub fn rootOf(ctx: *phantom.BuildContext, self: *Ui) phantom.Widget {
        return phantom.StatefulWidget(Screen, ctx.new(Screen{ .ui = self }));
    }
};
