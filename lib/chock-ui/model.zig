//! What a screen shows, as plain data. The session facts, the sandbox layers,
//! the plan rows, the header pieces, and the question a person answers.

const std = @import("std");
const phantom = @import("phantom");
const chock_proto = @import("chock-proto");

const layout = @import("layout.zig");

const Room = layout.Room;
const Measure = layout.Measure;
const grid_measure = layout.grid_measure;

const testing = std.testing;

pub const Attach = union(enum) {
    terminal: Terminal,
    window: Window,

    pub const Terminal = struct {
        in: std.Io.File,
        out: std.Io.File,
        size: ?phantom.tui.term.Size = null,
    };

    pub const Window = struct {
        width: u32 = 960,
        height: u32 = 640,
    };
};

pub const Facts = struct {
    project: []const u8 = "",
    workspace: []const u8 = "",
    model: []const u8 = "",
    provider: []const u8 = "",
    layers: []const Layer = &.{},
};

pub const Layer = struct {
    name: []const u8,
    note: []const u8 = "",
    state: State,

    pub const State = enum {
        on,
        off,
        unsupported,
        unavailable,

        pub fn glyph(self: State) []const u8 {
            return switch (self) {
                .on => "\u{2713}",
                .off, .unsupported, .unavailable => "\u{2717}",
            };
        }

        pub fn word(self: State) []const u8 {
            return switch (self) {
                .on => "",
                .off => "OFF",
                .unsupported => "NONE",
                .unavailable => "BLOCKED",
            };
        }
    };
};

/// What the band beside the transcript is showing.
pub const Sidebar = enum {
    none,
    /// The agent's task list.
    plan,
    /// The other sessions, so a person reads one and sees the rest at the same
    /// time rather than swapping between a list and a transcript.
    sessions,

    /// How wide this one wants to be, in columns. Sessions take more because a
    /// title is prose and a plan step is a few words.
    pub fn columns(self: Sidebar) u16 {
        return switch (self) {
            .none => 0,
            .plan => sidebar_columns,
            .sessions => sessions_sidebar_columns,
        };
    }
};

pub const sidebar_columns: u16 = 26;
pub const sessions_sidebar_columns: u16 = 34;

pub const sidebar_needs_columns: u16 = 80;

pub fn statusWord(status: chock_proto.event.PlanStatus) []const u8 {
    return switch (status) {
        .pending => "next",
        .in_progress => "now",
        .done => "done",
        .abandoned => "stopped",
        .unknown => "unknown",
    };
}

pub fn sizeMoved(
    now: phantom.tui.term.Size,
    viewport: phantom.PhysicalSize,
    dpr: f32,
) bool {
    const box = now.viewport();
    return box.width != viewport.width or
        box.height != viewport.height or
        now.dpr() != dpr;
}

pub fn isStatus(
    status: chock_proto.event.PlanStatus,
    wanted: std.meta.Tag(chock_proto.event.PlanStatus),
) bool {
    return std.meta.activeTag(status) == wanted;
}

pub const PlanLine = struct {
    text: []const u8,
    tone: Tone,

    pub const Tone = enum {
        title,
        now,
        step,
        aside,
    };
};

pub fn planRows(
    arena: std.mem.Allocator,
    plan: chock_proto.state.Plan,
    rows: u16,
) std.mem.Allocator.Error![]const PlanLine {
    var out: std.ArrayList(PlanLine) = .empty;
    if (rows == 0) return out.items;

    const counts = plan.counts();
    try out.append(arena, .{
        .tone = .title,
        .text = if (counts.total() == 0)
            try std.fmt.allocPrint(arena, " plan   nothing yet", .{})
        else
            try std.fmt.allocPrint(arena, " plan   {d}/{d} done", .{
                counts.done,
                counts.total(),
            }),
    });

    const total: u16 = @intCast(@min(plan.steps.items.len, std.math.maxInt(u16)));
    var room = rows -| 1;
    if (room == 0) return out.items;

    const hides = total > room;
    if (hides and room > 1) room -= 1;

    var first: u16 = 0;
    while (first < total and isStatus(plan.steps.items[first].status, .done)) first += 1;
    first = @min(first, total -| room);

    var at: u16 = first;
    while (at < total and at < first + room) : (at += 1) {
        const step = plan.steps.items[at];
        try out.append(arena, .{
            .tone = if (isStatus(step.status, .in_progress)) .now else .step,
            .text = try std.fmt.allocPrint(arena, " {s: <7} {s}", .{
                statusWord(step.status),
                step.subject,
            }),
        });
    }

    if (!hides or out.items.len >= rows) return out.items;
    const below = total -| at;
    try out.append(arena, .{
        .tone = .aside,
        .text = try std.fmt.allocPrint(arena, " {d} above, {d} below", .{ first, below }),
    });
    return out.items;
}

pub const HeaderPiece = struct {
    text: []const u8,
    tone: Tone,

    pub const Tone = enum {
        name,
        context,
        on,
        off,
    };
};

pub fn columnsOf(text: []const u8) f32 {
    return grid_measure.widthOf(text);
}

pub fn layerText(
    arena: std.mem.Allocator,
    one: Layer,
    narrow: bool,
) std.mem.Allocator.Error![]const u8 {
    if (narrow and one.state == .on) return one.state.glyph();

    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, one.state.glyph());
    try text.append(arena, ' ');
    try text.appendSlice(arena, one.name);
    if (one.note.len != 0 and !narrow) {
        try text.append(arena, ' ');
        try text.appendSlice(arena, one.note);
    }
    const said = one.state.word();
    if (said.len != 0) {
        try text.append(arena, ' ');
        try text.appendSlice(arena, said);
    }
    return text.items;
}

pub fn headerPieces(
    arena: std.mem.Allocator,
    facts: Facts,
    room: Room,
    into: *std.ArrayList(HeaderPiece),
) std.mem.Allocator.Error!void {
    const narrow = room.isNarrow();

    var layers: std.ArrayList(HeaderPiece) = .empty;
    var taken: f32 = 0;
    for (facts.layers) |one| {
        const said = try layerText(arena, one, narrow);
        const whole = try std.fmt.allocPrint(arena, "  {s}", .{said});
        taken += room.measure.widthOf(whole);
        try layers.append(arena, .{
            .text = whole,
            .tone = switch (one.state) {
                .on => .on,
                .off, .unsupported, .unavailable => .off,
            },
        });
    }

    var left = if (room.width > taken) room.width - taken else 0;
    const name = " chock";
    const named = room.measure.widthOf(name);
    if (named <= left) {
        left -= named;
        try into.append(arena, .{ .text = name, .tone = .name });
    }
    for ([_][]const u8{ facts.project, facts.workspace, facts.model, facts.provider }) |fact| {
        if (fact.len == 0) continue;
        const whole = try std.fmt.allocPrint(arena, "  {s}", .{fact});
        const width = room.measure.widthOf(whole);
        if (width > left) break;
        left -= width;
        try into.append(arena, .{ .text = whole, .tone = .context });
    }

    for (layers.items) |one| try into.append(arena, one);
}

pub const Voice = enum {
    chock,
    agent,

    pub fn prefix(self: Voice) []const u8 {
        return switch (self) {
            .chock => "\u{2502} ",
            .agent => "  ",
        };
    }
};

pub const Pane = struct {
    at: u16 = 0,

    kind: Kind,

    pub const Kind = enum { keys };

    pub fn move(self: *Pane, by: i8, room: u16, total: u16) void {
        const last = total -| room;
        const now: i32 = self.at;
        const wanted = now + by;
        if (wanted < 0) {
            self.at = 0;
            return;
        }
        self.at = @min(@as(u16, @intCast(@min(wanted, std.math.maxInt(u16)))), last);
    }

    pub fn hold(self: *Pane, room: u16, total: u16) void {
        self.at = @min(self.at, total -| room);
    }
};

pub const Fold = struct {
    kind: Kind,
    body: []const u8,
    dropped: usize = 0,
    open: bool = false,

    pub const Kind = enum { result, reasoning, compaction, subagent };
};

pub fn markerText(open: bool, focused: bool) []const u8 {
    if (open) return if (focused) "\u{25be} hide  Space" else "\u{25be} hide";
    return if (focused) "\u{25b8} show  Space" else "\u{25b8} show";
}

pub const Command = enum {
    help,
    plan,
    usage,
    @"resume",

    pub fn typed(self: Command) []const u8 {
        return switch (self) {
            .help => "/help",
            .plan => "/plan",
            .usage => "/usage",
            .@"resume" => "/resume",
        };
    }

    pub fn does(self: Command) []const u8 {
        return switch (self) {
            .help => "every key, and every command",
            .plan => "the plan, kept at the side of the screen",
            .usage => "the tokens and the cost so far",
            .@"resume" => "end this session and take up another",
        };
    }

    pub const all = [_]Command{ .help, .plan, .usage, .@"resume" };
};

pub fn commandOf(line: []const u8) ?Command {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return null;
    for (Command.all) |one| {
        if (std.mem.eql(u8, trimmed, one.typed())) return one;
    }
    return null;
}

pub fn yesNo(answer: bool) []const u8 {
    return if (answer) "yes" else "no";
}

pub const Resumable = struct {
    id: []const u8,
    words: []const u8,
    refusal: []const u8 = "",
    /// The project this belongs to. Rows carrying the same one are drawn under
    /// a single heading. Empty where the list covers one project and saying so
    /// on every row would be noise.
    group: []const u8 = "",
};

/// What one picker row says.
///
/// The title first, because that is what a person is looking for. The id after
/// it, because two pieces of work can carry the same title and only the id names
/// one. `note` is whatever the host knows that the other does not: how a session
/// ended on a terminal, whether it is live in a browser.
pub fn resumableWords(
    arena: std.mem.Allocator,
    id: []const u8,
    title: []const u8,
    note: []const u8,
) std.mem.Allocator.Error![]const u8 {
    if (title.len == 0) return std.fmt.allocPrint(arena, "{s}  {s}", .{ id, note });
    return std.fmt.allocPrint(arena, "{s}  {s}  {s}", .{ title, id, note });
}

pub const Approval = struct {
    request_id: u64,
    action: []const u8,
    summary: []const u8,
    reason: []const u8,
    chain: []const u8,
    depth: usize,
    detail: []const u8,
    review: []const u8 = "",
    left_ms: i64 = 0,
    view: View = .question,

    pub const View = enum {
        question,
        diff,
        why,
    };
};

pub const Answered = enum { approved, refused };

pub const Look = union(enum) {
    waiting,
    answered: Answered,
    canceled,
};

pub const Question = struct {
    agent_kind: []const u8 = "",
    text: []const u8,
    options: []const []const u8 = &.{},
    left_ms: i64 = 0,
    echo: Echo = .on,

    pub const Echo = enum {
        on,
        masked,
    };
};

pub const Text = union(enum) {
    waiting,
    canceled,
    answered: []const u8,
    declined,
};

pub const question_keys = " [1-9] choose  [Enter] send, or send nothing.  Answering allows nothing.";

pub const question_keys_open = " [Enter] send, or send nothing.  Answering allows nothing.";

pub const question_keys_narrow = " [1-9] choose  [Enter] send.  Allows nothing.";
pub const question_keys_open_narrow = " [Enter] send.  Allows nothing.";

pub fn questionKeys(room: Room, has_options: bool) []const u8 {
    if (room.isNarrow()) return if (has_options) question_keys_narrow else question_keys_open_narrow;
    return if (has_options) question_keys else question_keys_open;
}

/// One drawn line of the transcript: who said it, and what is pinned beside it.
pub const Line = struct {
    voice: Voice,
    /// What is drawn: the words with their markdown markers taken off, because
    /// a model writes markdown whether or not anything can draw it.
    text: []const u8,
    /// The runs `text` is made of, each with its own style. Every span borrows
    /// `text`, so the two live and die together.
    spans: []const phantom.text.markdown.Span = &.{},
    /// What kind of line this was, so a heading and a bullet can be drawn
    /// differently from prose.
    block: phantom.text.markdown.Block = .paragraph,
    pinned: []const u8 = "",
    fold: ?Fold = null,
    gap: bool = false,
};
