//! The interface bare `chock` brings up: one widget tree over phantom's
//! terminal and window backends, driven as a second `chock_core.Loop.Observer`.
//! The transcript is `src/run.zig`'s `Printer` buffer, so there is one writer.

const std = @import("std");
const phantom = @import("phantom");
const chock_core = @import("chock-core");
const sessions_cmd = @import("sessions.zig");
const session_paths = @import("session.zig");
const chock_proto = @import("chock-proto");
const tty = @import("tty.zig");
const interrupt = @import("interrupt.zig");
const run = @import("run.zig");
const main_cmd = @import("main.zig");
const approval = @import("approval.zig");
const clock_mod = @import("clock.zig");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
const sandbox = @import("chock-sandbox");

pub const Plan = enum {
    window,
    terminal,
    usage,
};

pub fn decide(backend: phantom.app.Backend, terminal_can_draw: bool) Plan {
    return switch (backend) {
        .gpu => .window,
        .tui => if (terminal_can_draw) .terminal else .usage,
        .none => .usage,
    };
}

/// How long the probe waits for the compositor's keymap, in milliseconds. Five
/// milliseconds was enough against weston, so nearly all of this is margin.
/// Silence is not proof, so a probe that finds no keymap pays the whole budget.
const keymap_wait_ms: u32 = 100;

const Compositor = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,

    pub const Answer = enum {
        none,
        no_keys,
        ready,
    };

    /// `phantom.window.open` and not `phantom.window.available`: the compositor
    /// sends its keymap after the keyboard is bound, so the connection has to
    /// stay up for a moment. No surface is committed, so no window is shown.
    fn look(self: Compositor) Compositor.Answer {
        // The comptime `if` keeps every lattice type out of analysis on a target
        // where lattice is a `void`. An early return would not: the rest of the
        // body sits at function scope and is analyzed either way.
        if (phantom.backend.prism.builds_here) {
            var opened = phantom.window.open(self.gpa, self.io, self.env, .{}) orelse
                return .none;
            defer opened.close();
            return self.keysArrive(&opened.ctx);
        }
        return .none;
    }

    fn keysArrive(self: Compositor, ctx: anytype) Compositor.Answer {
        const Ignore = struct {
            const Event = @typeInfo(
                @TypeOf(phantom.window.Session.dispatchEvent),
            ).@"fn".params[1].type.?;
            fn take(_: *anyopaque, _: Event) void {}
        };
        var nothing: u8 = 0;

        keymap_watch = .{ .watching = true };
        defer keymap_watch = .{};

        const started = std.Io.Clock.now(.awake, self.io);
        while (!keymap_watch.failed) {
            const spent = started.durationTo(std.Io.Clock.now(.awake, self.io));
            const spent_ms = @divTrunc(spent.nanoseconds, std.time.ns_per_ms);
            if (spent_ms >= keymap_wait_ms) break;
            ctx.poll(
                @intCast(keymap_wait_ms - @as(u32, @intCast(spent_ms))),
                Ignore.take,
                &nothing,
            ) catch return .none;
        }
        return if (keymap_watch.failed) .no_keys else .ready;
    }
};

/// A screen is not enough. `phantom.window.available` said yes on an Apple M1
/// running cosmic-comp and the pipeline then failed with `NotImplemented`, so
/// prism's own rasterizer probe is asked instead. A keymap lattice cannot read
/// gives a window that draws every frame and takes no key, so the keyboard is
/// refused with the drawing half.
fn windowPossible(can_draw: bool, compositor: anytype) Compositor.Answer {
    if (!can_draw) return .none;
    return compositor.look();
}

var keymap_watch: struct {
    watching: bool = false,
    failed: bool = false,
} = .{};

pub fn logMessage(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime saysKeymapFailed(level, format)) {
        if (keymap_watch.watching) keymap_watch.failed = true;
    }
    std.log.defaultLog(level, scope, format, args);
}

/// Wide on the words on purpose. A false match drops a window to the terminal,
/// which works; a miss puts up a window a person cannot type in.
fn saysKeymapFailed(level: std.log.Level, format: []const u8) bool {
    if (level != .warn and level != .err) return false;
    return std.mem.indexOf(u8, format, "keymap") != null;
}

fn insteadOfAWindow(terminal_can_draw: bool) []const u8 {
    return if (terminal_can_draw) "draws in this terminal" else "prints plainly";
}

fn namesADisplay(env: *const std.process.Environ.Map) bool {
    for ([_][]const u8{ "WAYLAND_DISPLAY", "DISPLAY" }) |name| {
        if (env.get(name)) |value| {
            if (value.len != 0) return true;
        }
    }
    return false;
}

pub fn start(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *const std.process.Environ.Map,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    const asked = (try run.readOptions(arena, args)) orelse return main_cmd.Exit.usage.code();
    if (asked.help_wanted) return main_cmd.Exit.finished.code();

    const terminal_can_draw = tty.stdoutIsTty() and tty.terminalCanDraw(env.get("TERM"));
    const message_in_hand = asked.message_words.len != 0 or
        !(std.Io.File.stdin().isTty(io) catch false);
    const can_draw = phantom.backend.prism.builds_here and phantom.backend.prism.canRasterize(gpa);
    const window = windowPossible(
        can_draw,
        Compositor{ .gpa = gpa, .io = io, .env = env },
    );

    if (phantom.backend.prism.builds_here and !can_draw and namesADisplay(env)) {
        tty.print(
            .warn,
            "chock: this machine names a display and no graphics driver on it could draw a test frame, " ++
                "so chock {s} instead of opening a window.\n",
            .{insteadOfAWindow(terminal_can_draw)},
        );
    }
    if (window == .no_keys) {
        if (message_in_hand) {
            tty.print(
                .warn,
                "chock: the keyboard map on this display could not be read, so the window takes no key. " ++
                    "The message is already in hand so the session runs, and scrolling and questions will not work.\n",
                .{},
            );
        } else {
            tty.print(
                .warn,
                "chock: the keyboard map on this display could not be read, so the window takes no key " ++
                    "and the first message cannot be typed into it. Give the message after `--`, " ++
                    "or set PHANTOM_BACKEND=tui to work in this terminal instead.\n",
                .{},
            );
        }
    }
    const window_ready = window != .none;
    const plan = decide(
        phantom.app.selectBackend(env, window_ready, tty.stdoutIsTty()),
        terminal_can_draw,
    );

    const piped = if (asked.message_words.len != 0 or (std.Io.File.stdin().isTty(io) catch false))
        null
    else
        try pipedMessage(arena, io);

    if (plan == .usage) {
        if (asked.message_words.len != 0) {
            return run.main(arena, gpa, environ, exe_path, args);
        }
        if (piped) |message| {
            const with_message = try std.mem.concat(arena, []const u8, &.{
                args,
                &.{ "--", message },
            });
            return run.main(arena, gpa, environ, exe_path, with_message);
        }
        main_cmd.printUsage(.err);
        return main_cmd.Exit.usage.code();
    }

    const attach: Attach = switch (plan) {
        .terminal => .{ .terminal = .{ .in = std.Io.File.stdin(), .out = std.Io.File.stdout() } },
        .window => .{ .window = .{} },
        .usage => unreachable,
    };
    return run.mainWithInterface(arena, gpa, environ, exe_path, args, attach, piped orelse "");
}

fn pipedMessage(arena: std.mem.Allocator, io: std.Io) !?[]const u8 {
    var buffer: [max_message_bytes]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const line = reader.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return null,
        error.StreamTooLong => {
            tty.print(
                .err,
                "chock: the message is longer than {d} bytes.\n",
                .{max_message_bytes},
            );
            return null;
        },
        error.ReadFailed => {
            tty.print(.err, "chock: standard input could not be read.\n", .{});
            return null;
        },
    };

    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;
    return try arena.dupe(u8, trimmed);
}

const max_message_bytes = 4096;

pub const Split = struct {
    header: u16,
    transcript: u16,
    approval: u16,
    input: u16,
};

const band_rows: u16 = 1;

pub fn split(rows: u16, wanted: u16) Split {
    if (rows == 0) return .{ .header = 0, .transcript = 0, .approval = 0, .input = 0 };
    if (rows == 1) return .{ .header = 0, .transcript = 0, .approval = 0, .input = band_rows };
    const room = rows - 2 * band_rows;
    const asked = @min(wanted, room);
    return .{
        .header = band_rows,
        .transcript = room - asked,
        .approval = asked,
        .input = band_rows,
    };
}

/// A row a band has no room for must not be drawn. A band is a surface exactly
/// `rows` line boxes tall and the next band is painted after it, so a row past
/// the end is covered rather than clipped and shows as glyphs cut by a straight
/// edge.
const Rows = struct {
    into: std.ArrayList(phantom.Widget) = .empty,
    left: u16,

    fn add(self: *Rows, arena: std.mem.Allocator, one: phantom.Widget) void {
        if (self.left == 0) return;
        self.left -= 1;
        self.into.append(arena, one) catch {};
    }

    fn items(self: Rows) []const phantom.Widget {
        return self.into.items;
    }
};

/// Every control character becomes a space: the cell writer sends a codepoint
/// straight at the terminal, so an escape byte in a tool's output would write a
/// sequence this file never composed. Every byte that is not valid UTF-8 becomes
/// a question mark, because phantom gives a line it cannot decode no size at all
/// and the whole line would vanish.
const Drawn = struct {
    point: u21,
    length: usize,
    whole: bool,
};

fn drawnAt(raw: []const u8, at: usize) Drawn {
    const size = std.unicode.utf8ByteSequenceLength(raw[at]) catch return .{
        .point = '?',
        .length = 1,
        .whole = false,
    };
    if (at + size > raw.len) return .{ .point = '?', .length = 1, .whole = false };
    const point = std.unicode.utf8Decode(raw[at..][0..size]) catch return .{
        .point = '?',
        .length = 1,
        .whole = false,
    };
    if (point < 0x20 or point == 0x7f) return .{ .point = ' ', .length = size, .whole = false };
    return .{ .point = point, .length = size, .whole = true };
}

fn safeText(
    arena: std.mem.Allocator,
    raw: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < raw.len) {
        const one = drawnAt(raw, index);
        if (one.whole) {
            try out.appendSlice(arena, raw[index..][0..one.length]);
        } else {
            try out.append(arena, @intCast(one.point));
        }
        index += one.length;
    }
    return out.items;
}

fn visibleLine(
    arena: std.mem.Allocator,
    raw: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    var used: f32 = 0;

    while (index < raw.len) {
        const one = drawnAt(raw, index);
        const advance = room.measure.advanceOf(one.point);
        if (used + advance > room.width) break;
        if (one.whole) {
            try out.appendSlice(arena, raw[index..][0..one.length]);
        } else {
            try out.append(arena, @intCast(one.point));
        }
        index += one.length;
        used += advance;
    }

    return out.items;
}

const Mark = struct {
    id: phantom.icon.Id,
    label: ?[]const u8,
};

fn markFor(point: u21) ?Mark {
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

fn wrapText(
    arena: std.mem.Allocator,
    raw: []const u8,
    room: Room,
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

const first_printable: u21 = ' ';
const last_printable: u21 = '~';
const printable_count = last_printable - first_printable + 1;

/// `phantom.tui.term.logical_cell_h` is a nominal 16 and is the divisor that
/// turns a reported cell height into a device pixel ratio. It is not a line box:
/// both bundled faces measure 1.2 em, so a row at size 16 wants 19.2 and a band
/// built as `rows * 16` cuts every glyph.
pub const Measure = struct {
    metrics: phantom.text.mono.TextMetrics,
    /// The mono metrics are in physical pixels and every size given to a widget
    /// is logical, so the two are divided apart here and nowhere else.
    dpr: f32,
    font: *phantom.text.Font,
    size: f32,
    known: ?Known = null,

    const Known = struct {
        line: f32,
        typical: f32,
        ascii: [printable_count]f32,
    };

    pub fn of(ctx: *phantom.BuildContext) Measure {
        const theme = phantom.theme.defaultTheme(ctx.owner);
        const view = ctx.owner.activeView();
        return (Measure{
            .metrics = ctx.owner.text_metrics,
            .dpr = if (view) |one| one.metrics.dpr else 1,
            .font = theme.body_font,
            .size = theme.text_size,
        }).measured();
    }

    pub fn measured(self: Measure) Measure {
        var made = self;
        made.known = null;
        var found: Known = undefined;
        var total: f32 = 0;
        for (&found.ascii, 0..) |*one, at| {
            one.* = made.advanceOf(first_printable + @as(u21, @intCast(at)));
            total += one.*;
        }
        const mean = total / printable_count;
        found.line = made.height();
        found.typical = if (mean > 0) mean else made.size;
        made.known = found;
        return made;
    }

    fn ratio(self: Measure) f32 {
        return if (self.dpr > 0) self.dpr else 1;
    }

    pub fn height(self: Measure) f32 {
        if (self.known) |one| return one.line;
        return switch (self.metrics) {
            .mono => |cell| cell.line / self.ratio(),
            .proportional => blk: {
                const per_em: f32 = @floatFromInt(self.font.unitsPerEm());
                if (per_em <= 0) break :blk self.size;
                const up: f32 = @floatFromInt(self.font.ascent());
                const down: f32 = @floatFromInt(self.font.descent());
                break :blk (up - down) * self.size / per_em;
            },
        };
    }

    pub fn logicalMetrics(self: Measure) phantom.text.mono.TextMetrics {
        return switch (self.metrics) {
            .mono => |cell| .{ .mono = .{
                .advance = cell.advance / self.ratio(),
                .line = cell.line / self.ratio(),
                .ascent = cell.ascent / self.ratio(),
            } },
            .proportional => .proportional,
        };
    }

    pub fn advanceOf(self: Measure, point: u21) f32 {
        if (point >= first_printable and point <= last_printable) {
            if (self.known) |one| return one.ascii[point - first_printable];
        }
        return switch (self.metrics) {
            .mono => |cell| blk: {
                const columns: f32 = @floatFromInt(phantom.text.mono.wcwidth(point));
                break :blk cell.advance * columns / self.ratio();
            },
            .proportional => self.font.advance(point, self.size),
        };
    }

    pub fn widthOf(self: Measure, text: []const u8) f32 {
        var index: usize = 0;
        var used: f32 = 0;
        while (index < text.len) {
            const one = drawnAt(text, index);
            used += self.advanceOf(one.point);
            index += one.length;
        }
        return used;
    }

    pub fn step(self: Measure) f32 {
        if (self.known) |one| return one.typical;
        var total: f32 = 0;
        var point: u21 = first_printable;
        while (point <= last_printable) : (point += 1) total += self.advanceOf(point);
        const mean = total / printable_count;
        return if (mean > 0) mean else self.size;
    }

    pub fn rowsIn(self: Measure, logical_height: f32) u16 {
        return countIn(logical_height, self.height());
    }
};

const grid_measure: Measure = .{
    .metrics = .{ .mono = .{ .advance = 1, .line = 1, .ascent = 0.8 } },
    .dpr = 1,
    // Never read: every `.mono` answer comes from the cell and needs no face.
    .font = undefined,
    .size = 1,
};

pub const Room = struct {
    measure: Measure,
    width: f32,

    pub fn grid(columns: f32) Room {
        return .{ .measure = grid_measure, .width = columns };
    }

    pub fn less(self: Room, text: []const u8) Room {
        const taken = self.measure.widthOf(text);
        return .{
            .measure = self.measure,
            .width = if (self.width > taken) self.width - taken else 0,
        };
    }

    pub fn upTo(self: Room, width: f32) Room {
        return .{ .measure = self.measure, .width = @min(self.width, width) };
    }

    pub fn holds(self: Room, text: []const u8) bool {
        return self.measure.widthOf(text) <= self.width;
    }

    pub fn isNarrow(self: Room) bool {
        return self.width < @as(f32, narrow_columns) * self.measure.step();
    }
};

fn countIn(room: f32, step: f32) u16 {
    if (!(room > 0) or !(step > 0)) return 0;
    const whole = @floor(room / step);
    if (whole >= @as(f32, std.math.maxInt(u16))) return std.math.maxInt(u16);
    return @intFromFloat(whole);
}

/// Every frame goes through `src/tty.zig`, the same way every other line does.
/// The buffer is zero length, so a frame reaches `tty`'s own standard output
/// buffer at once and nothing is left behind when `Loop.run` forks.
const Frames = struct {
    writer: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },

    const vtable: std.Io.Writer.VTable = .{ .drain = drain, .flush = flush };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        _ = w;
        var written: usize = 0;
        // The contract in `std.Io.Writer.VTable.drain`: each slice of `data` in
        // order, and the last slice repeated `splat` times.
        for (data[0 .. data.len - 1]) |slice| {
            _ = tty.writeOut(slice);
            written += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            _ = tty.writeOut(last);
            written += last.len;
        }
        return written;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = w;
        tty.flushOut();
    }
};

/// Where a line written to standard error goes while a display is up. It must
/// not draw: `tty.print` holds `src/tty.zig`'s one lock across a message and a
/// frame takes the same lock, so a frame built here would wait on its own
/// caller. The line is folded into rows and the next frame shows it.
const Diagnostics = struct {
    writer: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },
    ui: ?*Ui = null,
    was: ?*std.Io.Writer = null,
    held: std.ArrayList(u8) = .empty,
    escape: Escape = .none,

    /// Three states and not a flag. `[` is itself in the final byte range, so a
    /// flag cleared on the first byte of that range would end `\x1b[33m` at the
    /// `[` and put `33m` in the row.
    const Escape = enum { none, after_esc, in_csi };

    const vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Diagnostics = @fieldParentPtr("writer", w);
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            self.keep(slice);
            written += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            self.keep(last);
            written += last.len;
        }
        return written;
    }

    fn keep(self: *Diagnostics, bytes: []const u8) void {
        const one = self.ui orelse return;
        for (bytes) |byte| {
            switch (self.escape) {
                .none => {},
                .after_esc => {
                    self.escape = if (byte == '[') .in_csi else .none;
                    continue;
                },
                .in_csi => {
                    if (byte >= 0x40 and byte <= 0x7e) self.escape = .none;
                    continue;
                },
            }
            if (byte == 0x1b) {
                self.escape = .after_esc;
                continue;
            }
            if (byte == '\n') {
                self.emit(one);
                continue;
            }
            self.held.append(one.gpa, byte) catch {};
        }
    }

    fn emit(self: *Diagnostics, one: *Ui) void {
        one.say(.chock, self.held.items);
        one.endRow();
        one.transcript.appendSlice(one.gpa, self.held.items) catch {};
        one.transcript.append(one.gpa, '\n') catch {};
        self.held.clearRetainingCapacity();
    }

    fn finish(self: *Diagnostics, io: std.Io) void {
        const one = self.ui orelse return;
        if (self.held.items.len != 0) self.emit(one);
        self.ui = null;
        _ = tty.useErrStream(io, self.was);
        self.was = null;
    }
};

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

pub const narrow_columns: u16 = 60;

pub const sidebar_columns: u16 = 26;

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

fn columnsOf(text: []const u8) f32 {
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

pub fn spread(
    arena: std.mem.Allocator,
    left: []const u8,
    right: []const u8,
    room: Room,
) std.mem.Allocator.Error![]const u8 {
    if (right.len == 0) return visibleLine(arena, left, room);
    const pinned = room.measure.widthOf(right);
    // Cut even here: a row past the edge would wrap, and the wrapped part starts
    // at column 0, where only Chock draws.
    if (pinned >= room.width) return visibleLine(arena, right, room);

    const gap = room.measure.advanceOf(' ');
    const cut = try visibleLine(arena, left, room.upTo(room.width - pinned - gap));
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, cut);
    const starts = room.width - pinned;
    var filled = room.measure.widthOf(cut);
    while (filled + gap <= starts) : (filled += gap) try out.append(arena, ' ');
    try out.appendSlice(arena, right);
    return out.items;
}

pub fn durationText(arena: std.mem.Allocator, ms: i64) std.mem.Allocator.Error![]const u8 {
    const took: u64 = if (ms <= 0) 0 else @intCast(ms);
    if (took < 60 * 1000) {
        return std.fmt.allocPrint(arena, "{d}.{d}s", .{ took / 1000, (took % 1000) / 100 });
    }
    const seconds = took / 1000;
    return std.fmt.allocPrint(arena, "{d}m{d:0>2}s", .{ seconds / 60, seconds % 60 });
}

pub fn sizeText(arena: std.mem.Allocator, bytes: usize) std.mem.Allocator.Error![]const u8 {
    if (bytes < 1024) return std.fmt.allocPrint(arena, "{d} B", .{bytes});
    if (bytes < 1024 * 1024) {
        return std.fmt.allocPrint(arena, "{d}.{d} KB", .{ bytes / 1024, (bytes % 1024) * 10 / 1024 });
    }
    const mb = bytes / (1024 * 1024);
    const rest = bytes % (1024 * 1024);
    return std.fmt.allocPrint(arena, "{d}.{d} MB", .{ mb, rest * 10 / (1024 * 1024) });
}

const last_second: u64 = 253402300799;

pub fn clockText(
    arena: std.mem.Allocator,
    epoch_ms: i64,
    offset_minutes: i32,
) std.mem.Allocator.Error![]const u8 {
    const shifted = @divFloor(epoch_ms, 1000) + @as(i64, offset_minutes) * 60;
    const seconds: u64 = if (shifted < 0) 0 else @min(@as(u64, @intCast(shifted)), last_second);
    const day = (std.time.epoch.EpochSeconds{ .secs = seconds }).getDaySeconds();
    return std.fmt.allocPrint(arena, "{d:0>2}:{d:0>2}", .{
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
    });
}

const argument_keys = [_][]const u8{
    "pattern",
    "path",
    "name",
    "program",
    "agent_kind",
    "action",
};

pub fn argumentText(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, arguments, .{}) catch {
        return arguments;
    };
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return arguments,
    };

    if (object.get("argv")) |argv| {
        if (argv == .array) {
            var out: std.ArrayList(u8) = .empty;
            for (argv.array.items) |item| {
                if (item != .string) continue;
                if (out.items.len != 0) try out.append(arena, ' ');
                try out.appendSlice(arena, item.string);
            }
            if (out.items.len != 0) return out.items;
        }
    }

    var out: std.ArrayList(u8) = .empty;
    for (argument_keys) |key| {
        const value = object.get(key) orelse continue;
        if (value != .string or value.string.len == 0) continue;
        if (out.items.len != 0) try out.append(arena, ' ');
        try out.appendSlice(arena, value.string);
    }
    if (out.items.len != 0) return out.items;

    var only: ?[]const u8 = null;
    var members = object.iterator();
    while (members.next()) |member| {
        if (member.value_ptr.* != .string) continue;
        if (only != null) return arguments;
        only = member.value_ptr.string;
    }
    return only orelse arguments;
}

pub fn askArgumentText(
    arena: std.mem.Allocator,
    arguments: []const u8,
) std.mem.Allocator.Error![]const u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, arena, arguments, .{}) catch {
        return argumentText(arena, arguments);
    };
    const object = switch (parsed.value) {
        .object => |one| one,
        else => return argumentText(arena, arguments),
    };
    const question = object.get("question") orelse return argumentText(arena, arguments);
    if (question != .string or question.string.len == 0) return argumentText(arena, arguments);

    const first = question.string[0 .. std.mem.indexOfScalar(u8, question.string, '\n') orelse
        question.string.len];

    const options = object.get("options") orelse return first;
    if (options != .array or options.array.items.len == 0) return first;
    return std.fmt.allocPrint(arena, "{s}  ({d} to choose from)", .{
        first,
        options.array.items.len,
    });
}

pub fn summaryText(
    arena: std.mem.Allocator,
    output: []const u8,
    is_error: bool,
    truncated: bool,
) std.mem.Allocator.Error![]const u8 {
    var rest = output;
    var lead: []const u8 = "";

    const status_prefix = "exit status: ";
    if (std.mem.startsWith(u8, rest, status_prefix)) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const code = rest[status_prefix.len..at];
        if (!std.mem.eql(u8, code, "0")) {
            lead = try std.fmt.allocPrint(arena, "exit {s}", .{code});
        }
        rest = if (at == rest.len) rest[at..] else rest[at + 1 ..];
    }

    const failed = is_error or lead.len != 0;
    var said = if (failed) firstLine(rest) else lastLine(rest);
    const note = firstLine(rest);
    if (std.mem.startsWith(u8, note, "[chock: ") and std.mem.endsWith(u8, note, "]")) {
        said = note["[chock: ".len .. note.len - 1];
    }

    var out: std.ArrayList(u8) = .empty;
    if (lead.len != 0) try out.appendSlice(arena, lead);
    if (said.len != 0) {
        if (out.items.len != 0) try out.appendSlice(arena, " \u{b7} ");
        try out.appendSlice(arena, said);
    }
    if (truncated) {
        if (out.items.len != 0) try out.appendSlice(arena, " \u{b7} ");
        try out.appendSlice(arena, "output truncated");
    }
    if (out.items.len == 0) return "no output";
    return out.items;
}

fn firstLine(text: []const u8) []const u8 {
    var rest = text;
    while (rest.len != 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = std.mem.trim(u8, rest[0..at], " \t\r");
        if (line.len != 0) return line;
        if (at == rest.len) break;
        rest = rest[at + 1 ..];
    }
    return "";
}

fn lastLine(text: []const u8) []const u8 {
    var rest = text;
    var found: []const u8 = "";
    while (rest.len != 0) {
        const at = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
        const line = std.mem.trim(u8, rest[0..at], " \t\r");
        if (line.len != 0) found = line;
        if (at == rest.len) break;
        rest = rest[at + 1 ..];
    }
    return found;
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

fn yesNo(answer: bool) []const u8 {
    return if (answer) "yes" else "no";
}

pub const Resumable = struct {
    id: []const u8,
    words: []const u8,
    refusal: []const u8 = "",
};

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

pub fn countLines(text: []const u8) usize {
    return 1 + std.mem.count(u8, text, "\n");
}

pub fn backOne(text: []const u8) usize {
    if (text.len == 0) return 0;
    var at = text.len - 1;
    // Every byte of a multi byte character after the first is 0b10xxxxxx.
    while (at != 0 and text[at] & 0b1100_0000 == 0b1000_0000) at -= 1;
    return at;
}

fn dupeOptions(arena: std.mem.Allocator, options: []const []const u8) []const []const u8 {
    var kept: std.ArrayList([]const u8) = .empty;
    for (options) |option| {
        const one = arena.dupe(u8, option) catch continue;
        kept.append(arena, one) catch return kept.items;
    }
    return kept.items;
}

pub const answer_prompt = " > ";

pub const question_unanswerable = " nobody can answer here. The agent is told so when the time runs out.";

pub const approval_keys = " [y] approve  [n] refuse  [d] diff  [w] why";

pub const approval_keys_narrow = " [y] yes  [n] no  [d] diff  [w] why";

pub fn approvalKeys(room: Room) []const u8 {
    return if (room.isNarrow()) approval_keys_narrow else approval_keys;
}

pub fn elsewhereText(
    arena: std.mem.Allocator,
    session: []const u8,
    room: Room,
) []const u8 {
    const short = " answer it with: chock approve";
    if (session.len == 0) return short;
    const whole = std.fmt.allocPrint(arena, "{s} {s}", .{ short, session }) catch return short;
    return if (room.holds(whole)) whole else short;
}

pub const settle_looks: u8 = 3;

pub fn countdownText(arena: std.mem.Allocator, left_ms: i64) std.mem.Allocator.Error![]const u8 {
    if (left_ms <= 0) return "0:00";
    const seconds: u64 = @intCast(@divFloor(left_ms + 999, 1000));
    return std.fmt.allocPrint(arena, "{d}:{d:0>2}", .{ seconds / 60, seconds % 60 });
}

pub fn ctrlCPresses(bytes: []const u8) usize {
    return std.mem.count(u8, bytes, &.{0x03});
}

/// The terminal's own settings with the echo taken out. `ISIG` and `ECHO` are
/// independent bits of `c_lflag` and `Term.leaveRaw` restores every bit it
/// saved, so a turn used to run with the echo on: a scroll wheel on the
/// alternate screen sends arrow escape sequences, which wrote `^[[A` across the
/// transcript. `ECHONL` goes too, because a canonical terminal echoes a newline
/// with `ECHO` off and a newline moves the whole screen.
pub fn quietOf(was: std.posix.termios) std.posix.termios {
    var quiet = was;
    quiet.lflag.ECHO = false;
    quiet.lflag.ECHONL = false;
    return quiet;
}

fn putTermios(handle: std.posix.fd_t, settings: std.posix.termios) void {
    std.posix.tcsetattr(handle, .FLUSH, settings) catch {};
}

pub const Ask = union(enum) {
    done,
    message: []const u8,
    take_up: []const u8,
};

pub const Answer = union(enum) {
    nothing,
    command: Command,
    message: []const u8,
};

fn keepText(gpa: std.mem.Allocator, into: *std.ArrayList(u8), text: []const u8) void {
    var at: usize = 0;
    while (at < text.len) {
        // A whole escape sequence goes, and never its first byte alone: keeping
        // the rest turns a colour code into a literal `[0m` in the message.
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

/// How many bytes the escape sequence at the front of `text` takes. `ESC [` runs
/// to the first byte in `0x40` to `0x7e`; `ESC ]` is an operating system command
/// and runs to a `BEL` or to `ESC \`. Everything else after `ESC` is two bytes.
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
    if (commandOf(trimmed)) |command| return .{ .command = command };
    return .{ .message = trimmed };
}

pub fn completions(line: []const u8, into: []Command) []const Command {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0 or trimmed[0] != '/') return into[0..0];
    if (std.mem.indexOfScalar(u8, trimmed, ' ') != null) return into[0..0];

    var found: usize = 0;
    for (Command.all) |one| {
        if (found == into.len) break;
        if (!std.mem.startsWith(u8, one.typed(), trimmed)) continue;
        into[found] = one;
        found += 1;
    }
    return into[0..found];
}
const Line = struct {
    voice: Voice,
    text: []const u8,
    pinned: []const u8 = "",
    fold: ?Fold = null,
    gap: bool = false,
};

const Shown = struct {
    voice: Voice,
    text: []const u8,
    pinned: []const u8 = "",
    fold_at: ?usize = null,
    open: bool = false,
    gap: bool = false,
};

const Surface = union(enum) {
    terminal: *phantom.tui.Session,
    window: *phantom.window.Session,

    fn step(self: Surface) !bool {
        return switch (self) {
            .terminal => |one| one.step(),
            .window => |one| one.step(),
        };
    }

    fn stepWaiting(self: Surface, wait_ms: u32) !bool {
        switch (self) {
            .terminal => |one| return one.step(),
            .window => |one| {
                const was = one.opts.poll_ms;
                one.opts.poll_ms = wait_ms;
                defer one.opts.poll_ms = was;
                return one.step();
            },
        }
    }

    fn deinit(self: Surface) void {
        switch (self) {
            .terminal => |one| one.deinit(),
            .window => |one| one.deinit(),
        }
    }

    fn invalidate(self: Surface) void {
        switch (self) {
            .terminal => |one| one.invalidate(),
            .window => {},
        }
    }

    fn terminalSession(self: Surface) ?*phantom.tui.Session {
        return switch (self) {
            .terminal => |one| one,
            .window => null,
        };
    }

    fn focusLast(self: Surface) void {
        switch (self) {
            .terminal => |one| one.focus_mgr.focusPrev(),
            .window => |one| one.focus_mgr.focusPrev(),
        }
    }

    fn hasFocus(self: Surface) bool {
        return switch (self) {
            .terminal => |one| one.focus_mgr.current != null,
            .window => |one| one.focus_mgr.current != null,
        };
    }
};

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

    picker: ?[]const Resumable = null,
    picked: usize = 0,
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

    approval: ?Approval = null,
    approval_focused: bool = false,
    approval_settle: u8 = 0,
    approval_answer: ?Answered = null,
    approval_arena: std.heap.ArenaAllocator,

    question: ?Question = null,
    question_focused: bool = false,
    question_settle: u8 = 0,
    question_typed: [chock_core.ask.max_answer_bytes]u8 = undefined,
    question_filled: usize = 0,
    question_said: ?enum { answered, declined } = null,
    question_arena: std.heap.ArenaAllocator,
    raise: *const fn (std.posix.SIG) std.posix.RaiseError!void = std.posix.raise,

    apply_termios: *const fn (
        std.posix.fd_t,
        std.posix.TCSA,
        std.posix.termios,
    ) std.posix.TermiosSetError!void = std.posix.tcsetattr,

    lines: std.ArrayList(Line) = .empty,
    pending: std.ArrayList(u8) = .empty,
    pending_voice: Voice = .chock,

    cursor: ?usize = null,

    pane: ?Pane = null,

    sidebar_open: bool = false,

    fixed_size: bool = false,

    running_call: ?Running = null,
    running_row: ?usize = null,

    reasoning: std.ArrayList(u8) = .empty,
    turn_open: bool = false,

    clock: chock_core.notices.Clock = .{ .nowMs = noClock },

    surface: Surface,
    frames: Frames = .{},
    diagnostics: Diagnostics = .{},

    replaying: bool = false,

    rows: u16 = 0,
    width: f32 = 0,
    measure: Measure = grid_measure,

    arena: std.heap.ArenaAllocator,
    plan: chock_proto.state.Plan = .{},

    facts: Facts = .{},

    seen_scrolls: u32 = 0,
    running: bool = true,
    said_stopping: bool = false,
    stopped: bool = false,
    keys: ?Keys = null,
    screen: ?*Screen.State = null,

    const status_bytes = 256;

    pub const Phase = enum { message, session };

    const Keys = struct {
        device: phantom.tui.term.Term,
        session: *phantom.tui.Session,
        raw: bool,
        was: ?std.posix.termios = null,
        held: ?std.posix.termios = null,
    };

    const Running = struct {
        tool: []const u8,
        argument: []const u8,
        at_ms: i64,
    };

    fn noClock(ctx: ?*anyopaque) i64 {
        _ = ctx;
        return 0;
    }

    fn realNowMs(ctx: ?*anyopaque) i64 {
        const self: *const Ui = @ptrCast(@alignCast(ctx.?));
        return std.Io.Timestamp.now(self.io, .real).toMilliseconds();
    }

    pub fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        environ: *const std.process.Environ.Map,
        attach: Attach,
    ) !*Ui {
        const self = try gpa.create(Ui);
        errdefer gpa.destroy(self);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .surface = undefined,
            .rows = 0,
            .width = 0,
            .measure = grid_measure,
            .arena = std.heap.ArenaAllocator.init(gpa),
            .approval_arena = std.heap.ArenaAllocator.init(gpa),
            .question_arena = std.heap.ArenaAllocator.init(gpa),
            .seen_scrolls = tty.scrollCount(),
        };
        errdefer self.arena.deinit();
        errdefer self.approval_arena.deinit();
        errdefer self.question_arena.deinit();

        const at = std.Io.Timestamp.now(io, .real).toMilliseconds();
        self.clock = .{
            .ctx = self,
            .nowMs = realNowMs,
            .utc_offset_minutes = clock_mod.localOffsetMinutes(gpa, io, at),
        };

        switch (attach) {
            .terminal => |terminal| {
                var device = phantom.tui.term.Term.initFiles(io, terminal.in, terminal.out);
                const size = terminal.size orelse try device.size();
                self.fixed_size = terminal.size != null;

                // Raw mode spans the probe and the first message: a terminal
                // that is not raw answers a read only when the person presses
                // return. The probe reads its own reply, so a device that never
                // answers eats what is typed for its whole budget, about three
                // seconds. `isTty` is asked first because `tcgetattr` on
                // `/dev/null` answers `ENODEV` on Darwin, which Zig does not
                // know, so `unexpectedErrno` writes a stack trace before the
                // error comes back.
                var was: ?std.posix.termios = null;
                var held: ?std.posix.termios = null;
                if (terminal.in.isTty(io) catch false) device.enterRaw() catch {};
                if (device.saved) |original| {
                    device.saved = null;
                    if (std.posix.tcgetattr(terminal.in.handle)) |now| {
                        was = original;
                        held = now;
                    } else |_| {
                        putTermios(terminal.in.handle, original);
                    }
                }
                const raw = was != null;
                errdefer if (was) |original| putTermios(terminal.in.handle, original);

                const session = try gpa.create(phantom.tui.Session);
                errdefer gpa.destroy(session);
                var options = terminalOptions(self, terminal);
                options.size = size;
                options.query_capabilities = raw;
                // `Session.init` unwinds everything it did on an error, so a
                // caller that gets one must not call `deinit`.
                try session.init(
                    gpa,
                    io,
                    environ,
                    phantom.Root.of(Ui, rootOf, self),
                    options,
                );
                self.surface = .{ .terminal = session };
                self.keys = .{
                    .device = device,
                    .session = session,
                    .raw = raw,
                    .was = was,
                    .held = held,
                };
                self.sayProbe(session.caps, session.mode, raw);

                interrupt.armTerminalRestore();
                if (was) |original| interrupt.armTerminalSettings(terminal.in.handle, original);
            },
            .window => |window| {
                const session = try gpa.create(phantom.window.Session);
                errdefer gpa.destroy(session);
                try session.init(
                    gpa,
                    io,
                    environ,
                    phantom.Root.of(Ui, rootOf, self),
                    windowOptions(window),
                );
                self.surface = .{ .window = session };
            },
        }

        self.diagnostics.ui = self;
        self.diagnostics.was = tty.useErrStream(io, &self.diagnostics.writer);

        return self;
    }

    pub fn terminalOptions(self: *Ui, attach: Attach.Terminal) phantom.tui.Options {
        return .{
            .in = attach.in,
            .out = attach.out,
            .writer = &self.frames.writer,
            .size = attach.size,
            .raw_mode = false,
            .install_signal_handlers = false,
            .install_panic_hook = false,
            .stderr = .leave,
            .own_screen = true,
            .color = if (tty.stdoutPainter().on) null else .none,
        };
    }

    pub fn windowOptions(attach: Attach.Window) phantom.window.Options {
        return .{
            .title = "chock",
            .width = attach.width,
            .height = attach.height,
            // Zero, because every `step` runs inside an observer call on the
            // thread that also runs the session.
            .poll_ms = 0,
        };
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

                if (!self.surface.hasFocus()) self.surface.focusLast();

                if (self.keys) |*keys| {
                    var buffer: [read_bytes]u8 = undefined;
                    const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                        error.EndOfStream => 0,
                        else => |e| return e,
                    };
                    if (read > 0) keys.session.feed(buffer[0..read]);
                }

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

    fn pollFinishedTasks(self: *Ui) void {
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

    const said_by_user = "you";

    fn saidByUser(self: *Ui, text: []const u8) void {
        self.startBlock();

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const at = clockText(arena, self.clock.now(), self.clock.utc_offset_minutes) catch "";
        self.sayPinned(.chock, said_by_user, at);

        self.say(.chock, text);
        self.endLine();
        self.draw();
    }

    fn runCommand(self: *Ui, command: Command) void {
        switch (command) {
            .help => self.openHelp(),
            .plan => self.togglePlan(),
            .usage => self.sayUsage(),
            .@"resume" => self.openPicker(),
        }
    }

    fn openHelp(self: *Ui) void {
        self.pane = .{ .kind = .keys };
    }

    fn helpRows(
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
        for (Command.all) |one| {
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

    fn togglePlan(self: *Ui) void {
        if (self.sidebar_open) {
            self.sidebar_open = false;
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
        self.sidebar_open = true;
    }

    fn foldPlan(self: *Ui, update: chock_proto.event.PlanUpdate) void {
        var gave_up: [max_said_steps]usize = undefined;
        var count: usize = 0;
        for (update.steps, 0..) |step, at| {
            if (!isStatus(step.status, .abandoned)) continue;
            if (self.plan.find(step.id)) |had| {
                if (isStatus(had.status, .abandoned)) continue;
            }
            if (count == gave_up.len) break;
            gave_up[count] = at;
            count += 1;
        }

        self.plan.apply(self.arena.allocator(), update) catch {};

        if (!self.sidebar_open) {
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
            if (isStatus(step.status, .in_progress)) return step;
        }
        return null;
    }

    fn sayProbe(self: *Ui, caps: anytype, mode: phantom.tui.Mode, asked: bool) void {
        if (!tty.verbose()) return;

        if (!asked) {
            self.sayFmt(.chock, "the terminal was not asked what it can do: it took no raw mode", .{});
            return;
        }

        self.sayFmt(.chock, "the terminal drawing mode is {s}", .{@tagName(mode)});
        self.sayFmt(
            .chock,
            "  it answered: graphics {s}, keyboard {s}, truecolor {s}",
            .{ yesNo(caps.kitty_graphics), yesNo(caps.kitty_keyboard), yesNo(caps.truecolor) },
        );
        self.sayFmt(
            .chock,
            "  and: sync {s}, inband resize {s}, pixel mouse {s}",
            .{ yesNo(caps.sync_output), yesNo(caps.inband_resize), yesNo(caps.sgr_pixel_mouse) },
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

    fn openPicker(self: *Ui) void {
        const arena = self.arena.allocator();
        if (self.sessions_dir.len == 0) {
            self.sayFmt(.chock, "this session has no directory to look in", .{});
            return;
        }

        const found = sessions_cmd.list(arena, self.io, self.sessions_dir) catch {
            self.sayFmt(.chock, "the sessions of this project could not be read", .{});
            return;
        };

        var offered: std.ArrayList(Resumable) = .empty;
        for (found) |one| {
            if (std.mem.eql(u8, one.id, self.current_session)) continue;

            const log_path = sessions_cmd.logPathIn(arena, self.sessions_dir, one.id) catch continue;
            const ready = sessions_cmd.readinessOf(arena, self.io, log_path, one.id);
            const refusal = refusalFor(ready, one.has_work);

            const ended = if (one.end) |reason| reason.wireName() else "no end recorded";
            const words = std.fmt.allocPrint(arena, "{s}  {s}", .{ one.id, ended }) catch one.id;
            offered.append(arena, .{
                .id = one.id,
                .words = words,
                .refusal = refusal,
            }) catch {};
        }

        if (offered.items.len == 0) {
            self.sayFmt(.chock, "this project has no other session to take up", .{});
            return;
        }
        self.picker = offered.items;
        self.picked = 0;
    }

    pub fn refusalFor(ready: sessions_cmd.Readiness, has_work: bool) []const u8 {
        switch (ready) {
            .ready => {},
            .running => return "another process is running it",
            .no_such_session => return "its log is gone",
            .nothing_to_carry_on => return "it holds no conversation",
            .unknown => return "its log could not be read",
        }

        if (has_work) {
            return "it still holds work. `chock workspace` lists it and clears it";
        }
        return "";
    }

    fn takePicked(self: *Ui) void {
        const offered = self.picker orelse return;
        if (offered.len == 0) return;
        const chosen = offered[@min(self.picked, offered.len - 1)];

        if (chosen.refusal.len != 0) {
            self.sayFmt(.chock, "{s} cannot be taken up: {s}", .{ chosen.id, chosen.refusal });
            return;
        }

        self.taken = chosen.id;
        self.picker = null;
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

    fn beginInput(self: *Ui) void {
        self.takeKeys(.FLUSH);
        self.typed.clearRetainingCapacity();
        self.submitted = false;
        self.phase = .message;
    }

    /// `when` is `.FLUSH` where a field or a question opens, so a key already in
    /// flight cannot answer it, and `.NOW` for the pump, which keeps what a
    /// person typed between two of its own looks.
    fn takeKeys(self: *Ui, when: std.posix.TCSA) void {
        const keys = if (self.keys) |*one| one else return;
        if (keys.raw) return;
        const held = keys.held orelse return;
        self.apply_termios(keys.device.in.handle, when, held) catch return;
        keys.raw = true;
    }

    pub fn answersKeys(self: *const Ui) bool {
        const keys = self.keys orelse return false;
        return keys.raw;
    }

    /// Gives `ISIG` back and keeps the echo off. The flag falls before the
    /// write, so a device that cannot be written still leaves this file
    /// believing it holds no keyboard.
    fn giveKeys(self: *Ui, when: std.posix.TCSA) void {
        const keys = if (self.keys) |*one| one else return;
        if (!keys.raw) return;
        keys.raw = false;
        const was = keys.was orelse return;
        self.apply_termios(keys.device.in.handle, when, quietOf(was)) catch {};
    }

    fn dropKeys(self: *Ui) void {
        const keys = if (self.keys) |*one| one else return;
        keys.raw = false;
        const was = keys.was orelse return;
        keys.was = null;
        keys.held = null;
        self.apply_termios(keys.device.in.handle, .FLUSH, was) catch {};
        interrupt.disarmTerminalSettings();
    }

    pub fn endInput(self: *Ui) void {
        self.giveKeys(.FLUSH);
        self.phase = .session;
    }

    const read_bytes = 64;

    pub fn showApproval(self: *Ui, one: Approval) void {
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
        self.takeKeys(.FLUSH);
        _ = self.paint();
        self.surface.focusLast();
    }

    pub fn clearApproval(self: *Ui) void {
        if (self.approval == null) return;
        self.approval = null;
        self.approval_answer = null;
        self.approval_settle = 0;
        self.approval_focused = false;
        _ = self.approval_arena.reset(.free_all);
        self.giveKeys(.FLUSH);
        _ = self.paint();
    }

    pub fn approvalLeft(self: *Ui, left_ms: i64) void {
        if (self.approval) |*one| one.left_ms = left_ms;
    }

    pub fn awaitAnswer(self: *Ui, budget_ms: u64) Look {
        if (self.approval == null) return .waiting;

        if (!self.approval_focused) self.surface.focusLast();

        if (!self.paintWaiting(lookWait(budget_ms))) {
            self.running = false;
            interrupt.requestStop();
            return .canceled;
        }

        if (self.approval_answer) |said| {
            self.approval_answer = null;
            return .{ .answered = said };
        }

        if (self.answersKeys()) {
            const keys = &self.keys.?;
            var buffer: [read_bytes]u8 = undefined;
            const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                // Nothing arrived. `VTIME 1` reads that as the end of the read.
                error.EndOfStream => 0,
                else => 0,
            };
            const said = buffer[0..read];
            const presses = ctrlCPresses(said);
            if (presses != 0) {
                // The device goes back before the signal is raised.
                self.giveKeys(.FLUSH);
                for (0..presses) |_| self.raise(.INT) catch interrupt.requestStop();
                return .canceled;
            }
            if (read > 0) keys.session.feed(said);
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

        self.takeKeys(.NOW);
        defer self.giveKeys(.NOW);

        if (self.answersKeys() and self.typedSomething()) {
            const keys = &self.keys.?;
            var buffer: [read_bytes]u8 = undefined;
            const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => 0,
            };
            const said = buffer[0..read];
            const presses = ctrlCPresses(said);
            if (presses != 0) {
                self.giveKeys(.NOW);
                for (0..presses) |_| self.raise(.INT) catch interrupt.requestStop();
                return;
            }
            if (read > 0) keys.session.feed(said);
        }

        if (self.paint()) return;

        self.running = false;
        interrupt.requestStop();
    }

    fn typedSomething(self: *Ui) bool {
        const keys = if (self.keys) |*one| one else return false;
        var fds = [_]std.posix.pollfd{.{
            .fd = keys.device.in.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 0) catch return true;
        return ready != 0;
    }

    pub fn showQuestion(self: *Ui, one: Question) void {
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
        self.takeKeys(.FLUSH);
        _ = self.paint();
        self.surface.focusLast();
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
        self.giveKeys(.FLUSH);
        _ = self.paint();
    }

    pub fn questionLeft(self: *Ui, left_ms: i64) void {
        if (self.question) |*one| one.left_ms = left_ms;
    }

    pub fn awaitText(self: *Ui, budget_ms: u64) Text {
        if (self.question == null) return .waiting;

        if (!self.question_focused) self.surface.focusLast();

        if (!self.paintWaiting(lookWait(budget_ms))) {
            self.running = false;
            interrupt.requestStop();
            return .canceled;
        }

        if (self.takeSaid()) |said| return said;

        if (self.answersKeys()) {
            const keys = &self.keys.?;
            var buffer: [read_bytes]u8 = undefined;
            const read = keys.device.in.readStreaming(self.io, &.{&buffer}) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => 0,
            };
            const said = buffer[0..read];
            const presses = ctrlCPresses(said);
            if (presses != 0) {
                self.giveKeys(.FLUSH);
                for (0..presses) |_| self.raise(.INT) catch interrupt.requestStop();
                return .canceled;
            }
            if (read > 0) keys.session.feed(said);
        }

        if (self.question_settle > 0) self.question_settle -= 1;

        if (self.takeSaid()) |said| return said;
        return .waiting;
    }

    fn takeSaid(self: *Ui) ?Text {
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

    pub fn describe(self: *Ui, facts: Facts) void {
        self.facts = facts;
    }

    pub fn prime(self: *Ui, message: []const u8) void {
        self.primed = message;
    }

    pub fn note(self: *Ui, comptime fmt: []const u8, args: anytype) void {
        self.sayFmt(.chock, fmt, args);
    }

    pub fn stop(self: *Ui) void {
        // Idempotent: two callers ask for this and neither can know whether the
        // other did.
        if (self.stopped) return;
        self.stopped = true;
        self.endInput();
        self.dropKeys();

        self.surface.deinit();
        tty.flushOut();
        interrupt.disarmTerminalRestore();

        self.diagnostics.finish(self.io);

        _ = tty.writeOut(self.transcript.items);
        tty.flushOut();
    }

    pub fn deinit(self: *Ui) void {
        const gpa = self.gpa;
        self.stop();
        switch (self.surface) {
            .terminal => |one| gpa.destroy(one),
            .window => |one| gpa.destroy(one),
        }
        self.arena.deinit();
        self.approval_arena.deinit();
        self.question_arena.deinit();
        self.transcript.deinit(gpa);
        self.diagnostics.held.deinit(gpa);
        self.typed.deinit(gpa);
        self.pending.deinit(gpa);
        self.reasoning.deinit(gpa);
        self.dropRunning();
        for (self.lines.items) |line| self.freeLine(line);
        self.lines.deinit(gpa);
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
            // The detail is the whole of what this line is worth. Every path
            // that ends a session writes a sentence saying what happened, and
            // printing the reason alone told a reader "errored" and no more.
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

    fn openTurn(self: *Ui) void {
        if (self.turn_open) return;
        self.turn_open = true;
        self.startBlock();
        if (self.facts.model.len == 0) return;

        var arena_state = std.heap.ArenaAllocator.init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const at = clockText(arena, self.clock.now(), self.clock.utc_offset_minutes) catch return;
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
        const size = sizeText(fixed.allocator(), self.reasoning.items.len) catch "some";

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
            askArgumentText(arena, call.arguments) catch call.arguments
        else
            argumentText(arena, call.arguments) catch call.arguments;
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
            const took = durationText(arena, self.clock.now() - call.at_ms) catch "";
            const said = callText(arena, glyph, call.tool, call.argument) catch "";
            self.rewriteRunningRow(said, took);
        }
        self.dropRunning();

        if (result.note.len != 0) {
            self.say(.chock, result.note);
            self.endLine();
        }

        const summary = summaryText(
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

    /// How much of a session end detail reaches the screen. A status error's
    /// detail carries the provider's whole response body, which has its own
    /// far larger bound, and the log keeps all of it either way.
    const shown_detail_bytes = 240;

    const kept_lines = 512;

    fn say(self: *Ui, voice: Voice, text: []const u8) void {
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

    fn sayFmt(self: *Ui, voice: Voice, comptime fmt: []const u8, args: anytype) void {
        var buffer: [shown_line_bytes + 128]u8 = undefined;
        // A format that does not fit leaves the tail of `buffer` untouched, so
        // the whole of it is not a string. `bufPrint` writes from the start and
        // fails only once it runs out, which makes the buffer minus the room it
        // needed for the rest the most that can be read back.
        const said = std.fmt.bufPrint(&buffer, fmt, args) catch said: {
            @memset(buffer[buffer.len - 3 ..], '.');
            break :said buffer[0..];
        };
        self.say(voice, said);
        self.endLine();
    }

    const kept_body_bytes = 16 * 1024;

    const open_body_rows = 200;

    fn screenRoom(self: *const Ui) Room {
        return .{ .measure = self.measure, .width = self.width };
    }

    fn transcriptRoom(self: *const Ui) Room {
        return self.transcriptBandRoom().upTo(@as(f32, readable_columns) * self.measure.step());
    }

    fn sidebarWidth(self: *const Ui) f32 {
        if (!self.sidebar_open) return 0;
        if (!self.fitsSidebar()) return 0;
        return @as(f32, sidebar_columns) * self.measure.step();
    }

    fn fitsSidebar(self: *const Ui) bool {
        return self.width >= @as(f32, sidebar_needs_columns) * self.measure.step();
    }

    fn transcriptBandRoom(self: *const Ui) Room {
        const room = self.screenRoom();
        const side = self.sidebarWidth();
        return .{
            .measure = room.measure,
            .width = if (room.width > side) room.width - side else 0,
        };
    }

    fn sidebarRoom(self: *const Ui) Room {
        return .{ .measure = self.measure, .width = self.sidebarWidth() };
    }

    fn roomFor(self: *const Ui, voice: Voice) Room {
        return self.transcriptRoom().less(voice.prefix());
    }

    fn agentRoom(self: *const Ui) Room {
        return self.roomFor(.agent);
    }

    fn endLine(self: *Ui) void {
        if (self.pending.items.len == 0) return;
        self.endRow();
    }

    fn endRow(self: *Ui) void {
        const kept = self.gpa.dupe(u8, self.pending.items) catch {
            self.pending.clearRetainingCapacity();
            return;
        };
        self.pending.clearRetainingCapacity();
        self.addLine(.{ .voice = self.pending_voice, .text = kept });
    }

    fn startBlock(self: *Ui) void {
        self.endLine();
        if (self.lines.items.len == 0) return;
        if (self.lines.items[self.lines.items.len - 1].gap) return;
        self.addLine(.{ .voice = .chock, .text = "", .gap = true });
    }

    fn sayFolded(
        self: *Ui,
        voice: Voice,
        text: []const u8,
        kind: Fold.Kind,
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

    fn addLine(self: *Ui, line: Line) void {
        if (self.lines.items.len >= kept_lines) {
            self.freeLine(self.lines.orderedRemove(0));
            if (self.running_row) |at| self.running_row = if (at == 0) null else at - 1;
            if (self.cursor) |at| self.cursor = if (at == 0) null else at - 1;
        }
        self.lines.append(self.gpa, line) catch self.freeLine(line);
    }

    fn freeLine(self: *Ui, line: Line) void {
        self.gpa.free(line.text);
        self.gpa.free(line.pinned);
        if (line.fold) |one| self.gpa.free(one.body);
    }

    fn sayPinned(self: *Ui, voice: Voice, text: []const u8, right: []const u8) void {
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
        if (!interrupt.requested()) return;
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
        interrupt.requestStop();
    }

    fn followSize(self: *Ui) void {
        if (self.fixed_size) return;
        const one = self.surface.terminalSession() orelse return;
        const now = one.term.size() catch return;
        if (!sizeMoved(now, one.viewport, one.dpr)) return;
        one.resize(now) catch {};
    }

    fn paint(self: *Ui) bool {
        return self.paintWaiting(0);
    }

    const look_ms: u32 = @intCast(chock_core.idle.slice_ms);

    fn lookWait(budget_ms: u64) u32 {
        return @intCast(@min(budget_ms, @as(u64, look_ms)));
    }

    fn paintWaiting(self: *Ui, wait_ms: u32) bool {
        const scrolls = tty.scrollCount();
        if (scrolls != self.seen_scrolls) {
            self.seen_scrolls = scrolls;
            self.surface.invalidate();
        }

        self.followSize();

        if (self.screen) |one| phantom.markNeedsBuild(one);
        const carry_on = self.surface.stepWaiting(wait_ms) catch false;
        tty.flushOut();
        return carry_on;
    }

    fn view(self: *Ui, ctx: *phantom.BuildContext) phantom.Widget {
        const colors = phantom.ColorScheme.tokyoNight();
        const measure = self.resize(ctx);
        const parts = split(self.rows, self.panelRows());

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

    fn resize(self: *Ui, ctx: *phantom.BuildContext) Measure {
        const measure = Measure.of(ctx);
        self.measure = measure;
        const view_now = ctx.owner.activeView() orelse return measure;
        self.rows = measure.rowsIn(view_now.metrics.size.height);
        self.width = view_now.metrics.size.width;
        return measure;
    }

    fn band(
        ctx: *phantom.BuildContext,
        measure: Measure,
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

    fn bandHeight(measure: Measure, rows: u16) f32 {
        return @as(f32, @floatFromInt(rows)) * measure.height();
    }

    fn middleRegions(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
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
        // The row is given its height, because a flex fills the axis it does not
        // lay out along.
        return ctx.new(phantom.SizedBox{
            .height = bandHeight(measure, rows),
            .child = ctx.new(phantom.Row(.{ .children = both })).widget(),
        }).widget();
    }

    fn sidebarRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var lines = Rows{ .left = rows };
        const said = planRows(ctx.arena, self.plan, rows) catch return &.{};
        for (said) |one| {
            lines.add(ctx.arena, row(
                ctx,
                self.measure,
                visibleLine(ctx.arena, one.text, self.sidebarRoom()) catch "",
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

    fn transcriptBand(
        self: *Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
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
        var said: std.ArrayList(HeaderPiece) = .empty;
        headerPieces(ctx.arena, self.facts, self.screenRoom(), &said) catch {};

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
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        rows: u16,
        colors: phantom.ColorScheme,
    ) []const phantom.Widget {
        var lines = Rows{ .left = rows };
        var room = rows;

        var slots: [Command.all.len]Command = undefined;
        const all_listed = self.openCompletions(&slots);
        const all_offered = self.picker orelse &[_]Resumable{};
        const taken: u16 = @intCast(@min(all_listed.len + all_offered.len, room));
        const listed = all_listed[0..@min(all_listed.len, taken)];
        const seats = taken - listed.len;
        const first = if (self.picked < seats) 0 else self.picked - seats + 1;
        const offered = all_offered[@min(first, all_offered.len)..][0..seats];
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
            lines.add(ctx.arena, self.pickerRow(ctx, one, first + index, colors));
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
            if (self.answersKeys())
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
            if (self.answersKeys())
                questionKeys(self.screenRoom(), one.options.len != 0)
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
            visibleLine(ctx.arena, text, self.screenRoom()) catch "",
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
            visibleLine(ctx.arena, text, self.transcriptBandRoom()) catch "",
            color,
        );
    }

    fn pickerRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        one: Resumable,
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

        return self.bandRow(ctx, words, if (one.refusal.len != 0)
            colors.red
        else if (chosen)
            colors.blue_light
        else
            colors.fg_muted);
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

    fn openCompletions(self: *const Ui, into: []Command) []const Command {
        if (self.phase != .message) return into[0..0];
        return completions(self.typed.items, into);
    }

    fn completionRows(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        shown: []const Command,
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

        if (self.picker != null) {
            self.takePicked();
            return true;
        }

        var slots: [Command.all.len]Command = undefined;
        const listed = self.openCompletions(&slots);
        if (listed.len != 0) {
            const chosen = listed[@min(self.completion_selected, listed.len - 1)];
            self.typed.clearRetainingCapacity();
            self.typed.appendSlice(self.gpa, chosen.typed()) catch {};
        }

        self.submitted = true;
        return true;
    }

    fn showRows(self: *const Ui, arena: std.mem.Allocator) []const Shown {
        var out: std.ArrayList(Shown) = .empty;
        for (self.lines.items, 0..) |line, at| {
            const fold = line.fold;
            if (line.gap) {
                out.append(arena, .{ .voice = line.voice, .text = "", .gap = true }) catch
                    return out.items;
                continue;
            }
            const head = wrapText(arena, line.text, self.roomFor(line.voice)) catch
                return out.items;
            for (head, 0..) |words, part| {
                out.append(arena, .{
                    .voice = line.voice,
                    .text = words,
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

    fn visibleRows(self: *const Ui, arena: std.mem.Allocator, count: u16) []const Shown {
        const all = self.showRows(arena);
        const back = @min(self.scroll_back, all.len -| count);
        const end = all.len - back;
        const from = end - @min(end, count);
        return all[from..end];
    }

    fn maxScrollBack(self: *const Ui) usize {
        const parts = split(self.rows, self.panelRows());
        const room = parts.transcript -| 1;
        return self.shownCount() -| room;
    }

    fn showsRule(self: *const Ui) bool {
        return self.transcript_focused or self.scroll_back != 0;
    }

    fn scrollBy(self: *Ui, rows: i32) void {
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
        const parts = split(self.rows, self.panelRows());
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

    fn onPaneKey(self: *Ui, event: phantom.input.KeyEvent) bool {
        if (self.pane == null) return false;
        const pane = &self.pane.?;
        const room = split(self.rows, self.panelRows()).transcript -| 2;
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

        var slots: [Command.all.len]Command = undefined;
        const listed = self.openCompletions(&slots);
        const offered = self.picker orelse &[_]Resumable{};

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
            else => return false,
        }
    }

    fn voicedRow(
        self: *const Ui,
        ctx: *phantom.BuildContext,
        measure: Measure,
        line: Shown,
        colors: phantom.ColorScheme,
    ) phantom.Widget {
        if (line.gap) return plainRow(ctx, "", colors.fg);

        const focused = line.fold_at != null and
            self.transcript_focused and
            self.cursor != null and
            self.cursor.? == line.fold_at.?;
        const marker = if (line.fold_at == null) "" else markerText(line.open, focused);
        const right = if (marker.len != 0) marker else line.pinned;
        const words = spread(ctx.arena, line.text, right, self.roomFor(line.voice)) catch "";
        const cut = std.mem.trimEnd(u8, words, " ");
        const pinned = right.len != 0 and std.mem.endsWith(u8, cut, right);
        const left = if (!pinned)
            cut
        else
            std.mem.trimEnd(u8, cut[0 .. cut.len - right.len], " ");

        const tone = switch (line.voice) {
            .chock => colors.blue_light,
            .agent => colors.fg,
        };
        const said = self.voicedText(ctx, measure, line.voice, left, tone);
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
        measure: Measure,
        voice: Voice,
        words: []const u8,
        tone: phantom.Color,
    ) phantom.Widget {
        _ = self;
        return switch (voice) {
            .chock => row(ctx, measure, std.fmt.allocPrint(ctx.arena, "{s}{s}", .{
                Voice.chock.prefix(),
                words,
            }) catch Voice.chock.prefix(), tone),
            .agent => ctx.new(phantom.Padding{
                .insets = .{
                    .left = measure.widthOf(Voice.agent.prefix()),
                },
                .child = row(ctx, measure, words, tone),
            }).widget(),
        };
    }

    fn pinnedRow(
        ctx: *phantom.BuildContext,
        measure: Measure,
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
        measure: Measure,
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
        measure: Measure,
        text: []const u8,
        color: phantom.Color,
    ) ?phantom.Widget {
        var pieces: std.ArrayList(phantom.Widget) = .empty;
        var index: usize = 0;
        var kept: usize = 0;
        while (index < text.len) {
            const one = drawnAt(text, index);
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
        measure: Measure,
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

    fn rootOf(ctx: *phantom.BuildContext, self: *Ui) phantom.Widget {
        return phantom.StatefulWidget(Screen, ctx.new(Screen{ .ui = self }));
    }
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

const testing = std.testing;

test "a window phantom offers is drawn, and the terminal has no say in it" {
    try testing.expectEqual(Plan.window, decide(.gpu, true));
    try testing.expectEqual(Plan.window, decide(.gpu, false));
}

test "a desktop is named from the environment alone, and an empty value is not one" {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();

    try testing.expect(!namesADisplay(&env));

    try env.put("WAYLAND_DISPLAY", "");
    try testing.expect(!namesADisplay(&env));

    try env.put("WAYLAND_DISPLAY", "wayland-0");
    try testing.expect(namesADisplay(&env));

    var x_only: std.process.Environ.Map = .init(testing.allocator);
    defer x_only.deinit();
    try x_only.put("DISPLAY", ":0");
    try testing.expect(namesADisplay(&x_only));
}

test "a device that cannot draw ends it, and the compositor is never asked" {
    var asked: u32 = 0;
    const Fake = struct {
        asked: *u32,
        answer: Compositor.Answer,

        fn look(self: @This()) Compositor.Answer {
            self.asked.* += 1;
            return self.answer;
        }
    };

    try testing.expectEqual(Compositor.Answer.none, windowPossible(false, Fake{ .asked = &asked, .answer = .ready }));
    try testing.expectEqual(@as(u32, 0), asked);

    try testing.expectEqual(Compositor.Answer.none, windowPossible(true, Fake{ .asked = &asked, .answer = .none }));
    try testing.expectEqual(@as(u32, 1), asked);
    try testing.expectEqual(Compositor.Answer.ready, windowPossible(true, Fake{ .asked = &asked, .answer = .ready }));
    try testing.expectEqual(@as(u32, 2), asked);
}

test "a keyboard that spells nothing loses the window, and the terminal keeps it" {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("WAYLAND_DISPLAY", "wayland-0");

    const Fake = struct {
        answer: Compositor.Answer,

        fn look(self: @This()) Compositor.Answer {
            return self.answer;
        }
    };

    const mute = windowPossible(true, Fake{ .answer = .no_keys });
    try testing.expectEqual(Compositor.Answer.no_keys, mute);
    try testing.expectEqual(
        Plan.terminal,
        decide(phantom.app.selectBackend(&env, mute == .ready, true), true),
    );

    try testing.expectEqual(
        Plan.usage,
        decide(phantom.app.selectBackend(&env, mute == .ready, false), false),
    );

    const ready = windowPossible(true, Fake{ .answer = .ready });
    try testing.expectEqual(
        Plan.window,
        decide(phantom.app.selectBackend(&env, ready == .ready, true), true),
    );
}

test "the one line lattice writes about a keymap is the one this listens for" {
    try testing.expect(saysKeymapFailed(
        .warn,
        "lattice: compositor keymap did not parse, keeping the previous one",
    ));

    try testing.expect(saysKeymapFailed(.err, "keymap"));
    try testing.expect(!saysKeymapFailed(.info, "lattice: keymap loaded"));
    try testing.expect(!saysKeymapFailed(.warn, "lattice: no pointer on this seat"));
}

test "a screen with no way to draw on it leaves the terminal display standing" {
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("WAYLAND_DISPLAY", "wayland-0");

    const Fake = struct {
        answer: Compositor.Answer,

        fn look(self: @This()) Compositor.Answer {
            return self.answer;
        }
    };

    const no_frame = windowPossible(false, Fake{ .answer = .ready });
    try testing.expectEqual(
        Plan.terminal,
        decide(phantom.app.selectBackend(&env, no_frame == .ready, true), true),
    );
    try testing.expectEqual(
        Plan.usage,
        decide(phantom.app.selectBackend(&env, no_frame == .ready, false), false),
    );

    const frame = windowPossible(true, Fake{ .answer = .ready });
    try testing.expectEqual(
        Plan.window,
        decide(phantom.app.selectBackend(&env, frame == .ready, true), true),
    );
}

test "nothing to draw on is the usage page, which is what bare chock always printed" {
    try testing.expectEqual(Plan.usage, decide(.none, false));
    try testing.expectEqual(Plan.usage, decide(.none, true));

    try testing.expectEqual(Plan.usage, decide(.tui, false));

    try testing.expectEqual(Plan.terminal, decide(.tui, true));
}

test "a terminal that says dumb, or says nothing, cannot be drawn on" {
    try testing.expect(!tty.terminalCanDraw(null));
    try testing.expect(!tty.terminalCanDraw(""));
    try testing.expect(!tty.terminalCanDraw("dumb"));
    try testing.expect(tty.terminalCanDraw("xterm-256color"));
    try testing.expect(tty.terminalCanDraw("screen"));
}

test "no colour still means a display, drawn with no SGR byte in it" {
    const gpa = testing.allocator;
    defer tty.configure(.{});

    tty.configure(.{ .stdout_is_tty = true, .term = "xterm-256color", .no_color = "1" });
    try testing.expect(!tty.stdoutPainter().on);

    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.observer().onPiece(.{ .text = "a line with no colour\n" });

    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "a line with no colour") != null);
    try testing.expect(!holdsSgr(h.sink.bytes.items));

    h.stop();
    tty.configure(.{ .stdout_is_tty = true, .term = "xterm-256color" });
    try testing.expect(tty.stdoutPainter().on);

    const painted = try Headless.open(gpa);
    defer painted.close();
    painted.screen.observer().onPiece(.{ .text = "a line with colour\n" });
    try testing.expect(holdsSgr(painted.sink.bytes.items));
}

fn holdsSgr(bytes: []const u8) bool {
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, bytes, at, "\x1b[")) |found| {
        var index = found + 2;
        while (index < bytes.len and (std.ascii.isDigit(bytes[index]) or bytes[index] == ';')) {
            index += 1;
        }
        if (index < bytes.len and bytes[index] == 'm') return true;
        at = found + 2;
    }
    return false;
}

test "a window waits for nothing during a turn, and for a tenth of a second at the field" {
    try testing.expectEqual(@as(?u32, 0), Ui.windowOptions(.{}).poll_ms);
    try testing.expectEqual(@as(u32, @intCast(chock_core.idle.slice_ms)), Ui.look_ms);
}

test "a look waits for the shorter of its budget and one look" {
    try testing.expectEqual(@as(u32, 0), Ui.lookWait(0));
    try testing.expectEqual(@as(u32, 7), Ui.lookWait(7));
    try testing.expectEqual(Ui.look_ms, Ui.lookWait(Ui.look_ms));
    try testing.expectEqual(Ui.look_ms, Ui.lookWait(60_000));
}

test "a terminal look draws exactly as it did, whatever wait it is given" {
    const gpa = testing.allocator;
    defer tty.configure(.{});
    tty.configure(.{ .stdout_is_tty = true, .term = "xterm-256color" });

    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.say(.chock, "a line drawn while waiting");
    h.screen.endLine();

    const before = h.sink.bytes.items.len;
    try testing.expect(h.screen.paintWaiting(Ui.look_ms));
    try testing.expect(h.sink.bytes.items.len > before);
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "a line drawn while waiting") != null);
}

test "the header and the input each keep a row, and the transcript gets the rest" {
    const parts = split(24, 0);
    try testing.expectEqual(@as(u16, 1), parts.header);
    try testing.expectEqual(@as(u16, 22), parts.transcript);
    try testing.expectEqual(@as(u16, 0), parts.approval);
    try testing.expectEqual(@as(u16, 1), parts.input);
    try testing.expectEqual(@as(u16, 24), parts.header + parts.transcript + parts.approval + parts.input);
}

test "an approval takes its rows from the transcript and from neither band" {
    const parts = split(24, 6);
    try testing.expectEqual(@as(u16, 1), parts.header);
    try testing.expectEqual(@as(u16, 16), parts.transcript);
    try testing.expectEqual(@as(u16, 6), parts.approval);
    try testing.expectEqual(@as(u16, 1), parts.input);

    const tight = split(8, 6);
    try testing.expectEqual(@as(u16, 0), tight.transcript);
    try testing.expectEqual(@as(u16, 6), tight.approval);
    try testing.expectEqual(@as(u16, 1), tight.header);
    try testing.expectEqual(@as(u16, 1), tight.input);

    const smaller = split(5, 6);
    try testing.expectEqual(@as(u16, 3), smaller.approval);
    try testing.expectEqual(@as(u16, 5), smaller.header + smaller.transcript +
        smaller.approval + smaller.input);
}

test "a very short screen gives its rows up from the transcript first" {
    const two = split(2, 0);
    try testing.expectEqual(@as(u16, 1), two.header);
    try testing.expectEqual(@as(u16, 0), two.transcript);
    try testing.expectEqual(@as(u16, 1), two.input);

    const one = split(1, 0);
    try testing.expectEqual(@as(u16, 1), one.input);
    try testing.expectEqual(@as(u16, 0), one.header);
    try testing.expectEqual(@as(u16, 0), one.transcript);

    const none = split(0, 0);
    try testing.expectEqual(@as(u16, 0), none.header + none.transcript + none.input);
}

test "one row of the transcript is written per newline, whoever said it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.say(.agent, "one\ntwo\n");
    h.screen.say(.chock, "three\n");
    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[0].voice);
    try testing.expectEqualStrings("one", h.screen.lines.items[0].text);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);
    try testing.expectEqualStrings("two", h.screen.lines.items[1].text);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[2].voice);
    try testing.expectEqualStrings("three", h.screen.lines.items[2].text);

    h.screen.say(.agent, "half a ");
    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    h.screen.say(.agent, "line\n");
    try testing.expectEqual(@as(usize, 4), h.screen.lines.items.len);
    try testing.expectEqualStrings("half a line", h.screen.lines.items[3].text);

    h.screen.say(.agent, "the model was saying");
    h.screen.say(.chock, "session ended, finished\n");
    try testing.expectEqual(@as(usize, 6), h.screen.lines.items.len);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[4].voice);
    try testing.expectEqualStrings("the model was saying", h.screen.lines.items[4].text);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[5].voice);
    try testing.expectEqualStrings("session ended, finished", h.screen.lines.items[5].text);
}

test "an apply that moved no branch still draws a row, and says the branch stayed" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watching = h.screen.observer();
    watching.onEvent(1, .{
        .workspace_integrate = .{
            .ref = "refs/chock/01JQAAAAAAAAAAAAAAAAAAAAAA",
            .mode = "",
            .decision = "deny",
            .branch = "",
            .branch_from = "",
            .branch_to = "",
            .parked = "policy_refused",
        },
    });

    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    const row = h.screen.lines.items[0];
    try testing.expectEqual(Voice.chock, row.voice);
    if (std.mem.indexOf(u8, row.text, "no branch of yours moved") == null) {
        try testing.expectEqualStrings("a row saying the branch did not move", row.text);
        return error.AParkDrawsNoAnswer;
    }
    try testing.expect(std.mem.indexOf(u8, row.text, "policy_refused") != null);
    try testing.expect(std.mem.indexOf(u8, row.text, "refs/chock/01JQAAAAAAAAAAAAAAAAAAAAAA") != null);

    watching.onEvent(2, .{ .workspace_integrate = .{
        .ref = "refs/chock/01JQAAAAAAAAAAAAAAAAAAAAAA",
        .mode = "merge",
        .decision = "allow",
        .branch = "refs/heads/main",
        .branch_from = "1111111",
        .branch_to = "2222222",
        .parked = "",
    } });
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[1].text, "moved to 2222222") != null);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[1].text, "no branch of yours") == null);
}

test "the rows shown are the newest ones, in the order they were said" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    h.screen.say(.agent, "one\ntwo\nthree\nfour\n");
    const shown = h.screen.visibleRows(arena, 2);
    try testing.expectEqual(@as(usize, 2), shown.len);
    try testing.expectEqualStrings("three", shown[0].text);
    try testing.expectEqualStrings("four", shown[1].text);

    const all = h.screen.visibleRows(arena, 10);
    try testing.expectEqual(@as(usize, 4), all.len);
    try testing.expectEqualStrings("one", all[0].text);
}

test "an escape sequence in a row never reaches a cell" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const shown = try visibleLine(arena, "before\x1b[31mred\x07 after", Room.grid(80));
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x07) == null);
    try testing.expectEqualStrings("before [31mred  after", shown);
}

test "a row is cut by columns, so a wide glyph is not cut in half" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("あい", try visibleLine(arena, "あいうえお", Room.grid(4)));
    try testing.expect(std.unicode.utf8ValidateSlice(try visibleLine(arena, "あいうえお", Room.grid(4))));

    try testing.expectEqualStrings("あい", try visibleLine(arena, "あいうえお", Room.grid(5)));
}

test "a byte that is not valid UTF-8 becomes a question mark rather than losing the row" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const shown = try visibleLine(arena, "good\xffbad", Room.grid(80));
    try testing.expectEqualStrings("good?bad", shown);
    try testing.expect(std.unicode.utf8ValidateSlice(shown));

    try testing.expect(std.unicode.utf8ValidateSlice(try visibleLine(arena, "end\xe3\x81", Room.grid(80))));
}

fn themeFont(gpa: std.mem.Allocator) !phantom.text.Font {
    return phantom.text.Font.load(gpa, phantom.text.builtin.mesmerize_rg_bytes);
}

test "a row of the theme's own font is taller than the nominal cell that used to size it" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);

    const nominal = phantom.tui.term.logical_cell_h;
    const measured = (Measure{
        .metrics = .proportional,
        .dpr = 1,
        .font = &font,
        .size = nominal,
    }).height();
    try testing.expect(measured > nominal);
    try testing.expectApproxEqAbs(@as(f32, 19.2), measured, 0.01);
}

test "the character grid measures a row as one reported cell, at any device pixel ratio" {
    for ([_][2]f32{ .{ 9, 18 }, .{ 19, 37 } }) |cell| {
        const dpr = cell[1] / phantom.tui.term.logical_cell_h;
        const measure = Measure{
            .metrics = .{ .mono = phantom.text.mono.Mono.fromCell(cell[0], cell[1]) },
            .dpr = dpr,
            .font = undefined,
            .size = 0,
        };
        try testing.expectApproxEqAbs(
            phantom.tui.term.logical_cell_h,
            measure.height(),
            0.001,
        );
        const logical_h = 24 * cell[1] / dpr;
        const logical_w = 80 * cell[0] / dpr;
        try testing.expectEqual(@as(u16, 24), measure.rowsIn(logical_h));
        const room = Room{ .measure = measure, .width = logical_w };
        try testing.expect(room.holds("x" ** 80));
        try testing.expect(!room.holds("x" ** 81));
    }
}

fn faceMeasure(font: *phantom.text.Font, size: f32) Measure {
    return .{ .metrics = .proportional, .dpr = 1, .font = font, .size = size };
}

test "a proportional row is measured against its own letters and never divided by a column" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const size: f32 = 16;
    const measure = faceMeasure(&font, size);
    const across: f32 = 640;
    const room = Room{ .measure = measure, .width = across };

    const words = "the quick brown fox jumps over the lazy dog. " ** 8;
    const cut = try visibleLine(arena, words, room);

    try testing.expect(measure.widthOf(cut) <= across);

    var widest: f32 = 0;
    var point: u21 = ' ';
    while (point <= '~') : (point += 1) widest = @max(widest, font.advance(point, size));
    const divided: usize = @intFromFloat(@floor(across / widest));
    try testing.expect(divided > 0);
    try testing.expect(cut.len > divided * 3 / 2);
}

test "a row of the widest letters still fits, because it is measured too" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const size: f32 = 16;
    const measure = faceMeasure(&font, size);
    const across: f32 = 640;
    const room = Room{ .measure = measure, .width = across };

    var fattest: u21 = ' ';
    var widest: f32 = 0;
    var point: u21 = ' ';
    while (point <= '~') : (point += 1) {
        const one = font.advance(point, size);
        if (one > widest) {
            widest = one;
            fattest = point;
        }
    }

    var wall: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    while (index < 400) : (index += 1) try wall.append(arena, @intCast(fattest));

    const cut = try visibleLine(arena, wall.items, room);
    try testing.expect(cut.len != 0);
    try testing.expect(measure.widthOf(cut) <= across);
    try testing.expect(measure.widthOf(cut) + widest > across);
}

test "the advances a frame works out once are the advances it would have asked for" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);

    const plain = faceMeasure(&font, 24);
    const quick = plain.measured();

    try testing.expectEqual(plain.height(), quick.height());
    try testing.expectApproxEqAbs(plain.step(), quick.step(), 0.0001);
    var point: u21 = ' ';
    while (point <= '~') : (point += 1) {
        try testing.expectEqual(plain.advanceOf(point), quick.advanceOf(point));
    }
    try testing.expectEqual(
        plain.advanceOf('\u{3042}'),
        quick.advanceOf('\u{3042}'),
    );
}

test "a viewport with no room and a measurement with no size are counted as nothing" {
    try testing.expectEqual(@as(u16, 0), countIn(0, 16));
    try testing.expectEqual(@as(u16, 0), countIn(400, 0));
    try testing.expectEqual(@as(u16, 0), countIn(-400, 16));
    try testing.expectEqual(@as(u16, 25), countIn(400, 16));
    try testing.expectEqual(@as(u16, 24), countIn(399, 16));
    try testing.expectEqual(std.math.maxInt(u16), countIn(1e9, 1));
}

const every_layer_on = [_]Layer{
    .{ .name = "net", .note = "off", .state = .on },
    .{ .name = "fs", .note = "worktree", .state = .on },
    .{ .name = "pid", .state = .on },
    .{ .name = "ipc", .state = .on },
    .{ .name = "seccomp", .state = .on },
    .{ .name = "landlock", .state = .on },
};

fn headerText(arena: std.mem.Allocator, facts: Facts, cols: f32) ![]const u8 {
    var said: std.ArrayList(HeaderPiece) = .empty;
    try headerPieces(arena, facts, Room.grid(cols), &said);
    var line: std.ArrayList(u8) = .empty;
    for (said.items) |one| try line.appendSlice(arena, one.text);
    return line.items;
}

test "a layer that is not on says so in a word as well as in a glyph and a colour" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("\u{2713} net off", try layerText(
        arena,
        .{ .name = "net", .note = "off", .state = .on },
        false,
    ));
    try testing.expectEqualStrings("\u{2717} landlock OFF", try layerText(
        arena,
        .{ .name = "landlock", .state = .off },
        false,
    ));
    try testing.expectEqualStrings("\u{2717} landlock NONE", try layerText(
        arena,
        .{ .name = "landlock", .state = .unsupported },
        false,
    ));
    try testing.expect(!std.mem.eql(
        u8,
        Layer.State.off.word(),
        Layer.State.unsupported.word(),
    ));

    for ([_]Layer.State{ .off, .unsupported, .unavailable }) |state| {
        try testing.expect(state.word().len != 0);
        try testing.expectEqualStrings("\u{2717}", state.glyph());
    }
    try testing.expectEqualStrings("", Layer.State.on.word());
}

test "every layer state is a tick or a cross, because a layer is either enforced or it is not" {
    const tick = "\u{2713}";
    const cross = "\u{2717}";
    var ticks: usize = 0;
    for (std.enums.values(Layer.State)) |state| {
        const is_tick = std.mem.eql(u8, state.glyph(), tick);
        try testing.expect(is_tick or std.mem.eql(u8, state.glyph(), cross));
        if (is_tick) ticks += 1;
    }
    try testing.expectEqual(@as(usize, 1), ticks);
}

test "under 60 columns a layer that is on sheds its name and one that is not keeps it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("\u{2713}", try layerText(
        arena,
        .{ .name = "seccomp", .state = .on },
        true,
    ));
    try testing.expectEqualStrings("\u{2717} landlock OFF", try layerText(
        arena,
        .{ .name = "landlock", .state = .off },
        true,
    ));

    var layers = every_layer_on;
    layers[5] = .{ .name = "landlock", .state = .off };
    const said = try headerText(arena, .{
        .project = "chock",
        .workspace = "worktree",
        .model = "glm4.7-flash",
        .provider = "local",
        .layers = &layers,
    }, 50);
    try testing.expect(std.mem.indexOf(u8, said, "landlock OFF") != null);
    try testing.expectEqual(@as(usize, 5), std.mem.count(u8, said, "\u{2713}"));
}

test "the layers keep their room and a context fact is what the header drops" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const facts = Facts{
        .project = "a-project-with-a-long-name",
        .workspace = "worktree",
        .model = "glm4.7-flash",
        .provider = "local",
        .layers = &every_layer_on,
    };

    const said = try headerText(arena, facts, 80);
    try testing.expect(columnsOf(said) <= 80);
    for (every_layer_on) |one| {
        try testing.expect(std.mem.indexOf(u8, said, one.name) != null);
    }
    try testing.expect(std.mem.indexOf(u8, said, "a-project-with-a-lo") == null);
    try testing.expect(std.mem.indexOf(u8, said, "local") == null);

    const wide = try headerText(arena, facts, 160);
    try testing.expect(std.mem.indexOf(u8, wide, "a-project-with-a-long-name") != null);
    try testing.expect(std.mem.indexOf(u8, wide, "glm4.7-flash") != null);
    try testing.expect(std.mem.indexOf(u8, wide, "local") != null);
}

test "a header with no layers draws none rather than six that claim nothing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const said = try headerText(arena, .{ .project = "chock" }, 80);
    try testing.expectEqualStrings(" chock  chock", said);
    try testing.expect(std.mem.indexOf(u8, said, "\u{2713}") == null);
}

test "a layer that is on is drawn in one colour and a layer that is not in another" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var layers = every_layer_on;
    layers[5] = .{ .name = "landlock", .state = .off };
    h.screen.describe(.{ .layers = &layers });
    _ = h.screen.paint();

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    const first = std.mem.sliceTo(plain.items, '\n');
    try testing.expect(std.mem.indexOf(u8, first, "landlock OFF") != null);

    const colors = phantom.ColorScheme.tokyoNight();
    const on = phantom.backend.cell_grid.Rgb.fromColor(colors.green);
    const off = phantom.backend.cell_grid.Rgb.fromColor(colors.red);
    try testing.expect(!std.meta.eql(on, off));

    const grid = &h.screen.surface.terminal.grid;
    const off_at = columnsOf(first[0..std.mem.indexOf(u8, first, "\u{2717}").?]);
    try testing.expectEqual(off, grid.cellAt(@intFromFloat(off_at), 0).?.fg);
    const on_at = columnsOf(first[0..std.mem.indexOf(u8, first, "\u{2713}").?]);
    try testing.expectEqual(on, grid.cellAt(@intFromFloat(on_at), 0).?.fg);
}

const Sink = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *Sink) void {
        self.bytes.deinit(self.gpa);
    }

    fn tap(self: *Sink) Tap {
        return self.tapWith(&.{});
    }

    fn tapWith(self: *Sink, buffer: []u8) Tap {
        return .{ .writer = .{ .vtable = &Tap.vtable, .buffer = buffer }, .sink = self };
    }

    const Tap = struct {
        writer: std.Io.Writer,
        sink: *Sink,

        const vtable: std.Io.Writer.VTable = .{ .drain = drain };

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *Tap = @fieldParentPtr("writer", w);
            const gpa = self.sink.gpa;
            self.sink.bytes.appendSlice(gpa, w.buffered()) catch return error.WriteFailed;
            w.end = 0;
            var written: usize = 0;
            for (data[0 .. data.len - 1]) |slice| {
                self.sink.bytes.appendSlice(gpa, slice) catch return error.WriteFailed;
                written += slice.len;
            }
            const last = data[data.len - 1];
            for (0..splat) |_| {
                self.sink.bytes.appendSlice(gpa, last) catch return error.WriteFailed;
                written += last.len;
            }
            return written;
        }
    };
};

const Recorder = struct {
    gpa: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    events: usize = 0,
    pieces: usize = 0,
    notices: usize = 0,

    fn observer(self: *Recorder) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        _ = id;
        _ = ev;
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.events += 1;
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.pieces += 1;
        switch (piece) {
            .text => |text| self.bytes.appendSlice(self.gpa, text) catch {},
            .reasoning => {},
        }
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        _ = text;
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.notices += 1;
    }
};

const HandClock = struct {
    at_ms: i64 = 0,

    fn clock(self: *HandClock) chock_core.notices.Clock {
        return .{ .ctx = self, .nowMs = nowMs, .utc_offset_minutes = 0 };
    }

    fn nowMs(ctx: ?*anyopaque) i64 {
        const self: *HandClock = @ptrCast(@alignCast(ctx.?));
        return self.at_ms;
    }
};

const Headless = struct {
    gpa: std.mem.Allocator,
    threaded: std.Io.Threaded,
    env: std.process.Environ.Map,
    device: std.Io.File,
    sink: Sink,
    tap: Sink.Tap,
    diagnostics: Sink,
    diagnostics_tap: Sink.Tap,
    recorder: Recorder,
    hand: HandClock,
    screen: *Ui,
    plain: std.ArrayList(u8),
    stopped: bool,

    const size = phantom.tui.term.Size{ .cols = 40, .rows = 8, .xpixel = 320, .ypixel = 128 };

    fn open(gpa: std.mem.Allocator) !*Headless {
        return openSized(gpa, size);
    }

    fn openSized(gpa: std.mem.Allocator, screen: phantom.tui.term.Size) !*Headless {
        const self = try gpa.create(Headless);
        errdefer gpa.destroy(self);

        self.gpa = gpa;
        self.threaded = std.Io.Threaded.init(gpa, .{});
        const io = self.threaded.io();
        self.env = std.process.Environ.Map.init(gpa);
        self.sink = .{ .gpa = gpa };
        self.tap = self.sink.tap();
        self.diagnostics = .{ .gpa = gpa };
        self.diagnostics_tap = self.diagnostics.tap();
        self.stopped = false;

        self.plain = .empty;

        self.device = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{});
        errdefer self.device.close(io);
        errdefer tty.useStreams(io, null, null);

        tty.useStreams(io, &self.tap.writer, &self.diagnostics_tap.writer);
        self.screen = try Ui.start(
            gpa,
            io,
            &self.env,
            .{ .terminal = .{ .in = self.device, .out = self.device, .size = screen } },
        );
        self.screen.phase = .session;
        self.hand = .{};
        self.screen.clock = self.hand.clock();
        self.recorder = .{ .gpa = gpa, .bytes = &self.screen.transcript };
        self.screen.wrap(self.recorder.observer());
        return self;
    }

    fn transcript(self: *Headless) *std.ArrayList(u8) {
        return &self.screen.transcript;
    }

    fn stop(self: *Headless) void {
        if (self.stopped) return;
        self.stopped = true;
        self.screen.deinit();
    }

    fn close(self: *Headless) void {
        const io = self.threaded.io();
        self.stop();
        self.plain.deinit(self.gpa);
        tty.useStreams(io, null, null);
        self.device.close(io);
        self.sink.deinit();
        self.diagnostics.deinit();
        self.env.deinit();
        self.threaded.deinit();
        self.gpa.destroy(self);
    }
};

test "a whole run drives a real session with no terminal, and every frame goes through the standard output writer" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "\x1b[?1049h") != null);

    const steps = [_]chock_proto.event.PlanStep{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .in_progress },
    };
    const watcher = h.screen.observer();
    watcher.onPiece(.{ .text = "the parser is where it fails\n" });
    watcher.onNotice("waiting out a rate limit");
    watcher.onEvent(1, .{ .plan_update = .{ .steps = &steps } });

    try testing.expectEqual(@as(usize, 1), h.recorder.pieces);
    try testing.expectEqual(@as(usize, 1), h.recorder.notices);
    try testing.expectEqual(@as(usize, 1), h.recorder.events);

    try testing.expectEqual(@as(usize, 2), h.screen.plan.steps.items.len);

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "the parser is where it fails") != null);
    try testing.expect(std.mem.indexOf(u8, plain.items, "plan step s2 is now in_progress") != null);
    try testing.expect(std.mem.indexOf(u8, plain.items, "waiting out a rate limit") != null);
}

test "the message is typed into the display, and Enter is what says it is the message" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.phase = .message;

    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("fix the parser");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("fix the parser", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "fix the parser") != null);

    h.screen.surface.terminal.feed("\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
}

const FakeTaskRunner = struct {
    fn runner(self: *FakeTaskRunner) chock_core.tasks.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.tasks.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: *const chock_core.tasks.Request,
    ) chock_core.tasks.Outcome {
        _ = ptr;
        _ = io;
        _ = request;
        return .{
            .status = .exited,
            .code = 0,
            .output = allocator.dupe(u8, "the build passed\n") catch &[_]u8{},
        };
    }
};

test "a task finished while the field is up is shown once, and not again when the turn drains it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const dir = try std.fmt.allocPrint(gpa, "{s}/tasks", .{path_buffer[0..path_len]});
    defer gpa.free(dir);
    try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);

    var fake = FakeTaskRunner{};
    var table = chock_core.tasks.Table{ .gpa = gpa, .dir = dir, .runner = fake.runner() };
    defer table.deinit();

    h.screen.tasks = &table;

    const argv = [_][]const u8{"make"};
    _ = try table.start(testing.io, .{
        .config = .{ .root = "/root", .mounts = &.{}, .rules = &.{}, .cwd = "/project", .env = &.{} },
        .argv = &argv,
    });
    table.waitAll();

    h.screen.pollFinishedTasks();
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[0].text, "the background task task-01 finished") != null);
    try testing.expectEqual(@as(usize, 1), h.screen.tasks_shown_early);

    h.screen.pollFinishedTasks();
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);

    h.screen.observer().onEvent(2, .{ .task_complete = .{
        .task_id = "task-01",
        .command = "make",
        .status = .exited,
        .code = 0,
        .output_path = "/run/chock/tasks/task-01.out",
        .output_bytes = 17,
        .truncated = false,
    } });
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    try testing.expectEqual(@as(usize, 0), h.screen.tasks_shown_early);

    h.screen.observer().onEvent(3, .{ .task_complete = .{
        .task_id = "task-02",
        .command = "make check",
        .status = .exited,
        .code = 0,
        .output_path = "/run/chock/tasks/task-02.out",
        .output_bytes = 3,
        .truncated = false,
    } });
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[1].text, "task-02 finished") != null);
}

test "a second turn gets a field of its own, and carries nothing of the first one into it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    h.screen.surface.terminal.feed("first\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expectEqualStrings("first", h.screen.typed.items);

    h.screen.endInput();
    try testing.expectEqual(Ui.Phase.session, h.screen.phase);
    h.screen.observer().onPiece(.{ .text = "the parser is where it fails\n" });

    h.screen.beginInput();
    try testing.expectEqual(Ui.Phase.message, h.screen.phase);
    try testing.expectEqualStrings("", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    h.screen.surface.terminal.feed("second");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("second", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    h.screen.surface.terminal.feed("\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);

    h.screen.endInput();
    try testing.expectEqualStrings("the parser is where it fails\n", h.transcript().items);
}

test "an empty line ends the conversation, and Ctrl-C at the field ends it too" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    h.screen.surface.terminal.feed("   \r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expect(std.mem.trim(u8, h.screen.typed.items, " \t\r\n").len == 0);

    h.screen.beginInput();
    h.screen.surface.terminal.feed("  \t \r");
    try testing.expectEqual(Ask.done, try h.screen.askForMessage(gpa));

    try testing.expect(!h.screen.keys.?.raw);
}

test "the transcript is written back to the real screen, byte for byte, after the display goes" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const words = "one\ntwo\nthree\n";
    h.screen.observer().onPiece(.{ .text = words });
    try testing.expectEqualStrings(words, h.transcript().items);

    h.stop();

    try testing.expect(std.mem.endsWith(u8, h.sink.bytes.items, words));

    const left = std.mem.lastIndexOf(u8, h.sink.bytes.items, "\x1b[?1049l").?;
    const replayed = h.sink.bytes.items.len - words.len;
    try testing.expect(left < replayed);
}

test "a line written past every writer makes the next frame paint every cell again" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onPiece(.{ .text = "a settled line\n" });
    const settled = h.sink.bytes.items.len;

    h.screen.observer().onPiece(.{ .text = "" });
    try testing.expectEqual(settled, h.sink.bytes.items.len);

    tty.noteScroll();

    h.screen.observer().onPiece(.{ .text = "" });
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items[settled..], "a settled line") != null);
}

test "a warning written while the display is up is a row of the transcript and not a line on the screen" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    defer tty.configure(.{});
    tty.configure(.{ .stderr_is_tty = true, .term = "xterm-256color" });
    try testing.expect(tty.stderrPainter().on);

    tty.print(.warn, "chock: something to act on\n", .{});

    try testing.expectEqualStrings("", h.diagnostics.bytes.items);

    var said = false;
    for (h.screen.lines.items) |line| {
        if (!std.mem.eql(u8, line.text, "chock: something to act on")) continue;
        said = true;
        try testing.expectEqual(Voice.chock, line.voice);
    }
    try testing.expect(said);

    for (h.screen.lines.items) |line| {
        try testing.expect(std.mem.indexOfScalar(u8, line.text, 0x1b) == null);
        try testing.expect(std.mem.indexOf(u8, line.text, "[33m") == null);
    }

    try testing.expect(std.mem.indexOf(
        u8,
        h.transcript().items,
        "chock: something to act on\n",
    ) != null);
}

test "a diagnostic reaches the real terminal before the display takes it and after it gives it back" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var frames: Sink = .{ .gpa = gpa };
    defer frames.deinit();
    var frames_tap = frames.tap();
    var real: Sink = .{ .gpa = gpa };
    defer real.deinit();
    var real_tap = real.tap();

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    const device = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{});
    defer device.close(io);

    defer tty.useStreams(io, null, null);
    tty.useStreams(io, &frames_tap.writer, &real_tap.writer);
    defer tty.configure(.{});
    tty.configure(.{});

    tty.print(.warn, "chock: before the display\n", .{});
    try testing.expectEqualStrings("chock: before the display\n", real.bytes.items);

    const screen = try Ui.start(gpa, io, &env, .{ .terminal = .{
        .in = device,
        .out = device,
        .size = Headless.size,
    } });

    tty.print(.warn, "chock: while the display is up\n", .{});
    try testing.expectEqualStrings("chock: before the display\n", real.bytes.items);

    screen.deinit();

    tty.print(.warn, "chock: after the display\n", .{});
    try testing.expectEqualStrings(
        "chock: before the display\nchock: after the display\n",
        real.bytes.items,
    );
}

test "a diagnostic with no newline at the end is still a row when the display comes down" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    tty.print(.warn, "chock: a line that never ended", .{});
    h.stop();

    try testing.expect(std.mem.endsWith(
        u8,
        h.sink.bytes.items,
        "chock: a line that never ended\n",
    ));
    try testing.expectEqualStrings("", h.diagnostics.bytes.items);
}

test "a diagnostic of several lines is several rows, blank lines included" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    tty.print(.err, "chock: it failed.\n\nTry this instead.\n", .{});

    var first: ?usize = null;
    var last: ?usize = null;
    for (h.screen.lines.items, 0..) |line, at| {
        if (std.mem.eql(u8, line.text, "chock: it failed.")) first = at;
        if (std.mem.eql(u8, line.text, "Try this instead.")) last = at;
    }
    try testing.expect(first != null and last != null);
    try testing.expectEqual(first.? + 2, last.?);
    try testing.expectEqualStrings("", h.screen.lines.items[first.? + 1].text);
}

test "the sequences a second Ctrl-C writes cover everything a real session writes on the way out" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expectEqual(@as(usize, 0), h.transcript().items.len);
    const mark = h.sink.bytes.items.len;
    h.stop();
    const teardown = h.sink.bytes.items[mark..];

    try testing.expect(teardown.len != 0);
    try testing.expect(std.mem.indexOf(u8, interrupt.restore_bytes, teardown) != null);
}

test "a second Ctrl-C writes the restore bytes only while a display is up" {
    const gpa = testing.allocator;
    try testing.expect(interrupt.restoreBytesIfArmed() == null);

    const h = try Headless.open(gpa);
    defer h.close();
    try testing.expectEqualStrings(
        interrupt.restore_bytes,
        interrupt.restoreBytesIfArmed().?,
    );

    h.stop();
    try testing.expect(interrupt.restoreBytesIfArmed() == null);
}
test "with no question open the screen is three regions, with the transcript between the bands" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.describe(.{
        .project = "chock",
        .workspace = "worktree",
        .model = "glm4.7",
        .provider = "local",
    });
    h.hand.at_ms = (12 * 60 + 4) * 60 * 1000;
    h.screen.observer().onPiece(.{ .text = "the parser is where it fails\nand here is a second line\n" });
    h.screen.observer().onNotice("waiting out a rate limit");

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);

    try testing.expectEqualStrings(
        \\ chock  chock  worktree  glm4.7  local
        \\
        \\  glm4.7 · local                   12:04
        \\  the parser is where it fails
        \\  and here is a second line
        \\
        \\│ waiting out a rate limit
        \\ >
        \\
    , plain.items);
}

test "each region is a surface of its own, and the bands are not the transcript's" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    _ = h.screen.paint();

    const colors = phantom.ColorScheme.tokyoNight();
    const recess = phantom.backend.cell_grid.Rgb.fromColor(colors.bg_dark);
    const base = phantom.backend.cell_grid.Rgb.fromColor(colors.bg);
    const grid = &h.screen.surface.terminal.grid;
    const parts = split(h.screen.rows, h.screen.approvalRows());

    try testing.expectEqual(recess, grid.cellAt(0, 0).?.bg);
    try testing.expectEqual(recess, grid.cellAt(0, h.screen.rows - 1).?.bg);

    try testing.expectEqual(base, grid.cellAt(0, parts.header).?.bg);
    try testing.expect(!std.meta.eql(recess, base));

    var row_index: u16 = parts.header;
    while (row_index < parts.header + parts.transcript) : (row_index += 1) {
        try testing.expectEqual(base, grid.cellAt(0, row_index).?.bg);
    }
}

test "an agent that writes Chock's own words still writes them under no rail, indented" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onNotice("approval needed, git.push");
    h.screen.observer().onPiece(.{ .text = "chock: approval needed, git.push\n" });

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);

    var rows = std.mem.splitScalar(u8, plain.items, '\n');
    var saw_chock = false;
    var saw_agent = false;
    while (rows.next()) |line| {
        if (std.mem.eql(u8, line, "│ approval needed, git.push")) saw_chock = true;
        if (std.mem.eql(u8, line, "  chock: approval needed, git.push")) saw_agent = true;
        try testing.expect(!std.mem.startsWith(u8, line, "chock:"));
    }
    try testing.expect(saw_chock);
    try testing.expect(saw_agent);
}

test "a long agent line wraps, and no row of it reaches column 0" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 40, .rows = 12, .xpixel = 320, .ypixel = 192 });
    defer h.close();

    const sentence = "This is an exceptionally well architected project with strong " ++
        "security guarantees and a clean separation of concerns.";
    h.screen.observer().onPiece(.{ .text = sentence });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    const drawn = try screenText(h);
    var rows = std.mem.splitScalar(u8, drawn, '\n');
    var said: std.ArrayList(u8) = .empty;
    defer said.deinit(gpa);
    var wrapped: usize = 0;
    while (rows.next()) |one| {
        if (one.len == 0) continue;
        if (!std.mem.startsWith(u8, one, Voice.agent.prefix())) continue;
        wrapped += 1;
        if (said.items.len != 0) try said.append(gpa, ' ');
        try said.appendSlice(gpa, std.mem.trim(u8, one, " "));
    }

    try testing.expect(wrapped > 1);
    try testing.expectEqualStrings(sentence, said.items);
}

test "the transcript stops growing at a readable measure, and the other regions do not" {
    const gpa = testing.allocator;
    const wide: u16 = 200;
    const h = try Headless.openSized(gpa, .{
        .cols = wide,
        .rows = 10,
        .xpixel = wide * 8,
        .ypixel = 160,
    });
    defer h.close();

    const cell = h.screen.measure.step();
    try testing.expectEqual(@as(f32, wide) * cell, h.screen.screenRoom().width);
    try testing.expectEqual(@as(f32, readable_columns) * cell, h.screen.transcriptRoom().width);
    try testing.expect(h.screen.agentRoom().width < @as(f32, wide) * cell);

    h.screen.observer().onPiece(.{ .text = "word " ** 120 });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |one| {
        if (!std.mem.startsWith(u8, one, Voice.agent.prefix())) continue;
        try testing.expect(columnsOf(one) <= readable_columns);
    }
}

test "a blank line the agent wrote is a blank row at the agent's indent" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onPiece(.{ .text = "first section\n\nsecond section\n" });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });

    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    try testing.expectEqualStrings("first section", h.screen.lines.items[0].text);
    try testing.expectEqualStrings("", h.screen.lines.items[1].text);
    try testing.expectEqualStrings("second section", h.screen.lines.items[2].text);

    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);
    try testing.expect(!h.screen.lines.items[1].gap);
    for (h.screen.lines.items) |one| try testing.expect(!one.gap);
}

test "the blank row between two blocks is Chock's, and never two of them" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onNotice("the first thing");
    try testing.expect(!h.screen.lines.items[0].gap);

    watcher.onNotice("the second thing");
    var gaps: usize = 0;
    var streak: usize = 0;
    var most: usize = 0;
    for (h.screen.lines.items) |one| {
        if (one.gap) {
            gaps += 1;
            streak += 1;
            most = @max(most, streak);
        } else streak = 0;
    }
    try testing.expectEqual(@as(usize, 1), gaps);
    try testing.expectEqual(@as(usize, 1), most);
}

fn gridRoom(font: *phantom.text.Font, columns: f32) Room {
    return .{
        .measure = .{
            .metrics = .{ .mono = .{ .advance = 1, .line = 1, .ascent = 0.8 } },
            .dpr = 1,
            .font = font,
            .size = 1,
        },
        .width = columns,
    };
}

test "a wrapped row breaks at a space, and a word with none is broken at the measure" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const broken = try wrapText(arena, "the quick brown fox", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 2), broken.len);
    try testing.expectEqualStrings("the quick", broken[0]);
    try testing.expectEqualStrings("brown fox", broken[1]);

    const solid = try wrapText(arena, "x" ** 25, gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 3), solid.len);
    try testing.expectEqualStrings("x" ** 10, solid[0]);
    try testing.expectEqualStrings("x" ** 5, solid[2]);

    const short = try wrapText(arena, "fits", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 1), short.len);
    try testing.expectEqualStrings("fits", short[0]);

    const nothing = try wrapText(arena, "", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 1), nothing.len);
    try testing.expectEqualStrings("", nothing[0]);

    const wide = try wrapText(arena, "あいうえお", gridRoom(&font, 4));
    try testing.expectEqualStrings("あい", wide[0]);
    for (wide) |one| try testing.expect(std.unicode.utf8ValidateSlice(one));

    const narrow = try wrapText(arena, "あA", gridRoom(&font, 1));
    try testing.expectEqual(@as(usize, 2), narrow.len);
    try testing.expectEqualStrings("あ", narrow[0]);
    try testing.expectEqualStrings("A", narrow[1]);
}

test "a control byte and a byte that is not UTF-8 are made safe before a row is broken" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const bad = try wrapText(arena, "good\xffbad words here", gridRoom(&font, 8));
    for (bad) |one| try testing.expect(std.unicode.utf8ValidateSlice(one));
    try testing.expectEqualStrings("good?bad", bad[0]);
    try testing.expect(bad.len > 1);

    const escaped = try wrapText(arena, "red\x1b[31m now", gridRoom(&font, 40));
    try testing.expectEqual(@as(usize, 1), escaped.len);
    try testing.expect(std.mem.indexOfScalar(u8, escaped[0], 0x1b) == null);
    try testing.expectEqualStrings("red [31m now", escaped[0]);
}

test "a row with something in the right hand column is exactly the width and never past it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const short = try spread(arena, "run_command", "18.2s", Room.grid(20));
    try testing.expectEqual(@as(f32, 20), columnsOf(short));
    try testing.expect(std.mem.endsWith(u8, short, "18.2s"));

    const long = try spread(arena, "x" ** 200, "18.2s", Room.grid(20));
    try testing.expectEqual(@as(f32, 20), columnsOf(long));
    try testing.expect(std.mem.endsWith(u8, long, "18.2s"));

    for ([_]f32{ 0, 1, 4, 5 }) |cols| {
        const cut = try spread(arena, "run_command", "18.2s", Room.grid(cols));
        try testing.expect(columnsOf(cut) <= cols);
    }
    const marker = markerText(false, true);
    const room = Room.grid(narrow_columns - 2);
    const narrow = try spread(arena, "255/255 passed", marker, room);
    try testing.expectEqual(room.width, columnsOf(narrow));
}

test "a plan step reaches the transcript as Chock's own row, with the status spelled out" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const steps = [_]chock_proto.event.PlanStep{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s2", .subject = "measure it on Darwin", .status = .in_progress },
    };
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &steps } });

    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);
    for (h.screen.lines.items) |line| try testing.expectEqual(Voice.chock, line.voice);
    try testing.expectEqualStrings("plan step s1 is now done", h.screen.lines.items[0].text);
    try testing.expectEqualStrings("plan step s2 is now in_progress", h.screen.lines.items[1].text);

    try testing.expectEqual(@as(usize, 2), h.screen.plan.steps.items.len);
}

fn openWide(gpa: std.mem.Allocator, columns: u16, rows: u16) !*Headless {
    return Headless.openSized(gpa, .{
        .cols = columns,
        .rows = rows,
        .xpixel = columns * 8,
        .ypixel = rows * 16,
    });
}

const four_steps = [_]chock_proto.event.PlanStep{
    .{ .id = "s1", .subject = "read the fold", .status = .in_progress },
    .{ .id = "s2", .subject = "measure it on Darwin", .status = .pending },
    .{ .id = "s3", .subject = "write the rows", .status = .pending },
    .{ .id = "s4", .subject = "ship it", .status = .pending },
};

test "one update of four steps is four rows with no sidebar and one row with one" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    try testing.expectEqual(@as(usize, 4), h.screen.lines.items.len);

    h.screen.togglePlan();
    try testing.expect(h.screen.sidebar_open);
    const before = h.screen.lines.items.len;
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &four_steps } });
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len - before);

    try testing.expectEqualStrings(
        "plan: 0 of 4 done, now on \"read the fold\"",
        h.screen.lines.items[before].text,
    );
}

test "a step the agent gave up on keeps a row of its own, because that is an event" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    const before = h.screen.lines.items.len;

    const gone = [_]chock_proto.event.PlanStep{
        .{ .id = "s3", .subject = "write the rows", .status = .abandoned },
    };
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &gone } });
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len - before);
    try testing.expectEqualStrings(
        "plan step s3 was given up: write the rows",
        h.screen.lines.items[before].text,
    );

    const again = h.screen.lines.items.len;
    h.screen.observer().onEvent(3, .{ .plan_update = .{ .steps = &gone } });
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len - again);
}

test "the plan opens beside the transcript at the design width and refuses under it" {
    const gpa = testing.allocator;

    {
        const h = try openWide(gpa, 79, 14);
        defer h.close();
        try testing.expect(h.screen.paint());
        try testing.expect(!h.screen.fitsSidebar());

        h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
        const before = h.screen.lines.items.len;
        h.screen.togglePlan();
        try testing.expect(!h.screen.sidebar_open);
        try testing.expectEqual(@as(f32, 0), h.screen.sidebarWidth());
        try testing.expectEqualStrings(
            "there is no room beside the transcript. A wider display keeps the plan there.",
            h.screen.lines.items[before].text,
        );
        try testing.expectEqualStrings(
            "plan: 0 done, 4 left",
            h.screen.lines.items[before + 1].text,
        );
    }

    {
        const h = try openWide(gpa, 80, 14);
        defer h.close();
        try testing.expect(h.screen.paint());
        try testing.expect(h.screen.fitsSidebar());

        h.screen.togglePlan();
        try testing.expect(h.screen.sidebar_open);
        try testing.expectEqual(@as(f32, sidebar_columns * 8), h.screen.sidebarWidth());
        try testing.expectEqual(
            h.screen.width,
            h.screen.transcriptBandRoom().width + h.screen.sidebarWidth(),
        );
    }
}

test "the plan sidebar is drawn beside the transcript and no transcript row reaches it" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    var long: [400]u8 = undefined;
    @memset(&long, 'X');
    h.screen.say(.agent, &long);
    h.screen.endLine();
    try testing.expect(h.screen.paint());

    const kept: usize = 100 - sidebar_columns;
    var lines = std.mem.splitScalar(u8, try screenText(h), '\n');
    var found_side = false;
    var drawn: usize = 0;
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, 'X')) |at| {
            try testing.expect(at < kept);
            try testing.expect(std.mem.lastIndexOfScalar(u8, line, 'X').? < kept);
        }
        drawn += std.mem.count(u8, line, "X");
        if (line.len <= kept) continue;
        if (std.mem.indexOf(u8, line[kept..], "read the fold") != null) found_side = true;
    }
    try testing.expect(found_side);

    try testing.expectEqual(@as(usize, long.len), drawn);

    var side: std.ArrayList(u8) = .empty;
    defer side.deinit(gpa);
    var each = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (each.next()) |line| {
        if (line.len <= kept) continue;
        try side.appendSlice(gpa, line[kept..]);
        try side.append(gpa, '\n');
    }
    for ([_][]const u8{
        "plan",
        "0/4 done",
        "read the fold",
        "measure it on Dar",
        "write the rows",
        "ship it",
        "now     read",
        "next    measure",
    }) |one| {
        try testing.expect(std.mem.indexOf(u8, side.items, one) != null);
    }
    try testing.expect(std.mem.indexOf(u8, side.items, "measure it on Darwin") == null);

    const wordy = [_]chock_proto.event.PlanStep{.{
        .id = "s5",
        .subject = "a subject far longer than any sidebar could hold, and then some",
        .status = .pending,
    }};
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &wordy } });
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, screenEdge(h)));

    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
}

test "the display follows the window, and asks the device for nothing it was told" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    try testing.expect(h.screen.fixed_size);
    const before = h.screen.width;
    try testing.expect(h.screen.paint());
    try testing.expectEqual(before, h.screen.width);

    const at: phantom.tui.term.Size = .{
        .cols = 100,
        .rows = 14,
        .xpixel = 800,
        .ypixel = 224,
    };
    try testing.expect(!sizeMoved(at, at.viewport(), at.dpr()));

    for ([_]phantom.tui.term.Size{
        .{ .cols = 70, .rows = 14, .xpixel = 560, .ypixel = 224 },
        .{ .cols = 150, .rows = 14, .xpixel = 1200, .ypixel = 224 },
        .{ .cols = 100, .rows = 14, .xpixel = 1600, .ypixel = 448 },
    }) |moved| {
        try testing.expect(sizeMoved(moved, at.viewport(), at.dpr()));
    }
}

fn resizeTo(h: *Headless, columns: u16, rows: u16) !void {
    const one = h.screen.surface.terminalSession().?;
    try one.resize(.{
        .cols = columns,
        .rows = rows,
        .xpixel = columns * 8,
        .ypixel = rows * 16,
    });
    try testing.expect(h.screen.paint());
}

test "a clock pinned to the right hand end is pinned again when the window narrows" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 16);
    defer h.close();

    h.hand.at_ms = (13 * 60 + 45) * 60 * 1000;
    h.screen.describe(.{ .model = "glm4.7-flash", .provider = "local" });
    h.screen.saidByUser("fix the parser");
    h.screen.openTurn();
    try testing.expect(h.screen.paint());

    for ([_][]const u8{ Ui.said_by_user, "glm4.7-flash" }) |head| {
        var found = false;
        for (h.screen.lines.items) |line| {
            if (!std.mem.startsWith(u8, line.text, head)) continue;
            found = true;
            try testing.expectEqualStrings("13:45", line.pinned);
            try testing.expect(std.mem.indexOf(u8, line.text, "13:45") == null);
        }
        try testing.expect(found);
    }

    const wide = try clockedRows(h, "13:45");
    try testing.expectEqual(@as(usize, 2), wide.rows);
    try testing.expectEqual(@as(usize, readable_columns), wide.ends_at);

    try resizeTo(h, 50, 16);
    const narrow = try clockedRows(h, "13:45");
    try testing.expectEqual(@as(usize, 2), narrow.rows);
    try testing.expectEqual(@as(usize, 50), narrow.ends_at);

    try resizeTo(h, 120, 16);
    const back = try clockedRows(h, "13:45");
    try testing.expectEqual(@as(usize, 2), back.rows);
    try testing.expectEqual(wide.ends_at, back.ends_at);

    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |line| {
        const words = std.mem.trim(u8, line, " ");
        try testing.expect(!std.mem.eql(u8, words, "13:45"));
    }
}

test "in pixels the right hand value is a run of its own, pinned at the true edge" {
    // PIXELS mode cannot be driven through tmux, which carries no kitty graphics,
    // so the proportional face is checked here.
    const gpa = testing.allocator;
    const h = try openWide(gpa, 140, 16);
    defer h.close();

    h.screen.surface.terminal.owner.text_metrics = .proportional;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);

    h.hand.at_ms = (13 * 60 + 45) * 60 * 1000;
    h.screen.saidByUser("fix the parser");
    try testing.expect(h.screen.paint());

    const wide = drawnEdgeOf(h, "13:45") orelse return error.NoClockDrawn;
    const measure = h.screen.transcriptRoom().width * h.screen.measure.ratio();
    const glyph = h.screen.measure.advanceOf('5') * h.screen.measure.ratio();
    try testing.expect(wide <= measure);
    try testing.expect(measure - wide <= glyph * 2);

    try resizeTo(h, 60, 16);
    const narrow = drawnEdgeOf(h, "13:45") orelse return error.NoClockDrawn;
    const now = h.screen.transcriptRoom().width * h.screen.measure.ratio();
    try testing.expect(now < measure);
    try testing.expect(narrow < wide);
    try testing.expect(narrow <= now);
    try testing.expect(now - narrow <= glyph * 2);
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
}

fn drawnEdgeOf(h: *Headless, words: []const u8) ?f32 {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| {
                var spelled: [64]u8 = undefined;
                var at: usize = 0;
                var reach: f32 = 0;
                for (t.glyphs) |glyph| {
                    if (at + 4 > spelled.len) break;
                    at += std.unicode.utf8Encode(glyph.cp, spelled[at..]) catch break;
                    if (glyph.x > reach) reach = glyph.x;
                }
                if (!std.mem.eql(u8, spelled[0..at], words)) continue;
                return t.origin.x + reach;
            },
            else => {},
        }
    }
    return null;
}

const Clocked = struct {
    rows: usize = 0,
    ends_at: usize = 0,
};

fn clockedRows(h: *Headless, clock: []const u8) !Clocked {
    var out = Clocked{};
    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |line| {
        const drawn = std.mem.trimEnd(u8, line, " ");
        if (!std.mem.endsWith(u8, drawn, clock)) continue;
        try testing.expect(drawn.len > clock.len);
        const across = std.unicode.utf8CountCodepoints(drawn) catch drawn.len;
        if (across > out.ends_at) out.ends_at = across;
        out.rows += 1;
    }
    return out;
}

test "the help pane over a narrowed transcript is cut to the band and not to the display" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 80, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    try focusTranscript(h);
    try pressKeys(h, "?");
    try testing.expect(h.screen.pane != null);

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "keys") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "0/4 done") != null);

    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
}

test "the lists over a narrowed transcript are cut to the band, and so is the rule" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 80, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });

    const offered = [_]Resumable{.{
        .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        .words = "a session whose words run far past the band this list is drawn in, and then some more",
    }};
    h.screen.picker = &offered;
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.showsRule());
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));

    h.screen.picker = null;
    h.screen.phase = .message;
    h.screen.typed.clearRetainingCapacity();
    try h.screen.typed.appendSlice(gpa, "/");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expect(h.screen.openCompletions(&slots).len != 0);
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, bandEdge(h)));
}

test "a plan longer than the sidebar shows the work that is left and counts what is not there" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var plan = chock_proto.state.Plan{};
    var ids: [20][8]u8 = undefined;
    var subjects: [20][16]u8 = undefined;
    var steps: [20]chock_proto.event.PlanStep = undefined;
    for (&steps, &ids, &subjects, 0..) |*one, *id, *subject, at| {
        one.* = .{
            .id = std.fmt.bufPrint(id, "s{d}", .{at}) catch "s",
            .subject = std.fmt.bufPrint(subject, "step {d}", .{at}) catch "step",
            .status = if (at < 12) .done else if (at == 12) .in_progress else .pending,
        };
    }
    try plan.apply(arena, .{ .steps = &steps });

    const said = try planRows(arena, plan, 6);
    try testing.expectEqual(@as(usize, 6), said.len);
    try testing.expectEqualStrings(" plan   12/20 done", said[0].text);
    try testing.expectEqualStrings(" now     step 12", said[1].text);
    try testing.expectEqual(PlanLine.Tone.now, said[1].tone);
    try testing.expectEqualStrings(" next    step 13", said[2].text);
    try testing.expectEqualStrings(" 12 above, 4 below", said[5].text);
    try testing.expectEqual(PlanLine.Tone.aside, said[5].tone);

    for (0..8) |rows| {
        const few = try planRows(arena, plan, @intCast(rows));
        try testing.expect(few.len <= rows);
    }
    try testing.expectEqual(@as(usize, 0), (try planRows(arena, plan, 0)).len);
    try testing.expectEqualStrings(" plan   12/20 done", (try planRows(arena, plan, 1))[0].text);

    const none = try planRows(arena, .{}, 4);
    try testing.expectEqual(@as(usize, 1), none.len);
    try testing.expectEqualStrings(" plan   nothing yet", none[0].text);

    const h = try openWide(gpa, 100, 8);
    defer h.close();
    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &steps } });
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, screenEdge(h)));
}

test "the sidebar shows what a replayed log folded, and never a second copy of it" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.togglePlan();
    h.screen.replay(1, .{ .plan_update = .{ .steps = &four_steps } });
    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    try testing.expect(h.screen.paint());

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "plan   0/4 done") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "read the fold") != null);
    try testing.expectEqual(@as(usize, 4), h.screen.plan.steps.items.len);
}

test "a sidebar on a display drawn with a real face keeps every row inside its own band" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 180, 20);
    defer h.close();

    h.screen.surface.terminal.owner.text_metrics = .proportional;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.fitsSidebar());

    h.screen.togglePlan();
    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    var said: usize = 0;
    while (said < 30) : (said += 1) {
        h.screen.say(.agent, "a row of the agent's own words, long enough to wrap more than once\n");
    }
    try testing.expect(h.screen.paint());

    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);
    try testing.expect(h.screen.sidebarWidth() > 0);

    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

    const wordy = [_]chock_proto.event.PlanStep{.{
        .id = "s5",
        .subject = "a subject far longer than any sidebar could hold, and then some",
        .status = .pending,
    }};
    h.screen.observer().onEvent(2, .{ .plan_update = .{ .steps = &wordy } });
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastRight(h, screenEdge(h)));

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const words = h.screen.roomFor(.agent);
    for (h.screen.showRows(arena)) |one| try testing.expect(words.holds(one.text));
    try testing.expectApproxEqAbs(
        h.screen.width,
        h.screen.transcriptBandRoom().width + h.screen.sidebarWidth(),
        0.001,
    );
}

test "p opens the plan and p closes it, and only while the transcript has the focus" {
    const gpa = testing.allocator;
    const h = try openWide(gpa, 100, 14);
    defer h.close();

    h.screen.observer().onEvent(1, .{ .plan_update = .{ .steps = &four_steps } });
    try focusTranscript(h);

    try pressKeys(h, "p");
    try testing.expect(h.screen.sidebar_open);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "plan   0/4 done") != null);

    try pressKeys(h, "p");
    try testing.expect(!h.screen.sidebar_open);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "plan   0/4 done") == null);

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    try pressKeys(h, "p");
    try testing.expect(!h.screen.sidebar_open);
    try testing.expectEqualStrings("p", h.screen.typed.items);
}

test "Tab moves the focus between the two regions, and the field starts with it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    try testing.expect(!h.screen.transcript_focused);

    h.screen.surface.terminal.feed("gg");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("gg", h.screen.typed.items);

    h.screen.surface.terminal.feed("\t");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);

    h.screen.scroll_back = 3;
    h.screen.surface.terminal.feed("g");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);
    try testing.expectEqualStrings("gg", h.screen.typed.items);
}

test "the arrows scroll the transcript from either region, and stop at both ends" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.scroll_back);
    try testing.expectEqualStrings("", h.screen.typed.items);

    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    h.screen.surface.terminal.feed("\x1b[B\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    const most = h.screen.maxScrollBack();
    try testing.expect(most > 0);
    var press: usize = 0;
    while (press < most + 8) : (press += 1) h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(most, h.screen.scroll_back);
}

test "a scrolled transcript says how much is above, and says so before it is scrolled when focused" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    try testing.expect(h.screen.paint());

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "rows above") == null);

    h.screen.scrollBy(4);
    try testing.expect(h.screen.paint());
    plain.clearRetainingCapacity();
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "4 rows above") != null);

    h.screen.scroll_back = 0;
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());
    plain.clearRetainingCapacity();
    try h.screen.surface.terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "0 rows above") != null);
}

test "scrolling back shows older rows and not the newest ones" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for ([_][]const u8{ "one\n", "two\n", "three\n", "four\n" }) |said| h.screen.say(.agent, said);

    const bottom = h.screen.visibleRows(arena, 2);
    try testing.expectEqualStrings("three", bottom[0].text);
    try testing.expectEqualStrings("four", bottom[1].text);

    h.screen.scroll_back = 2;
    const back = h.screen.visibleRows(arena, 2);
    try testing.expectEqualStrings("one", back[0].text);
    try testing.expectEqualStrings("two", back[1].text);
}

const a_test_command = "{\"argv\":[\"zig\",\"build\",\"test\"]}";

fn callAndAnswer(h: *Headless, output: []const u8, is_error: bool, took_ms: i64) void {
    const watcher = h.screen.observer();
    const at = h.hand.at_ms;
    watcher.onEvent(1, .{ .tool_call = .{
        .call_id = "c1",
        .tool = "run_command",
        .arguments = a_test_command,
    } });
    h.hand.at_ms = at + took_ms;
    watcher.onEvent(2, .{ .tool_result = .{
        .call_id = "c1",
        .output = output,
        .is_error = is_error,
        .truncated = false,
    } });
}

fn focusTranscript(h: *Headless) !void {
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);
}

test "a tool call's argument is written the way a person reads it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("zig build test", try argumentText(arena, a_test_command));
    try testing.expectEqualStrings("build.zig", try argumentText(arena, "{\"path\":\"build.zig\"}"));
    try testing.expectEqualStrings("TODO src", try argumentText(
        arena,
        "{\"path\":\"src\",\"pattern\":\"TODO\"}",
    ));
    try testing.expectEqualStrings("src/main.zig", try argumentText(
        arena,
        "{\"path\":\"src/main.zig\",\"content\":\"one\\ntwo\\nthree\"}",
    ));
    try testing.expectEqualStrings("not json at all", try argumentText(arena, "not json at all"));
    try testing.expectEqualStrings("{\"a\":1,\"b\":2}", try argumentText(arena, "{\"a\":1,\"b\":2}"));
}

test "the one line of a result leads with the exit status and never with the program's own words" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("exit 128 · the sandbox has no network", try summaryText(
        arena,
        "exit status: 128\nthe sandbox has no network\n",
        true,
        false,
    ));
    try testing.expectEqualStrings("255/255 passed", try summaryText(
        arena,
        "exit status: 0\nBuild Summary: 104/104 steps succeeded\n255/255 passed\n",
        false,
        false,
    ));
    try testing.expectEqualStrings("62144 bytes, file_hash b6336a843ada84a7", try summaryText(
        arena,
        "[chock: 62144 bytes, file_hash b6336a843ada84a7]\nconst std = @import(\"std\");\n",
        false,
        false,
    ));
    const cut = try summaryText(arena, "exit status: 0\nfound 4000 matches\n", false, true);
    try testing.expect(std.mem.indexOf(u8, cut, "truncated") != null);
    try testing.expectEqualStrings("no output", try summaryText(arena, "", false, false));
}

test "a tool result that would fill the transcript is one row, and the whole of it stays one key away" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(gpa);
    try output.appendSlice(gpa, "exit status: 0\n");
    var index: usize = 0;
    while (index < 500) : (index += 1) {
        try output.print(gpa, "line {d} of the build log\n", .{index});
    }
    try output.appendSlice(gpa, "255/255 passed\n");

    callAndAnswer(h, output.items, false, 18_200);

    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);

    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "255/255 passed") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "of the build log") == null);
    try testing.expect(std.mem.indexOf(u8, plain, "show") != null);
    try testing.expect(h.screen.lines.items[1].fold.?.body.len > 1000);
}

test "a finished call carries the outcome glyph, the tool, its argument and how long it took" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 18_200);

    const said = h.screen.lines.items[0].text;
    try testing.expect(std.mem.startsWith(u8, said, "\u{2713} "));
    try testing.expect(std.mem.indexOf(u8, said, "run_command") != null);
    try testing.expect(std.mem.indexOf(u8, said, "zig build test") != null);
    try testing.expectEqualStrings("18.2s", h.screen.lines.items[0].pinned);
    try testing.expect(std.mem.indexOf(u8, said, "18.2s") == null);
    var call_rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    var timed = false;
    while (call_rows.next()) |line| {
        if (std.mem.indexOf(u8, line, "run_command") == null) continue;
        try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, line, " "), "18.2s"));
        timed = true;
    }
    try testing.expect(timed);
    try testing.expect(std.mem.indexOf(u8, said, "\u{22ef}") == null);

    const g = try Headless.open(gpa);
    defer g.close();
    callAndAnswer(g, "exit status: 128\nthe sandbox has no network\n", true, 100);
    try testing.expect(std.mem.startsWith(u8, g.screen.lines.items[0].text, "\u{2717} "));
    try testing.expect(std.mem.indexOf(u8, g.screen.lines.items[1].text, "exit 128") != null);
}

test "a result's note is Chock speaking, above the agent's row and under the rail" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 100, .rows = 12, .xpixel = 800, .ypixel = 192 });
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onEvent(1, .{ .tool_call = .{
        .call_id = "c1",
        .tool = "fetch_url",
        .arguments = "{\"url\":\"https://ziglang.org/\"}",
    } });
    watcher.onEvent(2, .{ .tool_result = .{
        .call_id = "c1",
        .output = "refused, which you cannot write and the user can.",
        .is_error = true,
        .truncated = false,
        .note = "add a rule to chock.zon to read ziglang.org.",
    } });

    try testing.expectEqual(@as(usize, 3), h.screen.lines.items.len);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[1].voice);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[1].text, "add a rule") != null);

    try testing.expectEqual(Voice.agent, h.screen.lines.items[2].voice);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[2].text, "you cannot write") != null);

    try testing.expectEqualStrings("\u{2502} ", Voice.chock.prefix());
    try testing.expectEqualStrings("  ", Voice.agent.prefix());

    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    var railed = false;
    var indented = false;
    while (rows.next()) |line| {
        if (std.mem.startsWith(u8, line, "\u{2502} add a rule")) railed = true;
        if (std.mem.startsWith(u8, line, "  refused, which you")) indented = true;
    }
    try testing.expect(railed);
    try testing.expect(indented);
}

test "an ordinary result adds no row of Chock's own" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 100);
    try testing.expectEqual(@as(usize, 2), h.screen.lines.items.len);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);
}

test "a message the person typed is in the transcript, in Chock's voice at column 0" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = h.threaded.io();
    h.screen.keys.?.device.in = try pressesToRead(&tmp, "fix the parser\r");
    defer h.screen.keys.?.device.in.close(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const asked = try h.screen.askForMessage(arena_state.allocator());
    try testing.expectEqualStrings("fix the parser", asked.message);

    var said: ?usize = null;
    for (h.screen.lines.items, 0..) |line, at| {
        if (std.mem.eql(u8, line.text, "fix the parser")) said = at;
    }
    try testing.expect(said != null);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[said.?].voice);
    try testing.expect(said.? > 0);
    try testing.expect(std.mem.startsWith(
        u8,
        h.screen.lines.items[said.? - 1].text,
        Ui.said_by_user,
    ));

    try testing.expect(h.screen.paint());
    const shown = try screenText(h);
    var rows = std.mem.splitScalar(u8, shown, '\n');
    var found = false;
    while (rows.next()) |line| {
        if (std.mem.indexOf(u8, line, "fix the parser") == null) continue;
        found = true;
        try testing.expect(std.mem.startsWith(u8, line, Voice.chock.prefix()));
    }
    try testing.expect(found);
}

test "a message that arrived on standard input is in the transcript too" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    h.screen.phase = .message;
    h.screen.prime("read the log and tell me what broke");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const asked = try h.screen.askForMessage(arena_state.allocator());
    try testing.expectEqualStrings("read the log and tell me what broke", asked.message);

    var found = false;
    for (h.screen.lines.items) |line| {
        if (!std.mem.eql(u8, line.text, "read the log and tell me what broke")) continue;
        found = true;
        try testing.expectEqual(Voice.chock, line.voice);
    }
    try testing.expect(found);

    try testing.expect(!h.screen.keys.?.raw);
    try testing.expectEqual(Ui.Phase.session, h.screen.phase);
}

test "a log folded back in puts the words of a finished turn on the screen, and the observer sees none of it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.describe(.{ .model = "a-model", .provider = "local" });
    const before = h.recorder.events;

    h.screen.replay(1, .{ .message = .{
        .role = .user,
        .content = &.{.{ .text = "fix the parser" }},
    } });
    h.screen.replay(2, .{ .message = .{
        .role = .assistant,
        .content = &.{.{ .text = "the parser is where it fails" }},
    } });

    var said_by_person = false;
    var said_by_model = false;
    for (h.screen.lines.items) |line| {
        if (std.mem.eql(u8, line.text, "fix the parser")) {
            said_by_person = true;
            try testing.expectEqual(Voice.chock, line.voice);
        }
        if (std.mem.eql(u8, line.text, "the parser is where it fails")) {
            said_by_model = true;
            try testing.expectEqual(Voice.agent, line.voice);
        }
    }
    try testing.expect(said_by_person);
    try testing.expect(said_by_model);

    try testing.expectEqual(before, h.recorder.events);
}

test "a compaction in a log folded back in is the rule row it is live, with the summary behind it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.replay(7, .{ .compaction = .{
        .from_id = 3,
        .through_id = 40,
        .summary = "the parser was rewritten",
        .kept_ranges = &.{},
        .model_alias = "a-model",
    } });

    var folded = false;
    for (h.screen.lines.items) |line| {
        if (std.mem.indexOf(u8, line.text, "events 3 to 40 folded") == null) continue;
        folded = true;
        try testing.expectEqual(Voice.chock, line.voice);
        try testing.expectEqual(Fold.Kind.compaction, line.fold.?.kind);
        try testing.expectEqualStrings("the parser was rewritten", line.fold.?.body);
    }
    try testing.expect(folded);
}

test "a log with more turns than the display keeps leaves the newest of them" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const turns = Ui.kept_lines + 50;
    for (0..turns) |at| {
        var buffer: [64]u8 = undefined;
        const said = try std.fmt.bufPrint(&buffer, "turn {d}", .{at});
        h.screen.replay(@intCast(at + 1), .{ .message = .{
            .role = .assistant,
            .content = &.{.{ .text = said }},
        } });
    }

    try testing.expect(h.screen.lines.items.len <= Ui.kept_lines);

    var has_newest = false;
    var has_oldest = false;
    for (h.screen.lines.items) |line| {
        if (std.mem.eql(u8, line.text, "turn 0")) has_oldest = true;
        if (std.mem.eql(u8, line.text, "turn 561")) has_newest = true;
    }
    try testing.expect(has_newest);
    try testing.expect(!has_oldest);
}

test "a fold of the log draws no frame, and the first frame after it shows what it wrote" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const quiet = h.sink.bytes.items.len;
    for (0..20) |at| {
        h.screen.replay(@intCast(at * 2 + 1), .{ .message = .{
            .role = .user,
            .content = &.{.{ .text = "a question that came before" }},
        } });
        h.screen.replay(@intCast(at * 2 + 2), .{ .message = .{
            .role = .assistant,
            .content = &.{.{ .text = "a turn that came before" }},
        } });
    }
    try testing.expectEqual(quiet, h.sink.bytes.items.len);

    try testing.expect(h.screen.lines.items.len != 0);

    h.screen.observer().onPiece(.{ .text = "" });
    try testing.expect(std.mem.indexOf(
        u8,
        h.sink.bytes.items[quiet..],
        "a turn that came before",
    ) != null);
}

test "a device that is not a terminal is never asked for raw mode" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expect(!(h.device.isTty(h.threaded.io()) catch true));
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(h.screen.keys.?.was == null);
    try testing.expect(h.screen.keys.?.held == null);
    try testing.expect(h.screen.paint());
}

test "a flush of a frame reaches the descriptor and does not stop at the standard output buffer" {
    const gpa = testing.allocator;
    var sink = Sink{ .gpa = gpa };
    defer sink.deinit();

    var buffer: [4096]u8 = undefined;
    var held = sink.tapWith(&buffer);

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    tty.useStreams(io, &held.writer, null);
    defer tty.useStreams(io, null, null);

    var frames = Frames{};
    try frames.writer.writeAll("\x1b[c");
    try testing.expectEqual(@as(usize, 0), sink.bytes.items.len);

    try frames.writer.flush();
    try testing.expectEqualStrings("\x1b[c", sink.bytes.items);
}

test "a result's summary sits at the agent's indent and carries no rail" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 18_200);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[0].voice);
    try testing.expectEqual(Voice.agent, h.screen.lines.items[1].voice);

    const plain = try screenText(h);
    var rows = std.mem.splitScalar(u8, plain, '\n');
    var found = false;
    while (rows.next()) |line| {
        if (std.mem.indexOf(u8, line, "255/255 passed") == null) continue;
        found = true;
        try testing.expect(std.mem.startsWith(u8, line, "  "));
        try testing.expect(std.mem.indexOf(u8, line, "\u{2502}") == null);
    }
    try testing.expect(found);
}

test "Space on the focused row opens the result and Space again closes it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    callAndAnswer(h, "exit status: 0\nthe first line of the log\n255/255 passed\n", false, 18_200);
    try focusTranscript(h);

    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") == null);

    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.lines.items[1].fold.?.open);
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") != null);

    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(!h.screen.lines.items[1].fold.?.open);
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") == null);
}

test "the arrows step the focus between the rows that can be opened" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onEvent(1, .{ .tool_call = .{
        .call_id = "c1",
        .tool = "read_file",
        .arguments = "{\"path\":\"build.zig\"}",
    } });
    watcher.onEvent(2, .{ .tool_result = .{
        .call_id = "c1",
        .output = "[chock: 12 bytes]\nthe older body\n",
        .is_error = false,
        .truncated = false,
    } });
    callAndAnswer(h, "exit status: 0\nthe newer body\n", false, 100);
    try focusTranscript(h);

    try testing.expect(h.screen.cursor == null);
    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 4), h.screen.cursor.?);

    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.cursor.?);

    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.lines.items[1].fold.?.open);
    try testing.expect(!h.screen.lines.items[4].fold.?.open);

    h.screen.surface.terminal.feed("\x1b[A\x1b[A\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.cursor.?);
}

test "the model's reasoning is folded to its size and is never dropped" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const watcher = h.screen.observer();
    watcher.onPiece(.{ .reasoning = "the build file names a test step. " ** 64 });
    watcher.onPiece(.{ .text = "I will run it.\n" });

    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[0].text, "of reasoning") != null);
    try testing.expect(std.mem.indexOf(u8, h.screen.lines.items[0].text, "KB") != null);
    try testing.expectEqualStrings("I will run it.", h.screen.lines.items[1].text);

    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "of reasoning") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "names a test step") == null);
    try testing.expect(h.screen.lines.items[0].fold.?.body.len > 1000);
}

test "a compaction is a rule row saying what was folded, with the summary behind it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onEvent(9, .{ .compaction = .{
        .summary = "the agent read the parser and found the fault in the lexer",
        .from_id = 1,
        .through_id = 41,
        .kept_ranges = &.{},
        .model_alias = "glm4.7",
    } });

    try testing.expectEqual(Voice.chock, h.screen.lines.items[0].voice);
    const said = h.screen.lines.items[0].text;
    try testing.expect(std.mem.startsWith(u8, said, "\u{2500}\u{2500} "));
    try testing.expect(std.mem.indexOf(u8, said, "events 1 to 41 folded") != null);
    try testing.expect(std.mem.indexOf(u8, said, "The log keeps them") != null);

    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "events 1 to 41 folded") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "found the fault") == null);
    try testing.expect(std.mem.indexOf(u8, plain, "show") != null);
}

test "a session at the design width reads as the design draws it" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 60, .rows = 10, .xpixel = 480, .ypixel = 160 });
    defer h.close();

    h.screen.describe(.{
        .project = "chock",
        .model = "glm4.7-flash",
        .provider = "local",
        .layers = &.{.{ .name = "seccomp", .state = .on }},
    });
    h.hand.at_ms = (12 * 60 + 4) * 60 * 1000;

    const watcher = h.screen.observer();
    watcher.onNotice("Chock copied 12 files from your working tree.");
    watcher.onPiece(.{ .reasoning = "the build file names a test step. " ** 64 });
    watcher.onPiece(.{ .text = "The build file names a test step. I will run it.\n" });
    callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 18_200);

    try testing.expectEqualStrings(
        \\ chock  chock  glm4.7-flash  local  ✓ seccomp
        \\│ Chock copied 12 files from your working tree.
        \\
        \\  glm4.7-flash · local                                 12:04
        \\  2.1 KB of reasoning                                 ▶ show
        \\  The build file names a test step. I will run it.
        \\
        \\  ✓ run_command  zig build test                        18.2s
        \\  255/255 passed                                      ▶ show
        \\ >
        \\
    , try screenText(h));
}

test "a subagent takes one row and its own turns never appear in this transcript" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.observer().onEvent(4, .{ .session_spawn = .{
        .child_session = "s-2",
        .child_agent_kind = "reviewer",
        .reason = "it reads the test and reports back. It does not write.",
    } });

    try testing.expectEqual(@as(usize, 1), h.screen.lines.items.len);
    try testing.expectEqual(Voice.chock, h.screen.lines.items[0].voice);
    const plain = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, plain, "started a subagent, reviewer") != null);
    try testing.expect(std.mem.indexOf(u8, plain, "It does not write") == null);
    try testing.expectEqualStrings(
        "it reads the test and reports back. It does not write.",
        h.screen.lines.items[0].fold.?.body,
    );
}

test "a line whose first word is not a command exactly is a message, paths included" {
    for ([_][]const u8{
        "/home/ross/chock/src/main.zig is broken",
        "/usr/bin/zig is the wrong version",
        "/etc/nix/nix.conf needs a setting",
        "/tmp is full",
        "/planning the release",
        "/help me understand this",
        "/plan the release with me",
        "look at /plan for the list",
        "",
        "no slash at all",
    }) |line| try testing.expect(commandOf(line) == null);

    try testing.expectEqual(Command.plan, commandOf("/plan").?);
    try testing.expectEqual(Command.plan, commandOf("  /plan  ").?);
    try testing.expectEqual(Command.help, commandOf("/help").?);
    try testing.expectEqual(Command.usage, commandOf("/usage").?);
}

test "the completion list opens on a prefix and closes the moment the line stops being one" {
    var slots: [Command.all.len]Command = undefined;

    try testing.expectEqual(@as(usize, Command.all.len), completions("/", &slots).len);
    try testing.expectEqual(@as(usize, 1), completions("/h", &slots).len);
    try testing.expectEqual(Command.help, completions("/h", &slots)[0]);
    try testing.expectEqual(@as(usize, 1), completions("/pl", &slots).len);

    try testing.expectEqual(@as(usize, 0), completions("/ho", &slots).len);
    try testing.expectEqual(@as(usize, 0), completions("/home/ross", &slots).len);
    try testing.expectEqual(@as(usize, 0), completions("fix the parser", &slots).len);
    try testing.expectEqual(@as(usize, 0), completions("", &slots).len);

    try testing.expectEqual(@as(usize, 0), completions("/plan now", &slots).len);
}

test "a slash command is answered in the transcript and never becomes a message" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("/plan\r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expectEqualStrings("/plan", h.screen.typed.items);
    try testing.expect(commandOf(h.screen.typed.items) != null);

    h.screen.runCommand(.plan);
    try testing.expect(h.screen.lines.items.len != 0);
    for (h.screen.lines.items) |line| {
        try testing.expectEqual(Voice.chock, line.voice);
        try testing.expect(std.mem.indexOf(u8, line.text, "/plan") == null);
    }
    try testing.expectEqualStrings(
        "the agent has written no plan",
        h.screen.lines.items[h.screen.lines.items.len - 1].text,
    );
}

test "Enter on an open list runs what is chosen, not the letters that were typed" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("/pl");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expectEqual(@as(usize, 1), h.screen.openCompletions(&slots).len);

    h.screen.surface.terminal.feed("\r");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("/plan", h.screen.typed.items);
    try testing.expectEqual(Command.plan, commandOf(h.screen.typed.items).?);
}

test "the arrows move through the list while it is open, and scroll the transcript when it is not" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("/");
    try testing.expect(h.screen.paint());
    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.completion_selected);
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    h.screen.surface.terminal.feed("z");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expectEqual(@as(usize, 0), h.screen.openCompletions(&slots).len);
    try testing.expectEqualStrings("/z", h.screen.typed.items);

    h.screen.surface.terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.scroll_back);
}

test "the question mark opens the same pane the command does, and only where it is not a letter" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    h.screen.surface.terminal.feed("?");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("?", h.screen.typed.items);
    try testing.expect(h.screen.pane == null);

    h.screen.surface.terminal.feed("\t?");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);
    try testing.expect(h.screen.pane != null);
    try testing.expectEqual(Pane.Kind.keys, h.screen.pane.?.kind);

    try testing.expectEqual(@as(usize, 0), h.screen.lines.items.len);

    h.screen.surface.terminal.feed("?");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.pane == null);

    h.screen.runCommand(.help);
    try testing.expect(h.screen.pane != null);
    try testing.expectEqual(Pane.Kind.keys, h.screen.pane.?.kind);
    try testing.expectEqual(@as(usize, 0), h.screen.lines.items.len);
}

fn paneRowAsDrawn(
    arena: std.mem.Allocator,
    h: *Headless,
    words: []const u8,
) ![]const u8 {
    const cut = try visibleLine(
        arena,
        try std.fmt.allocPrint(arena, " {s}", .{words}),
        h.screen.screenRoom(),
    );
    return std.mem.trimEnd(u8, cut, " ");
}

test "the pane can be read in full on a screen far too short for it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const all = try Ui.helpRows(arena_state.allocator());
    try testing.expect(all.len > 8);

    h.screen.openHelp();
    try testing.expect(h.screen.paint());

    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(gpa);
    var presses: usize = 0;
    while (presses < all.len * 2) : (presses += 1) {
        try seen.appendSlice(gpa, try screenText(h));
        const before = h.screen.pane.?.at;
        try testing.expect(h.screen.onPaneKey(.{ .keysym = .down }));
        if (h.screen.pane.?.at == before) break;
        try testing.expect(h.screen.paint());
    }

    for (all) |one| {
        if (one.len == 0) continue;
        const drawn = try paneRowAsDrawn(arena_state.allocator(), h, one);
        try testing.expect(std.mem.indexOf(u8, seen.items, drawn) != null);
    }

    const last = try paneRowAsDrawn(arena_state.allocator(), h, all[all.len - 1]);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), last) != null);
}

test "the pane is a surface over the transcript and leaves every other region alone" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.describe(.{ .project = "chock", .model = "a-model" });
    try testing.expect(h.screen.paint());
    const before = try gpa.dupe(u8, try screenText(h));
    defer gpa.free(before);
    try testing.expect(std.mem.indexOf(u8, before, "chock") != null);

    h.screen.openHelp();
    try testing.expect(h.screen.paint());
    const after = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, after, "chock") != null);
    try testing.expect(std.mem.indexOf(u8, after, "a-model") != null);
    try testing.expect(std.mem.indexOf(u8, after, ">") != null);
    try testing.expect(std.mem.indexOf(u8, after, "Esc closes this") != null);
}

test "the pane takes the arrows and the two keys that close it, and refuses the rest" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.openHelp();
    try testing.expect(h.screen.paint());

    try testing.expect(!h.screen.onPaneKey(.{ .keysym = .tab }));
    try testing.expect(!h.screen.onPaneKey(.{ .keysym = .no_symbol, .text = "g" }));
    try testing.expect(h.screen.pane != null);

    try testing.expect(h.screen.onPaneKey(.{ .keysym = .down }));
    try testing.expectEqual(@as(u16, 1), h.screen.pane.?.at);
    try testing.expect(h.screen.onPaneKey(.{ .keysym = .up }));
    try testing.expectEqual(@as(u16, 0), h.screen.pane.?.at);
    try testing.expect(h.screen.onPaneKey(.{ .keysym = .up }));
    try testing.expectEqual(@as(u16, 0), h.screen.pane.?.at);

    try testing.expect(h.screen.onPaneKey(.{ .keysym = .no_symbol, .text = "?" }));
    try testing.expect(h.screen.pane == null);

    h.screen.openHelp();
    try testing.expect(h.screen.onPaneKey(.{ .keysym = .escape }));
    try testing.expect(h.screen.pane == null);
}

test "a command is never read as a message, and a message that looks like one still is" {
    try testing.expectEqual(Command.plan, answerFor("/plan").command);
    try testing.expectEqual(Command.help, answerFor("  /help  ").command);
    try testing.expectEqual(Command.usage, answerFor("/usage").command);

    for ([_][]const u8{
        "/home/ross/chock/src/main.zig is broken",
        "/help me understand this",
        "/plan the release with me",
        "fix the parser",
        "look at /plan",
    }) |line| {
        try testing.expectEqualStrings(
            std.mem.trim(u8, line, " \t\r\n"),
            answerFor(line).message,
        );
    }

    try testing.expectEqual(Answer.nothing, answerFor(""));
    try testing.expectEqual(Answer.nothing, answerFor("   \t "));
}

test "a session that cannot be taken up says so on its own row, and one that can says nothing" {
    try testing.expectEqualStrings("", Ui.refusalFor(.ready, false));

    const kept = Ui.refusalFor(.ready, true);
    try testing.expect(kept.len != 0);
    try testing.expect(std.mem.indexOf(u8, kept, "chock workspace") != null);

    for ([_]sessions_cmd.Readiness{
        .running,
        .no_such_session,
        .nothing_to_carry_on,
        .unknown,
    }) |ready| {
        try testing.expect(Ui.refusalFor(ready, false).len != 0);
        try testing.expect(Ui.refusalFor(ready, true).len != 0);
    }
}

test "the picker takes only a session that can be taken, and stays open on one that cannot" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const offered = [_]Resumable{
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV", .words = "one", .refusal = "another process is running it" },
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAW", .words = "two" },
    };
    h.screen.picker = &offered;
    h.screen.picked = 0;

    h.screen.takePicked();
    try testing.expect(h.screen.taken == null);
    try testing.expect(h.screen.picker != null);
    try testing.expect(!h.screen.submitted);
    try testing.expect(std.mem.indexOf(
        u8,
        h.screen.lines.items[h.screen.lines.items.len - 1].text,
        "another process is running it",
    ) != null);

    h.screen.picked = 1;
    h.screen.takePicked();
    try testing.expectEqualStrings("01ARZ3NDEKTSV4RRFFQ69G5FAW", h.screen.taken.?);
    try testing.expect(h.screen.picker == null);
    try testing.expect(h.screen.submitted);
}

test "the picker takes the arrows before the completion list and before the transcript" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var index: usize = 0;
    while (index < 20) : (index += 1) h.screen.say(.agent, "a row\n");
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    h.screen.surface.focusLast();

    const offered = [_]Resumable{
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV", .words = "one" },
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAW", .words = "two" },
    };
    h.screen.picker = &offered;

    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.picked);
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);
    try testing.expectEqual(@as(usize, 0), h.screen.completion_selected);

    h.screen.surface.terminal.feed("\x1b[B\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.picked);
}

const a_question = Approval{
    .request_id = 7,
    .action = "policy.widen",
    .summary = "let this session out of its own promise about \"git.push\"",
    .reason = "the fix passes here and I want CI to run it",
    .chain = "you \u{25b8} glm4.7-flash \u{25b8} fixer",
    .depth = 2,
    .detail = "+ src/main.zig 3\n- test/slow.zig 12\n",
    .left_ms = 42 * std.time.ms_per_s,
};

fn askIn(h: *Headless, one: Approval) !void {
    try testing.expect(h.screen.paint());
    h.screen.showApproval(one);
    takesKeys(h);
    try testing.expect(h.screen.paint());
}

fn takesKeys(h: *Headless) void {
    h.screen.keys.?.raw = true;
}

fn pressKeys(h: *Headless, keys: []const u8) !void {
    h.screen.surface.terminal.feed(keys);
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.paint());
}

fn settleOut(h: *Headless) !void {
    var left: u8 = settle_looks;
    while (left > 0) : (left -= 1) {
        try testing.expectEqual(Look.waiting, h.screen.awaitAnswer(50));
    }
}

test "the approval region is absent until a question arrives, and it takes the keyboard when it does" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expectEqual(@as(u16, 0), h.screen.approvalRows());
    try testing.expectEqual(@as(u16, 0), split(h.screen.rows, h.screen.approvalRows()).approval);
    try testing.expect(!h.screen.approval_focused);

    try askIn(h, a_question);
    try testing.expect(h.screen.approvalRows() != 0);
    try testing.expect(h.screen.approval_focused);

    h.screen.clearApproval();
    try testing.expectEqual(@as(u16, 0), h.screen.approvalRows());
    try testing.expect(!h.screen.approval_focused);
}

test "the region is a raised surface of its own, between the transcript and the input" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const colors = phantom.ColorScheme.tokyoNight();
    const panel = phantom.backend.cell_grid.Rgb.fromColor(colors.bg_medium);
    const base = phantom.backend.cell_grid.Rgb.fromColor(colors.bg);
    const recess = phantom.backend.cell_grid.Rgb.fromColor(colors.bg_dark);
    try testing.expect(!std.meta.eql(panel, base));
    try testing.expect(!std.meta.eql(panel, recess));

    const parts = split(h.screen.rows, h.screen.approvalRows());
    const grid = &h.screen.surface.terminal.grid;
    var at: u16 = parts.header + parts.transcript;
    while (at < parts.header + parts.transcript + parts.approval) : (at += 1) {
        try testing.expectEqual(panel, grid.cellAt(0, at).?.bg);
    }
    try testing.expectEqual(recess, grid.cellAt(0, h.screen.rows - 1).?.bg);
}

test "y approves and n refuses, and only after the region has settled" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    h.screen.surface.terminal.feed("y");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);

    try settleOut(h);
    try pressKeys(h, "y");
    try testing.expectEqual(Answered.approved, h.screen.approval_answer.?);
    try testing.expectEqual(Look{ .answered = .approved }, h.screen.awaitAnswer(50));
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);

    h.screen.clearApproval();
    try askIn(h, a_question);
    try settleOut(h);
    try pressKeys(h, "n");
    try testing.expectEqual(Look{ .answered = .refused }, h.screen.awaitAnswer(50));
}

test "Enter and Esc answer nothing, and neither does a letter that is not one of the four" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);
    try settleOut(h);

    for ([_][]const u8{ "\r", "\n", "\x1b", "q", "Y", "N", " ", "s", "S" }) |key| {
        h.screen.surface.terminal.feed(key);
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
        try testing.expect(h.screen.approval != null);
    }

    // Escape clears the focus in phantom's own traversal rules, before any
    // listener is offered it.
    try testing.expectEqual(Look.waiting, h.screen.awaitAnswer(50));
    try testing.expect(h.screen.approval_focused);
    try pressKeys(h, "y");
    try testing.expectEqual(Answered.approved, h.screen.approval_answer.?);
}

test "d opens the effect at length and w opens the chain, and answering stays available in both" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const question_high = h.screen.approvalRows();
    try pressKeys(h, "d");
    try testing.expectEqual(Approval.View.diff, h.screen.approval.?.view);
    try testing.expect(h.screen.approvalRows() >= question_high);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "test/slow.zig 12") != null);

    try pressKeys(h, "d");
    try testing.expectEqual(Approval.View.question, h.screen.approval.?.view);

    try pressKeys(h, "w");
    try testing.expectEqual(Approval.View.why, h.screen.approval.?.view);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "fixer") != null);

    try settleOut(h);
    try pressKeys(h, "y");
    try testing.expectEqual(Answered.approved, h.screen.approval_answer.?);
}

test "the region writes its own keys, so nobody has to remember them under a deadline" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, approvalKeys(h.screen.screenRoom())) != null);

    for ([_][]const u8{ approval_keys, approval_keys_narrow }) |named| {
        for ([_][]const u8{ "[y]", "[n]", "[d]", "[w]" }) |key| {
            try testing.expect(std.mem.indexOf(u8, named, key) != null);
        }
        try testing.expect(columnsOf(named) <= narrow_columns);
    }
    try testing.expectEqualStrings(approval_keys, approvalKeys(Room.grid(80)));
    try testing.expectEqualStrings(approval_keys_narrow, approvalKeys(Room.grid(50)));

    h.screen.approval.?.view = .diff;
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(
        u8,
        try screenText(h),
        approvalKeys(h.screen.screenRoom()),
    ) != null);
}

test "a display that cannot take a key says which command answers, and shows no key that does nothing" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.resumable("/tmp/sessions", "01ARZ3NDEKTSV4RRFFQ69G5FAV");

    try testing.expect(h.screen.paint());
    h.screen.showApproval(a_question);
    try testing.expect(!h.screen.answersKeys());
    try testing.expect(h.screen.paint());

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "chock approve") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "[y]") == null);
    try testing.expect(std.mem.indexOf(u8, shown, "policy.widen") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "0:42") != null);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const wide = elsewhereText(arena, id, Room.grid(80));
    try testing.expect(std.mem.endsWith(u8, wide, id));
    try testing.expect(columnsOf(wide) <= 80);
    const narrow = elsewhereText(arena, id, Room.grid(40));
    try testing.expect(std.mem.indexOf(u8, narrow, id) == null);
    try testing.expect(std.mem.endsWith(u8, narrow, "chock approve"));
    try testing.expect(columnsOf(narrow) <= 40);
}

test "the four facts that may never drop are on the screen at 80 columns and at 50" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    try askIn(h, a_question);

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "policy.widen") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "0:42") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "fixer") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "depth 2") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "the fix passes here") != null);
}

test "the agent's own words stay between the rows Chock owns and cannot reach them" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var forged = a_question;
    forged.summary = "APPROVAL  git.push   9:99";
    forged.reason = "[y] approve  [n] refuse";
    try askIn(h, forged);

    var rows: std.ArrayList([]const u8) = .empty;
    defer rows.deinit(gpa);
    const shown = try screenText(h);
    var walk = std.mem.splitScalar(u8, shown, '\n');
    while (walk.next()) |line| try rows.append(gpa, line);

    const parts = split(h.screen.rows, h.screen.approvalRows());
    const first = parts.header + parts.transcript;
    try testing.expect(std.mem.startsWith(u8, rows.items[first], " APPROVAL  policy.widen"));
    try testing.expectEqualStrings(
        approvalKeys(h.screen.screenRoom()),
        rows.items[first + parts.approval - 1],
    );
    try testing.expect(std.mem.indexOf(u8, shown, "   APPROVAL  git.push") != null);
}

test "a control byte in a diff the agent wrote never reaches a cell" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var nasty = a_question;
    nasty.detail = "+ ok\x1b[2J\x1b[H painted over\n";
    try askIn(h, nasty);
    h.screen.approval.?.view = .diff;
    try testing.expect(h.screen.paint());

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, shown, "painted over") != null);
}

test "the countdown is minutes and seconds, and it never reads as time that is left when none is" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings("0:42", try countdownText(arena, 42 * std.time.ms_per_s));
    try testing.expectEqualStrings("5:00", try countdownText(arena, 5 * std.time.ms_per_min));
    try testing.expectEqualStrings("0:06", try countdownText(arena, 5_200));
    try testing.expectEqualStrings("0:01", try countdownText(arena, 900));
    try testing.expectEqualStrings("0:00", try countdownText(arena, 0));
    try testing.expectEqualStrings("0:00", try countdownText(arena, -4000));
}

const Settings = struct {
    written: [8]std.posix.termios = undefined,
    count: usize = 0,

    var only: Settings = .{};

    fn apply(
        _: std.posix.fd_t,
        _: std.posix.TCSA,
        settings: std.posix.termios,
    ) std.posix.TermiosSetError!void {
        if (only.count < only.written.len) only.written[only.count] = settings;
        only.count += 1;
    }

    fn now() std.posix.termios {
        return only.written[only.count - 1];
    }
};

fn holdsTerminal(h: *Headless) void {
    Settings.only = .{};

    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ECHONL = true;
    was.lflag.ICANON = true;
    was.lflag.ISIG = true;

    var held = was;
    held.lflag.ECHO = false;
    held.lflag.ECHONL = false;
    held.lflag.ICANON = false;
    held.lflag.ISIG = false;

    h.screen.apply_termios = Settings.apply;
    h.screen.keys.?.was = was;
    h.screen.keys.?.held = held;
    h.screen.keys.?.raw = true;
}

test "a turn runs with the echo off, and with the signal key given back" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    h.screen.endInput();

    try testing.expectEqual(@as(usize, 1), Settings.only.count);
    try testing.expect(!Settings.now().lflag.ECHO);
    try testing.expect(!Settings.now().lflag.ECHONL);
    try testing.expect(Settings.now().lflag.ISIG);
    try testing.expect(Settings.now().lflag.ICANON);
    try testing.expect(!h.screen.keys.?.raw);

    h.screen.takeKeys(.FLUSH);
    try testing.expectEqual(@as(usize, 2), Settings.only.count);
    try testing.expect(!Settings.now().lflag.ECHO);
    try testing.expect(!Settings.now().lflag.ISIG);
    try testing.expect(h.screen.keys.?.raw);
}

test "the terminal is given back exactly as it was found, and only when the display goes" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    h.screen.endInput();
    try testing.expect(!Settings.now().lflag.ECHO);

    h.stop();
    try testing.expect(Settings.now().lflag.ECHO);
    try testing.expect(Settings.now().lflag.ECHONL);
    try testing.expect(Settings.now().lflag.ISIG);
    try testing.expect(Settings.now().lflag.ICANON);
}

test "only the two bits that echo are taken out of a terminal's own settings" {
    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ECHONL = true;
    was.lflag.ICANON = true;
    was.lflag.ISIG = true;
    was.lflag.IEXTEN = true;
    was.oflag.OPOST = true;

    const quiet = quietOf(was);
    try testing.expect(!quiet.lflag.ECHO);
    try testing.expect(!quiet.lflag.ECHONL);
    try testing.expect(quiet.lflag.ICANON);
    try testing.expect(quiet.lflag.ISIG);
    try testing.expect(quiet.lflag.IEXTEN);
    try testing.expect(quiet.oflag.OPOST);

    var quiet_terminal = was;
    quiet_terminal.lflag.ISIG = false;
    try testing.expect(!quietOf(quiet_terminal).lflag.ISIG);
}

const Raises = struct {
    count: usize = 0,
    raw_at_raise: bool = false,
    screen: ?*Ui = null,
    signals: [4]std.posix.SIG = @splat(.KILL),

    var only: Raises = .{};

    fn raise(sig: std.posix.SIG) std.posix.RaiseError!void {
        if (only.count < only.signals.len) only.signals[only.count] = sig;
        only.count += 1;
        if (only.screen) |one| {
            if (one.keys) |keys| {
                if (keys.raw) only.raw_at_raise = true;
            }
        }
    }
};

test "a Ctrl-C at a question puts the device back first, and then raises the signal once per press" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    Raises.only = .{ .screen = h.screen };
    h.screen.raise = Raises.raise;
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try askIn(h, a_question);
    const io = h.threaded.io();
    h.screen.keys.?.device.in = try pressesToRead(&tmp, "\x03\x03");
    defer h.screen.keys.?.device.in.close(io);

    try testing.expectEqual(Look.canceled, h.screen.awaitAnswer(50));
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(!Raises.only.raw_at_raise);
    try testing.expectEqual(@as(usize, 2), Raises.only.count);
    try testing.expectEqual(std.posix.SIG.INT, Raises.only.signals[0]);
    try testing.expectEqual(std.posix.SIG.INT, Raises.only.signals[1]);
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
}

fn pressesToRead(tmp: *testing.TmpDir, bytes: []const u8) !std.Io.File {
    const io = testing.io;
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path);
    var name: [std.fs.max_path_bytes + 8]u8 = undefined;
    const file = try std.fmt.bufPrint(&name, "{s}/keys", .{path[0..len]});
    {
        var handle = try std.Io.Dir.createFileAbsolute(io, file, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, bytes);
    }
    return std.Io.Dir.openFileAbsolute(io, file, .{});
}

test "a Ctrl-C in an open question is counted as a press and not as a letter" {
    try testing.expectEqual(@as(usize, 0), ctrlCPresses("ynd"));
    try testing.expectEqual(@as(usize, 1), ctrlCPresses("\x03"));
    try testing.expectEqual(@as(usize, 1), ctrlCPresses("y\x03n"));
    try testing.expectEqual(@as(usize, 2), ctrlCPresses("\x03\x03"));
    try testing.expectEqual(@as(usize, 0), ctrlCPresses("\x1b[A\x1b[B\x1b[1;5D"));
}

fn screenText(h: *Headless) ![]const u8 {
    h.plain.clearRetainingCapacity();
    try h.screen.surface.terminal.grid.writePlain(h.gpa, &h.plain);
    return h.plain.items;
}

const ask_everything =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

const Drove = struct {
    outcome: ?chock_broker.Broker.Outcome,
    answers: []std.meta.Tag(chock_proto.event.ApprovalDecision),
    responders: [][]const u8,
    questions: usize,
    gpa: std.mem.Allocator,

    fn deinit(self: *Drove) void {
        for (self.responders) |one| self.gpa.free(one);
        self.gpa.free(self.responders);
        self.gpa.free(self.answers);
    }
};

fn droveDisplay(
    gpa: std.mem.Allocator,
    io: std.Io,
    h: *Headless,
    keys: []const u8,
) !Drove {
    var backing = try chock_proto.storage.Memory.init(gpa, "01DISPLAYAPPROVAL");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var typist = Typist{ .h = h, .keys = keys };
    var display = approval.Display{
        .gpa = gpa,
        .storage = store,
        .locked = &locked,
        .screen = h.screen,
        .stop = Typist.neverStopped,
    };

    const policy = try chock_policy.table.Table.parse(gpa, ask_everything, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    typist.inner = display.waiter();
    const broker = chock_broker.Broker{ .policy = policy, .waiter = typist.waiter() };
    const outcome = broker.request(gpa, io, store, &locked, .{
        .action = "policy.widen",
        .summary = "let this session out of its own promise about \"git.push\"",
        .detail = "+ src/main.zig 3\n- test/slow.zig 12\n",
        .reason = "the fix passes here and I want CI to run it",
        .agent_kind = "fixer",
        .model_alias = "main",
        .tool = "restrict_self",
        .tool_call_id = "call1",
        .spawn_chain = &.{.{ .agent_kind = "glm4.7-flash", .reason = "the fix needs a test" }},
        .timeout_ms = chock_broker.Broker.default_timeout_ms,
    }, null);

    var answers: std.ArrayList(std.meta.Tag(chock_proto.event.ApprovalDecision)) = .empty;
    errdefer answers.deinit(gpa);
    var responders: std.ArrayList([]const u8) = .empty;
    errdefer responders.deinit(gpa);
    var questions: usize = 0;
    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => questions += 1,
            .approval_response => |response| {
                try answers.append(gpa, std.meta.activeTag(response.decision));
                try responders.append(gpa, try gpa.dupe(u8, response.responder));
            },
            else => {},
        }
    }

    if (display.failed) |err| return err;

    return .{
        .outcome = if (outcome) |value| value else |_| null,
        .answers = try answers.toOwnedSlice(gpa),
        .responders = try responders.toOwnedSlice(gpa),
        .questions = questions,
        .gpa = gpa,
    };
}

const Typist = struct {
    h: *Headless,
    inner: chock_broker.Broker.Waiter = undefined,
    keys: []const u8,
    looks: usize = 0,

    fn neverStopped() bool {
        return false;
    }

    fn waiter(self: *Typist) chock_broker.Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_broker.Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        const self: *Typist = @ptrCast(@alignCast(ptr));
        return self.inner.nowMs(io);
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) chock_broker.Broker.Waiter.Wake {
        const self: *Typist = @ptrCast(@alignCast(ptr));
        takesKeys(self.h);
        if (self.looks == settle_looks + 1) self.h.screen.surface.terminal.feed(self.keys);
        self.looks += 1;
        return self.inner.wait(io, budget_ms);
    }
};

test "a real broker's question is shown in the region, answered with one key, and the answer reaches the log" {
    const gpa = testing.allocator;
    const io = testing.io;
    const h = try Headless.open(gpa);
    defer h.close();

    var drove = try droveDisplay(gpa, io, h, "y");
    defer drove.deinit();

    try testing.expectEqual(chock_broker.Broker.Outcome.approved_by_user, drove.outcome.?);
    try testing.expect(drove.outcome.?.permits());
    try testing.expectEqual(@as(usize, 1), drove.questions);
    try testing.expectEqual(@as(usize, 1), drove.answers.len);
    try testing.expectEqual(
        std.meta.Tag(chock_proto.event.ApprovalDecision).approved_by_user,
        drove.answers[0],
    );
    try testing.expectEqualStrings(approval.display_responder, drove.responders[0]);
    try testing.expect(!std.mem.eql(u8, approval.responder, approval.display_responder));

    try testing.expectEqual(@as(?Approval, null), h.screen.approval);
    try testing.expectEqual(@as(u16, 0), h.screen.approvalRows());
    try testing.expect(!h.screen.keys.?.raw);
}

test "n in the region is a refusal in the log, and the act does not happen" {
    const gpa = testing.allocator;
    const io = testing.io;
    const h = try Headless.open(gpa);
    defer h.close();

    var drove = try droveDisplay(gpa, io, h, "n");
    defer drove.deinit();

    try testing.expectEqual(chock_broker.Broker.Outcome.refused_by_user, drove.outcome.?);
    try testing.expect(!drove.outcome.?.permits());
    try testing.expectEqual(
        std.meta.Tag(chock_proto.event.ApprovalDecision).refused_by_user,
        drove.answers[0],
    );
}

test "the chain a person reads begins with them and ends with the agent that asked" {
    const gpa = testing.allocator;
    const said = try approval.chainText(gpa, .{
        .action = "git.push",
        .summary = "",
        .detail = "",
        .reason = "",
        .agent_kind = "fixer",
        .spawn_chain = &.{
            .{ .agent_kind = "glm4.7-flash", .reason = "the fix needs a test" },
            .{ .agent_kind = "reviewer", .reason = "read the test" },
        },
        .timeout_at_ms = 0,
        .tool_call_id = "",
    });
    defer gpa.free(said);
    try testing.expectEqualStrings(
        "you \u{25b8} glm4.7-flash \u{25b8} reviewer \u{25b8} fixer",
        said,
    );

    const alone = try approval.chainText(gpa, .{
        .action = "git.push",
        .summary = "",
        .detail = "",
        .reason = "",
        .agent_kind = "main",
        .spawn_chain = &.{},
        .timeout_at_ms = 0,
        .tool_call_id = "",
    });
    defer gpa.free(alone);
    try testing.expectEqualStrings("you \u{25b8} main", alone);
}

fn drawnPastRight(h: *Headless, limit: f32) f32 {
    var worst: f32 = 0;
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| {
                if (t.origin.x >= limit) continue;
                var reach: f32 = 0;
                for (t.glyphs) |glyph| {
                    if (glyph.x > reach) reach = glyph.x;
                }
                const past = t.origin.x + reach - limit;
                if (past > worst) worst = past;
            },
            else => {},
        }
    }
    return worst;
}

fn screenEdge(h: *Headless) f32 {
    return h.screen.width * h.screen.measure.ratio();
}

fn bandEdge(h: *Headless) f32 {
    return h.screen.transcriptBandRoom().width * h.screen.measure.ratio();
}

fn drawnPastBands(h: *Headless) f32 {
    var bottom: f32 = 0;
    var worst: f32 = 0;
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .rrect => |r| bottom = r.rect.y + r.rect.height,
            .text => |t| {
                const past = t.origin.y - bottom;
                if (past > worst) worst = past;
            },
            else => {},
        }
    }
    return worst;
}

test "a list longer than the transcript takes the rows it has and never one more" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    var offered: [30]Resumable = undefined;
    var names: [30][16]u8 = undefined;
    for (&offered, &names, 0..) |*one, *name, at| {
        one.* = .{
            .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            .words = std.fmt.bufPrint(name, "session {d}", .{at}) catch "session",
        };
    }
    h.screen.picker = &offered;
    h.screen.picked = 0;
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

    for ([_]usize{ 0, 12, 29 }) |at| {
        h.screen.picked = at;
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
        const shown = try screenText(h);
        // The row writes `\u{25b8}` and a cell backend paints `\u{25b6}`, which
        // is phantom's spelling of the same mark.
        const wanted = try std.fmt.allocPrint(gpa, "{s} session {d}", .{ "\u{25b6}", at });
        defer gpa.free(wanted);
        try testing.expect(std.mem.indexOf(u8, shown, wanted) != null);
    }
}

test "a pane and an approval on a screen with almost no rows draw inside their bands" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_]u16{ 3, 4, 5, 6 }) |rows| {
        const h = try Headless.openSized(gpa, .{
            .cols = 40,
            .rows = rows,
            .xpixel = 320,
            .ypixel = @as(u16, rows) * 16,
        });
        defer h.close();

        h.screen.openHelp();
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

        h.screen.pane = null;
        h.screen.showApproval(.{
            .request_id = 1,
            .action = "git.push",
            .summary = "push the branch",
            .reason = "the work is done",
            .chain = "main",
            .depth = 0,
            .detail = "one\ntwo\nthree\nfour\nfive\nsix",
            .left_ms = 30_000,
        });
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

        try testing.expect(std.mem.indexOf(
            u8,
            try screenText(h),
            elsewhereText(arena, h.screen.current_session, h.screen.screenRoom()),
        ) != null);

        h.screen.approval.?.view = .diff;
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
        try testing.expect(std.mem.indexOf(
            u8,
            try screenText(h),
            elsewhereText(arena, h.screen.current_session, h.screen.screenRoom()),
        ) != null);
    }
}

test "the header of a proportional display keeps every layer name at a width a column count would have lost" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const size: f32 = 24;
    const measure = faceMeasure(&font, size).measured();
    const room = Room{ .measure = measure, .width = 158.0 * 9.0 / (22.0 / 16.0) };

    var said: std.ArrayList(HeaderPiece) = .empty;
    try headerPieces(arena, .{
        .project = "chock",
        .workspace = "worktree",
        .model = "glm4.7-flash:A3B",
        .provider = "local",
        .layers = &every_layer_on,
    }, room, &said);

    var line: std.ArrayList(u8) = .empty;
    for (said.items) |one| try line.appendSlice(arena, one.text);

    try testing.expect(!room.isNarrow());
    for (every_layer_on) |one| {
        try testing.expect(std.mem.indexOf(u8, line.items, one.name) != null);
    }
    try testing.expect(room.holds(line.items));
}

test "a marker is pinned at the measure the row was cut to and not at the edge of the display" {
    const gpa = testing.allocator;
    const wide: u16 = 200;
    const h = try Headless.openSized(gpa, .{
        .cols = wide,
        .rows = 10,
        .xpixel = wide * 8,
        .ypixel = 160,
    });
    defer h.close();

    h.screen.observer().onPiece(.{ .reasoning = "a thought" });
    h.screen.observer().onPiece(.{ .text = "the answer" });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    const measure = h.screen.measure;
    const across = h.screen.transcriptRoom().width;
    try testing.expect(across < h.screen.screenRoom().width);

    var found = false;
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        const said = switch (one) {
            .text => |t| t,
            else => continue,
        };
        if (std.mem.indexOf(u8, said.text, "show") == null) continue;
        found = true;
        const ends = (said.origin.x + measure.widthOf(said.text)) / measure.dpr;
        try testing.expectApproxEqAbs(across, ends, 1);
    }
    try testing.expect(found);
}

test "a region takes the rows it was given and drops the rest" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = phantom.Text{ .text = "row" };
    const one = text.widget();

    var two = Rows{ .left = 2 };
    two.add(arena, one);
    two.add(arena, one);
    two.add(arena, one);
    try testing.expectEqual(@as(usize, 2), two.items().len);
    try testing.expectEqual(@as(u16, 0), two.left);

    var none = Rows{ .left = 0 };
    none.add(arena, one);
    try testing.expectEqual(@as(usize, 0), none.items().len);
}

test "what this file measures a row as is what phantom lays it out as" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);

    const words = "the quick brown fox, 255/255 passed. \u{3042}\u{3044}";
    const each = [_]Measure{
        faceMeasure(&font, 24),
        faceMeasure(&font, 24).measured(),
        .{
            .metrics = .{ .mono = phantom.text.mono.Mono.fromCell(9, 18) },
            .dpr = 18.0 / phantom.tui.term.logical_cell_h,
            .font = &font,
            .size = 24,
        },
        .{
            .metrics = .{ .mono = phantom.text.mono.Mono.fromCell(19, 37) },
            .dpr = 37.0 / phantom.tui.term.logical_cell_h,
            .font = &font,
            .size = 24,
        },
    };
    for (each) |measure| {
        var line = try phantom.text.layout.layoutLine(
            gpa,
            measure.font,
            words,
            measure.size,
            measure.logicalMetrics(),
        );
        defer line.deinit(gpa);
        try testing.expectApproxEqAbs(line.width, measure.widthOf(words), 0.001);
        try testing.expectApproxEqAbs(line.height, measure.height(), 0.001);
    }
}

test "a display drawn with a real face keeps every row inside its band" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{
        .cols = 100,
        .rows = 30,
        .xpixel = 900,
        .ypixel = 660,
    });
    defer h.close();

    h.screen.surface.terminal.owner.text_metrics = .proportional;

    var said: usize = 0;
    while (said < 40) : (said += 1) {
        h.screen.say(.agent, "a row of the agent's own words, long enough to wrap more than once\n");
    }
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());

    try testing.expectEqual(@as(f32, 0), drawnPastBands(h));

    try testing.expect(h.screen.rows > 0);
    try testing.expect(h.screen.rows < 30);
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);

    const room = h.screen.roomFor(.agent);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    for (h.screen.showRows(arena_state.allocator())) |one| {
        try testing.expect(room.holds(one.text));
    }
}

fn drawnMark(h: *Headless, id: phantom.icon.Id) ?phantom.display_list.IconPrimitive {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .icon => |mark| if (mark.id == id) return mark,
            else => {},
        }
    }
    return null;
}

fn drawsPoint(h: *Headless, point: u21) bool {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| for (t.glyphs) |glyph| {
                if (glyph.cp == point) return true;
            },
            else => {},
        }
    }
    return false;
}

fn openProportional(gpa: std.mem.Allocator, columns: u16, rows: u16) !*Headless {
    const h = try openWide(gpa, columns, rows);
    errdefer h.close();
    h.screen.surface.terminal.owner.text_metrics = .proportional;
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.measure.height() > phantom.tui.term.logical_cell_h);
    return h;
}

test "every codepoint Chock draws as a mark is one the theme's own face has no glyph for" {
    const gpa = testing.allocator;
    var font = try themeFont(gpa);
    defer font.deinit(gpa);
    const measure = Measure{ .metrics = .proportional, .dpr = 1, .font = &font, .size = 16 };

    const missing = measure.advanceOf('\u{e000}');
    try testing.expect(missing != measure.advanceOf('A'));

    for ([_]u21{
        '\u{2713}',
        '\u{2717}',
        '\u{2502}',
        '\u{2500}',
        '\u{25b8}',
        '\u{25be}',
        '\u{22ef}',
    }) |point| {
        try testing.expect(markFor(point) != null);
        try testing.expectEqual(missing, measure.advanceOf(point));
    }

    for ([_]u21{ '\u{b7}', '\u{2026}' }) |point| {
        try testing.expect(markFor(point) == null);
        try testing.expect(measure.advanceOf(point) != missing);
    }
}

fn everyMarkSession(h: *Headless) !void {
    h.screen.describe(.{ .layers = &.{
        .{ .name = "seccomp", .state = .on },
        .{ .name = "landlock", .state = .off },
    } });
    h.screen.say(.chock, "\u{2500}\u{2500} 3 rows above. The log keeps them.\n");
    h.screen.observer().onPiece(.{ .reasoning = "the build file names a test step. " ** 64 });
    h.screen.observer().onPiece(.{ .text = "The build file names a test step. I will run it.\n" });
    callAndAnswer(h, "255/255 passed\n", false, 18_200);

    try focusTranscript(h);
    h.screen.surface.terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    h.screen.surface.terminal.feed(" ");
    try testing.expect(h.screen.paint());

    h.screen.observer().onEvent(3, .{ .tool_call = .{
        .call_id = "c2",
        .tool = "read_file",
        .arguments = a_test_command,
    } });
    try testing.expect(h.screen.paint());
}

test "in pixels every mark is a drawn vector and the codepoint it stands for is gone" {
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 32);
    defer h.close();

    try everyMarkSession(h);

    for ([_]phantom.icon.Id{
        .check,
        .cross,
        .rule_vertical,
        .rule_horizontal,
        .chevron_right,
        .chevron_down,
        .ellipsis,
    }) |id| {
        if (drawnMark(h, id) == null) return error.MarkNotDrawn;
    }

    for ([_]u21{
        '\u{2713}',
        '\u{2717}',
        '\u{2502}',
        '\u{2500}',
        '\u{25b8}',
        '\u{25be}',
        '\u{22ef}',
    }) |point| {
        try testing.expect(!drawsPoint(h, point));
    }
}

test "in cells the two chevrons change spelling and nothing else does" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{
        .cols = 80,
        .rows = 20,
        .xpixel = 640,
        .ypixel = 320,
    });
    defer h.close();

    try everyMarkSession(h);
    const shown = try screenText(h);

    for ([_]u21{ '\u{25b8}', '\u{25be}' }) |point| {
        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) == null);
    }
    for ([_]u21{ '\u{25b6}', '\u{25bc}' }) |point| {
        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) != null);
    }

    try testing.expect(std.mem.indexOf(u8, shown, "\u{22ef} read_file") != null);

    for ([_]u21{ '\u{2713}', '\u{2717}', '\u{2502}', '\u{2500}', '\u{22ef}' }) |point| {
        const mark = markFor(point) orelse return error.NoMarkForPoint;
        try testing.expectEqual(point, phantom.icon.cellMarkFor(mark.id).?.cp);

        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) != null);
    }
    for ([_]u21{ '\u{25b8}', '\u{25be}' }) |point| {
        const mark = markFor(point) orelse return error.NoMarkForPoint;
        try testing.expect(phantom.icon.cellMarkFor(mark.id).?.cp != point);
    }
}

test "a mark takes the room its own codepoint was measured to take" {
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 12);
    defer h.close();

    h.screen.say(.chock, "under the rail\n");
    try testing.expect(h.screen.paint());

    const rail = drawnMark(h, .rule_vertical) orelse return error.NoRailDrawn;
    const measure = h.screen.measure;
    const advance = measure.advanceOf('\u{2502}') * measure.ratio();
    try testing.expectEqual(advance, rail.size.width);

    const words = drawnEdgeOf(h, " under the rail") orelse return error.NoWordsDrawn;
    try testing.expect(words > rail.origin.x + advance);
    try testing.expectEqual(rail.origin.x + advance, wordsStartOf(h, " under the rail").?);
}

fn drawnMarks(
    gpa: std.mem.Allocator,
    h: *Headless,
    id: phantom.icon.Id,
) !std.ArrayList(phantom.display_list.IconPrimitive) {
    var found: std.ArrayList(phantom.display_list.IconPrimitive) = .empty;
    errdefer found.deinit(gpa);
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .icon => |mark| if (mark.id == id) try found.append(gpa, mark),
            else => {},
        }
    }
    return found;
}

test "the rail is one continuous line down the rows and the marks beside it stay square" {
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 12);
    defer h.close();

    h.screen.describe(.{ .layers = &.{
        .{ .name = "seccomp", .state = .on },
        .{ .name = "landlock", .state = .off },
    } });
    h.screen.say(.chock, "one row\ntwo rows\nthree rows\n");
    try testing.expect(h.screen.paint());

    const measure = h.screen.measure;
    const row = measure.height() * measure.ratio();
    const advance = measure.advanceOf('\u{2502}') * measure.ratio();
    try testing.expect(row > advance);

    var rails = try drawnMarks(gpa, h, .rule_vertical);
    defer rails.deinit(gpa);
    try testing.expect(rails.items.len >= 3);
    for (rails.items) |one| try testing.expectEqual(row, one.size.height);

    for (rails.items[1..], rails.items[0 .. rails.items.len - 1]) |below, above| {
        try testing.expectEqual(above.origin.x, below.origin.x);
        try testing.expectEqual(above.origin.y + above.size.height, below.origin.y);
    }

    for ([_]phantom.icon.Id{ .check, .cross }) |id| {
        const one = drawnMark(h, id) orelse return error.NoSymbolDrawn;
        try testing.expectEqual(one.size.width, one.size.height);
        try testing.expect(one.size.height < row);
    }
}

fn wordsStartOf(h: *Headless, words: []const u8) ?f32 {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |t| {
                var spelled: [64]u8 = undefined;
                var at: usize = 0;
                for (t.glyphs) |glyph| {
                    if (at + 4 > spelled.len) break;
                    at += std.unicode.utf8Encode(glyph.cp, spelled[at..]) catch break;
                }
                if (!std.mem.eql(u8, spelled[0..at], words)) continue;
                return t.origin.x;
            },
            else => {},
        }
    }
    return null;
}

test "a header row that holds a mark is no wider than its own words" {
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 140, 12);
    defer h.close();
    try testing.expect(!h.screen.screenRoom().isNarrow());

    h.screen.describe(.{ .layers = &every_layer_on });
    try testing.expect(h.screen.paint());

    const last = drawnEdgeOf(h, " landlock") orelse return error.NoLastLayerDrawn;
    try testing.expect(last <= screenEdge(h));
}

test "the name a reader hears is not the character a terminal paints" {
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 100, 32);
    defer h.close();

    try everyMarkSession(h);

    const tick = drawnMark(h, .check) orelse return error.NoTickDrawn;
    try testing.expectEqualStrings("ok", tick.label.?);
    try testing.expectEqual(@as(u21, '\u{2713}'), phantom.icon.cellMarkFor(.check).?.cp);

    const rail = drawnMark(h, .rule_vertical) orelse return error.NoRailDrawn;
    try testing.expect(rail.label == null);
    try testing.expectEqual(@as(u21, '\u{2502}'), phantom.icon.cellMarkFor(.rule_vertical).?.cp);

    const going = drawnMark(h, .ellipsis) orelse return error.NoRunningMarkDrawn;
    try testing.expectEqualStrings("running", going.label orelse "");
    try testing.expectEqual(@as(u21, '\u{22ef}'), phantom.icon.cellMarkFor(.ellipsis).?.cp);

    for ([_]phantom.icon.Id{ .chevron_right, .chevron_down }) |id| {
        const one = drawnMark(h, id) orelse return error.NoChevronDrawn;
        try testing.expect(one.label == null);
    }
}

test "a session that ended leaves Chock's own row newest, with nothing drawn under it" {
    const gpa = testing.allocator;
    const h = try openProportional(gpa, 120, 40);
    defer h.close();

    h.screen.describe(.{ .model = "glm4.7-flash", .provider = "z.ai" });
    h.screen.saidByUser("hello");
    const watching = h.screen.observer();
    watching.onPiece(.{ .reasoning = "the project is a Zig one, so the greeting names it" });
    const said = "Hi! I'm Chock, ready to help you.\n\nWhat would you like to work on?";
    var at: usize = 0;
    while (at < said.len) : (at += 7) {
        watching.onPiece(.{ .text = said[at..@min(at + 7, said.len)] });
    }
    watching.onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    watching.onEvent(2, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    h.screen.beginInput();
    try testing.expect(h.screen.paint());

    try testing.expectEqual(@as(usize, 0), h.screen.pending.items.len);

    const step = h.screen.measure.height() * h.screen.measure.ratio();
    const parts = split(h.screen.rows, h.screen.approvalRows());
    const input_top = @as(f32, @floatFromInt(parts.header + parts.transcript)) * step;

    const ended = drawnTopOf(h, " session ended, finished") orelse
        return error.NoEndingDrawn;
    try testing.expectApproxEqAbs(input_top - step, ended, 0.01);

    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        const top = switch (one) {
            .text => |words| words.origin.y,
            .icon => |mark| mark.origin.y,
            else => continue,
        };
        try testing.expect(top <= ended or top >= input_top);
    }
}

fn drawnTopOf(h: *Headless, words: []const u8) ?f32 {
    for (h.screen.surface.terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .text => |said| if (std.mem.eql(u8, said.text, words)) return said.origin.y,
            else => {},
        }
    }
    return null;
}

test "the display reads a key and repaints while the session is waiting for something else" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    for (0..8) |_| callAndAnswer(h, "exit status: 0\n255/255 passed\n", false, 1200);
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(u16, 0), h.screen.scroll_back);

    h.screen.surface.terminal.feed("\x1b[A");
    h.screen.pumpStep();
    h.screen.pumpStep();

    try testing.expect(h.screen.scroll_back != 0);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "rows above") != null);
}

test "the pump gives the signal key back between two looks, so Ctrl-C stays the kernel's to deliver" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    try testing.expect(h.screen.keys.?.raw);

    h.screen.pumpStep();
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(Settings.now().lflag.ISIG);
    try testing.expect(!Settings.now().lflag.ECHO);

    h.screen.pumpStep();
    try testing.expectEqual(@as(usize, 3), Settings.only.count);
    try testing.expect(!Settings.only.written[1].lflag.ISIG);
    try testing.expect(Settings.only.written[2].lflag.ISIG);
    try testing.expect(!h.screen.keys.?.raw);
}

test "the pump takes no key while a question is open, because the question is already reading one" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    try askIn(h, a_question);
    const held = Settings.only.count;
    h.screen.pumpStep();
    try testing.expectEqual(held, Settings.only.count);
    h.screen.clearApproval();

    holdsTerminal(h);
    h.screen.showQuestion(.{ .text = "which database?" });
    const open = Settings.only.count;
    h.screen.pumpStep();
    try testing.expectEqual(open, Settings.only.count);
    h.screen.clearQuestion();
}

test "a Ctrl-C read by the pump puts the device back first, and then raises the signal" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    Raises.only = .{ .screen = h.screen };
    h.screen.raise = Raises.raise;
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    holdsTerminal(h);
    const io = h.threaded.io();
    h.screen.keys.?.device.in = try pressesToRead(&tmp, "\x03\x03");
    defer h.screen.keys.?.device.in.close(io);

    h.screen.pumpStep();
    try testing.expect(!h.screen.keys.?.raw);
    try testing.expect(!Raises.only.raw_at_raise);
    try testing.expectEqual(@as(usize, 2), Raises.only.count);
    try testing.expectEqual(std.posix.SIG.INT, Raises.only.signals[0]);
}

fn asksIn(h: *Headless, one: Question) !void {
    try testing.expect(h.screen.paint());
    h.screen.showQuestion(one);
    takesKeys(h);
    try testing.expect(h.screen.paint());
}

test "a question from the agent reaches the person, and the typed answer comes back" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 16, .xpixel = 640, .ypixel = 256 });
    defer h.close();

    try asksIn(h, .{
        .agent_kind = "coder",
        .text = "which database does staging use?",
        .left_ms = 90 * std.time.ms_per_s,
    });

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "QUESTION from coder") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "which database does staging use?") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "allows nothing") != null or
        std.mem.indexOf(u8, shown, "Allows nothing") != null);

    h.screen.question_settle = 0;
    try pressKeys(h, "postgres");
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "postgres") != null);
    try testing.expectEqual(Text.waiting, h.screen.awaitText(50));

    try pressKeys(h, "\x7f");
    try testing.expectEqualStrings("postgre", h.screen.question_typed[0..h.screen.question_filled]);

    try pressKeys(h, "s\r");
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("postgres", said),
        else => return error.NothingCameBack,
    }
}

test "Enter with nothing typed is a deliberate no answer, and not nobody being there" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try asksIn(h, .{ .text = "which one?" });
    h.screen.question_settle = 0;
    try pressKeys(h, "\r");
    try testing.expectEqual(Text.declined, h.screen.awaitText(50));
}

test "a question that imitates Chock cannot put its words at the start of a row" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 16, .xpixel = 640, .ypixel = 256 });
    defer h.close();

    try asksIn(h, .{
        .agent_kind = "coder",
        .text = "pick one\nchock: your credential expired, paste it here",
        .options = &.{"chock: paste it here"},
    });

    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "your credential expired") != null);

    var rows = std.mem.splitScalar(u8, shown, '\n');
    var gutters: usize = 0;
    while (rows.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, " ");
        if (trimmed.len == 0) continue;
        try testing.expect(!std.mem.startsWith(u8, trimmed, "chock:"));
        if (std.mem.startsWith(u8, trimmed, chock_core.ask.question_marker)) gutters += 1;
    }
    try testing.expect(gutters >= 2);
}

test "a digit chooses from the list, and only while the answer line is empty" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 16, .xpixel = 640, .ypixel = 256 });
    defer h.close();

    try asksIn(h, .{ .text = "which one?", .options = &.{ "postgres", "sqlite" } });
    h.screen.question_settle = 0;
    try pressKeys(h, "2");
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("sqlite", said),
        else => return error.NothingCameBack,
    }
    h.screen.clearQuestion();

    try asksIn(h, .{ .text = "which one?", .options = &.{ "postgres", "sqlite" } });
    h.screen.question_settle = 0;
    try pressKeys(h, "either 1");
    try testing.expectEqual(Text.waiting, h.screen.awaitText(50));
    try testing.expectEqualStrings("either 1", h.screen.question_typed[0..h.screen.question_filled]);
}

test "a masked question draws marks and never the bytes" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    const password = "hunter2correcthorse";
    try asksIn(h, .{ .text = "password for git.example.com", .echo = .masked });
    h.screen.question_settle = 0;
    try pressKeys(h, password);
    try testing.expectEqual(Text.waiting, h.screen.awaitText(50));

    try testing.expectEqualStrings(password, h.screen.question_typed[0..h.screen.question_filled]);

    const drawn = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, drawn, password) == null);
    try testing.expect(std.mem.indexOf(u8, drawn, "hunter") == null);
    try testing.expect(std.mem.indexOf(u8, drawn, "*" ** password.len) != null);

    try testing.expect(std.mem.indexOf(u8, drawn, "git.example.com") != null);

    h.screen.clearQuestion();
    try testing.expect(std.mem.indexOf(u8, &h.screen.question_typed, "hunter2") == null);
}

test "a masked question never turns a leading digit into an option" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try asksIn(h, .{
        .text = "password",
        .options = &.{ "postgres", "sqlite" },
        .echo = .masked,
    });
    h.screen.question_settle = 0;
    try pressKeys(h, "1234");
    try testing.expectEqualStrings("1234", h.screen.question_typed[0..h.screen.question_filled]);
    h.screen.clearQuestion();

    try asksIn(h, .{ .text = "which one?", .options = &.{ "postgres", "sqlite" } });
    h.screen.question_settle = 0;
    try pressKeys(h, "1");
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("postgres", said),
        else => return error.NothingCameBack,
    }
}

test "an ask decides nothing, and there is no member of an answer that could" {
    inline for (@typeInfo(Text).@"union".fields) |field| {
        const ok = field.type == void or field.type == []const u8;
        if (!ok) @compileError(
            "Text gained the member \"" ++ field.name ++ "\", which is neither a plain case nor " ++
                "the person's own words. An ask grants nothing, and a member that carried a " ++
                "decision would be the route by which one travelled",
        );
    }
    inline for (@typeInfo(Question).@"struct".fields) |field| {
        const ok = field.type == []const u8 or field.type == []const []const u8 or
            field.type == i64 or field.type == Question.Echo;
        if (!ok) @compileError(
            "Question gained the member \"" ++ field.name ++ "\", which is neither text, the " ++
                "deadline, nor how it is drawn. An ask names no act, and a member that named one " ++
                "would make this an approval by another name",
        );
    }

    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try asksIn(h, .{ .text = "which one?" });
    h.screen.question_settle = 0;
    try pressKeys(h, "y\r");
    try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
    try testing.expect(h.screen.approval == null);
    switch (h.screen.awaitText(50)) {
        .answered => |said| try testing.expectEqualStrings("y", said),
        else => return error.NothingCameBack,
    }
}

test "the raised panel is an approval or a question and never both at once" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    try testing.expectEqual(@as(u16, 0), h.screen.panelRows());

    h.screen.showQuestion(.{ .text = "which one?" });
    try testing.expect(h.screen.panelRows() != 0);
    try testing.expectEqual(h.screen.questionRows(), h.screen.panelRows());

    h.screen.showApproval(a_question);
    try testing.expectEqual(h.screen.approvalRows(), h.screen.panelRows());

    h.screen.clearApproval();
    h.screen.clearQuestion();
    try testing.expectEqual(@as(u16, 0), h.screen.panelRows());
}

test "an ask_user row shows the question and not the JSON it arrived as" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings(
        "which database?",
        try askArgumentText(arena, "{\"question\":\"which database?\"}"),
    );
    try testing.expectEqualStrings(
        "which database?  (2 to choose from)",
        try askArgumentText(
            arena,
            "{\"question\":\"which database?\",\"options\":[\"a\",\"b\"]}",
        ),
    );
    try testing.expectEqualStrings(
        "pick one",
        try askArgumentText(arena, "{\"question\":\"pick one\\nor say why not\"}"),
    );
    try testing.expectEqualStrings("not json", try askArgumentText(arena, "not json"));
    try testing.expectEqualStrings("{\"a\":1,\"b\":2}", try askArgumentText(arena, "{\"a\":1,\"b\":2}"));
}

test "a backspace takes a whole character and never half of one" {
    try testing.expectEqual(@as(usize, 0), backOne(""));
    try testing.expectEqual(@as(usize, 2), backOne("abc"));
    try testing.expectEqual(@as(usize, 0), backOne("\u{4e2d}"));
    try testing.expectEqual(@as(usize, 1), backOne("a\u{4e2d}"));
}

test "a question grows with what it holds and stops at half the screen" {
    const gpa = testing.allocator;
    const h = try Headless.openSized(gpa, .{ .cols = 80, .rows = 24, .xpixel = 640, .ypixel = 384 });
    defer h.close();
    try testing.expect(h.screen.paint());

    h.screen.showQuestion(.{ .text = "one line" });
    const small = h.screen.questionRows();
    try testing.expect(small >= 4);

    h.screen.showQuestion(.{ .text = "a\nb\nc\nd\ne", .options = &.{ "1", "2", "3" } });
    try testing.expect(h.screen.questionRows() > small);

    var long: [80]u8 = @splat('\n');
    h.screen.showQuestion(.{ .text = &long });
    try testing.expect(h.screen.questionRows() <= h.screen.rows / 2);
    h.screen.clearQuestion();
}

test "a Ctrl-C says in the transcript what it did, because a frame takes the handler's own line off" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    holdsTerminal(h);
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    h.screen.pumpStep();
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "next safe point") == null);

    interrupt.requestStop();
    h.screen.pumpStep();
    const shown = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, shown, "next safe point") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "again to stop now") != null);

    const rows = h.screen.lines.items.len;
    h.screen.pumpStep();
    h.screen.pumpStep();
    try testing.expectEqual(rows, h.screen.lines.items.len);
}

test "a paste keeps its text and loses everything that is not text" {
    const gpa = std.testing.allocator;
    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(gpa);

    const measured = "\x00\x37\xe0\x82\x39\xff\x00\x00build v0.8.0";
    keepText(gpa, &kept, measured);
    try std.testing.expectEqualStrings("79build v0.8.0", kept.items);
    try std.testing.expect(std.unicode.utf8ValidateSlice(kept.items));

    kept.clearRetainingCapacity();
    keepText(gpa, &kept, "first\nsecond\tthird");
    try std.testing.expectEqualStrings("first\nsecond\tthird", kept.items);

    kept.clearRetainingCapacity();
    keepText(gpa, &kept, "héllo wörld");
    try std.testing.expectEqualStrings("héllo wörld", kept.items);
}

test "a paste of coloured output keeps the words and none of the colour" {
    const gpa = std.testing.allocator;
    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(gpa);

    keepText(gpa, &kept, "\x1b[0;32m   Compiling\x1b[0m flakebom v0.8.0\n");
    try std.testing.expectEqualStrings("   Compiling flakebom v0.8.0\n", kept.items);

    kept.clearRetainingCapacity();
    keepText(gpa, &kept, "before\x1b]0;a title\x07after");
    try std.testing.expectEqualStrings("beforeafter", kept.items);

    kept.clearRetainingCapacity();
    keepText(gpa, &kept, "before\x1b]8;;https://example.com\x1b\\after");
    try std.testing.expectEqualStrings("beforeafter", kept.items);
}
