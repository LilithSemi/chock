//! The interface bare `chock` brings up: one widget tree over phantom's terminal and window backends.
//! It runs as a second `chock_core.Loop.Observer`, and the transcript is `src/run.zig`'s own buffer.

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
const chock_ui = @import("chock-ui");

const ui_text = chock_ui.text;
const ui_layout = chock_ui.layout;
const ui_model = chock_ui.model;

pub const Split = ui_layout.Split;
pub const split = ui_layout.split;
pub const Measure = ui_layout.Measure;
pub const Room = ui_layout.Room;
pub const spread = ui_layout.spread;
pub const narrow_columns = ui_layout.narrow_columns;
const grid_measure = ui_layout.grid_measure;
const countIn = ui_layout.countIn;
const drawnAt = ui_layout.drawnAt;
const visibleLine = ui_layout.visibleLine;

pub const durationText = ui_text.durationText;
pub const sizeText = ui_text.sizeText;
pub const clockText = ui_text.clockText;
pub const argumentText = ui_text.argumentText;
pub const askArgumentText = ui_text.askArgumentText;
pub const summaryText = ui_text.summaryText;

pub const Attach = ui_model.Attach;
pub const Facts = ui_model.Facts;
pub const Layer = ui_model.Layer;
pub const statusWord = ui_model.statusWord;
pub const sizeMoved = ui_model.sizeMoved;
pub const isStatus = ui_model.isStatus;
pub const PlanLine = ui_model.PlanLine;
pub const planRows = ui_model.planRows;
pub const HeaderPiece = ui_model.HeaderPiece;
pub const layerText = ui_model.layerText;
pub const headerPieces = ui_model.headerPieces;
pub const Voice = ui_model.Voice;
pub const Pane = ui_model.Pane;
pub const Fold = ui_model.Fold;
pub const markerText = ui_model.markerText;
pub const Command = ui_model.Command;
pub const commandOf = ui_model.commandOf;
pub const Resumable = ui_model.Resumable;
pub const Approval = ui_model.Approval;
pub const Answered = ui_model.Answered;
pub const Look = ui_model.Look;
pub const Question = ui_model.Question;
pub const Text = ui_model.Text;
pub const questionKeys = ui_model.questionKeys;
pub const sidebar_columns = ui_model.sidebar_columns;
pub const sidebar_needs_columns = ui_model.sidebar_needs_columns;
const columnsOf = ui_model.columnsOf;
const yesNo = ui_model.yesNo;

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

    fn look(self: Compositor) Compositor.Answer {
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

// The buffer is zero length, so a frame reaches tty's own buffer at once and nothing is left behind when Loop.run forks.
const Frames = struct {
    writer: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },

    const vtable: std.Io.Writer.VTable = .{ .drain = drain, .flush = flush };

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        _ = w;
        var written: usize = 0;
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

// Must not draw: tty.print holds src/tty.zig's one lock across a message, and a frame taking the same lock here would wait on its own caller.
const Diagnostics = struct {
    writer: std.Io.Writer = .{ .vtable = &vtable, .buffer = &.{} },
    ui: ?*Ui = null,
    was: ?*std.Io.Writer = null,
    held: std.ArrayList(u8) = .empty,
    escape: Escape = .none,

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

fn putTermios(handle: std.posix.fd_t, settings: std.posix.termios) void {
    std.posix.tcsetattr(handle, .FLUSH, settings) catch {};
}

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

/// What a terminal gives the interface. The other side of `chock_ui.Host`, and
/// the only place in this file that reaches `tty` or `interrupt` on behalf of a
/// screen.
/// What stops a session being taken up, in words, or empty when nothing does.
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

fn terminalOptions(frames: *Frames, attach: chock_ui.model.Attach.Terminal) phantom.tui.Options {
    return .{
        .in = attach.in,
        .out = attach.out,
        .writer = &frames.writer,
        .size = attach.size,
        .raw_mode = false,
        .install_signal_handlers = false,
        .install_panic_hook = false,
        .stderr = .leave,
        .own_screen = true,
        .color = if (tty.stdoutPainter().on) null else .none,
    };
}

pub fn windowOptions(attach: chock_ui.model.Attach.Window) phantom.window.Options {
    return .{
        .title = "chock",
        .width = attach.width,
        .height = attach.height,
        .poll_ms = 0,
    };
}

/// The surface behind a native interface. Valid only for one made by `startUi`,
/// which is every interface this file builds, and is how a test reaches the grid
/// a frame was drawn into.
fn surfaceOf(screen: *Ui) *Surface {
    const self: *TerminalHost = @ptrCast(@alignCast(screen.host.ptr));
    return &self.surface;
}

/// The terminal settings with the two echo bits off, and nothing else touched.
fn quietOf(was: std.posix.termios) std.posix.termios {
    var quiet = was;
    quiet.lflag.ECHO = false;
    quiet.lflag.ECHONL = false;
    return quiet;
}

fn ctrlCPresses(bytes: []const u8) usize {
    return std.mem.count(u8, bytes, &.{0x03});
}

const TerminalHost = struct {
    ui: *Ui,
    /// The keyboard, while the interface holds it. Null until a terminal is
    /// attached, which is every other host.
    keys: ?Keys = null,
    raise: *const fn (std.posix.SIG) std.posix.RaiseError!void = std.posix.raise,
    apply_termios: *const fn (
        std.posix.fd_t,
        std.posix.TCSA,
        std.posix.termios,
    ) std.posix.TermiosSetError!void = std.posix.tcsetattr,

    /// The thing frames are drawn on. Native only: a browser draws its own.
    surface: Surface = undefined,
    /// The writer phantom draws a terminal frame through.
    frames: Frames = .{},
    /// What the session wrote to standard error while the interface held it.
    diagnostics: Diagnostics = .{},

    fn flushOut(_: *anyopaque) void {
        tty.flushOut();
    }
    fn writeOut(_: *anyopaque, bytes: []const u8) void {
        _ = tty.writeOut(bytes);
    }
    fn scrollCount(_: *anyopaque) usize {
        return tty.scrollCount();
    }
    fn verbose(_: *anyopaque) bool {
        return tty.verbose();
    }
    fn colorOn(_: *anyopaque) bool {
        return tty.stdoutPainter().on;
    }
    fn requestStop(_: *anyopaque) void {
        interrupt.requestStop();
    }
    fn stopRequested(_: *anyopaque) bool {
        return interrupt.requested();
    }
    /// A press is a real signal, so the session's own handler runs. Falling back
    /// to `requestStop` keeps the stop happening on a machine that refused it.
    fn interruptTimes(ptr: *anyopaque, times: usize) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        for (0..times) |_| self.raise(.INT) catch interrupt.requestStop();
    }
    const Keys = struct {
        device: phantom.tui.term.Term,
        session: *phantom.tui.Session,
        raw: bool,
        was: ?std.posix.termios = null,
        held: ?std.posix.termios = null,
    };

    /// The most one read takes. A person types a key at a time and an escape
    /// sequence is a few bytes, so this is a paste and not a stream.
    const read_bytes = 64;

    fn whenOf(when: chock_ui.host.When) std.posix.TCSA {
        return switch (when) {
            .now => .NOW,
            .flush => .FLUSH,
        };
    }

    fn takeKeys(ptr: *anyopaque, when: chock_ui.host.When) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const keys = if (self.keys) |*one| one else return;
        if (keys.raw) return;
        const held = keys.held orelse return;
        self.apply_termios(keys.device.in.handle, whenOf(when), held) catch return;
        keys.raw = true;
    }

    fn giveKeys(ptr: *anyopaque, when: chock_ui.host.When) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const keys = if (self.keys) |*one| one else return;
        if (!keys.raw) return;
        keys.raw = false;
        const was = keys.was orelse return;
        self.apply_termios(keys.device.in.handle, whenOf(when), quietOf(was)) catch {};
    }

    fn answersKeys(ptr: *anyopaque) bool {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const keys = self.keys orelse return false;
        return keys.raw;
    }

    fn dropKeys(ptr: *anyopaque) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const keys = if (self.keys) |*one| one else return;
        keys.raw = false;
        const was = keys.was orelse return;
        keys.was = null;
        keys.held = null;
        self.apply_termios(keys.device.in.handle, .FLUSH, was) catch {};
    }

    /// Read what has arrived, hand everything but the interrupt to the tree,
    /// and answer how many interrupts there were.
    fn pumpKeys(ptr: *anyopaque) usize {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const keys = if (self.keys) |*one| one else return 0;

        var buffer: [read_bytes]u8 = undefined;
        const read = keys.device.in.readStreaming(self.ui.io, &.{&buffer}) catch 0;
        const said = buffer[0..read];

        const presses = ctrlCPresses(said);
        if (presses != 0) return presses;
        if (read > 0) keys.session.feed(said);
        return 0;
    }

    fn keysWaiting(ptr: *anyopaque) bool {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const keys = if (self.keys) |*one| one else return false;
        var fds = [_]std.posix.pollfd{.{
            .fd = keys.device.in.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        // True where it cannot tell: the read that follows finds nothing.
        const ready = std.posix.poll(&fds, 0) catch return true;
        return ready != 0;
    }

    fn step(ptr: *anyopaque, wait_ms: u32) bool {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        return self.surface.stepWaiting(wait_ms) catch false;
    }

    fn followSize(ptr: *anyopaque) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const one = self.surface.terminalSession() orelse return;
        const now = one.term.size() catch return;
        if (!chock_ui.model.sizeMoved(now, one.viewport, one.dpr)) return;
        one.resize(now) catch {};
    }

    fn invalidate(ptr: *anyopaque) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        self.surface.invalidate();
    }

    fn focusLast(ptr: *anyopaque) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        self.surface.focusLast();
    }

    fn hasFocus(ptr: *anyopaque) bool {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        return self.surface.hasFocus();
    }

    /// Put the terminal back the way it was found, before the transcript is
    /// written out past the interface.
    fn finish(ptr: *anyopaque) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        self.surface.deinit();
        interrupt.disarmTerminalRestore();
        interrupt.disarmTerminalSettings();
        self.diagnostics.finish(self.ui.io);
    }

    /// The other sessions of this project, read off the disk.
    fn resumables(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        current: []const u8,
    ) ?[]const chock_ui.model.Resumable {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const ui_self = self.ui;
        if (ui_self.sessions_dir.len == 0) return &.{};

        const found = sessions_cmd.list(arena, ui_self.io, ui_self.sessions_dir) catch return null;

        var offered: std.ArrayList(chock_ui.model.Resumable) = .empty;
        for (found) |one| {
            if (std.mem.eql(u8, one.id, current)) continue;
            const log_path = sessions_cmd.logPathIn(arena, ui_self.sessions_dir, one.id) catch continue;
            const ready = sessions_cmd.readinessOf(arena, ui_self.io, log_path, one.id);
            const ended = if (one.end) |reason| reason.wireName() else "no end recorded";
            const words = chock_ui.model.resumableWords(arena, one.id, one.title, ended) catch one.id;
            offered.append(arena, .{
                .id = one.id,
                .words = words,
                .refusal = refusalFor(ready, one.has_work),
            }) catch {};
        }
        return offered.items;
    }

    fn release(ptr: *anyopaque) void {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        const gpa = self.ui.gpa;
        self.diagnostics.held.deinit(gpa);
        // The session was allocated here, so it is freed here. `finish` has
        // already taken it down; this is only the memory.
        switch (self.surface) {
            .terminal => |one| gpa.destroy(one),
            .window => |one| gpa.destroy(one),
        }
        gpa.destroy(self);
    }

    fn nowMs(ptr: *anyopaque) i64 {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        return self.ui.clock.now();
    }
    fn utcOffsetMinutes(ptr: *anyopaque) i32 {
        const self: *TerminalHost = @ptrCast(@alignCast(ptr));
        return self.ui.clock.utc_offset_minutes;
    }

    const vtable: chock_ui.Host.VTable = .{
        .flushOut = flushOut,
        .writeOut = writeOut,
        .scrollCount = scrollCount,
        .verbose = verbose,
        .colorOn = colorOn,
        .requestStop = requestStop,
        .stopRequested = stopRequested,
        .interrupt = interruptTimes,
        .nowMs = nowMs,
        .utcOffsetMinutes = utcOffsetMinutes,
        .invalidate = invalidate,
        .focusLast = focusLast,
        .hasFocus = hasFocus,
        .takeKeys = takeKeys,
        .giveKeys = giveKeys,
        .answersKeys = answersKeys,
        .dropKeys = dropKeys,
        .pumpKeys = pumpKeys,
        .keysWaiting = keysWaiting,
        .step = step,
        .followSize = followSize,
        .finish = finish,
        .release = release,
        .resumables = resumables,
    };

    fn host(self: *TerminalHost) chock_ui.Host {
        return .{ .ptr = self, .vtable = &vtable, .name = "terminal" };
    }
};

pub const Ui = @import("chock-ui").Ui;

/// Make the interface and attach it to a terminal or a window.
///
/// Native only: it reaches a real terminal, and it is what installs the host
/// the tree then draws through.
pub fn startUi(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: *const std.process.Environ.Map,
    attach: chock_ui.model.Attach,
) !*Ui {
    const terminal_host = try gpa.create(TerminalHost);
    errdefer gpa.destroy(terminal_host);

    const self = try Ui.init(gpa, io, terminal_host.host());
    errdefer gpa.destroy(self);
    errdefer self.arena.deinit();
    errdefer self.approval_arena.deinit();
    errdefer self.question_arena.deinit();

    terminal_host.* = .{ .ui = self };

    const at = std.Io.Timestamp.now(io, .real).toMilliseconds();
    self.setClock(self, Ui.realNowMs, clock_mod.localOffsetMinutes(gpa, io, at));

    switch (attach) {
        .terminal => |terminal| {
            var device = phantom.tui.term.Term.initFiles(io, terminal.in, terminal.out);
            const size = terminal.size orelse try device.size();
            self.fixed_size = terminal.size != null;

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
            var options = terminalOptions(&terminal_host.frames, terminal);
            options.size = size;
            options.query_capabilities = raw;
            try session.init(
                gpa,
                io,
                environ,
                phantom.Root.of(Ui, Ui.rootOf, self),
                options,
            );
            terminal_host.surface = .{ .terminal = session };
            terminal_host.keys = .{
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
                phantom.Root.of(Ui, Ui.rootOf, self),
                windowOptions(window),
            );
            terminal_host.surface = .{ .window = session };
        },
    }

    terminal_host.diagnostics.ui = self;
    terminal_host.diagnostics.was = tty.useErrStream(io, &terminal_host.diagnostics.writer);

    return self;
}

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
    try testing.expectEqual(@as(?u32, 0), windowOptions(.{}).poll_ms);
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
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);
    const first = std.mem.sliceTo(plain.items, '\n');
    try testing.expect(std.mem.indexOf(u8, first, "landlock OFF") != null);

    const colors = phantom.ColorScheme.tokyoNight();
    const on = phantom.backend.cell_grid.Rgb.fromColor(colors.green);
    const off = phantom.backend.cell_grid.Rgb.fromColor(colors.red);
    try testing.expect(!std.meta.eql(on, off));

    const grid = &surfaceOf(h.screen).terminal.grid;
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
        self.screen = try startUi(
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

    /// The host behind the interface, so a test can reach the terminal the
    /// interface itself no longer holds.
    fn terminal(self: *Headless) *TerminalHost {
        return @ptrCast(@alignCast(self.screen.host.ptr));
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
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);
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
    surfaceOf(h.screen).focusLast();

    surfaceOf(h.screen).terminal.feed("fix the parser");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("fix the parser", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, h.sink.bytes.items, "fix the parser") != null);

    surfaceOf(h.screen).terminal.feed("\r");
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
    surfaceOf(h.screen).focusLast();
    surfaceOf(h.screen).terminal.feed("first\r");
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
    surfaceOf(h.screen).focusLast();
    surfaceOf(h.screen).terminal.feed("second");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("second", h.screen.typed.items);
    try testing.expect(!h.screen.submitted);

    surfaceOf(h.screen).terminal.feed("\r");
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
    surfaceOf(h.screen).focusLast();
    surfaceOf(h.screen).terminal.feed("   \r");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.submitted);
    try testing.expect(std.mem.trim(u8, h.screen.typed.items, " \t\r\n").len == 0);

    h.screen.beginInput();
    surfaceOf(h.screen).terminal.feed("  \t \r");
    try testing.expectEqual(chock_ui.ui.Ask.done, try h.screen.askForMessage(gpa));

    try testing.expect(!h.terminal().keys.?.raw);
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

    const screen = try startUi(gpa, io, &env, .{ .terminal = .{
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
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);

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
    const grid = &surfaceOf(h.screen).terminal.grid;
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
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);

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
    try testing.expectEqual(@as(f32, chock_ui.ui.readable_columns) * cell, h.screen.transcriptRoom().width);
    try testing.expect(h.screen.agentRoom().width < @as(f32, wide) * cell);

    h.screen.observer().onPiece(.{ .text = "word " ** 120 });
    h.screen.observer().onEvent(1, .{ .message = .{ .role = .assistant, .content = &.{} } });
    try testing.expect(h.screen.paint());

    var rows = std.mem.splitScalar(u8, try screenText(h), '\n');
    while (rows.next()) |one| {
        if (!std.mem.startsWith(u8, one, Voice.agent.prefix())) continue;
        try testing.expect(columnsOf(one) <= chock_ui.ui.readable_columns);
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

    const broken = try chock_ui.ui.wrapText(arena, "the quick brown fox", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 2), broken.len);
    try testing.expectEqualStrings("the quick", broken[0]);
    try testing.expectEqualStrings("brown fox", broken[1]);

    const solid = try chock_ui.ui.wrapText(arena, "x" ** 25, gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 3), solid.len);
    try testing.expectEqualStrings("x" ** 10, solid[0]);
    try testing.expectEqualStrings("x" ** 5, solid[2]);

    const short = try chock_ui.ui.wrapText(arena, "fits", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 1), short.len);
    try testing.expectEqualStrings("fits", short[0]);

    const nothing = try chock_ui.ui.wrapText(arena, "", gridRoom(&font, 10));
    try testing.expectEqual(@as(usize, 1), nothing.len);
    try testing.expectEqualStrings("", nothing[0]);

    const wide = try chock_ui.ui.wrapText(arena, "あいうえお", gridRoom(&font, 4));
    try testing.expectEqualStrings("あい", wide[0]);
    for (wide) |one| try testing.expect(std.unicode.utf8ValidateSlice(one));

    const narrow = try chock_ui.ui.wrapText(arena, "あA", gridRoom(&font, 1));
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

    const bad = try chock_ui.ui.wrapText(arena, "good\xffbad words here", gridRoom(&font, 8));
    for (bad) |one| try testing.expect(std.unicode.utf8ValidateSlice(one));
    try testing.expectEqualStrings("good?bad", bad[0]);
    try testing.expect(bad.len > 1);

    const escaped = try chock_ui.ui.wrapText(arena, "red\x1b[31m now", gridRoom(&font, 40));
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
    try testing.expectEqual(chock_ui.model.Sidebar.plan, h.screen.sidebar);
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
        try testing.expectEqual(chock_ui.model.Sidebar.none, h.screen.sidebar);
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
        try testing.expectEqual(chock_ui.model.Sidebar.plan, h.screen.sidebar);
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
    const one = surfaceOf(h.screen).terminalSession().?;
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
    try testing.expectEqual(@as(usize, chock_ui.ui.readable_columns), wide.ends_at);

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
    const gpa = testing.allocator;
    const h = try openWide(gpa, 140, 16);
    defer h.close();

    surfaceOf(h.screen).terminal.owner.text_metrics = .proportional;
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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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

    surfaceOf(h.screen).terminal.owner.text_metrics = .proportional;
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
    try testing.expectEqual(chock_ui.model.Sidebar.plan, h.screen.sidebar);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "plan   0/4 done") != null);

    try pressKeys(h, "p");
    try testing.expectEqual(chock_ui.model.Sidebar.none, h.screen.sidebar);
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "plan   0/4 done") == null);

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).focusLast();
    try pressKeys(h, "p");
    try testing.expectEqual(chock_ui.model.Sidebar.none, h.screen.sidebar);
    try testing.expectEqualStrings("p", h.screen.typed.items);
}

test "Tab moves the focus between the two regions, and the field starts with it" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).focusLast();
    try testing.expect(!h.screen.transcript_focused);

    surfaceOf(h.screen).terminal.feed("gg");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("gg", h.screen.typed.items);

    surfaceOf(h.screen).terminal.feed("\t");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);

    h.screen.scroll_back = 3;
    surfaceOf(h.screen).terminal.feed("g");
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
    surfaceOf(h.screen).focusLast();

    surfaceOf(h.screen).terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.scroll_back);
    try testing.expectEqualStrings("", h.screen.typed.items);

    surfaceOf(h.screen).terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    surfaceOf(h.screen).terminal.feed("\x1b[B\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    const most = h.screen.maxScrollBack();
    try testing.expect(most > 0);
    var press: usize = 0;
    while (press < most + 8) : (press += 1) surfaceOf(h.screen).terminal.feed("\x1b[A");
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
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "rows above") == null);

    h.screen.scrollBy(4);
    try testing.expect(h.screen.paint());
    plain.clearRetainingCapacity();
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);
    try testing.expect(std.mem.indexOf(u8, plain.items, "4 rows above") != null);

    h.screen.scroll_back = 0;
    h.screen.transcript_focused = true;
    try testing.expect(h.screen.paint());
    plain.clearRetainingCapacity();
    try surfaceOf(h.screen).terminal.grid.writePlain(gpa, &plain);
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
    surfaceOf(h.screen).focusLast();
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
    h.terminal().keys.?.device.in = try pressesToRead(&tmp, "fix the parser\r");
    defer h.terminal().keys.?.device.in.close(io);

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

    try testing.expect(!h.terminal().keys.?.raw);
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
    try testing.expect(!h.terminal().keys.?.raw);
    try testing.expect(h.terminal().keys.?.was == null);
    try testing.expect(h.terminal().keys.?.held == null);
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

    surfaceOf(h.screen).terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.lines.items[1].fold.?.open);
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(u8, try screenText(h), "the first line of the log") != null);

    surfaceOf(h.screen).terminal.feed(" ");
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
    surfaceOf(h.screen).terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 4), h.screen.cursor.?);

    surfaceOf(h.screen).terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.cursor.?);

    surfaceOf(h.screen).terminal.feed(" ");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.lines.items[1].fold.?.open);
    try testing.expect(!h.screen.lines.items[4].fold.?.open);

    surfaceOf(h.screen).terminal.feed("\x1b[A\x1b[A\x1b[A");
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

    try testing.expectEqual(@as(usize, Command.all.len), chock_ui.ui.completions("/", &slots).len);
    try testing.expectEqual(@as(usize, 1), chock_ui.ui.completions("/h", &slots).len);
    try testing.expectEqual(Command.help, chock_ui.ui.completions("/h", &slots)[0]);
    try testing.expectEqual(@as(usize, 1), chock_ui.ui.completions("/pl", &slots).len);

    try testing.expectEqual(@as(usize, 0), chock_ui.ui.completions("/ho", &slots).len);
    try testing.expectEqual(@as(usize, 0), chock_ui.ui.completions("/home/ross", &slots).len);
    try testing.expectEqual(@as(usize, 0), chock_ui.ui.completions("fix the parser", &slots).len);
    try testing.expectEqual(@as(usize, 0), chock_ui.ui.completions("", &slots).len);

    try testing.expectEqual(@as(usize, 0), chock_ui.ui.completions("/plan now", &slots).len);
}

test "a slash command is answered in the transcript and never becomes a message" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).focusLast();

    surfaceOf(h.screen).terminal.feed("/plan\r");
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
    surfaceOf(h.screen).focusLast();

    surfaceOf(h.screen).terminal.feed("/pl");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expectEqual(@as(usize, 1), h.screen.openCompletions(&slots).len);

    surfaceOf(h.screen).terminal.feed("\r");
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
    surfaceOf(h.screen).focusLast();

    surfaceOf(h.screen).terminal.feed("/");
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.completion_selected);
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);

    surfaceOf(h.screen).terminal.feed("z");
    try testing.expect(h.screen.paint());
    var slots: [Command.all.len]Command = undefined;
    try testing.expectEqual(@as(usize, 0), h.screen.openCompletions(&slots).len);
    try testing.expectEqualStrings("/z", h.screen.typed.items);

    surfaceOf(h.screen).terminal.feed("\x1b[A");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.scroll_back);
}

test "the question mark opens the same pane the command does, and only where it is not a letter" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.beginInput();
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).focusLast();

    surfaceOf(h.screen).terminal.feed("?");
    try testing.expect(h.screen.paint());
    try testing.expectEqualStrings("?", h.screen.typed.items);
    try testing.expect(h.screen.pane == null);

    surfaceOf(h.screen).terminal.feed("\t?");
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.transcript_focused);
    try testing.expect(h.screen.pane != null);
    try testing.expectEqual(Pane.Kind.keys, h.screen.pane.?.kind);

    try testing.expectEqual(@as(usize, 0), h.screen.lines.items.len);

    surfaceOf(h.screen).terminal.feed("?");
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
    try testing.expectEqual(Command.plan, chock_ui.ui.answerFor("/plan").command);
    try testing.expectEqual(Command.help, chock_ui.ui.answerFor("  /help  ").command);
    try testing.expectEqual(Command.usage, chock_ui.ui.answerFor("/usage").command);

    for ([_][]const u8{
        "/home/ross/chock/src/main.zig is broken",
        "/help me understand this",
        "/plan the release with me",
        "fix the parser",
        "look at /plan",
    }) |line| {
        try testing.expectEqualStrings(
            std.mem.trim(u8, line, " \t\r\n"),
            chock_ui.ui.answerFor(line).message,
        );
    }

    try testing.expectEqual(chock_ui.ui.Answer.nothing, chock_ui.ui.answerFor(""));
    try testing.expectEqual(chock_ui.ui.Answer.nothing, chock_ui.ui.answerFor("   \t "));
}

test "a session that cannot be taken up says so on its own row, and one that can says nothing" {
    try testing.expectEqualStrings("", refusalFor(.ready, false));

    const kept = refusalFor(.ready, true);
    try testing.expect(kept.len != 0);
    try testing.expect(std.mem.indexOf(u8, kept, "chock workspace") != null);

    for ([_]sessions_cmd.Readiness{
        .running,
        .no_such_session,
        .nothing_to_carry_on,
        .unknown,
    }) |ready| {
        try testing.expect(refusalFor(ready, false).len != 0);
        try testing.expect(refusalFor(ready, true).len != 0);
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
    surfaceOf(h.screen).focusLast();

    const offered = [_]Resumable{
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAV", .words = "one" },
        .{ .id = "01ARZ3NDEKTSV4RRFFQ69G5FAW", .words = "two" },
    };
    h.screen.picker = &offered;

    surfaceOf(h.screen).terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    try testing.expectEqual(@as(usize, 1), h.screen.picked);
    try testing.expectEqual(@as(usize, 0), h.screen.scroll_back);
    try testing.expectEqual(@as(usize, 0), h.screen.completion_selected);

    surfaceOf(h.screen).terminal.feed("\x1b[B\x1b[B");
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
    h.terminal().keys.?.raw = true;
}

fn pressKeys(h: *Headless, keys: []const u8) !void {
    surfaceOf(h.screen).terminal.feed(keys);
    try testing.expect(h.screen.paint());
    try testing.expect(h.screen.paint());
}

fn settleOut(h: *Headless) !void {
    var left: u8 = chock_ui.ui.settle_looks;
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
    const grid = &surfaceOf(h.screen).terminal.grid;
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

    surfaceOf(h.screen).terminal.feed("y");
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
        surfaceOf(h.screen).terminal.feed(key);
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(?Answered, null), h.screen.approval_answer);
        try testing.expect(h.screen.approval != null);
    }

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
    try testing.expect(std.mem.indexOf(u8, shown, chock_ui.ui.approvalKeys(h.screen.screenRoom())) != null);

    for ([_][]const u8{ chock_ui.ui.approval_keys, chock_ui.ui.approval_keys_narrow }) |named| {
        for ([_][]const u8{ "[y]", "[n]", "[d]", "[w]" }) |key| {
            try testing.expect(std.mem.indexOf(u8, named, key) != null);
        }
        try testing.expect(columnsOf(named) <= narrow_columns);
    }
    try testing.expectEqualStrings(chock_ui.ui.approval_keys, chock_ui.ui.approvalKeys(Room.grid(80)));
    try testing.expectEqualStrings(chock_ui.ui.approval_keys_narrow, chock_ui.ui.approvalKeys(Room.grid(50)));

    h.screen.approval.?.view = .diff;
    try testing.expect(h.screen.paint());
    try testing.expect(std.mem.indexOf(
        u8,
        try screenText(h),
        chock_ui.ui.approvalKeys(h.screen.screenRoom()),
    ) != null);
}

test "a display that cannot take a key says which command answers, and shows no key that does nothing" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();
    h.screen.resumable("/tmp/sessions", "01ARZ3NDEKTSV4RRFFQ69G5FAV");

    try testing.expect(h.screen.paint());
    h.screen.showApproval(a_question);
    try testing.expect(!h.screen.host.answersKeys());
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
    const wide = chock_ui.ui.elsewhereText(arena, id, Room.grid(80));
    try testing.expect(std.mem.endsWith(u8, wide, id));
    try testing.expect(columnsOf(wide) <= 80);
    const narrow = chock_ui.ui.elsewhereText(arena, id, Room.grid(40));
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
        chock_ui.ui.approvalKeys(h.screen.screenRoom()),
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

    try testing.expectEqualStrings("0:42", try chock_ui.ui.countdownText(arena, 42 * std.time.ms_per_s));
    try testing.expectEqualStrings("5:00", try chock_ui.ui.countdownText(arena, 5 * std.time.ms_per_min));
    try testing.expectEqualStrings("0:06", try chock_ui.ui.countdownText(arena, 5_200));
    try testing.expectEqualStrings("0:01", try chock_ui.ui.countdownText(arena, 900));
    try testing.expectEqualStrings("0:00", try chock_ui.ui.countdownText(arena, 0));
    try testing.expectEqualStrings("0:00", try chock_ui.ui.countdownText(arena, -4000));
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

    h.terminal().apply_termios = Settings.apply;
    h.terminal().keys.?.was = was;
    h.terminal().keys.?.held = held;
    h.terminal().keys.?.raw = true;
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
    try testing.expect(!h.terminal().keys.?.raw);

    h.screen.host.takeKeys(.flush);
    try testing.expectEqual(@as(usize, 2), Settings.only.count);
    try testing.expect(!Settings.now().lflag.ECHO);
    try testing.expect(!Settings.now().lflag.ISIG);
    try testing.expect(h.terminal().keys.?.raw);
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
    terminal: ?*TerminalHost = null,
    signals: [4]std.posix.SIG = @splat(.KILL),

    var only: Raises = .{};

    fn raise(sig: std.posix.SIG) std.posix.RaiseError!void {
        if (only.count < only.signals.len) only.signals[only.count] = sig;
        only.count += 1;
        if (only.terminal) |one| {
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

    Raises.only = .{ .terminal = h.terminal() };
    h.terminal().raise = Raises.raise;
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try askIn(h, a_question);
    const io = h.threaded.io();
    h.terminal().keys.?.device.in = try pressesToRead(&tmp, "\x03\x03");
    defer h.terminal().keys.?.device.in.close(io);

    try testing.expectEqual(Look.canceled, h.screen.awaitAnswer(50));
    try testing.expect(!h.terminal().keys.?.raw);
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
    try surfaceOf(h.screen).terminal.grid.writePlain(h.gpa, &h.plain);
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
        if (self.looks == chock_ui.ui.settle_looks + 1) surfaceOf(self.h.screen).terminal.feed(self.keys);
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
    try testing.expect(!h.terminal().keys.?.raw);
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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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
            chock_ui.ui.elsewhereText(arena, h.screen.current_session, h.screen.screenRoom()),
        ) != null);

        h.screen.approval.?.view = .diff;
        try testing.expect(h.screen.paint());
        try testing.expectEqual(@as(f32, 0), drawnPastBands(h));
        try testing.expect(std.mem.indexOf(
            u8,
            try screenText(h),
            chock_ui.ui.elsewhereText(arena, h.screen.current_session, h.screen.screenRoom()),
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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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

    var two = chock_ui.ui.Rows{ .left = 2 };
    two.add(arena, one);
    two.add(arena, one);
    two.add(arena, one);
    try testing.expectEqual(@as(usize, 2), two.items().len);
    try testing.expectEqual(@as(u16, 0), two.left);

    var none = chock_ui.ui.Rows{ .left = 0 };
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

    surfaceOf(h.screen).terminal.owner.text_metrics = .proportional;

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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
        switch (one) {
            .icon => |mark| if (mark.id == id) return mark,
            else => {},
        }
    }
    return null;
}

fn drawsPoint(h: *Headless, point: u21) bool {
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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
    surfaceOf(h.screen).terminal.owner.text_metrics = .proportional;
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
        try testing.expect(chock_ui.ui.markFor(point) != null);
        try testing.expectEqual(missing, measure.advanceOf(point));
    }

    for ([_]u21{ '\u{b7}', '\u{2026}' }) |point| {
        try testing.expect(chock_ui.ui.markFor(point) == null);
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
    surfaceOf(h.screen).terminal.feed("\x1b[B");
    try testing.expect(h.screen.paint());
    surfaceOf(h.screen).terminal.feed(" ");
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
        const mark = chock_ui.ui.markFor(point) orelse return error.NoMarkForPoint;
        try testing.expectEqual(point, phantom.icon.cellMarkFor(mark.id).?.cp);

        var spelled: [4]u8 = undefined;
        const len = try std.unicode.utf8Encode(point, &spelled);
        try testing.expect(std.mem.indexOf(u8, shown, spelled[0..len]) != null);
    }
    for ([_]u21{ '\u{25b8}', '\u{25be}' }) |point| {
        const mark = chock_ui.ui.markFor(point) orelse return error.NoMarkForPoint;
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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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

    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
        const top = switch (one) {
            .text => |words| words.origin.y,
            .icon => |mark| mark.origin.y,
            else => continue,
        };
        try testing.expect(top <= ended or top >= input_top);
    }
}

fn drawnTopOf(h: *Headless, words: []const u8) ?f32 {
    for (surfaceOf(h.screen).terminal.canvas.list.primitives.items) |one| {
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

    surfaceOf(h.screen).terminal.feed("\x1b[A");
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
    try testing.expect(h.terminal().keys.?.raw);

    h.screen.pumpStep();
    try testing.expect(!h.terminal().keys.?.raw);
    try testing.expect(Settings.now().lflag.ISIG);
    try testing.expect(!Settings.now().lflag.ECHO);

    h.screen.pumpStep();
    try testing.expectEqual(@as(usize, 3), Settings.only.count);
    try testing.expect(!Settings.only.written[1].lflag.ISIG);
    try testing.expect(Settings.only.written[2].lflag.ISIG);
    try testing.expect(!h.terminal().keys.?.raw);
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

    Raises.only = .{ .terminal = h.terminal() };
    h.terminal().raise = Raises.raise;
    interrupt.forgetForTest();
    defer interrupt.forgetForTest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    holdsTerminal(h);
    const io = h.threaded.io();
    h.terminal().keys.?.device.in = try pressesToRead(&tmp, "\x03\x03");
    defer h.terminal().keys.?.device.in.close(io);

    h.screen.pumpStep();
    try testing.expect(!h.terminal().keys.?.raw);
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
    try testing.expectEqual(@as(usize, 0), chock_ui.ui.backOne(""));
    try testing.expectEqual(@as(usize, 2), chock_ui.ui.backOne("abc"));
    try testing.expectEqual(@as(usize, 0), chock_ui.ui.backOne("\u{4e2d}"));
    try testing.expectEqual(@as(usize, 1), chock_ui.ui.backOne("a\u{4e2d}"));
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
    chock_ui.ui.keepText(gpa, &kept, measured);
    try std.testing.expectEqualStrings("79build v0.8.0", kept.items);
    try std.testing.expect(std.unicode.utf8ValidateSlice(kept.items));

    kept.clearRetainingCapacity();
    chock_ui.ui.keepText(gpa, &kept, "first\nsecond\tthird");
    try std.testing.expectEqualStrings("first\nsecond\tthird", kept.items);

    kept.clearRetainingCapacity();
    chock_ui.ui.keepText(gpa, &kept, "héllo wörld");
    try std.testing.expectEqualStrings("héllo wörld", kept.items);
}

test "a paste of coloured output keeps the words and none of the colour" {
    const gpa = std.testing.allocator;
    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(gpa);

    chock_ui.ui.keepText(gpa, &kept, "\x1b[0;32m   Compiling\x1b[0m flakebom v0.8.0\n");
    try std.testing.expectEqualStrings("   Compiling flakebom v0.8.0\n", kept.items);

    kept.clearRetainingCapacity();
    chock_ui.ui.keepText(gpa, &kept, "before\x1b]0;a title\x07after");
    try std.testing.expectEqualStrings("beforeafter", kept.items);

    kept.clearRetainingCapacity();
    chock_ui.ui.keepText(gpa, &kept, "before\x1b]8;;https://example.com\x1b\\after");
    try std.testing.expectEqualStrings("beforeafter", kept.items);
}

test "an agent's markdown is drawn as words, with the markers off and the runs kept" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.say(.agent, "**What changed** in `Terminal.astro`\n");
    try testing.expect(h.screen.paint());

    const drawn = try screenText(h);
    try testing.expect(std.mem.indexOf(u8, drawn, "What changed in Terminal.astro") != null);
    // The markers themselves never reach a reader.
    try testing.expect(std.mem.indexOf(u8, drawn, "**") == null);
    try testing.expect(std.mem.indexOf(u8, drawn, "`") == null);

    // The runs are kept beside the words, so a renderer can still tell them
    // apart after the markers are gone.
    const line = h.screen.lines.items[h.screen.lines.items.len - 1];
    try testing.expectEqualStrings("What changed in Terminal.astro", line.text);
    try testing.expectEqual(@as(usize, 3), line.spans.len);
    try testing.expectEqualStrings("What changed", line.spans[0].text);
    try testing.expect(line.spans[0].style.strong);
    try testing.expectEqualStrings(" in ", line.spans[1].text);
    try testing.expect(!line.spans[1].style.strong);
    try testing.expectEqualStrings("Terminal.astro", line.spans[2].text);
    try testing.expect(line.spans[2].style.code);

    // Every span points into the line's own text, so the two are freed together.
    for (line.spans) |one| {
        const at = @intFromPtr(one.text.ptr) - @intFromPtr(line.text.ptr);
        try testing.expect(at + one.text.len <= line.text.len);
    }
}

test "a fenced block keeps its code verbatim, markers and all" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.say(.agent, "```zig\nconst a = b.*;\n```\n");
    try testing.expect(h.screen.paint());

    // Inside a fence nothing is read as emphasis, so the stars stay.
    var found = false;
    for (h.screen.lines.items) |one| {
        if (std.mem.indexOf(u8, one.text, "const a = b.*;") != null) found = true;
    }
    try testing.expect(found);
}

test "a styled run is drawn as a run, and a row with none keeps the plain path" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    h.screen.say(.agent, "plain words only\n");
    h.screen.say(.agent, "**bold** words\n");
    try testing.expect(h.screen.paint());

    var room = std.heap.ArenaAllocator.init(gpa);
    defer room.deinit();
    const rows = h.screen.showRows(room.allocator());

    var saw_plain = false;
    var saw_styled = false;
    for (rows) |one| {
        if (std.mem.eql(u8, one.text, "plain words only")) {
            saw_plain = true;
            // One run, carrying no style, so this draws the way it always did.
            for (one.spans) |span| try testing.expect(!span.style.strong);
        }
        if (std.mem.eql(u8, one.text, "bold words")) {
            saw_styled = true;
            try testing.expectEqual(@as(usize, 2), one.spans.len);
            try testing.expect(one.spans[0].style.strong);
            try testing.expect(!one.spans[1].style.strong);
        }
    }
    try testing.expect(saw_plain);
    try testing.expect(saw_styled);
}

test "a long styled line wraps and every row keeps its runs" {
    const gpa = testing.allocator;
    const h = try Headless.open(gpa);
    defer h.close();

    // Wider than the 40 column headless screen, so it has to break.
    h.screen.say(.agent, "**start of it** and then a good deal more text that cannot fit on one row\n");
    try testing.expect(h.screen.paint());

    var room = std.heap.ArenaAllocator.init(gpa);
    defer room.deinit();
    const rows = h.screen.showRows(room.allocator());

    const Row = @TypeOf(rows[0]);
    var first: ?Row = null;
    var second: ?Row = null;
    for (rows) |one| {
        if (std.mem.startsWith(u8, one.text, "start of it")) first = one;
        if (std.mem.startsWith(u8, one.text, "text that cannot fit")) second = one;
    }

    // The row the emphasis is on keeps it, split into the strong run and the
    // rest of the row.
    const head = first orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), head.spans.len);
    try testing.expectEqualStrings("start of it", head.spans[0].text);
    try testing.expect(head.spans[0].style.strong);
    try testing.expect(!head.spans[1].style.strong);

    // A row the emphasis does not reach carries one plain run.
    const tail = second orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), tail.spans.len);
    try testing.expect(!tail.spans[0].style.strong);

    // No row keeps a marker, wrapped or not.
    for (rows) |one| try testing.expect(std.mem.indexOf(u8, one.text, "**") == null);
}
