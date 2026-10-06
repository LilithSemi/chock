//! Colour, and how much a command says. One helper for every subcommand.

const std = @import("std");
const interrupt = @import("interrupt.zig");

pub const Choice = enum {
    auto,
    always,
    never,
};

pub const Rank = enum {
    plain,
    dim,
    warn,
    err,
};

pub const Conditions = struct {
    choice: Choice = .auto,
    stream_is_tty: bool = false,
    no_color: ?[]const u8 = null,
    clicolor_force: ?[]const u8 = null,
    term: ?[]const u8 = null,
};

pub fn decide(conditions: Conditions) bool {
    switch (conditions.choice) {
        .never => return false,
        .always => return true,
        .auto => {},
    }

    if (isSet(conditions.no_color)) return false;

    if (isSet(conditions.clicolor_force)) {
        if (!std.mem.eql(u8, conditions.clicolor_force.?, "0")) return true;
    }

    if (!terminalCanDraw(conditions.term)) return false;

    return conditions.stream_is_tty;
}

pub fn terminalCanDraw(term: ?[]const u8) bool {
    const name = term orelse return false;
    if (name.len == 0) return false;
    return !std.mem.eql(u8, name, "dumb");
}

fn isSet(value: ?[]const u8) bool {
    const text = value orelse return false;
    return text.len != 0;
}

pub const Painter = struct {
    on: bool,

    pub const off: Painter = .{ .on = false };
    pub const colour: Painter = .{ .on = true };

    pub fn open(self: Painter, rank: Rank) []const u8 {
        if (!self.on) return "";
        return switch (rank) {
            .plain => "",
            .dim => "\x1b[2m",
            .warn => "\x1b[33m",
            .err => "\x1b[31m",
        };
    }

    pub fn close(self: Painter, rank: Rank) []const u8 {
        if (!self.on) return "";
        return switch (rank) {
            .plain => "",
            .dim, .warn, .err => "\x1b[0m",
        };
    }
};

pub const Settings = struct {
    choice: Choice = .auto,
    verbose: bool = false,
    stdout_is_tty: bool = false,
    stderr_is_tty: bool = false,
    no_color: ?[]const u8 = null,
    clicolor_force: ?[]const u8 = null,
    term: ?[]const u8 = null,
};

var state: struct {
    out: Painter = .off,
    err: Painter = .off,
    verbose: bool = false,
    stdout_is_tty: bool = false,
} = .{};

pub fn configure(settings: Settings) void {
    state = .{
        .out = .{ .on = decide(.{
            .choice = settings.choice,
            .stream_is_tty = settings.stdout_is_tty,
            .no_color = settings.no_color,
            .clicolor_force = settings.clicolor_force,
            .term = settings.term,
        }) },
        .err = .{ .on = decide(.{
            .choice = settings.choice,
            .stream_is_tty = settings.stderr_is_tty,
            .no_color = settings.no_color,
            .clicolor_force = settings.clicolor_force,
            .term = settings.term,
        }) },
        .verbose = settings.verbose,
        .stdout_is_tty = settings.stdout_is_tty,
    };
}

pub fn stdoutIsTty() bool {
    return state.stdout_is_tty;
}

pub fn stdoutPainter() Painter {
    return state.out;
}

pub fn stderrPainter() Painter {
    return state.err;
}

pub fn verbose() bool {
    return state.verbose;
}

var streams: struct {
    io: ?std.Io = null,
    out: ?*std.Io.Writer = null,
    err: ?*std.Io.Writer = null,
} = .{};

pub fn useStreams(io: std.Io, out_stream: ?*std.Io.Writer, err_stream: ?*std.Io.Writer) void {
    streams = .{ .io = io, .out = out_stream, .err = err_stream };
}

pub fn useErrStream(io: std.Io, err_stream: ?*std.Io.Writer) ?*std.Io.Writer {
    const was = streams.err;
    streams.io = io;
    streams.err = err_stream;
    return was;
}

pub const Capture = struct {
    out_sink: TerminalSink,
    err_sink: TerminalSink,
    out_tap: TerminalSink.Tap,
    err_tap: TerminalSink.Tap,

    pub fn start(self: *Capture, io: std.Io, gpa: std.mem.Allocator) void {
        self.out_sink = .{ .gpa = gpa };
        self.err_sink = .{ .gpa = gpa };
        self.out_tap = self.out_sink.tap(&.{});
        self.err_tap = self.err_sink.tap(&.{});
        useStreams(io, &self.out_tap.writer, &self.err_tap.writer);
    }

    pub fn stop(self: *Capture, io: std.Io) void {
        useStreams(io, null, null);
        self.out_sink.deinit();
        self.err_sink.deinit();
    }

    pub fn out(self: *const Capture) []const u8 {
        return self.out_sink.bytes.items;
    }

    pub fn err(self: *const Capture) []const u8 {
        return self.err_sink.bytes.items;
    }

    pub fn clear(self: *Capture) void {
        self.out_sink.bytes.clearRetainingCapacity();
        self.err_sink.bytes.clearRetainingCapacity();
    }
};

// One lock for both streams, never one each: print touches stdout before stderr, and two locks taken in order is where deadlocks come from.
// Never taken in a signal handler: src/interrupt.zig writes its line with a raw write syscall instead, since a handler that waits on a lock the interrupted thread holds never returns.
var lock: std.Io.Mutex = .init;

fn take() void {
    const io = streams.io orelse return;
    lock.lockUncancelable(io);
}

fn release() void {
    const io = streams.io orelse return;
    lock.unlock(io);
}

pub fn writeOut(bytes: []const u8) bool {
    take();
    defer release();
    const stream = streams.out orelse return false;
    stream.writeAll(bytes) catch {};
    return true;
}

pub fn flushOut() void {
    take();
    defer release();
    flushOutHoldingLock();
}

fn flushOutHoldingLock() void {
    const stream = streams.out orelse return;
    stream.flush() catch {};
}

pub fn out(rank: Rank, comptime fmt: []const u8, args: anytype) void {
    take();
    defer release();
    const paint = stdoutPainter();
    const stream = streams.out orelse return printThroughDebug(paint, rank, fmt, args);
    write(stream, paint, rank, fmt, args);
}

// An atomic and not a value under the lock, because one of the two writers is a signal handler.
var scrolled: std.atomic.Value(u32) = .init(0);

pub fn scrollCount() u32 {
    return scrolled.load(.monotonic);
}

pub fn noteScroll() void {
    _ = scrolled.fetchAdd(1, .monotonic);
}

pub fn print(rank: Rank, comptime fmt: []const u8, args: anytype) void {
    take();
    defer release();
    flushOutHoldingLock();
    noteScroll();
    const paint = stderrPainter();
    const stream = streams.err orelse return printThroughDebug(paint, rank, fmt, args);
    write(stream, paint, rank, fmt, args);
}

fn write(
    stream: *std.Io.Writer,
    paint: Painter,
    rank: Rank,
    comptime fmt: []const u8,
    args: anytype,
) void {
    stream.writeAll(paint.open(rank)) catch return;
    stream.print(fmt, args) catch return;
    stream.writeAll(paint.close(rank)) catch return;
}

fn printThroughDebug(
    paint: Painter,
    rank: Rank,
    comptime fmt: []const u8,
    args: anytype,
) void {
    var buffer: [256]u8 = undefined;
    const stderr = std.debug.lockStderr(&buffer);
    defer std.debug.unlockStderr();
    write(&stderr.file_writer.interface, paint, rank, fmt, args);
}

pub const Stream = enum { out, err };

pub fn say(stream: Stream, rank: Rank, comptime fmt: []const u8, args: anytype) void {
    switch (stream) {
        .out => out(rank, fmt, args),
        .err => print(rank, fmt, args),
    }
}

pub fn detail(comptime fmt: []const u8, args: anytype) void {
    if (!state.verbose) return;
    print(.dim, fmt, args);
}

pub const SecretError = error{
    NotATerminal,
    EchoStuck,
    Unreadable,
    Empty,
    TooLong,
};

pub fn secretTermios(was: std.posix.termios) std.posix.termios {
    var quiet = was;
    quiet.lflag.ECHO = false;
    quiet.lflag.ECHONL = false;
    return quiet;
}

pub fn readSecret(io: std.Io, question: []const u8, into: []u8) SecretError![]const u8 {
    const fd = std.posix.STDIN_FILENO;
    const original = std.posix.tcgetattr(fd) catch return error.NotATerminal;

    std.posix.tcsetattr(fd, .FLUSH, secretTermios(original)) catch return error.EchoStuck;
    interrupt.armTerminalSettings(fd, original);
    defer {
        std.posix.tcsetattr(fd, .FLUSH, original) catch {};
        interrupt.disarmTerminalSettings();
        print(.plain, "\n", .{});
    }

    print(.plain, "{s}", .{question});

    var filled: usize = 0;
    while (true) {
        var one: [1]u8 = undefined;
        const read = std.Io.File.stdin().readStreaming(io, &.{&one}) catch
            return error.Unreadable;
        if (read == 0) break;
        if (one[0] == '\n') break;
        if (one[0] == '\r') continue;
        if (filled == into.len) return error.TooLong;
        into[filled] = one[0];
        filled += 1;
    }

    if (filled == 0) return error.Empty;
    return into[0..filled];
}

pub const options_text =
    \\  --verbose           Also print what a healthy run does not need: the log
    \\                      path, the dev shell, the toolchain cache, and the rest.
    \\  --color=<when>      auto (the default), always, or never. auto means colour
    \\                      when the stream is a terminal that can show it.
    \\
;

pub const Global = struct {
    args: []const []const u8,
    choice: Choice = .auto,
    verbose: bool = false,
};

pub const FlagError = error{BadColorValue} || std.mem.Allocator.Error;

pub fn takeGlobalFlags(
    arena: std.mem.Allocator,
    args: []const []const u8,
) FlagError!Global {
    var kept: std.ArrayList([]const u8) = .empty;
    var result = Global{ .args = &.{} };

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];

        if (std.mem.eql(u8, argument, "--")) {
            try kept.appendSlice(arena, args[index..]);
            break;
        }
        if (std.mem.eql(u8, argument, "--verbose")) {
            result.verbose = true;
            continue;
        }
        if (std.mem.startsWith(u8, argument, "--color=")) {
            const value = argument["--color=".len..];
            result.choice = std.meta.stringToEnum(Choice, value) orelse {
                print(
                    .err,
                    "chock: --color takes auto, always, or never, and \"{s}\" is none of them.\n",
                    .{value},
                );
                return error.BadColorValue;
            };
            continue;
        }
        try kept.append(arena, argument);
    }

    result.args = try kept.toOwnedSlice(arena);
    return result;
}

const testing = std.testing;

test "a stream that is not a terminal gets no colour, which is the pipe and the file" {
    try testing.expect(!decide(.{ .stream_is_tty = false, .term = "xterm-256color" }));
    try testing.expect(decide(.{ .stream_is_tty = true, .term = "xterm-256color" }));
}

test "NO_COLOR turns colour off on a terminal, and an empty NO_COLOR does not" {
    const on_a_terminal = Conditions{ .stream_is_tty = true, .term = "xterm-256color" };
    try testing.expect(decide(on_a_terminal));

    var with = on_a_terminal;
    with.no_color = "1";
    try testing.expect(!decide(with));

    with.no_color = "0";
    try testing.expect(!decide(with));

    with.no_color = "anything at all";
    try testing.expect(!decide(with));

    with.no_color = "";
    try testing.expect(decide(with));
}

test "TERM=dumb and no TERM at all both turn colour off, even on a terminal" {
    try testing.expect(!decide(.{ .stream_is_tty = true, .term = "dumb" }));
    try testing.expect(!decide(.{ .stream_is_tty = true, .term = null }));
    try testing.expect(!decide(.{ .stream_is_tty = true, .term = "" }));
    try testing.expect(decide(.{ .stream_is_tty = true, .term = "screen" }));
}

test "--color=never beats a terminal, and --color=always beats a pipe and NO_COLOR" {
    try testing.expect(!decide(.{ .choice = .never, .stream_is_tty = true, .term = "xterm" }));
    try testing.expect(!decide(.{ .choice = .never, .clicolor_force = "1", .term = "xterm" }));

    try testing.expect(decide(.{ .choice = .always, .stream_is_tty = false }));
    try testing.expect(decide(.{ .choice = .always, .stream_is_tty = false, .no_color = "1" }));
    try testing.expect(decide(.{ .choice = .always, .stream_is_tty = false, .term = "dumb" }));
}

test "CLICOLOR_FORCE turns colour on for a pipe, and CLICOLOR_FORCE=0 does not" {
    try testing.expect(decide(.{ .stream_is_tty = false, .clicolor_force = "1" }));
    try testing.expect(decide(.{ .stream_is_tty = false, .clicolor_force = "yes" }));

    try testing.expect(!decide(.{ .stream_is_tty = false, .clicolor_force = "0" }));
    try testing.expect(!decide(.{ .stream_is_tty = false, .clicolor_force = "" }));

    try testing.expect(!decide(.{ .stream_is_tty = false, .clicolor_force = "1", .no_color = "1" }));
}

test "a painter that is off writes no byte for any rank, and one that is on writes an escape" {
    for ([_]Rank{ .plain, .dim, .warn, .err }) |rank| {
        try testing.expectEqualStrings("", Painter.off.open(rank));
        try testing.expectEqualStrings("", Painter.off.close(rank));
    }

    try testing.expectEqualStrings("", Painter.colour.open(.plain));
    try testing.expectEqualStrings("", Painter.colour.close(.plain));

    for ([_]Rank{ .dim, .warn, .err }) |rank| {
        try testing.expect(Painter.colour.open(rank).len != 0);
        try testing.expectEqualStrings("\x1b[0m", Painter.colour.close(rank));
    }
}

test "the three coloured ranks look different from each other" {
    const dim = Painter.colour.open(.dim);
    const warn = Painter.colour.open(.warn);
    const bad = Painter.colour.open(.err);
    try testing.expect(!std.mem.eql(u8, dim, warn));
    try testing.expect(!std.mem.eql(u8, dim, bad));
    try testing.expect(!std.mem.eql(u8, warn, bad));
}

test "--verbose and --color are taken off the arguments and the rest is untouched" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const taken = try takeGlobalFlags(arena, &.{
        "--verbose",
        "--project",
        "/tmp/p",
        "--color=never",
        "fix",
        "the",
        "parser",
    });
    try testing.expect(taken.verbose);
    try testing.expectEqual(Choice.never, taken.choice);
    try testing.expectEqual(@as(usize, 5), taken.args.len);
    try testing.expectEqualStrings("--project", taken.args[0]);
    try testing.expectEqualStrings("/tmp/p", taken.args[1]);
    try testing.expectEqualStrings("fix", taken.args[2]);
    try testing.expectEqualStrings("the", taken.args[3]);
    try testing.expectEqualStrings("parser", taken.args[4]);
}

test "a message word after -- keeps its --verbose spelling" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const taken = try takeGlobalFlags(arena, &.{ "--", "--verbose", "--color=always" });
    try testing.expect(!taken.verbose);
    try testing.expectEqual(Choice.auto, taken.choice);
    try testing.expectEqual(@as(usize, 3), taken.args.len);
    try testing.expectEqualStrings("--", taken.args[0]);
    try testing.expectEqualStrings("--verbose", taken.args[1]);
    try testing.expectEqualStrings("--color=always", taken.args[2]);
}

test "a --color value that is not one of the three is refused and does not silently mean auto" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var said: Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadColorValue,
        takeGlobalFlags(arena_state.allocator(), &.{"--color=maybe"}),
    );

    try testing.expectEqualStrings("", said.out());
    try testing.expect(std.mem.indexOf(u8, said.err(), "maybe") != null);
    for ([_][]const u8{ "auto", "always", "never" }) |one| {
        try testing.expect(std.mem.indexOf(u8, said.err(), one) != null);
    }
}

test "the two painters are decided one stream at a time" {
    defer configure(.{});

    configure(.{ .stdout_is_tty = false, .stderr_is_tty = true, .term = "xterm-256color" });
    try testing.expect(!stdoutPainter().on);
    try testing.expect(stderrPainter().on);

    configure(.{ .stdout_is_tty = true, .stderr_is_tty = false, .term = "xterm-256color" });
    try testing.expect(stdoutPainter().on);
    try testing.expect(!stderrPainter().on);
}

const TerminalSink = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *TerminalSink) void {
        self.bytes.deinit(self.gpa);
    }

    fn tap(self: *TerminalSink, buffer: []u8) Tap {
        return .{
            .writer = .{ .vtable = &Tap.vtable, .buffer = buffer },
            .sink = self,
        };
    }

    const Tap = struct {
        writer: std.Io.Writer,
        sink: *TerminalSink,

        const vtable: std.Io.Writer.VTable = .{ .drain = drain };

        fn drain(
            w: *std.Io.Writer,
            data: []const []const u8,
            splat: usize,
        ) std.Io.Writer.Error!usize {
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

test "a detail line is written only with --verbose, and a ranked line is written either way" {
    const gpa = testing.allocator;
    var sink: TerminalSink = .{ .gpa = gpa };
    defer sink.deinit();
    var stderr_stream = sink.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, null, &stderr_stream.writer);

    configure(.{ .verbose = false });
    detail("a healthy fact\n", .{});
    try testing.expectEqualStrings("", sink.bytes.items);

    print(.warn, "something to act on\n", .{});
    try testing.expectEqualStrings("something to act on\n", sink.bytes.items);

    sink.bytes.clearRetainingCapacity();
    configure(.{ .verbose = true });
    detail("a healthy fact\n", .{});
    try testing.expectEqualStrings("a healthy fact\n", sink.bytes.items);
}

test "a row goes to standard output and a warning goes to standard error, and neither reaches the other" {
    const gpa = testing.allocator;
    var rows: TerminalSink = .{ .gpa = gpa };
    defer rows.deinit();
    var diagnostics: TerminalSink = .{ .gpa = gpa };
    defer diagnostics.deinit();

    var out_stream = rows.tap(&.{});
    var err_stream = diagnostics.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, &out_stream.writer, &err_stream.writer);
    configure(.{});

    out(.plain, "sess-01  finished\n", .{});
    print(.warn, "chock sessions: sess-02 could not be read\n", .{});

    try testing.expectEqualStrings("sess-01  finished\n", rows.bytes.items);
    try testing.expectEqualStrings(
        "chock sessions: sess-02 could not be read\n",
        diagnostics.bytes.items,
    );
}

test "a buffered standard output is flushed before a warning, so one terminal reads them in order" {
    const gpa = testing.allocator;
    var terminal: TerminalSink = .{ .gpa = gpa };
    defer terminal.deinit();

    var out_buffer: [4096]u8 = undefined;
    var out_stream = terminal.tap(&out_buffer);
    var err_stream = terminal.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, &out_stream.writer, &err_stream.writer);
    configure(.{});

    out(.plain, "first row\n", .{});
    out(.plain, "second row\n", .{});
    print(.warn, "a warning\n", .{});
    out(.plain, "third row\n", .{});
    flushOut();

    try testing.expectEqualStrings(
        "first row\nsecond row\na warning\nthird row\n",
        terminal.bytes.items,
    );
}

test "standard error is unbuffered, so a diagnostic is at the terminal before anything flushes" {
    const gpa = testing.allocator;
    var terminal: TerminalSink = .{ .gpa = gpa };
    defer terminal.deinit();

    var out_buffer: [4096]u8 = undefined;
    var out_stream = terminal.tap(&out_buffer);
    var err_stream = terminal.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, &out_stream.writer, &err_stream.writer);
    configure(.{});

    print(.err, "chock: it failed\n", .{});
    try testing.expectEqualStrings("chock: it failed\n", terminal.bytes.items);

    out(.plain, "a row\n", .{});
    try testing.expectEqualStrings("chock: it failed\n", terminal.bytes.items);
    flushOut();
    try testing.expectEqualStrings("chock: it failed\na row\n", terminal.bytes.items);
}

test "a piped standard output gets no escape sequence while a terminal standard error still does" {
    const gpa = testing.allocator;
    var rows: TerminalSink = .{ .gpa = gpa };
    defer rows.deinit();
    var diagnostics: TerminalSink = .{ .gpa = gpa };
    defer diagnostics.deinit();

    var out_stream = rows.tap(&.{});
    var err_stream = diagnostics.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, &out_stream.writer, &err_stream.writer);
    configure(.{
        .stdout_is_tty = false,
        .stderr_is_tty = true,
        .term = "xterm-256color",
    });

    out(.warn, "a row that asked for a rank\n", .{});
    print(.warn, "a warning\n", .{});

    try testing.expectEqualStrings("a row that asked for a rank\n", rows.bytes.items);
    try testing.expect(std.mem.indexOf(u8, rows.bytes.items, "\x1b") == null);

    try testing.expectEqualStrings("\x1b[33ma warning\n\x1b[0m", diagnostics.bytes.items);
}

test "a plain line carries no escape on either stream, so an unranked call site is unchanged" {
    const gpa = testing.allocator;
    var terminal: TerminalSink = .{ .gpa = gpa };
    defer terminal.deinit();

    var out_stream = terminal.tap(&.{});
    var err_stream = terminal.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, &out_stream.writer, &err_stream.writer);
    configure(.{ .choice = .always });
    try testing.expect(stdoutPainter().on and stderrPainter().on);

    out(.plain, "a row {d}\n", .{7});
    print(.plain, "a line {d}\n", .{8});
    try testing.expectEqualStrings("a row 7\na line 8\n", terminal.bytes.items);
}

test "a stream nobody set says so rather than swallowing the bytes" {
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, null, null);
    flushOut();
    try testing.expect(!writeOut("bytes with nowhere to go"));

    var sink: TerminalSink = .{ .gpa = testing.allocator };
    defer sink.deinit();
    var tap = sink.tap(&.{});
    useStreams(testing.io, &tap.writer, null);
    try testing.expect(writeOut("bytes with somewhere to go"));
    try testing.expectEqualStrings("bytes with somewhere to go", sink.bytes.items);
}

test "useErrStream moves standard error alone and gives back the writer it replaced" {
    const gpa = testing.allocator;
    var frames: TerminalSink = .{ .gpa = gpa };
    defer frames.deinit();
    var real: TerminalSink = .{ .gpa = gpa };
    defer real.deinit();
    var rows: TerminalSink = .{ .gpa = gpa };
    defer rows.deinit();

    var out_stream = frames.tap(&.{});
    var err_stream = real.tap(&.{});
    var row_stream = rows.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, &out_stream.writer, &err_stream.writer);
    configure(.{});

    const was = useErrStream(testing.io, &row_stream.writer);
    try testing.expectEqual(@as(?*std.Io.Writer, &err_stream.writer), was);

    print(.warn, "a warning under a display\n", .{});
    out(.plain, "a frame\n", .{});
    try testing.expectEqualStrings("a warning under a display\n", rows.bytes.items);
    try testing.expectEqualStrings("a frame\n", frames.bytes.items);
    try testing.expectEqualStrings("", real.bytes.items);

    _ = useErrStream(testing.io, was);
    print(.warn, "a warning with no display\n", .{});
    try testing.expectEqualStrings("a warning with no display\n", real.bytes.items);
    try testing.expectEqualStrings("a warning under a display\n", rows.bytes.items);
}

test "a warning through a moved standard error is still counted as a scroll" {
    const gpa = testing.allocator;
    var rows: TerminalSink = .{ .gpa = gpa };
    defer rows.deinit();
    var row_stream = rows.tap(&.{});
    defer configure(.{});
    defer useStreams(testing.io, null, null);
    useStreams(testing.io, null, null);
    configure(.{});

    const was = useErrStream(testing.io, &row_stream.writer);
    defer _ = useErrStream(testing.io, was);

    const before = scrollCount();
    print(.warn, "a warning\n", .{});
    try testing.expectEqual(before + 1, scrollCount());
}

test "settings that say nothing leave both painters off and verbosity off" {
    defer configure(.{});
    configure(.{});
    try testing.expect(!stdoutPainter().on);
    try testing.expect(!stderrPainter().on);
    try testing.expect(!verbose());
}

test "a secret is typed with the echo off and with everything else left alone" {
    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ECHONL = true;
    was.lflag.ISIG = true;
    was.lflag.ICANON = true;

    const quiet = secretTermios(was);
    try testing.expect(!quiet.lflag.ECHO);
    try testing.expect(!quiet.lflag.ECHONL);
    try testing.expect(quiet.lflag.ISIG);
    try testing.expect(quiet.lflag.ICANON);
    try testing.expect(was.lflag.ECHO);
}
