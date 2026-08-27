//! Colour, and how much a command says. One helper for every subcommand.
//!
//! ## Colour is rank, and never decoration
//!
//! Before this file, a healthy fact and a warning printed identically, so a
//! person had to read seven startup lines to find the one that mattered. The
//! answer is not more colour. The answer is that colour states **how much this
//! line matters**, and nothing else. See `Rank`: there are four, one of them
//! paints nothing, and none of them names a subject. A palette that gives the
//! cache one colour and the dev shell another teaches the reader a code they
//! never asked to learn, and it hides the warning again.
//!
//! ## The decision is a pure function, so a test can make every case
//!
//! `decide` reads a `Conditions` value and returns true or false. It calls
//! nothing, it reads no environment, and it touches no terminal. A test states
//! the conditions it wants. That matters because the cases which age badly are
//! exactly the ones that are hard to set up by hand: a pipe, a dumb terminal,
//! `NO_COLOR`, and a person who pipes into `less -R` and wants the escapes kept.
//!
//! ## The one piece of process state, and why it is here
//!
//! `configure` sets a painter for standard output and a painter for standard
//! error, once, in `main`. IronStyle says to inject rather than to reach for a
//! global, and that rule is about a library which two callers can hold at once.
//! This is a program, the terminal it writes to is a property of the process,
//! and `std.debug.print` is already a process wide sink. Threading a painter
//! through the hundred and eighty call sites that print would be the large
//! reshuffling IronStyle warns about, and it would buy nothing: there is one
//! terminal.
//!
//! **Two painters, because the streams are two.** A warning goes to standard
//! error and the model's own answer goes to standard output, so `chock run
//! > answer.txt` leaves a terminal on one and a file on the other. A helper
//! that asked "is stdout a terminal" would then colour the warning wrongly in
//! both directions.
//!
//! ## Two streams, and every line has to say which one it is
//!
//! `print` writes to standard error and `out` writes to standard output. That
//! is the whole split, and it is the reason this file holds writers at all.
//! Before it, every line in the program went to standard error, because
//! `std.debug.print` writes there and nowhere else. So `chock sessions | grep`
//! read an empty pipe while the rows went past on the terminal.
//!
//! **What goes to standard output is what another program would want**: the
//! rows of `chock sessions`, `chock usage`, `chock plan` and `chock
//! workspace`, the text of a note, and the model's own answer. **What goes to
//! standard error is what a person needs**: warnings, refusals, faults, and
//! the `--verbose` lines.
//!
//! ## Standard output is buffered, standard error is not
//!
//! A table is many small writes and one system call each would be wasteful, so
//! `main` gives standard output a buffer and flushes it with `defer`. That
//! `defer` runs on every path, because no command in `src/` calls
//! `std.process.exit` and none of them panics: every one returns an exit code
//! up through `main`, refusals included.
//!
//! **Standard error has a zero length buffer**, so `std.Io.Writer.flush` on it
//! is a no-op and no diagnostic can be lost, whatever happens next.
//!
//! ## The one ordering rule
//!
//! **`print` flushes standard output before it writes.** The two streams
//! usually reach one terminal, and one of them is buffered, so without this a
//! warning can appear above rows that were written before it. The gate is here,
//! in `print`, and there is one of it.
//!
//! **Never from a signal handler.** `std.Io.Writer.consume` does a `@memmove`
//! and then sets `end`, with no lock, so a signal landing between the two
//! duplicates or corrupts what is in the buffer. `src/interrupt.zig` sets a
//! flag and the work happens at a safe point. Keep it that way.
//!
//! ## What is never coloured
//!
//! The session log. It is JSON, a machine reads it, and `chock_proto.log`
//! writes it through a path that does not reach this file at all. It writes
//! with `File.writeStreamingAll` straight to the descriptor, which is what
//! lets a byte offset be an event id, so it must never be routed through a
//! writer. The same holds for anything else this program writes for another
//! program.

const std = @import("std");
/// For `readSecret` alone: the terminal's settings are handed over before the
/// echo goes off, so a Ctrl-C during the read puts them back.
const interrupt = @import("interrupt.zig");

/// What a caller asked for with `--color`.
pub const Choice = enum {
    /// Colour when the stream is a terminal that can show it. The default.
    auto,
    /// Colour, whatever the stream is. What a person piping into `less -R`
    /// needs.
    always,
    /// No colour, whatever the stream is.
    never,
};

/// How much one line matters. **Not what it is about.**
///
/// Four ranks, and a reader has to learn only three of them, because `plain`
/// looks like every line did before this existed.
pub const Rank = enum {
    /// The ordinary line. No escape sequence at all, even with colour on.
    plain,
    /// A fact about a healthy run. Worth having on screen, not worth stopping
    /// for.
    dim,
    /// Something the person has to act on. The line the other six were hiding.
    warn,
    /// Something failed.
    err,
};

/// Everything the colour decision reads. Every field is an input, so `decide`
/// is a pure function and a test states a pipe or a dumb terminal instead of
/// arranging one.
pub const Conditions = struct {
    /// What `--color` said. `.auto` when nobody said anything.
    choice: Choice = .auto,
    /// Whether **the stream this painter writes to** is a terminal. Never
    /// standard output in general: see this file's own top comment.
    stream_is_tty: bool = false,
    /// `NO_COLOR` from the environment, or null when it is not set.
    no_color: ?[]const u8 = null,
    /// `CLICOLOR_FORCE` from the environment, or null when it is not set.
    clicolor_force: ?[]const u8 = null,
    /// `TERM` from the environment, or null when it is not set.
    term: ?[]const u8 = null,
};

/// Whether this stream gets colour.
///
/// The order below is the whole rule, and it is an order and not a set of
/// independent tests, because two of these can be true at once:
///
/// 1. `--color=never` wins over everything. It is the most explicit "no".
/// 2. `--color=always` wins over the environment. The person typed it on this
///    command line, and the environment was set some time before. This is what
///    a pipe into `less -R` uses.
/// 3. `NO_COLOR`, set and not empty, turns colour off. The convention at
///    no-color.org is exactly that: present and not an empty string, whatever
///    the value is. An empty value is therefore not a "no", because a shell
///    that exports an unset variable would otherwise silence every program.
/// 4. `CLICOLOR_FORCE`, set, not empty, and not "0", turns colour on for a
///    stream that is not a terminal.
/// 5. `TERM` of "dumb", or no `TERM` at all, turns colour off. A terminal that
///    says it cannot do escape sequences is believed.
/// 6. Otherwise, colour when the stream is a terminal.
pub fn decide(conditions: Conditions) bool {
    switch (conditions.choice) {
        .never => return false,
        .always => return true,
        .auto => {},
    }

    if (isSet(conditions.no_color)) return false;

    // "0" is the one value that means "do not force". Anything else that is
    // set and not empty is a request for colour.
    if (isSet(conditions.clicolor_force)) {
        if (!std.mem.eql(u8, conditions.clicolor_force.?, "0")) return true;
    }

    if (!terminalCanDraw(conditions.term)) return false;

    return conditions.stream_is_tty;
}

/// Whether a terminal of this name can do anything but put characters in the
/// order they were written.
///
/// **One answer with two readers, and not two answers.** Colour is one thing a
/// terminal that says `dumb` cannot do, and a full screen display is another,
/// so `decide` reads this and so does `src/ui.zig`. A second copy of the rule
/// would be the beginning of two conventions, which is the fault this whole
/// file exists to avoid.
///
/// No `TERM` at all is the same answer as `dumb`. A terminal that never said
/// what it is has not earned an escape sequence.
pub fn terminalCanDraw(term: ?[]const u8) bool {
    const name = term orelse return false;
    if (name.len == 0) return false;
    return !std.mem.eql(u8, name, "dumb");
}

/// The convention's own reading of "set": present, and not the empty string.
fn isSet(value: ?[]const u8) bool {
    const text = value orelse return false;
    return text.len != 0;
}

/// The escape sequences one stream uses, or none at all.
///
/// **`off` writes not one byte of escape.** That is the property a pipe needs,
/// and it is why `open` and `close` return an empty slice rather than a
/// sequence that happens to be harmless.
pub const Painter = struct {
    on: bool,

    pub const off: Painter = .{ .on = false };
    pub const colour: Painter = .{ .on = true };

    /// What goes before the text of a line of this rank.
    pub fn open(self: Painter, rank: Rank) []const u8 {
        if (!self.on) return "";
        return switch (rank) {
            // Never an escape, even with colour on. A palette of three is a
            // palette a reader can hold, and the ordinary line is the one that
            // has to look ordinary.
            .plain => "",
            .dim => "\x1b[2m",
            .warn => "\x1b[33m",
            .err => "\x1b[31m",
        };
    }

    /// What goes after it. Empty for the rank that opened with nothing, so a
    /// plain line is byte for byte what it was before colour existed.
    pub fn close(self: Painter, rank: Rank) []const u8 {
        if (!self.on) return "";
        return switch (rank) {
            .plain => "",
            .dim, .warn, .err => "\x1b[0m",
        };
    }
};

/// What `configure` is told, once, by `main`.
pub const Settings = struct {
    choice: Choice = .auto,
    /// Print the lines that only say a healthy run is healthy. See `detail`.
    verbose: bool = false,
    stdout_is_tty: bool = false,
    stderr_is_tty: bool = false,
    no_color: ?[]const u8 = null,
    clicolor_force: ?[]const u8 = null,
    term: ?[]const u8 = null,
};

/// The process wide state. See this file's own top comment for why it is here
/// and not injected. Both painters start `off`, so a program that never calls
/// `configure` writes no escape sequence at all, which is the safe direction.
var state: struct {
    out: Painter = .off,
    err: Painter = .off,
    verbose: bool = false,
    /// Whether standard output is a terminal. Kept apart from the painter,
    /// because the two answer different questions: `--color=always` piped into
    /// `less -R` turns the painter on for a stream that is still a pipe. See
    /// `stdoutIsTty`.
    stdout_is_tty: bool = false,
} = .{};

/// Set the two painters and the verbosity for the rest of the process.
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

/// Whether standard output is a terminal, as `main` measured it.
///
/// **Not the same question as `stdoutPainter`.** A painter that is on says
/// escape sequences are wanted; this says a full screen application would have
/// a screen to take. `--color=always | less -R` answers yes to the first and no
/// to the second, and `src/ui.zig` needs both to agree before it takes over the
/// display.
pub fn stdoutIsTty() bool {
    return state.stdout_is_tty;
}

/// The painter for standard output. `src/run.zig`'s `Printer` writes there,
/// because what the model says is the program's answer.
pub fn stdoutPainter() Painter {
    return state.out;
}

/// The painter for standard error, which is where every `chock:` line goes.
pub fn stderrPainter() Painter {
    return state.err;
}

/// Whether the caller asked for the lines a healthy run does not need. Callers
/// that would have to do work to build such a line ask first.
pub fn verbose() bool {
    return state.verbose;
}

/// Where the bytes of each stream go. Both null until `main` calls
/// `useStreams`, and a test sets them to read what a command wrote.
///
/// **A null stream is not a dropped stream.** It falls back to
/// `std.debug.lockStderr`, which is where every line in this program went
/// before the split existed, so nothing can be lost by a path that runs before
/// `main` has wired anything. What proves the real program does not stay in
/// that state is `test/cli/streams.zig`, which runs the built binary and reads
/// the two streams apart. No unit test can see that, because a unit test is
/// not `main`.
var streams: struct {
    /// What the writers were built over, kept because `std.Io.Mutex` needs one
    /// to wait on. See `lock`.
    io: ?std.Io = null,
    out: ?*std.Io.Writer = null,
    err: ?*std.Io.Writer = null,
} = .{};

/// Point the two streams at writers, for the rest of the process.
///
/// `main` passes standard output and standard error. A test passes whatever it
/// wants to read afterwards, and it may pass two writers over one buffer to see
/// the order the two streams reach a terminal in.
pub fn useStreams(io: std.Io, out_stream: ?*std.Io.Writer, err_stream: ?*std.Io.Writer) void {
    streams = .{ .io = io, .out = out_stream, .err = err_stream };
}

/// Point **standard error alone** at a writer, and give back the one it had.
///
/// ## Why this is not `useStreams`
///
/// `useStreams` writes both, and a caller that wants to move one has no way to
/// read the other first. `src/ui.zig` is that caller: while a display is up,
/// standard output belongs to `Frames`, which is how a frame reaches the
/// terminal at all. A display that called `useStreams` to take standard error
/// would take standard output away from itself with the same call.
///
/// ## Why the old writer comes back rather than being remembered here
///
/// The display puts it back in `stop`, and a second piece of process state
/// saying which writer to go back to would be a second answer to a question the
/// caller already knows. `Capture` in this file replaces both and restores
/// both, which is a different shape for a different job: a test owns the whole
/// process while it runs, and a display shares it with `main`.
///
/// **Not a silencer.** A warning written while a display is up used to land on
/// the alternate screen and be painted over by the next frame, which lost it.
/// The writer a display installs turns each line into a row of its transcript,
/// so the line is read rather than erased. See `src/ui.zig`'s `Diagnostics`.
pub fn useErrStream(io: std.Io, err_stream: ?*std.Io.Writer) ?*std.Io.Writer {
    const was = streams.err;
    streams.io = io;
    streams.err = err_stream;
    return was;
}

/// Everything one command wrote, for a test that calls one.
///
/// ## Why this exists at all
///
/// **A test that lets a command's lines reach the terminal is not checking
/// them.** It is also a fault in the build log: `zig build` prints a
/// `failed command:` line for any run step that wrote to standard error,
/// whatever that step's exit status, so a note from a suite that passed reads
/// exactly like a suite that failed. `test/proto/lock.zig` states that in full
/// and is the test that enforces it.
///
/// A command function called from a test has no streams set, so every line it
/// writes falls back to the real standard error of the test binary: see
/// `streams`. This is the seam's own answer. A test opens one of these, calls
/// the command, and reads the two streams apart afterwards.
///
/// ## Two buffers and not one
///
/// The tests below this file use one buffer on purpose, because what they pin
/// is an order across the two streams. A test of a command wants the opposite:
/// which stream a line went to. `chock sessions` puts its rows on standard
/// output so a pipe can read them and its refusals on standard error, and a
/// capture with one buffer could not tell those apart.
///
/// ## Built in place
///
/// Each tap holds the address of the sink beside it, so a `Capture` returned by
/// value would leave both aimed at the temporary it was copied out of. `start`
/// therefore takes a pointer and fills it in.
pub const Capture = struct {
    out_sink: TerminalSink,
    err_sink: TerminalSink,
    out_tap: TerminalSink.Tap,
    err_tap: TerminalSink.Tap,

    /// Point both streams at this capture's own buffers.
    ///
    /// **`configure` is not touched**, so a test that wants colour off, or
    /// `--verbose` on, still says so itself. What this owns is where the bytes
    /// go and nothing about how they are painted.
    pub fn start(self: *Capture, io: std.Io, gpa: std.mem.Allocator) void {
        self.out_sink = .{ .gpa = gpa };
        self.err_sink = .{ .gpa = gpa };
        self.out_tap = self.out_sink.tap(&.{});
        self.err_tap = self.err_sink.tap(&.{});
        useStreams(io, &self.out_tap.writer, &self.err_tap.writer);
    }

    /// Put the streams back and free what was kept. **On every path out of a
    /// test**, because the next test in the binary would otherwise write into a
    /// buffer that has gone.
    pub fn stop(self: *Capture, io: std.Io) void {
        useStreams(io, null, null);
        self.out_sink.deinit();
        self.err_sink.deinit();
    }

    /// What went to standard output: the rows a pipe would read.
    pub fn out(self: *const Capture) []const u8 {
        return self.out_sink.bytes.items;
    }

    /// What went to standard error: every `chock:` line.
    pub fn err(self: *const Capture) []const u8 {
        return self.err_sink.bytes.items;
    }

    /// Forget what has been written so far, so one test can read two commands
    /// apart without opening a second capture.
    pub fn clear(self: *Capture) void {
        self.out_sink.bytes.clearRetainingCapacity();
        self.err_sink.bytes.clearRetainingCapacity();
    }
};

/// Held for the whole of one message, on either stream.
///
/// **`chock daemon` has threads**, and each session it starts is watched by one
/// of them, so two can report at once. A message is an escape, a text, and a
/// reset, and standard output is a buffer another thread can be draining, so
/// none of that may be split. `std.debug.lockStderr` used to give exactly this,
/// and taking the writers away from `std.debug` took it away with them.
///
/// **One lock for both streams, and not one each.** The ordering rule makes
/// `print` touch standard output before it touches standard error, so two locks
/// would be two locks taken in an order by one caller, which is where deadlocks
/// come from.
///
/// **Never taken in a signal handler.** See this file's own top comment:
/// `src/interrupt.zig` writes its one line with a raw `write` syscall and takes
/// no lock, because a handler that waits on a lock the interrupted thread holds
/// never returns.
var lock: std.Io.Mutex = .init;

/// Take the lock, when there is an `Io` to wait with.
///
/// **A process with no `Io` set has no threads either**: `useStreams` is what
/// brings both, and the only code that runs before it is single threaded by
/// construction. So skipping the lock there guards nothing that needs guarding.
fn take() void {
    const io = streams.io orelse return;
    lock.lockUncancelable(io);
}

fn release() void {
    const io = streams.io orelse return;
    lock.unlock(io);
}

/// Send some bytes to standard output, unranked and unformatted.
///
/// **For a caller that streams bytes it did not compose here**: `src/run.zig`'s
/// `Printer`, which shows the model's answer as it arrives and never paints it,
/// and `src/approval.zig`'s prompt. Both used to write straight to the
/// descriptor, which is what breaks the order now that standard output holds
/// bytes that have not left yet.
///
/// False when no stream is set at all, so a caller that has its own idea of
/// where the bytes should go can use it. See `streams`.
pub fn writeOut(bytes: []const u8) bool {
    take();
    defer release();
    const stream = streams.out orelse return false;
    // A stream that went away, for example a pipe into `head`, must not end a
    // session that is doing real work.
    stream.writeAll(bytes) catch {};
    return true;
}

/// Push what standard output is holding out to the descriptor.
///
/// `main` calls this with `defer`, and `print` calls it before every write to
/// standard error. See this file's own top comment for why the second one is
/// the whole ordering rule.
pub fn flushOut() void {
    take();
    defer release();
    flushOutHoldingLock();
}

/// `flushOut`, for a caller that already holds the lock. `std.Thread.Mutex` is
/// not recursive, so `print` cannot simply call `flushOut`.
fn flushOutHoldingLock() void {
    const stream = streams.out orelse return;
    stream.flush() catch {};
}

/// Print one ranked message on **standard output**: a row of a table, the text
/// of a note, a help page. What another program would read.
///
/// Ranked with the standard output painter, which is decided from whether
/// standard output is a terminal and never from standard error.
pub fn out(rank: Rank, comptime fmt: []const u8, args: anytype) void {
    take();
    defer release();
    const paint = stdoutPainter();
    const stream = streams.out orelse return printThroughDebug(paint, rank, fmt, args);
    write(stream, paint, rank, fmt, args);
}

/// How many times something has been written straight at the terminal, past
/// whatever is drawing on it.
///
/// **A full screen display has to be told, and it cannot see this itself.** The
/// display keeps a copy of what each cell holds and sends only the cells that
/// changed. A warning printed on standard error scrolls the real screen and
/// changes not one cell of that copy, so the next frame would send nothing and
/// leave the display wrong until something else happened to move. A reader that
/// sees this number change repaints every cell once. See `src/ui.zig`.
///
/// **An atomic, because one of the two writers is a signal handler.**
/// `src/interrupt.zig` prints its own line with the raw write syscall, and an
/// add on an atomic is the whole of what it does here: no lock, no allocation,
/// and nothing that can be left half done between two instructions.
var scrolled: std.atomic.Value(u32) = .init(0);

/// How many lines have gone past a display. See `scrolled`.
pub fn scrollCount() u32 {
    return scrolled.load(.monotonic);
}

/// Say that a line went straight to the terminal, past any display.
///
/// **Safe from a signal handler**, and that is the only reason it is public:
/// `src/interrupt.zig` writes its first press line with a raw syscall, which
/// this file's own writers never see. Every other writer here calls it itself.
pub fn noteScroll() void {
    _ = scrolled.fetchAdd(1, .monotonic);
}

/// Print one ranked message on **standard error**: a warning, a refusal, a
/// fault, a `--verbose` line. What a person reads.
///
/// **A `plain` message is byte for byte what `std.debug.print` writes.** So a
/// call site that is genuinely unranked may use the plain rank without being a
/// second convention: it is what the line always was.
///
/// **Standard output is flushed first**, so the two streams reach one terminal
/// in the order they were written. See this file's own top comment.
pub fn print(rank: Rank, comptime fmt: []const u8, args: anytype) void {
    take();
    defer release();
    flushOutHoldingLock();
    // Counted before the write, so a display that reads it can never see the
    // bytes on screen without having been told they are there. See `scrolled`.
    noteScroll();
    const paint = stderrPainter();
    const stream = streams.err orelse return printThroughDebug(paint, rank, fmt, args);
    write(stream, paint, rank, fmt, args);
}

/// The escape, the text, and the reset, in that order.
///
/// **One call per piece and not three prints**, because `chock daemon` has
/// threads: a line broken into three writes can take another thread's line
/// between them and leave a colour open across it.
///
/// A failed write is dropped. A terminal that went away, for example a pipe
/// into `head`, must not end a session that is doing real work, and the session
/// log still holds every one of these bytes.
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

/// The fallback for a stream nobody has set. See `streams`.
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

/// Which of the two streams, for a caller that has to choose while it runs.
pub const Stream = enum { out, err };

/// Print one ranked message on the stream `stream` names.
///
/// **For the caller whose stream is not known when it is compiled.** A usage
/// text is the answer when a person typed `--help` and a complaint when they
/// mistyped a command, and it is one block of text either way: see
/// `src/main.zig`'s `printUsage`. Every other call site knows which stream it
/// is and says so by calling `out` or `print`.
pub fn say(stream: Stream, rank: Rank, comptime fmt: []const u8, args: anytype) void {
    switch (stream) {
        .out => out(rank, fmt, args),
        .err => print(rank, fmt, args),
    }
}

/// A line that says a healthy run is healthy. Printed only with `--verbose`.
///
/// **Nothing is deleted, it moves.** Every line this now hides was added
/// because something was once invisible, so each one has a command that answers
/// the same question when somebody asks: `chock sessions`, `chock cache`,
/// `chock usage`, and `chock memory`. A line whose fact no command can answer
/// does not belong here.
pub fn detail(comptime fmt: []const u8, args: anytype) void {
    if (!state.verbose) return;
    print(.dim, fmt, args);
}

/// Why nothing was read.
pub const SecretError = error{
    /// Standard input is not a terminal, so there is nobody to prompt. **The
    /// caller must have already known this**: a caller that reaches this had
    /// written a prompt to a pipe.
    NotATerminal,
    /// The terminal would not turn its echo off, so nothing was asked.
    /// **Nothing is read in this state**: a secret must not be shown on screen.
    EchoStuck,
    /// The line could not be read at all.
    Unreadable,
    /// Nothing was typed. A person pressing Enter or Ctrl-D lands here, and it
    /// is a refusal.
    Empty,
    /// More was typed than `out` holds. **Refused and never cut short**: half
    /// of a PIN is a wrong PIN, and a card counts a wrong PIN against a counter
    /// that blocks after three.
    TooLong,
};

/// The terminal settings a secret is typed under.
///
/// **`ECHONL` as well as `ECHO`.** A terminal in canonical mode echoes the
/// newline through `ECHONL` even with `ECHO` off, which would put the end of the
/// typing on screen. `src/ui.zig`'s own `quietOf` clears the same two bits for
/// the same reason.
///
/// **Nothing else comes off.** The terminal stays canonical, so it goes on doing
/// the line editing a person expects and a backspace still works, and `ISIG`
/// stays on, so Ctrl-C is still a signal and not a byte in the answer.
///
/// A function and not four lines inside `readSecret`, because a test cannot open
/// a terminal and this is the part that must be right.
pub fn secretTermios(was: std.posix.termios) std.posix.termios {
    var quiet = was;
    quiet.lflag.ECHO = false;
    quiet.lflag.ECHONL = false;
    return quiet;
}

/// Read one line with the terminal's echo off, into `into`, and answer the part
/// that was used.
///
/// **The echo is put back whatever happens**, including on a Ctrl-C: the
/// settings are handed to `src/interrupt.zig` before the read and taken back
/// after it, so the handler puts them back on the way out. Without that, a
/// person who interrupts a prompt is left with a shell that shows nothing they
/// type.
///
/// **`tcsetattr` is given `FLUSH`**, so whatever was typed and not yet read is
/// thrown away rather than left in the terminal's line buffer for the next
/// program to read. That is the second half of the same fault.
///
/// **Only `ECHO` and `ECHONL` come off.** The terminal stays in its canonical
/// mode, so it goes on doing the line editing a person expects, and `ISIG` stays
/// on, so Ctrl-C is still a signal and not a byte. See `src/ui.zig`'s `quietOf`,
/// which makes the same two bits the whole of the change for the same reason.
///
/// **The bytes are read one at a time into `into` and into nothing else.** A
/// buffered reader would leave a copy of the secret in a buffer this function
/// does not own. A PIN is eight bytes, so the cost is eight system calls.
pub fn readSecret(io: std.Io, question: []const u8, into: []u8) SecretError![]const u8 {
    const fd = std.posix.STDIN_FILENO;
    const original = std.posix.tcgetattr(fd) catch return error.NotATerminal;

    std.posix.tcsetattr(fd, .FLUSH, secretTermios(original)) catch return error.EchoStuck;
    interrupt.armTerminalSettings(fd, original);
    defer {
        std.posix.tcsetattr(fd, .FLUSH, original) catch {};
        interrupt.disarmTerminalSettings();
        // The person's own newline was swallowed with the echo, so put one
        // back: without it the next line starts beside the prompt.
        print(.plain, "\n", .{});
    }

    // The question goes through this file's own stream, the one every other
    // thing a person needs goes through, so `chock sessions seal > file` still
    // shows the prompt and a test can read it back with `Capture`.
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

/// The two options every subcommand takes, listed once. Appended to each
/// subcommand's own usage text, so a person reading `chock usage --help` is
/// told about them where they are looking.
pub const options_text =
    \\  --verbose           Also print what a healthy run does not need: the log
    \\                      path, the dev shell, the toolchain cache, and the rest.
    \\  --color=<when>      auto (the default), always, or never. auto means colour
    \\                      when the stream is a terminal that can show it.
    \\
;

/// What `takeGlobalFlags` gives back: the arguments with `--verbose` and
/// `--color=` removed, and what those two said.
pub const Global = struct {
    args: []const []const u8,
    choice: Choice = .auto,
    verbose: bool = false,
};

pub const FlagError = error{BadColorValue} || std.mem.Allocator.Error;

/// Take `--verbose` and `--color=<when>` off a subcommand's arguments.
///
/// **Handled here and not in each subcommand's own parser**, because a colour
/// flag that only `chock run` understood would be the beginning of two
/// conventions, which is the fault this whole file exists to avoid.
///
/// **Only the `--color=value` spelling, and never `--color value`.** `chock
/// run` takes the message as free words, so a two word form would eat the first
/// word of `chock run --color fix the parser`. The `=` form cannot.
///
/// **`--` ends the scan**, the same rule `chock run`'s own parser already
/// keeps, so a word after it reaches the subcommand untouched.
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
    // The property the whole file exists for: `chock run > out.txt` and
    // `chock sessions | grep` hold no escape sequence.
    try testing.expect(!decide(.{ .stream_is_tty = false, .term = "xterm-256color" }));
    try testing.expect(decide(.{ .stream_is_tty = true, .term = "xterm-256color" }));
}

test "NO_COLOR turns colour off on a terminal, and an empty NO_COLOR does not" {
    // no-color.org: present and not an empty string, whatever the value is. An
    // empty value is not a "no", or a shell that exports an unset variable
    // would silence every program on the machine.
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
    // The order in `decide` is the rule, and this is what it buys. `always` is
    // what a person piping into `less -R` types, and it has to win over an
    // environment that was set long before this command line was.
    try testing.expect(!decide(.{ .choice = .never, .stream_is_tty = true, .term = "xterm" }));
    try testing.expect(!decide(.{ .choice = .never, .clicolor_force = "1", .term = "xterm" }));

    try testing.expect(decide(.{ .choice = .always, .stream_is_tty = false }));
    try testing.expect(decide(.{ .choice = .always, .stream_is_tty = false, .no_color = "1" }));
    try testing.expect(decide(.{ .choice = .always, .stream_is_tty = false, .term = "dumb" }));
}

test "CLICOLOR_FORCE turns colour on for a pipe, and CLICOLOR_FORCE=0 does not" {
    try testing.expect(decide(.{ .stream_is_tty = false, .clicolor_force = "1" }));
    try testing.expect(decide(.{ .stream_is_tty = false, .clicolor_force = "yes" }));

    // Set to "0" is the one value that means "do not force", so the stream
    // decides again, and a pipe is still a pipe.
    try testing.expect(!decide(.{ .stream_is_tty = false, .clicolor_force = "0" }));
    try testing.expect(!decide(.{ .stream_is_tty = false, .clicolor_force = "" }));

    // NO_COLOR is read before CLICOLOR_FORCE, so the two together are a no.
    try testing.expect(!decide(.{ .stream_is_tty = false, .clicolor_force = "1", .no_color = "1" }));
}

test "a painter that is off writes no byte for any rank, and one that is on writes an escape" {
    // Mutation check: this fails if `Painter.open` ever returns a sequence for
    // an off painter, which is the one way a pipe could get an escape.
    for ([_]Rank{ .plain, .dim, .warn, .err }) |rank| {
        try testing.expectEqualStrings("", Painter.off.open(rank));
        try testing.expectEqualStrings("", Painter.off.close(rank));
    }

    // Plain is plain even with colour on, so an ordinary line is byte for byte
    // what it was before this file existed.
    try testing.expectEqualStrings("", Painter.colour.open(.plain));
    try testing.expectEqualStrings("", Painter.colour.close(.plain));

    for ([_]Rank{ .dim, .warn, .err }) |rank| {
        try testing.expect(Painter.colour.open(rank).len != 0);
        try testing.expectEqualStrings("\x1b[0m", Painter.colour.close(rank));
    }
}

test "the three coloured ranks look different from each other" {
    // A warning that painted the same as a healthy fact would leave the reader
    // exactly where they started: reading every line to find the one that
    // matters.
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
    // `chock run -- --verbose` asks the agent about the word, and does not turn
    // the option on. The same rule `chock run`'s own parser keeps for every
    // other option.
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
    // **And the refusal names the three**, because a person who typed a fourth
    // word cannot guess them. Captured rather than let through: a test that let
    // the line reach the terminal would not be reading it, and it would put a
    // `failed command:` line in the build log of a suite that passed. See
    // `Capture`, and `test/proto/lock.zig`.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var said: Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadColorValue,
        takeGlobalFlags(arena_state.allocator(), &.{"--color=maybe"}),
    );

    // A refusal is a diagnostic, so it goes to standard error and never into
    // the rows a pipe reads.
    try testing.expectEqualStrings("", said.out());
    try testing.expect(std.mem.indexOf(u8, said.err(), "maybe") != null);
    for ([_][]const u8{ "auto", "always", "never" }) |one| {
        try testing.expect(std.mem.indexOf(u8, said.err(), one) != null);
    }
}

test "the two painters are decided one stream at a time" {
    // `chock run > answer.txt` on a terminal: standard output is a file and
    // standard error is a terminal. A helper that asked about standard output
    // in general would colour the warning wrongly in both directions.
    defer configure(.{});

    configure(.{ .stdout_is_tty = false, .stderr_is_tty = true, .term = "xterm-256color" });
    try testing.expect(!stdoutPainter().on);
    try testing.expect(stderrPainter().on);

    configure(.{ .stdout_is_tty = true, .stderr_is_tty = false, .term = "xterm-256color" });
    try testing.expect(stdoutPainter().on);
    try testing.expect(!stderrPainter().on);
}

/// One buffer standing in for the terminal both streams reach, holding the
/// bytes in the order they actually arrived at it.
///
/// **Not two separate buffers**, because the fact under test is an order across
/// the two streams, and two buffers cannot hold an order between them. This is
/// the same shape the real program has: a buffered standard output and an
/// unbuffered standard error, both ending at one place.
const TerminalSink = struct {
    gpa: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    fn deinit(self: *TerminalSink) void {
        self.bytes.deinit(self.gpa);
    }

    /// A writer into this sink. `buffer` decides whether it is buffered:
    /// standard output gets one, standard error gets an empty slice, which is
    /// what makes its `flush` a no-op.
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
            // The contract in `std.Io.Writer.VTable.drain`: what is already
            // buffered goes first, then each slice of `data` in order, and the
            // last slice is repeated `splat` times.
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
    // The mechanism the whole startup triage rests on. Mutation check: drop the
    // guard in `detail` and the first half of this fails.
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
    // The point of the whole change. Before it, `std.debug.print` sent both to
    // standard error, so `chock sessions | grep` read an empty pipe.
    //
    // Mutation check: point `out` at the standard error stream and the first
    // two expectations swap; drop the split entirely and both fail.
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
    // The ordering rule, and the only test that can see it: two rows, then a
    // warning, then a third row. Standard output is buffered here exactly as
    // `main` buffers it, so without the flush in `print` the warning would
    // reach the terminal first and the three rows would arrive after it.
    //
    // Mutation check: delete the `flushOut()` call at the top of `print` and
    // this fails with the warning at the front.
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
    // Why `main` gives standard error a zero length buffer: `std.Io.Writer`
    // says a zero length buffer makes `flush` a no-op, and the bytes therefore
    // went out on the write itself. So a fault cannot be lost by whatever
    // happens next, and no path needs to remember to flush it.
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
    // Nothing has been flushed, and it is already there.
    try testing.expectEqualStrings("chock: it failed\n", terminal.bytes.items);

    // And a row written now is still held, which is what says the buffering is
    // real and this test is not passing because both streams are unbuffered.
    out(.plain, "a row\n", .{});
    try testing.expectEqualStrings("chock: it failed\n", terminal.bytes.items);
    flushOut();
    try testing.expectEqualStrings("chock: it failed\na row\n", terminal.bytes.items);
}

test "a piped standard output gets no escape sequence while a terminal standard error still does" {
    // `chock sessions | grep` with the errors still on a terminal. The two
    // painters are decided one stream at a time, and `out` has to use the
    // standard output one. Mutation check: give `out` the standard error
    // painter and the row arrives wrapped in escapes.
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

    // Not one byte of escape on the pipe, whatever rank the caller asked for.
    try testing.expectEqualStrings("a row that asked for a rank\n", rows.bytes.items);
    try testing.expect(std.mem.indexOf(u8, rows.bytes.items, "\x1b") == null);

    // And the terminal on the other stream is unaffected by it.
    try testing.expectEqualStrings("\x1b[33ma warning\n\x1b[0m", diagnostics.bytes.items);
}

test "a plain line carries no escape on either stream, so an unranked call site is unchanged" {
    // The property that lets a call site stay plain rather than become a second
    // convention: with colour fully on, a plain line is byte for byte what
    // `std.debug.print` wrote before any of this existed.
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
    // The fallback path in `streams`. A command that writes before `main` has
    // wired anything must not crash, there is nothing to push, and a caller
    // that streams raw bytes has to be told they went nowhere so it can send
    // them itself. `src/run.zig`'s `Printer` and `src/approval.zig`'s prompt
    // both read this answer.
    //
    // Mutation check: make `writeOut` return true whatever `streams.out` is and
    // this fails, and the model's answer would be dropped instead of printed.
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
    // What a display needs and `useStreams` cannot give it: standard output
    // still reaches the frames writer while standard error is diverted, and the
    // old writer comes back so `stop` can put it back.
    //
    // Mutation check: set `streams.out` to null here as `useStreams` would and
    // the second expectation fails, which is a display that stopped drawing the
    // moment it took the warnings.
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
    // Standard output was never touched, which is the whole reason this is not
    // `useStreams`.
    try testing.expectEqualStrings("a frame\n", frames.bytes.items);
    try testing.expectEqualStrings("", real.bytes.items);

    // And putting it back sends the next warning where it always went.
    _ = useErrStream(testing.io, was);
    print(.warn, "a warning with no display\n", .{});
    try testing.expectEqualStrings("a warning with no display\n", real.bytes.items);
    try testing.expectEqualStrings("a warning under a display\n", rows.bytes.items);
}

test "a warning through a moved standard error is still counted as a scroll" {
    // **The count is what a display reads to decide it must repaint**, and a
    // display that installed its own writer no longer needs that repaint for its
    // own warnings. `src/interrupt.zig` writes its first press line with a raw
    // syscall that no writer here can see, so the count has to keep meaning what
    // it meant.
    //
    // Mutation check: move `noteScroll` in `print` behind the stream lookup and
    // this fails.
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
    // The safe direction. `Settings` is all defaults here, which is the shape
    // `main` builds when there is no terminal, no `TERM`, and no flag, and it
    // has to come out silent rather than coloured.
    defer configure(.{});
    configure(.{});
    try testing.expect(!stdoutPainter().on);
    try testing.expect(!stderrPainter().on);
    try testing.expect(!verbose());
}

test "a secret is typed with the echo off and with everything else left alone" {
    // **The fault this is about**: a PIN left on screen. `ECHO` and `ECHONL` are
    // separate bits and a terminal in canonical mode echoes the newline through
    // the second one, so clearing only the first still shows where the typing
    // ended.
    //
    // **A fact and not a `tcsetattr`**, because a test binary has no terminal to
    // set. `src/interrupt.zig` keeps its own settings test the same way.
    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ECHONL = true;
    was.lflag.ISIG = true;
    was.lflag.ICANON = true;

    const quiet = secretTermios(was);
    try testing.expect(!quiet.lflag.ECHO);
    try testing.expect(!quiet.lflag.ECHONL);
    // Ctrl-C is still a signal, so a person can leave the prompt, and the
    // terminal still does the line editing they expect.
    try testing.expect(quiet.lflag.ISIG);
    try testing.expect(quiet.lflag.ICANON);
    // And the settings that come back are the ones that went in, so the `defer`
    // in `readSecret` puts the terminal back as it found it.
    try testing.expect(was.lflag.ECHO);
}
