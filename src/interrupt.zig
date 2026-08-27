//! Ctrl-C, and the one thing a signal handler is allowed to do about it.
//!
//! **A log that stops with no `session.end` cannot be told apart from a
//! process that died mid write.** `chock_core.Loop.run`'s own doc comment
//! promises a `session.end` in every case, so a reader never finds a session
//! that stops mid conversation with nothing saying why, and an interrupt was
//! the one case that broke that promise: a signal does not run a deferred
//! append, so a real log of a killed session ends on a `tool.result` and says
//! nothing at all. Anything replaying that log, `--continue` included, then
//! has to guess.
//!
//! ## What a handler may do here, and what it may not
//!
//! **It sets one flag and writes one line, and that is all.** A signal handler
//! runs between any two instructions of the program it interrupts, so the
//! session log's exclusive lock may be held at that moment, an allocator may
//! be halfway through a free, and `std.Io` may be inside a syscall. Appending
//! an event from here would take a lock the interrupted code already holds,
//! and allocate underneath an allocator that is not in a state to allocate.
//! So the handler does neither. `Loop.run` reads the flag at its own safe
//! points, where it already holds the lock legitimately, and writes the event
//! there: see `chock_core.Loop.Deps.canceled`.
//!
//! The one line it writes goes out with the raw write syscall rather than
//! through a formatter, for the same reason: a formatter allocates and locks,
//! and a raw write does neither.
//!
//! ## Two presses, because the first one is not always quick
//!
//! The first press asks the session to stop, and the session stops at its next
//! safe point: between two turns, or between two tool calls. It is not
//! instant. A model call already in flight is read to its end first, which
//! with a slow provider is a wait the user did not ask for.
//!
//! So the second press restores the signal's own default and raises it again,
//! which ends the process exactly as it would have ended with no handler here
//! at all. **That leaves a log with no `session.end`, which is the state this
//! file exists to avoid**, and it is still the right answer for a second
//! press: a user pressing it twice is saying they want out now, and refusing
//! would be worse than an incomplete log. The message the first press prints
//! says both halves, so nobody has to guess which press does what.
//!
//! ## The second press has to end the running tool call itself
//!
//! **A terminal sends `SIGINT` to its whole foreground process group.** So
//! before `Sandbox.spawn` put a call in a group of its own, one press reached
//! the loop *and* killed whatever program the session was running, which made
//! the first press message a false promise: the work did not continue to a
//! safe point, it died on that press. The sandbox now takes a group of its
//! own, and the first press means what it says.
//!
//! That leaves the second press with work it used to get from the terminal
//! for free. Nothing from the keyboard reaches the call any more, so this
//! file ends it, through `chock_core.tools.cancelRunningTool`, before it ends
//! the process. A call nobody can stop with the key they just pressed twice
//! is a runaway, and that would be a worse fault than the one the group fixed.

const std = @import("std");
const builtin = @import("builtin");
const chock_core = @import("chock-core");
const tty = @import("tty.zig");

/// What the first press prints. A plain sentence, written with one syscall:
/// see this file's own top comment.
pub const first_message = "\nchock: stopping at the next safe point, and writing the session end. " ++
    "Press Ctrl-C again to stop now.\n";

/// Where that sentence goes.
///
/// **A number and not a stream, because a signal handler writes it.** The
/// handler may not allocate and may not take a lock, so it cannot go through
/// `src/tty.zig`; it writes the bytes with one raw syscall on this descriptor.
/// Standard error is the real answer and the only one a real run ever has.
///
/// **A test points it at a file of its own**, for two reasons. The first is
/// that a test which let this line through would be writing to the test
/// binary's own standard error, which `test/proto/lock.zig` forbids for the
/// whole project. The second is better: nothing checked the sentence at all
/// before, and a test that captures it can read what a person is told.
///
/// An atomic, because the handler reads it and a test writes it, and a plain
/// load is all a handler may do.
var message_fd: std.atomic.Value(i32) = .init(std.posix.STDERR_FILENO);

/// Send the first press's line somewhere a test can read. **Only a test may
/// call this.** It gives the descriptor back so the caller can put it as it
/// was.
pub fn messageToForTest(fd: std.posix.fd_t) std.posix.fd_t {
    return message_fd.swap(fd, .monotonic);
}

/// What puts a terminal back after a full screen display was on it: show the
/// cursor, leave the alternate screen, and reset the graphic attributes.
///
/// **A constant, because the second press writes it from a signal handler.**
/// The handler may not allocate, may not lock and may not call into the display
/// library, so it cannot ask the display to tear itself down. Three escape
/// sequences it can write with one syscall are what it can do, and they are
/// exactly what the display's own teardown writes: `src/ui.zig` pins that
/// against a real phantom session rather than against a copy of this list.
///
/// Restoring a terminal that was never switched is harmless, and the flag below
/// makes sure this is never written at all unless a display really took over.
pub const restore_bytes = "\x1b[?25h" ++ "\x1b[?1049l" ++ "\x1b[0m";

/// Whether a full screen display owns standard output right now.
///
/// **Never write `restore_bytes` without it.** A run whose standard output is a
/// pipe or a file has no display and no screen to put back, and three escape
/// sequences written into that pipe would be exactly the corruption
/// `src/tty.zig` exists to keep out of one.
var display_up: std.atomic.Value(bool) = .init(false);

/// Say that a full screen display has taken standard output, so a second press
/// puts the terminal back before it ends the process. See `restore_bytes`.
pub fn armTerminalRestore() void {
    display_up.store(true, .monotonic);
}

/// Say that the display has gone. Called on every path that takes it down, so
/// a press after that writes nothing at a terminal already put back.
pub fn disarmTerminalRestore() void {
    display_up.store(false, .monotonic);
}

/// The settings the terminal had before the display took it.
///
/// **A plain variable beside an atomic, and not an atomic itself.** A `termios`
/// is a structure and no machine has an atomic load of one. `settings_fd` is
/// what the handler tests, and it is written after this and cleared before it,
/// so a handler that finds a descriptor finds settings that were complete
/// before it was stored.
var saved_settings: std.posix.termios = undefined;

/// Which descriptor `saved_settings` belongs to, or -1 when no display holds a
/// terminal's settings. See `armTerminalSettings`.
var settings_fd: std.atomic.Value(i32) = .init(-1);

/// Say what the terminal's settings were, so a second press puts them back.
///
/// **The escape sequences are not enough on their own.** A session runs its
/// turns with the echo off, because `ISIG` and `ECHO` are separate bits and only
/// the first may come back while a turn runs: see `src/ui.zig`'s `quietOf`. A
/// process that ended there would leave a shell that shows nothing a person
/// types, which is exactly the state `restore_bytes` exists to avoid for the
/// screen.
pub fn armTerminalSettings(fd: std.posix.fd_t, was: std.posix.termios) void {
    saved_settings = was;
    settings_fd.store(fd, .monotonic);
}

/// Say that nothing holds the terminal's settings any more. Called on every
/// path that puts them back, so a press after that writes nothing at a terminal
/// already put back.
pub fn disarmTerminalSettings() void {
    settings_fd.store(-1, .monotonic);
}

/// A terminal whose settings a second press has to put back, and what to put
/// them back to.
pub const Armed = struct {
    fd: std.posix.fd_t,
    was: std.posix.termios,
};

/// What the second press puts the terminal's settings back to, or null when no
/// display holds any.
///
/// **A function and not an `if` inside the handler**, for the same reason
/// `restoreBytesIfArmed` is one: the handler ends the process on the line after
/// it runs, so nothing can watch it from the inside and the decision has to be
/// somewhere a test can reach.
pub fn settingsIfArmed() ?Armed {
    const fd = settings_fd.load(.monotonic);
    if (fd < 0) return null;
    return .{ .fd = fd, .was = saved_settings };
}

/// Put the terminal's settings back, if a display took them.
///
/// **A signal handler may call this.** `tcsetattr` is one of the calls POSIX
/// names as safe from a handler: it allocates nothing and takes no lock of this
/// program's. A device that refuses is dropped for the reason every other write
/// on this path is: a terminal that has gone away must not turn a Ctrl-C into a
/// crash.
pub fn restoreTerminalSettings() void {
    const armed = settingsIfArmed() orelse return;
    std.posix.tcsetattr(armed.fd, .FLUSH, armed.was) catch {};
}

/// What the second press writes before it re-raises, or null when no display is
/// up and there is nothing to put back.
///
/// **A function and not an `if` inside the handler**, because the handler ends
/// the process on the line after this one: nothing can watch it from the inside,
/// so the decision has to be somewhere a test can reach. See `display_up`.
pub fn restoreBytesIfArmed() ?[]const u8 {
    if (!display_up.load(.monotonic)) return null;
    return restore_bytes;
}

/// Whether a session has been asked to stop. **Read, never taken**: a caller
/// that cleared it would make a second reader believe nothing happened.
var stop_asked: std.atomic.Value(bool) = .init(false);

/// The signals `install` handles. `INT` is Ctrl-C. `TERM` is what a service
/// manager sends, and a session killed by one deserves the same readable log
/// ending as one a person stopped.
const handled = [_]std.posix.SIG{ .INT, .TERM };

/// Whether the session should stop now. This is the shape
/// `chock_core.Loop.Deps.canceled` wants, so it is passed there by name.
pub fn requested() bool {
    return stop_asked.load(.monotonic);
}

/// Ask the session to stop, from ordinary code rather than from a signal.
///
/// **Closing a window is a Ctrl-C.** The window a display draws in has a close
/// button, and no signal is sent when a person presses it. A session that went
/// on running with nothing showing it would be exactly the runaway this file's
/// own top comment is about, so `src/ui.zig` says so here and the loop stops at
/// its next safe point with a `session.end` written, the same as any other stop.
///
/// **Only sets the flag**, so this and the handler have one behaviour between
/// them and there is no second path to reason about.
pub fn requestStop() void {
    stop_asked.store(true, .monotonic);
}

/// Forget that a stop was asked for. **Only a test may call this**: inside a
/// session there is no such thing as un-asking, and a caller that cleared the
/// flag would hide a user's own Ctrl-C from the loop.
pub fn forgetForTest() void {
    stop_asked.store(false, .monotonic);
}

/// Handle `handled` from here on. Safe to call more than once.
pub fn install() void {
    // Windows has no `sigaction`, and Chock builds for Linux and Darwin only. A
    // build for anything else keeps the old behaviour rather than failing to
    // compile over a signal.
    if (builtin.os.tag == .windows) return;

    const action = std.posix.Sigaction{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        // **No `SA_RESTART`.** A restarted syscall would hide the signal from
        // a read that is already waiting, and the point of the flag is that
        // the loop notices.
        .flags = 0,
    };
    for (handled) |sig| std.posix.sigaction(sig, &action, null);
}

/// The handler itself. See this file's own top comment for the two things it
/// is allowed to do.
fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    if (stop_asked.swap(true, .monotonic)) {
        // The second press. End every running tool call first, because
        // nothing else reaches one now that the sandbox has a process group
        // of its own: see this file's own top comment, and
        // `chock_core.tools.cancelRunningTool` for why a fixed number of
        // atomic reads and signals are all a handler may do here, and for the
        // one narrow race that call leaves, which the re-raise below is part
        // of the argument for. Every call and not one: a background task runs
        // beside the foreground call, and "stop now" cannot leave a build
        // running. Does nothing when no call is running.
        chock_core.tools.cancelRunningTool();

        // Put the terminal back before the process ends, because the raise
        // below runs no deferred teardown and a shell left on the alternate
        // screen with a hidden cursor is a shell the user has to fix by hand.
        // Standard output and not standard error: that is the descriptor the
        // display drew on. The result is dropped for the same reason the line
        // below drops its own: a terminal that has gone away must not turn a
        // Ctrl-C into a crash.
        if (restoreBytesIfArmed()) |bytes| {
            _ = std.posix.system.write(std.posix.STDOUT_FILENO, bytes.ptr, bytes.len);
        }

        // And the terminal's own settings, which the escape sequences above say
        // nothing about: a turn runs with the echo off, so a shell handed back
        // here would show nothing a person types. See `armTerminalSettings`.
        restoreTerminalSettings();

        // Put the signal back the way it was and raise it again, so the
        // process ends exactly as it would have with no handler installed at
        // all.
        const default = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.DFL },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(sig, &default, null);
        std.posix.raise(sig) catch {};
        return;
    }
    // This line goes past whatever is drawing on the terminal, so a full screen
    // display has to be told to paint every cell again. An add on an atomic is
    // all this does, which is the whole of what a handler may do: see
    // `src/tty.zig`'s `scrolled`.
    tty.noteScroll();
    // The raw syscall, and its result is deliberately dropped: a terminal that
    // has gone away must not turn a Ctrl-C into a crash. See `message_fd` for
    // why the descriptor is read out of a variable rather than named here.
    _ = std.posix.system.write(message_fd.load(.monotonic), first_message.ptr, first_message.len);
}

const testing = std.testing;

/// Take the line the handler writes, instead of letting it reach the test
/// binary's own standard error.
///
/// **A file and not a buffer**, because the handler writes with one raw
/// syscall and there is no stream in this program for it to go through: see
/// `message_fd`. The caller reads the file back afterwards, which is what makes
/// the sentence itself something a test checks rather than something a person
/// sees scroll past in a build log.
const Said = struct {
    tmp: testing.TmpDir,
    file: std.Io.File,
    was: std.posix.fd_t,
    path: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn open(self: *Said) !void {
        const io = testing.io;
        self.tmp = testing.tmpDir(.{});
        var dir: [std.fs.max_path_bytes]u8 = undefined;
        const at = try self.tmp.dir.realPath(io, &dir);
        const named = try std.fmt.bufPrint(&self.path, "{s}/said", .{dir[0..at]});
        self.len = named.len;
        self.file = try std.Io.Dir.createFileAbsolute(io, named, .{});
        self.was = messageToForTest(self.file.handle);
    }

    /// Put the descriptor back and read what landed in the file. The result
    /// belongs to the caller.
    fn close(self: *Said, gpa: std.mem.Allocator) ![]u8 {
        const io = testing.io;
        _ = messageToForTest(self.was);
        self.file.close(io);
        const text = try std.Io.Dir.cwd().readFileAlloc(
            io,
            self.path[0..self.len],
            gpa,
            .limited(4096),
        );
        self.tmp.cleanup();
        return text;
    }
};

test "a real signal is what sets the flag, and the line a person reads says both presses" {
    // Driven with a real `raise`, not by calling the handler directly: what
    // is pinned is that the handler this file installs is the one the kernel
    // reaches, which a direct call would not say anything about.
    //
    // **And what it wrote, which nothing checked before.** The first press is
    // not instant, so the sentence has to say what it did and what a second
    // press does, or a person waiting on a slow provider cannot tell a session
    // that is stopping from one that has hung. Mutation check: drop the second
    // half of `first_message` and the last expectation fails.
    const gpa = testing.allocator;
    forgetForTest();
    try testing.expect(!requested());

    var said: Said = undefined;
    try said.open();

    install();
    try std.posix.raise(.INT);
    try testing.expect(requested());

    const line = try said.close(gpa);
    defer gpa.free(line);
    try testing.expectEqualStrings(first_message, line);
    try testing.expect(std.mem.indexOf(u8, line, "next safe point") != null);
    try testing.expect(std.mem.indexOf(u8, line, "again to stop now") != null);

    // And the flag stays set: a stop that could be forgotten is a stop the loop
    // can miss between two of its own safe points.
    try testing.expect(requested());
    forgetForTest();
}

test "a second press has the terminal's own settings to put back, and only while a display holds them" {
    // **The escape sequences say nothing about the echo**, and a session runs
    // every turn with the echo off: `ISIG` and `ECHO` are separate bits and only
    // the first may come back while a turn runs, so that this file owns Ctrl-C.
    // See `src/ui.zig`'s `quietOf`. A process that ended on a second press with
    // only `restore_bytes` written put the screen back and left a shell that
    // showed nothing a person typed.
    //
    // **A fact and not a `tcsetattr`**, because a test binary has no terminal
    // to read one back from. What is pinned is the decision the handler makes:
    // whether there is anything to put back, and what.
    //
    // Mutation check: store the settings after the descriptor in
    // `armTerminalSettings` and a handler between the two writes reads settings
    // that were never given to it. Drop `disarmTerminalSettings` from the
    // display's teardown and the last expectation finds settings for a terminal
    // nothing is drawing on any more.
    try testing.expect(settingsIfArmed() == null);

    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ISIG = true;
    armTerminalSettings(7, was);

    const armed = settingsIfArmed().?;
    try testing.expectEqual(@as(std.posix.fd_t, 7), armed.fd);
    try testing.expect(armed.was.lflag.ECHO);
    try testing.expect(armed.was.lflag.ISIG);

    disarmTerminalSettings();
    try testing.expect(settingsIfArmed() == null);
}

test "a terminated session is asked to stop the same way an interrupted one is" {
    // A service manager sends TERM, and that session's log deserves the same
    // readable ending as one a person stopped with Ctrl-C. So it reaches the
    // same handler and writes the same line.
    const gpa = testing.allocator;
    forgetForTest();

    var said: Said = undefined;
    try said.open();

    install();
    try std.posix.raise(.TERM);
    try testing.expect(requested());

    const line = try said.close(gpa);
    defer gpa.free(line);
    try testing.expectEqualStrings(first_message, line);
    forgetForTest();
}
