//! What the interface needs from the machine it runs on.
//!
//! The widget tree is the same in a terminal, a window and a browser. What
//! differs is the handful of things only the host can do: write to a terminal,
//! raise a signal, say what time it is. Those are a value here, so the tree
//! holds no branch on which host it is running under.
//!
//! The same decision `Sandbox.Driver` and `chock-ui`'s own `Source` make.

const std = @import("std");

const model = @import("model.zig");

/// When a change to the keyboard takes effect.
pub const When = enum {
    /// Right away, keeping whatever a person already typed.
    now,
    /// After what is waiting is thrown away.
    flush,
};

/// A terminal, a window or a browser, as the interface sees it.
pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    /// What this is, for a screen that says where it is drawing.
    name: []const u8,

    pub const VTable = struct {
        /// Push whatever has been written. Nothing to do where there is no
        /// terminal behind the tree.
        flushOut: *const fn (ptr: *anyopaque) void,

        /// Write past the interface, straight to the terminal. Used when the
        /// interface is coming down and the transcript has to survive it.
        /// A host with no terminal drops it, which is why this answers nothing.
        writeOut: *const fn (ptr: *anyopaque, bytes: []const u8) void,

        /// How many times the view has been scrolled by the host itself. A
        /// terminal counts its own scrollback; a browser scrolls the page and
        /// answers zero, because the interface is not the one moving it.
        scrollCount: *const fn (ptr: *anyopaque) usize,

        /// Whether the person asked for more detail than usual.
        verbose: *const fn (ptr: *anyopaque) bool,

        /// Whether colour is wanted. A terminal decides from its own rules and
        /// the environment; a browser always paints.
        colorOn: *const fn (ptr: *anyopaque) bool,

        /// Ask the session to stop. On a terminal this is the interrupt a
        /// person pressed; elsewhere it is whatever that host calls the same
        /// thing.
        requestStop: *const fn (ptr: *anyopaque) void,

        /// Whether a stop has already been asked for.
        stopRequested: *const fn (ptr: *anyopaque) bool,

        /// Interrupt the running work `times` over. Separate from
        /// `requestStop` because a person pressing twice means something
        /// stronger than pressing once, and only the host knows how to say it.
        interrupt: *const fn (ptr: *anyopaque, times: usize) void,

        /// Milliseconds since the epoch. The host's own clock: a browser's
        /// `Date.now`, a terminal's system clock.
        nowMs: *const fn (ptr: *anyopaque) i64,

        /// Minutes east of UTC, for a clock a person reads. Zero where the host
        /// does not know, which draws a UTC time rather than a wrong local one.
        utcOffsetMinutes: *const fn (ptr: *anyopaque) i32,

        /// Ask for the tree to be drawn again. A terminal marks its surface
        /// dirty; a browser marks the element needing a build. Without this a
        /// change to the state would sit unseen until something else repainted.
        invalidate: *const fn (ptr: *anyopaque) void,

        /// Put the keyboard on the last focusable thing drawn. Used after a
        /// panel appears, so the keys a person presses reach it rather than
        /// whatever had the focus before.
        focusLast: *const fn (ptr: *anyopaque) void,

        /// Whether anything currently holds the keyboard.
        hasFocus: *const fn (ptr: *anyopaque) bool,

        /// Take the keyboard, so keys reach the interface rather than the
        /// shell. A terminal switches its own settings; a browser already has
        /// the keys and does nothing.
        takeKeys: *const fn (ptr: *anyopaque, when: When) void,

        /// Give the keyboard back.
        giveKeys: *const fn (ptr: *anyopaque, when: When) void,

        /// Whether the keyboard is held right now. False where there is nothing
        /// to hold, which is what stops the interface drawing a key hint nobody
        /// can press.
        answersKeys: *const fn (ptr: *anyopaque) bool,

        /// Give the keyboard back for good and forget what it was. Called once,
        /// as the interface stops.
        dropKeys: *const fn (ptr: *anyopaque) void,

        /// Take whatever keys have arrived and hand them to the tree. Answers
        /// how many times the interrupt key was pressed, because that is the one
        /// press the interface acts on itself rather than passing along.
        pumpKeys: *const fn (ptr: *anyopaque) usize,

        /// Whether anything is waiting to be read. A terminal polls its own
        /// descriptor. Answering true where it cannot tell is right: the read
        /// that follows finds nothing and costs one call.
        keysWaiting: *const fn (ptr: *anyopaque) bool,

        /// Draw one frame and wait up to `wait_ms` for something to happen.
        /// Answers false when the host is finished and the loop should stop.
        ///
        /// This is the line between a terminal and a browser: a terminal blocks
        /// here waiting for a key, and a browser never does, because its frames
        /// come from the page. A host that does not drive its own frames answers
        /// true and waits for nothing.
        step: *const fn (ptr: *anyopaque, wait_ms: u32) bool,

        /// Take the size the host is now, if it changed. A terminal re-reads its
        /// window; a browser is resized by the page and has nothing to do.
        followSize: *const fn (ptr: *anyopaque) void,

        /// Let the host go. Called once, when the interface is coming down and
        /// before the transcript is written out.
        finish: *const fn (ptr: *anyopaque) void,

        /// Free whatever the host allocated for itself. The last call it gets,
        /// made as the interface is destroyed, after `finish`. Separate from
        /// `finish` because stopping and being destroyed are different moments
        /// and a session can be stopped without being thrown away.
        release: *const fn (ptr: *anyopaque) void,

        /// The other sessions of this project, ready to show in a picker, or
        /// null when they could not be read. The host enumerates them because
        /// only it knows where they are: a log directory on one, a daemon on
        /// another. `current` is left out of the answer.
        resumables: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            current: []const u8,
        ) ?[]const model.Resumable,
    };

    pub fn flushOut(self: Host) void {
        self.vtable.flushOut(self.ptr);
    }
    pub fn writeOut(self: Host, bytes: []const u8) void {
        self.vtable.writeOut(self.ptr, bytes);
    }
    pub fn scrollCount(self: Host) usize {
        return self.vtable.scrollCount(self.ptr);
    }
    pub fn verbose(self: Host) bool {
        return self.vtable.verbose(self.ptr);
    }
    pub fn colorOn(self: Host) bool {
        return self.vtable.colorOn(self.ptr);
    }
    pub fn requestStop(self: Host) void {
        self.vtable.requestStop(self.ptr);
    }
    pub fn stopRequested(self: Host) bool {
        return self.vtable.stopRequested(self.ptr);
    }
    pub fn interrupt(self: Host, times: usize) void {
        self.vtable.interrupt(self.ptr, times);
    }
    pub fn nowMs(self: Host) i64 {
        return self.vtable.nowMs(self.ptr);
    }
    pub fn utcOffsetMinutes(self: Host) i32 {
        return self.vtable.utcOffsetMinutes(self.ptr);
    }
    pub fn invalidate(self: Host) void {
        self.vtable.invalidate(self.ptr);
    }
    pub fn focusLast(self: Host) void {
        self.vtable.focusLast(self.ptr);
    }
    pub fn hasFocus(self: Host) bool {
        return self.vtable.hasFocus(self.ptr);
    }
    pub fn takeKeys(self: Host, when: When) void {
        self.vtable.takeKeys(self.ptr, when);
    }
    pub fn giveKeys(self: Host, when: When) void {
        self.vtable.giveKeys(self.ptr, when);
    }
    pub fn answersKeys(self: Host) bool {
        return self.vtable.answersKeys(self.ptr);
    }
    pub fn dropKeys(self: Host) void {
        self.vtable.dropKeys(self.ptr);
    }
    pub fn pumpKeys(self: Host) usize {
        return self.vtable.pumpKeys(self.ptr);
    }
    pub fn keysWaiting(self: Host) bool {
        return self.vtable.keysWaiting(self.ptr);
    }
    pub fn step(self: Host, wait_ms: u32) bool {
        return self.vtable.step(self.ptr, wait_ms);
    }
    pub fn followSize(self: Host) void {
        self.vtable.followSize(self.ptr);
    }
    pub fn finish(self: Host) void {
        self.vtable.finish(self.ptr);
    }
    pub fn release(self: Host) void {
        self.vtable.release(self.ptr);
    }
    pub fn resumables(
        self: Host,
        arena: std.mem.Allocator,
        current: []const u8,
    ) ?[]const model.Resumable {
        return self.vtable.resumables(self.ptr, arena, current);
    }
};

/// A host that does nothing, for a test and for a tree drawn before its real
/// host exists. Every call is answered rather than refused, because a screen
/// that cannot draw without a terminal is a screen that cannot be tested.
pub const quiet: Host = .{
    .ptr = undefined,
    .vtable = &.{
        .flushOut = nothing,
        .writeOut = dropped,
        .scrollCount = none,
        .verbose = off,
        .colorOn = off,
        .requestStop = nothing,
        .stopRequested = off,
        .interrupt = ignored,
        .nowMs = noClock,
        .utcOffsetMinutes = noOffset,
        .invalidate = nothing,
        .focusLast = nothing,
        .hasFocus = off,
        .takeKeys = atKeys,
        .giveKeys = atKeys,
        .answersKeys = off,
        .dropKeys = nothing,
        .pumpKeys = none,
        .keysWaiting = off,
        .step = carryOn,
        .followSize = nothing,
        .finish = nothing,
        .release = nothing,
        .resumables = noSessions,
    },
    .name = "nothing",
};

fn nothing(_: *anyopaque) void {}
fn dropped(_: *anyopaque, _: []const u8) void {}
fn none(_: *anyopaque) usize {
    return 0;
}
fn off(_: *anyopaque) bool {
    return false;
}
fn ignored(_: *anyopaque, _: usize) void {}
fn atKeys(_: *anyopaque, _: When) void {}
fn noClock(_: *anyopaque) i64 {
    return 0;
}
fn noOffset(_: *anyopaque) i32 {
    return 0;
}
/// A host that drives no frames of its own never ends the loop.
fn carryOn(_: *anyopaque, _: u32) bool {
    return true;
}
/// An empty list and not null: nothing to take up is a fact, where null would
/// say the sessions could not be read.
fn noSessions(_: *anyopaque, _: std.mem.Allocator, _: []const u8) ?[]const model.Resumable {
    return &.{};
}

const testing = std.testing;

test "a host that does nothing answers every call rather than refusing one" {
    try testing.expectEqual(@as(usize, 0), quiet.scrollCount());
    try testing.expect(!quiet.verbose());
    try testing.expect(!quiet.colorOn());
    try testing.expect(!quiet.stopRequested());
    try testing.expectEqual(@as(i64, 0), quiet.nowMs());
    try testing.expectEqual(@as(i32, 0), quiet.utcOffsetMinutes());
    try testing.expect(!quiet.hasFocus());
    // No keyboard to hold, so no key hint is drawn and no press arrives.
    try testing.expect(!quiet.answersKeys());
    try testing.expect(!quiet.keysWaiting());
    try testing.expectEqual(@as(usize, 0), quiet.pumpKeys());
    // These answer nothing, and the point is that they do not refuse.
    quiet.flushOut();
    quiet.writeOut("dropped");
    quiet.requestStop();
    quiet.interrupt(2);
    quiet.invalidate();
    quiet.focusLast();
    quiet.takeKeys(.flush);
    quiet.giveKeys(.now);
    quiet.dropKeys();
    quiet.followSize();
    quiet.finish();
    quiet.release();
    // Nothing to take up, which is not the same as a failure to look.
    try testing.expectEqual(@as(usize, 0), quiet.resumables(testing.allocator, "01JQ").?.len);
    // A host with no frames of its own never asks the loop to stop.
    try testing.expect(quiet.step(0));
}
