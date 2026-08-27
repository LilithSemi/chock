//! What the caller does while this library waits for something slow.
//!
//! ## The display is frozen between two events, and this is why it need not be
//!
//! A full screen display reads the keyboard and repaints in one place, and that
//! place runs when an event arrives: a person pressed Enter, a record was
//! appended, a token streamed in, a notice was raised. Between two of those
//! nothing reads the keyboard at all, so a person cannot scroll while a tool
//! call runs, and cannot scroll at all while the harness waits for the first
//! token of a reply.
//!
//! **A second thread is not the answer here, and must never become it.** The
//! sandbox needs a single threaded caller: `fork` carries only the calling
//! thread, and `namespace.enter` refuses a process with more than one, which is
//! why a subagent is a child process and not a thread. A display thread that was
//! running at the moment a tool call forks would break the sandbox, and the
//! sandbox is the product. See `lib/chock-core/tools.zig`'s own top comment for
//! the one thread this library does start and the narrow rules it runs under.
//!
//! **So the answer is to give the caller the time this library is already
//! spending on a wait.** Every long wait in a session is a poll or a bounded
//! read: the provider going quiet between two pieces of a reply, and the pipe a
//! sandboxed program writes its output to. Each of those now waits in slices of
//! `slice_ms` and calls `Idle.step` between them, on the one thread that was
//! going to sit in that wait anyway.
//!
//! ## What an implementation may do, and what it may not
//!
//! **It may read a device and paint a screen. It may not append to the log,
//! start a turn, run a tool, or change what the session is doing.** A step runs
//! in the middle of a call this library is halfway through, so anything that
//! reached back into the session would be re-entering a call that has not
//! returned. `src/ui.zig`'s own `pumpStep` is the implementation this exists
//! for, and it does exactly two things: it reads what has been typed, and it
//! draws one frame.
//!
//! **A step must be short.** It runs between two slices of a wait, so time
//! spent here is time the provider's own bytes sit unread.

const std = @import("std");

/// How long one slice of a wait is, in milliseconds.
///
/// **The same tenth of a second the message field already runs at.** Raw mode's
/// `VTIME 1` gives `src/ui.zig` a read that comes back every hundred
/// milliseconds while a person is typing, so a display that repaints at this
/// rate during a turn repaints no faster than one that is waiting for a message,
/// and there is one number to reason about rather than two.
pub const slice_ms: u64 = 100;

/// `slice_ms` as nanoseconds, for a caller whose deadline is in those.
pub const slice_ns: u64 = slice_ms * std.time.ns_per_ms;

/// The seam itself.
///
/// **A vtable for the reason `chock_core.ask.Asker` is one**: what fills a wait
/// is a display, and `src/` owns every device because `lib/` writes to none.
///
/// **Built in place and never copied**, the same rule every other seam in this
/// library carries: the value holds a pointer, so a copy is a pointer to
/// something that has moved.
pub const Idle = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// One look. **It cannot fail and it cannot say anything**: a wait must
        /// behave the same whether or not anybody is watching it, so there is
        /// nothing here for a caller to branch on.
        step: *const fn (ptr: *anyopaque) void,
    };

    pub fn step(self: Idle) void {
        self.vtable.step(self.ptr);
    }
};

const testing = std.testing;

/// An `Idle` a test counts.
const Counter = struct {
    steps: usize = 0,

    fn idle(self: *Counter) Idle {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Idle.VTable{ .step = stepFn };

    fn stepFn(ptr: *anyopaque) void {
        const self: *Counter = @ptrCast(@alignCast(ptr));
        self.steps += 1;
    }
};

test "a step reaches the value behind the seam" {
    var counter = Counter{};
    const one = counter.idle();
    one.step();
    one.step();
    try testing.expectEqual(@as(usize, 2), counter.steps);
}

test "one slice is short enough that a key is not left waiting" {
    // A person who presses a key must not wait longer for the screen to answer
    // than they already wait at the message field. See `slice_ms`.
    try testing.expect(slice_ms <= 100);
    try testing.expectEqual(slice_ms * std.time.ns_per_ms, slice_ns);
}
