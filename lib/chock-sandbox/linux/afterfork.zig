//! The things a forked child has to put right before it is confined, because
//! `fork` copies them from a parent that had other work.
//!
//! **Every one of these is a hole no later layer closes.** Landlock and seccomp
//! go on a process and decide what it may open and call. Neither says anything
//! about a descriptor that was already open, a handler the parent installed, or
//! a process group a terminal still signals. So a child closes, resets and
//! detaches first, and takes its boundary afterwards.
//!
//! The Linux driver's own helpers and `src/vmm.zig`'s forked guest both come
//! here, so there is one spelling of each of these and not two.

const std = @import("std");
const linux = std.os.linux;

/// Close every descriptor but these. **Before the filter goes on**, because
/// `close_range` is on no allowlist this project builds.
///
/// A descriptor named twice is allowed, so a caller with one thing to keep does
/// not need a second shape.
pub fn keepOnlyDescriptors(keep: []const i32) void {
    std.debug.assert(keep.len > 0 and keep.len <= 8);
    var sorted: [8]i32 = undefined;
    @memcpy(sorted[0..keep.len], keep);
    const held = sorted[0..keep.len];
    std.mem.sort(i32, held, {}, std.sort.asc(i32));

    const all: u32 = std.math.maxInt(u32);
    if (held[0] > 0) _ = linux.syscall3(.close_range, 0, @intCast(held[0] - 1), 0);
    for (held[1..], held[0 .. held.len - 1]) |high, low| {
        if (high > low + 1) {
            _ = linux.syscall3(.close_range, @intCast(low + 1), @intCast(high - 1), 0);
        }
    }
    _ = linux.syscall3(.close_range, @intCast(held[held.len - 1] + 1), all, 0);
}

const last_reset_signal: u32 = 31;

/// Put every signal back to its default action with an empty mask. A child of
/// `fork` keeps the caller's own handlers: `chock run`'s `SIGTERM` handler was
/// inherited here, so the signal a deadline sent to cancel a call was caught,
/// this process did not die, and the timeout cancelled nothing. A blocked
/// signal defeats the same cancellation as a caught one.
pub fn resetSignalState() void {
    // **Every type here is `linux`'s, because every call here is.** `std.posix`
    // carries the POSIX shapes and the raw calls below carry the kernel's, and the
    // two differ: a `sigset_t` is one word to the kernel and sixteen to POSIX, so
    // a mask built by one and passed to the other is the wrong size.
    const to_default = linux.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    var number: u32 = 1;
    while (number <= last_reset_signal) : (number += 1) {
        const sig: std.posix.SIG = @enumFromInt(number);
        if (sig == .KILL or sig == .STOP) continue;
        _ = linux.sigaction(sig, &to_default, null);
    }

    const empty = std.mem.zeroes(linux.sigset_t);
    _ = linux.sigprocmask(std.posix.SIG.SETMASK, &empty, null);
}
