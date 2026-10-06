//! The things a forked child has to put right before it is confined, on macOS.
//!
//! The same two calls as the Linux file beside this one, for the same reason: a
//! Seatbelt profile says nothing about a descriptor that was already open, a
//! handler the parent installed, or a process group a terminal still signals.
//!
//! **macOS has no `close_range`,** so the loop below closes one descriptor at a
//! time up to the table's own size. That is the whole difference between the two
//! files.

const std = @import("std");

/// The most descriptors this looks at. `getdtablesize` is the real answer and is
/// read first; this is the ceiling for a process whose limit is unbounded.
const table_ceiling: i32 = 1 << 16;

/// Close every descriptor but these. **Before the profile goes on**, because a
/// confined process may not be able to ask the kernel anything about itself.
///
/// A descriptor named twice is allowed, so a caller with one thing to keep does
/// not need a second shape.
pub fn keepOnlyDescriptors(keep: []const i32) void {
    std.debug.assert(keep.len > 0 and keep.len <= 8);
    var sorted: [8]i32 = undefined;
    @memcpy(sorted[0..keep.len], keep);
    const held = sorted[0..keep.len];
    std.mem.sort(i32, held, {}, std.sort.asc(i32));

    var fd: i32 = 0;
    const top = tableSize();
    while (fd < top) : (fd += 1) {
        if (std.mem.indexOfScalar(i32, held, fd) != null) continue;
        _ = std.c.close(fd);
    }
}

fn tableSize() i32 {
    var limit: std.c.rlimit = undefined;
    if (std.c.getrlimit(.NOFILE, &limit) != 0) return table_ceiling;
    if (limit.cur > table_ceiling) return table_ceiling;
    return @intCast(limit.cur);
}

const last_reset_signal: u32 = 31;

/// Put every signal back to its default action with an empty mask. A child of
/// `fork` keeps the caller's own handlers, and a blocked signal defeats the same
/// cancellation as a caught one.
pub fn resetSignalState() void {
    const to_default: std.c.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.mem.zeroes(std.c.sigset_t),
        .flags = 0,
    };
    var number: u32 = 1;
    while (number <= last_reset_signal) : (number += 1) {
        const sig: std.posix.SIG = @enumFromInt(number);
        if (sig == .KILL or sig == .STOP) continue;
        _ = std.c.sigaction(sig, &to_default, null);
    }

    const empty = std.mem.zeroes(std.c.sigset_t);
    _ = std.c.sigprocmask(std.posix.SIG.SETMASK, &empty, null);
}

test "the descriptor table is never read as unbounded" {
    // A ceiling and not the raw limit: `RLIMIT_NOFILE` may be unbounded, and a
    // loop to that would never end.
    try std.testing.expect(tableSize() <= table_ceiling);
    try std.testing.expect(tableSize() > 0);
}
