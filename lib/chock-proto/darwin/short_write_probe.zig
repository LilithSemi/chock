//! The Darwin driver for `../short_write_probe.zig`. See that file's own top
//! comment for what this scaffolding is for and why it is not in `chock-io`.
//!
//! Both calls go through `std.c`, never `std.os.linux`. That is not a style
//! rule here, it is the only thing that works: on arm64 macOS the system call
//! number is read from `x16`, and Zig's Linux path puts it in `x8`, so a
//! `std.os.linux` call on this platform enters an arbitrary Darwin system
//! call. `std.os.linux.errno` treats only the range -4095 to -1 as a failure,
//! so the arbitrary result reads as success. The failure is silent, and it
//! returns a plausible number. This exact mechanism made a healthy `flock`
//! helper look broken and made `git` receive a 22 byte nonsense path as its
//! working directory. Nothing in this directory may use `std.os.linux`.
//!
//! `std.c.fcntl` is declared variadic, which is what Darwin needs. On Apple
//! arm64 a variadic argument goes on the stack and a named one goes in a
//! register, so a fixed three argument declaration puts the third argument in
//! the wrong place. `F_SETFL` then reports success and sets a value nobody
//! asked for. Use `std.c.fcntl` and never declare a private one.

const std = @import("std");
const iface = @import("../short_write_probe.zig");

/// Add `O_NONBLOCK` to `fd`. `std.c.O` is a packed struct of the real flag
/// bits, so the flag word goes out and comes back through it rather than
/// through a hand written mask.
pub fn setNonblocking(fd: std.posix.fd_t) iface.Error!void {
    const current = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (current < 0) return error.Unexpected;

    var flags: std.c.O = @bitCast(@as(u32, @intCast(current)));
    flags.NONBLOCK = true;

    const updated = std.c.fcntl(fd, std.c.F.SETFL, @as(c_int, @bitCast(@as(u32, @bitCast(flags)))));
    if (updated < 0) return error.Unexpected;
}

/// Darwin has no `F_GETPIPE_SZ`, so this answers with an upper bound instead
/// of the exact size. macOS gives a pipe 16 KiB and grows it to at most
/// `BIG_PIPE_SIZE`, which is 64 KiB. 8 MiB is 128 times that maximum.
///
/// A bound is safe here in a way a guess at the exact size would not be. See
/// `../short_write_probe.zig`'s own `overCapacity`: a count below the real
/// buffer makes the write succeed and the test fail on the absent
/// `error.ShortWrite`. Being wrong high costs a larger write and nothing
/// else. Being wrong low is loud.
pub fn overCapacity(fd: std.posix.fd_t) iface.Error!usize {
    _ = fd;
    return 8 * 1024 * 1024;
}
