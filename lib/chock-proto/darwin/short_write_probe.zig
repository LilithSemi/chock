//! The Darwin driver for `../short_write_probe.zig`.
//!
//! Nothing in this directory may use `std.os.linux`. On arm64 macOS the system
//! call number comes from `x16` and Zig's Linux path puts it in `x8`, so such a
//! call enters an arbitrary Darwin system call and `std.os.linux.errno` reads
//! the arbitrary result as success. Also use `std.c.fcntl` and never declare a
//! private one: it is variadic, and on Apple arm64 a variadic argument goes on
//! the stack where a named one goes in a register, so a fixed three argument
//! declaration makes `F_SETFL` report success and set a value nobody asked for.

const std = @import("std");
const iface = @import("../short_write_probe.zig");

pub fn setNonblocking(fd: std.posix.fd_t) iface.Error!void {
    const current = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (current < 0) return error.Unexpected;

    var flags: std.c.O = @bitCast(@as(u32, @intCast(current)));
    flags.NONBLOCK = true;

    const updated = std.c.fcntl(fd, std.c.F.SETFL, @as(c_int, @bitCast(@as(u32, @bitCast(flags)))));
    if (updated < 0) return error.Unexpected;
}

/// Darwin has no `F_GETPIPE_SZ`, so this answers with an upper bound. macOS
/// gives a pipe 16 KiB and grows it to at most `BIG_PIPE_SIZE`, 64 KiB.
pub fn overCapacity(fd: std.posix.fd_t) iface.Error!usize {
    _ = fd;
    return 8 * 1024 * 1024;
}
