//! The Darwin driver for `../short_write_probe.zig`. Never use `std.os.linux`
//! here: on arm64 macOS it reads the syscall number from the wrong register.
//! Always call `std.c.fcntl` variadic; a fixed declaration mis-sets the flags.

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

/// Darwin has no `F_GETPIPE_SZ`, so this answers with an upper bound.
pub fn overCapacity(fd: std.posix.fd_t) iface.Error!usize {
    _ = fd;
    return 8 * 1024 * 1024;
}
