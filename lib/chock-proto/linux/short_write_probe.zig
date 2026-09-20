//! The Linux driver for `../short_write_probe.zig`.

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{Unexpected};

/// `std.posix` has no `fcntl` in this Zig version, so this reaches
/// `std.os.linux` directly.
pub fn setNonblocking(fd: std.posix.fd_t) Error!void {
    const current = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(current) != .SUCCESS) return error.Unexpected;

    var flags: linux.O = @bitCast(@as(u32, @intCast(current)));
    flags.NONBLOCK = true;

    const updated = linux.fcntl(fd, linux.F.SETFL, @as(u32, @bitCast(flags)));
    if (linux.errno(updated) != .SUCCESS) return error.Unexpected;
}

/// Linux can name the exact size, so this asks. The traditional 65536 byte
/// default is not guaranteed on every host. `F_GETPIPE_SZ` has no Darwin
/// equivalent, which is why the shared contract asks for a bound.
pub fn overCapacity(fd: std.posix.fd_t) Error!usize {
    const result = linux.fcntl(fd, linux.F.GETPIPE_SZ, 0);
    if (linux.errno(result) != .SUCCESS) return error.Unexpected;
    return result + std.heap.pageSize();
}
