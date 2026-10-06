//! Scaffolding for one regression test in `log.zig`: make an open pipe
//! nonblocking and name a byte count above that pipe's kernel buffer, so a
//! single write returns a short count instead of blocking.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{Unexpected};

/// `F_SETFL` replaces the whole flag word, so a driver keeps the flags it found.
pub fn setNonblocking(fd: std.posix.fd_t) Error!void {
    return driver.setNonblocking(fd);
}

/// A count below the real buffer size makes the write complete instead of
/// short, so a driver may answer with an upper bound but never go low.
pub fn overCapacity(fd: std.posix.fd_t) Error!usize {
    return driver.overCapacity(fd);
}

const driver = switch (builtin.os.tag) {
    .linux => @import("linux/short_write_probe.zig"),
    .macos => @import("darwin/short_write_probe.zig"),
    else => @compileError("chock-proto: no short write probe for target os " ++ @tagName(builtin.os.tag)),
};

test {
    _ = driver;
}
