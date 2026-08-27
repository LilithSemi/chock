//! The Linux driver for `../short_write_probe.zig`: make an already open
//! descriptor nonblocking, and name a byte count above the pipe's own kernel
//! buffer, so a write of that many bytes returns a short count instead of
//! blocking forever with nobody there to read the other end.
//!
//! See `../short_write_probe.zig`'s own top comment for what this scaffolding
//! is for, and why neither function belongs in `lib/chock-io`. In short,
//! `pipeCloseOnExec` is about exec safety and `growPipeBuffer` is about
//! throughput, and neither of these is either of those. `growPipeBuffer` also
//! cannot stand in for `overCapacity` below: it only ever asks the kernel to
//! grow a buffer, best effort, and never promises the request took effect, so
//! it cannot pin a pipe at a size a test may rely on.
//!
//! `std.posix` has no `fcntl` in this Zig version, the same gap `chock-io`'s
//! own top comment names, so this reaches `std.os.linux` directly, the same
//! as every other Linux only file in this codebase, from inside a `linux`
//! directory of its own.

const std = @import("std");
const linux = std.os.linux;

pub const Error = error{Unexpected};

/// Set `O_NONBLOCK` on `fd`, an already open descriptor. Read-modify-write,
/// not a blind overwrite: `F_SETFL` replaces the whole flag word, so this
/// keeps whatever flags `F_GETFL` reports and only adds `O_NONBLOCK` to them.
/// `linux.O` is a packed struct of the real flag bits, not a plain integer,
/// so the flag word round-trips through it rather than through a hand
/// written bitmask.
pub fn setNonblocking(fd: std.posix.fd_t) Error!void {
    const current = linux.fcntl(fd, linux.F.GETFL, 0);
    if (linux.errno(current) != .SUCCESS) return error.Unexpected;

    var flags: linux.O = @bitCast(@as(u32, @intCast(current)));
    flags.NONBLOCK = true;

    const updated = linux.fcntl(fd, linux.F.SETFL, @as(u32, @bitCast(flags)));
    if (linux.errno(updated) != .SUCCESS) return error.Unexpected;
}

/// A byte count larger than `fd`'s own pipe buffer, read from the kernel with
/// `fcntl`/`F_GETPIPE_SZ` and then raised by one page.
///
/// Linux can name the exact size, so this driver asks instead of assuming. A
/// guess at the exact size would be wrong on any host whose default pipe size
/// is not the traditional 65536 bytes, and that default is not guaranteed.
/// `F_GETPIPE_SZ` has no Darwin equivalent, which is why the shared contract
/// in `../short_write_probe.zig` asks for a bound and not for the size: see
/// `../darwin/short_write_probe.zig` for the answer that has to do without it.
pub fn overCapacity(fd: std.posix.fd_t) Error!usize {
    const result = linux.fcntl(fd, linux.F.GETPIPE_SZ, 0);
    if (linux.errno(result) != .SUCCESS) return error.Unexpected;
    return result + std.heap.pageSize();
}
