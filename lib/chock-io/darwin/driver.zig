//! The Darwin driver for `chock-io`. See `../../chock-io.zig`'s own top comment for
//! the two primitives this implements and why this module exists at all.
//!
//! Pure Zig bends here. On Darwin the rule is no third party C library, and it is not
//! no C. This file is where that bend happens for `chock-io`: it goes through `std.c`,
//! the libc binding Zig already links on every Darwin target, rather than through
//! Linux's own `os.linux` syscall bindings, which do not exist on this platform.

const std = @import("std");
const iface = @import("../../chock-io.zig");

/// There is no `pipe2` on Darwin, so this is `pipe` followed by `fcntl` on
/// each end, two calls where Linux's driver needs one. **This is not atomic.**
/// Between the `pipe` call returning and the second `fcntl` call setting
/// `FD_CLOEXEC` on the write end, both descriptors exist in this process with
/// no close-on-exec flag at all. A `fork` from another thread inside that
/// window inherits both, still open, into the forked child, which then carries
/// them across its own `execve` whether this code wanted that or not. This
/// project has already been bitten once by a `fork` racing descriptor state it
/// assumed was already settled: see the PID namespace's own second fork, and
/// `lib/chock-core/tools.zig`'s own top comment on why `spawnCapturing` calls
/// `Sandbox.spawn` from a dedicated thread that touches nothing else this
/// process shares. The same caution applies here: a caller on Darwin that
/// forks concurrently with this function has a real, if narrow, window to leak
/// a descriptor across an unrelated `exec`. Closing it needs a process-wide
/// fork lock or `posix_spawn`, neither of which this function can provide on
/// its own; the fact that the window exists is what this comment exists to
/// make impossible to miss.
fn pipeCloseOnExecFn(ptr: *anyopaque) iface.PipeError!iface.Pipe {
    _ = ptr;
    var fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&fds) != 0) return error.Unexpected;
    if (std.c.fcntl(fds[0], std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1) return error.Unexpected;
    if (std.c.fcntl(fds[1], std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1) return error.Unexpected;
    return .{ .read_fd = fds[0], .write_fd = fds[1] };
}

/// **There is no Darwin equivalent of `F_SETPIPE_SZ`, and this does nothing.**
/// This is exactly the sanctioned case: a pipe buffer size request is a
/// throughput tweak, never a correctness requirement, so an
/// honest no-operation is the right answer where the platform has no such
/// call at all, rather than a stub that pretends to try. See
/// `../../chock-io.zig`'s own doc comment on `Io.growPipeBuffer`: its return
/// type is `void` on every platform for exactly this reason, so nothing
/// about this function's signature lets a caller believe it did anything
/// here.
fn growPipeBufferFn(ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void {
    _ = ptr;
    _ = write_fd;
    _ = target_bytes;
}

/// How long a filesystem type name is in Darwin's own `struct statfs`, from
/// `sys/mount.h`. Named rather than written into the structure below, because a
/// reader has to be able to check it against the header.
const mfs_type_name_len = 16;

/// How long a mount path is in the same structure, which is `MAXPATHLEN`.
const max_path_len = 1024;

/// Darwin's `struct statfs`, the 64 bit inode variant, written out by hand
/// because `std.c` binds neither this type nor the call that fills it. **On
/// arm64 macOS there is only this variant**: the `$INODE64` suffixed symbols
/// that x86 once needed never existed on this architecture, so the plain name
/// is the right one and the layout below is the only one it can have.
///
/// The trailing fields are here because the structure's total size is what the
/// kernel writes, and a shorter type would have the kernel write past the end
/// of it.
const Statfs = extern struct {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_owner: u32,
    f_type: u32,
    f_flags: u32,
    f_fssubtype: u32,
    f_fstypename: [mfs_type_name_len]u8,
    f_mntonname: [max_path_len]u8,
    f_mntfromname: [max_path_len]u8,
    f_flags_ext: u32,
    f_reserved: [7]u32,
};

extern "c" fn statfs(path: [*:0]const u8, buf: *Statfs) c_int;

/// `statfs`, reading `f_bavail` and never `f_bfree`. See
/// `../../chock-io.zig`'s own doc comment on `Io.freeBytes` for why the
/// available count is the one that answers the question a caller is asking.
///
/// **This is a real implementation and not the honest no-operation
/// `growPipeBuffer` is.** Darwin has the call; it is only Zig's standard
/// library that does not bind it.
fn freeBytesFn(ptr: *anyopaque, path: []const u8) ?u64 {
    _ = ptr;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    // A path this cannot terminate is refused rather than cut short: a
    // truncated path names a different directory, and possibly a different
    // filesystem, which is the one answer worse than no answer.
    if (path.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..path.len], path);
    buffer[path.len] = 0;

    var stat_buf: Statfs = undefined;
    if (statfs(buffer[0..path.len :0].ptr, &stat_buf) != 0) return null;
    return stat_buf.f_bavail *| @as(u64, stat_buf.f_bsize);
}

const vtable = iface.Io.VTable{
    .pipeCloseOnExec = pipeCloseOnExecFn,
    .growPipeBuffer = growPipeBufferFn,
    .freeBytes = freeBytesFn,
};

/// This driver carries no state of its own: both functions above ignore
/// `ptr`. See `../linux/driver.zig`'s own `driver` for the same convention.
pub fn driver() iface.Io {
    return .{ .ptr = undefined, .vtable = &vtable };
}
