//! The Linux driver for `chock-io`. See `../../chock-io.zig`'s own top comment for
//! the two primitives this implements and why this module exists at all.

const std = @import("std");
const linux = std.os.linux;
const iface = @import("../../chock-io.zig");

/// `pipe2` with `O_CLOEXEC`. One syscall, atomic: both descriptors already
/// carry the flag the instant this call returns, so there is no window in
/// which a `fork` on another thread could inherit either one without it.
/// Compare `../darwin/driver.zig`'s own implementation, which has no such call
/// and is not atomic for exactly that reason.
fn pipeCloseOnExecFn(ptr: *anyopaque) iface.PipeError!iface.Pipe {
    _ = ptr;
    var fds: [2]std.posix.fd_t = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
    return .{ .read_fd = fds[0], .write_fd = fds[1] };
}

/// `fcntl`/`F_SETPIPE_SZ`, best effort. A kernel that refuses this, for
/// example because `target_bytes` is above `/proc/sys/fs/pipe-max-size` on
/// this host, leaves the pipe at whatever size it already had. The return
/// value of `fcntl` is discarded on purpose: see `../../chock-io.zig`'s own
/// doc comment on `Io.growPipeBuffer` for why this function's signature must
/// not let a caller depend on the request having worked.
fn growPipeBufferFn(ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void {
    _ = ptr;
    _ = linux.fcntl(write_fd, linux.F.SETPIPE_SZ, target_bytes);
}

/// The kernel's `struct statfs`, written out by hand because neither `std.os`
/// nor `std.posix` binds it. The same 64 bit layout, from the kernel's own
/// `asm-generic/statfs.h`, that `chock-sandbox/linux/namespace.zig` needs for
/// its own reading of a scratch area, and it is a second copy on purpose: this
/// module may not import that one, and a shared spelling would put a
/// filesystem structure in a module about pipes or a pipe module in the
/// sandbox. Every target this project builds for is 64 bit, where `statfs` and
/// `statfs64` carry the same structure.
const Statfs = extern struct {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]u32,
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [4]u64,
};

/// `statfs`, reading `f_bavail` and never `f_bfree`. See
/// `../../chock-io.zig`'s own doc comment on `Io.freeBytes` for why the
/// available count is the one that answers the question a caller is asking.
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
    const rc = linux.syscall2(
        .statfs,
        @intFromPtr(buffer[0..path.len :0].ptr),
        @intFromPtr(&stat_buf),
    );
    if (linux.errno(rc) != .SUCCESS) return null;
    return stat_buf.f_bavail *| stat_buf.f_bsize;
}

const vtable = iface.Io.VTable{
    .pipeCloseOnExec = pipeCloseOnExecFn,
    .growPipeBuffer = growPipeBufferFn,
    .freeBytes = freeBytesFn,
};

/// This driver carries no state of its own: both functions above ignore
/// `ptr`. `.ptr = undefined` is the same convention `std.heap.page_allocator`
/// uses for a stateless vtable implementation.
pub fn driver() iface.Io {
    return .{ .ptr = undefined, .vtable = &vtable };
}

test "pipeCloseOnExec really does set the close-on-exec flag on both ends" {
    // The strongest proof available without a Darwin machine to run the other
    // driver on: this pins the actual kernel behaviour the Linux driver
    // claims, by reading it back with a second, independent fcntl call,
    // rather than only trusting that pipe2's own flag name means what it
    // says. The Darwin driver has to reach this same end state by a
    // different, non-atomic route: see ../darwin/driver.zig's own top
    // comment.
    const p = try pipeCloseOnExecFn(undefined);
    defer _ = linux.close(p.read_fd);
    defer _ = linux.close(p.write_fd);

    const read_flags = linux.fcntl(p.read_fd, linux.F.GETFD, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(read_flags));
    try std.testing.expect(read_flags & linux.FD_CLOEXEC != 0);

    const write_flags = linux.fcntl(p.write_fd, linux.F.GETFD, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(write_flags));
    try std.testing.expect(write_flags & linux.FD_CLOEXEC != 0);
}

test "growPipeBuffer does not fail the caller when the kernel refuses an oversized request" {
    // fs.pipe-max-size bounds what an unprivileged process may request. A
    // request far past any plausible limit exercises the "best effort,
    // kernel refuses" path without this test depending on the exact limit of
    // whatever machine runs it.
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    // Nothing to assert past "this returns": growPipeBuffer is void, and the
    // whole point of best effort is that a kernel refusal is not this
    // function's failure to report. A hang or a crash here would be the only
    // way this test could fail.
    growPipeBufferFn(undefined, fds[1], std.math.maxInt(usize));
}
