//! The Linux driver for `chock-io`.

const std = @import("std");
const linux = std.os.linux;
const iface = @import("../../chock-io.zig");

/// `pipe2` with `O_CLOEXEC`, atomically.
fn pipeCloseOnExecFn(ptr: *anyopaque) iface.PipeError!iface.Pipe {
    _ = ptr;
    var fds: [2]std.posix.fd_t = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) return error.Unexpected;
    return .{ .read_fd = fds[0], .write_fd = fds[1] };
}

/// Best effort.
fn growPipeBufferFn(ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void {
    _ = ptr;
    _ = linux.fcntl(write_fd, linux.F.SETPIPE_SZ, target_bytes);
}

/// Every target here is 64 bit.
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

fn freeBytesFn(ptr: *anyopaque, path: []const u8) ?u64 {
    _ = ptr;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    // A truncated path reads the wrong filesystem.
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

/// Stateless: both functions above ignore `ptr`.
pub fn driver() iface.Io {
    return .{ .ptr = undefined, .vtable = &vtable };
}

test "pipeCloseOnExec really does set the close-on-exec flag on both ends" {
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
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(.SUCCESS, linux.errno(linux.pipe2(&fds, .{})));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    growPipeBufferFn(undefined, fds[1], std.math.maxInt(usize));
}
