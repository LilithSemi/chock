//! The Darwin driver for `chock-io`.

const std = @import("std");
const iface = @import("../../chock-io.zig");

/// No `pipe2` on Darwin: `pipe` then `fcntl` on each end. Not atomic.
fn pipeCloseOnExecFn(ptr: *anyopaque) iface.PipeError!iface.Pipe {
    _ = ptr;
    var fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&fds) != 0) return error.Unexpected;
    if (std.c.fcntl(fds[0], std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1) return error.Unexpected;
    if (std.c.fcntl(fds[1], std.c.F.SETFD, @as(c_int, std.c.FD_CLOEXEC)) == -1) return error.Unexpected;
    return .{ .read_fd = fds[0], .write_fd = fds[1] };
}

/// No Darwin equivalent of `F_SETPIPE_SZ`.
fn growPipeBufferFn(ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void {
    _ = ptr;
    _ = write_fd;
    _ = target_bytes;
}

const mfs_type_name_len = 16;

const max_path_len = 1024;

/// Dropping the trailing fields lets the kernel write past the end.
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

fn freeBytesFn(ptr: *anyopaque, path: []const u8) ?u64 {
    _ = ptr;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    // A truncated path reads the wrong filesystem.
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

/// Stateless: both functions above ignore `ptr`.
pub fn driver() iface.Io {
    return .{ .ptr = undefined, .vtable = &vtable };
}
