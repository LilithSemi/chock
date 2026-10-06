//! Primitives `std.Io` does not have: pipeCloseOnExec, growPipeBuffer, freeBytes.

const std = @import("std");
const builtin = @import("builtin");

pub const Pipe = struct {
    read_fd: std.posix.fd_t,
    write_fd: std.posix.fd_t,
};

pub const PipeError = error{Unexpected};

pub const Io = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        pipeCloseOnExec: *const fn (ptr: *anyopaque) PipeError!Pipe,
        growPipeBuffer: *const fn (ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void,
        freeBytes: *const fn (ptr: *anyopaque, path: []const u8) ?u64,
    };

    pub fn pipeCloseOnExec(self: Io) PipeError!Pipe {
        return self.vtable.pipeCloseOnExec(self.ptr);
    }

    pub fn growPipeBuffer(self: Io, write_fd: std.posix.fd_t, target_bytes: usize) void {
        self.vtable.growPipeBuffer(self.ptr, write_fd, target_bytes);
    }

    pub fn freeBytes(self: Io, path: []const u8) ?u64 {
        return self.vtable.freeBytes(self.ptr, path);
    }
};

const driver_impl = switch (builtin.os.tag) {
    .linux => @import("chock-io/linux/driver.zig"),
    .macos => @import("chock-io/darwin/driver.zig"),
    else => @compileError("chock-io: no driver for target os " ++ @tagName(builtin.os.tag)),
};

pub fn default() Io {
    return driver_impl.driver();
}

pub const Fake = struct {
    pub fn driver() Io {
        return .{ .ptr = undefined, .vtable = &vtable };
    }

    fn pipeCloseOnExecFn(ptr: *anyopaque) PipeError!Pipe {
        _ = ptr;
        return error.Unexpected;
    }

    fn growPipeBufferFn(ptr: *anyopaque, write_fd: std.posix.fd_t, target_bytes: usize) void {
        _ = ptr;
        _ = write_fd;
        _ = target_bytes;
    }

    fn freeBytesFn(ptr: *anyopaque, path: []const u8) ?u64 {
        _ = ptr;
        _ = path;
        return null;
    }

    const vtable = Io.VTable{
        .pipeCloseOnExec = pipeCloseOnExecFn,
        .growPipeBuffer = growPipeBufferFn,
        .freeBytes = freeBytesFn,
    };
};

test "the fake driver always fails pipeCloseOnExec, so a caller's error path is reachable" {
    const driver = Fake.driver();
    try std.testing.expectError(error.Unexpected, driver.pipeCloseOnExec());
}

test "the real driver reads free space, and answers nothing for a path that is not there" {
    const driver = default();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const free = driver.freeBytes(path_buffer[0..path_len]);
    try std.testing.expect(free != null);
    try std.testing.expect(free.? > 0);

    try std.testing.expectEqual(@as(?u64, null), driver.freeBytes("/nonexistent-chock-free-space"));
    const too_long = [_]u8{'a'} ** (std.fs.max_path_bytes + 1);
    try std.testing.expectEqual(@as(?u64, null), driver.freeBytes(&too_long));
}

test "the fake driver answers nothing for free space, which is not the same as no room" {
    const driver = Fake.driver();
    try std.testing.expectEqual(@as(?u64, null), driver.freeBytes("/"));
}

test "the fake driver's growPipeBuffer takes no descriptor and reports nothing" {
    const driver = Fake.driver();
    driver.growPipeBuffer(-1, 1024);
}

test {
    std.testing.refAllDecls(@This());
}
