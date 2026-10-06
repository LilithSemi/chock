//! What the `chock-vmm` module is on a build that cannot run a guest.

const std = @import("std");

pub const available = false;

pub const Options = struct {
    kernel: []const u8 = "",
    initrd: ?[]const u8 = null,
    cmdline: []const u8 = "",
    memory_mb: u64 = 512,
    cpus: u32 = 1,
    session: []const u8 = "",
    port: u32 = 1024,
    shares: []const Share = &.{},
    seconds: ?u64 = null,
    control: i32,

    pub const Share = struct {
        name: []const u8,
        host_path: []const u8,
        writable: bool,
    };
};

pub const fork_sets_control: i32 = -1;

pub fn shareCovers(path: []const u8, root: []const u8) bool {
    if (root.len == 0) return false;
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    if (root[root.len - 1] == '/') return true;
    return path[root.len] == '/';
}

pub fn shareNameFor(
    allocator: std.mem.Allocator,
    taken: []const Options.Share,
    directory: []const u8,
) std.mem.Allocator.Error![]const u8 {
    _ = taken;
    return allocator.dupe(u8, std.fs.path.basename(directory));
}

pub const Reached = union(enum) {
    connected: std.posix.fd_t,
    refused,
};

pub const Reaches = struct {
    ptr: *anyopaque,
    decide: *const fn (ptr: *anyopaque, text: []const u8, port: u16) Reached,
};

pub fn serveReaching(
    io: std.Io,
    control: std.posix.fd_t,
    reaches: Reaches,
    stopping: *std.atomic.Value(bool),
) void {
    _ = io;
    _ = control;
    _ = reaches;
    _ = stopping;
}

pub const Fault = struct {
    said: []const u8,
    detail: []const u8 = "",
};

pub const ForkError = error{
    NoChannel,
    NoFork,
    NoGuest,
};

pub const SendError = error{ OutOfMemory, Broke };

pub const ReadyError = error{ GuestRefused, GuestGone, GuestSlow };

pub const Child = struct {
    pid: std.posix.pid_t,
    control: i32,
    sev: Sev = .off,

    pub fn sendShares(
        self: *Child,
        allocator: std.mem.Allocator,
        shares: []const Options.Share,
    ) SendError!void {
        _ = self;
        _ = allocator;
        _ = shares;
        return error.Broke;
    }

    pub fn waitReady(self: *Child, io: std.Io, limit_ms: u64) ReadyError!void {
        _ = self;
        _ = io;
        _ = limit_ms;
        return error.GuestGone;
    }

    pub fn fault(self: *Child) ?Fault {
        _ = self;
        return .{ .said = "this build runs no guest" };
    }

    pub fn stop(self: *Child) void {
        _ = self;
    }

    pub fn wait(self: *Child) u8 {
        _ = self;
        return 1;
    }
};

pub fn forkHost(io: std.Io, options: Options, console_fd: std.posix.fd_t) ForkError!Child {
    _ = io;
    _ = options;
    _ = console_fd;
    return error.NoGuest;
}

pub const Attached = struct {
    control: std.posix.fd_t,
    stream: std.posix.fd_t,
};

pub const AttachError = error{
    NoGuest,
    ShareRefused,
    NoStream,
};

pub fn attach(
    io: std.Io,
    socket_path: []const u8,
    shares: anytype,
    port: u32,
    refused: anytype,
) AttachError!Attached {
    _ = io;
    _ = socket_path;
    _ = shares;
    _ = port;
    _ = refused;
    return error.NoGuest;
}
