//! Small process and receipt primitives shared by independently supervised
//! work. Host-only branches keep chock-core usable by the freestanding web
//! interface while using the native process API on Linux and macOS.

const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;
pub const Pid = i32;

pub const ForkError = error{SupervisorNotStarted};

pub const receipts_leaf = "supervisors";

pub fn receiptPath(
    allocator: std.mem.Allocator,
    tasks_dir: []const u8,
    name: []const u8,
) std.mem.Allocator.Error![]u8 {
    const parent = std.fs.path.dirname(tasks_dir) orelse tasks_dir;
    return std.fs.path.join(allocator, &.{ parent, receipts_leaf, name });
}

pub fn ensureReceiptDir(allocator: std.mem.Allocator, io: std.Io, tasks_dir: []const u8) !void {
    const parent = std.fs.path.dirname(tasks_dir) orelse tasks_dir;
    const path = try std.fs.path.join(allocator, &.{ parent, receipts_leaf });
    defer allocator.free(path);
    try std.Io.Dir.cwd().createDirPath(io, path);
}

/// Null is the supervisor child; a pid is the session owner.
pub fn fork() ForkError!?Pid {
    if (comptime !supported) return error.SupervisorNotStarted;
    if (comptime builtin.os.tag == .macos) {
        const pid = std.c.fork();
        if (pid < 0) return error.SupervisorNotStarted;
        return if (pid == 0) null else pid;
    }
    const rc = std.os.linux.fork();
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SupervisorNotStarted;
    return if (rc == 0) null else @intCast(rc);
}

pub fn exit() noreturn {
    if (comptime builtin.os.tag == .macos) std.c._exit(0);
    std.process.exit(0);
}

/// Gives the supervisor a process group of its own. Commands and subagents it
/// starts inherit the group, so cancellation cannot strand a grandchild.
pub fn beginSupervisor() void {
    if (comptime builtin.os.tag == .macos) {
        _ = std.c.setsid();
    } else if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.setsid();
    }
}

pub fn terminate(pid: Pid) void {
    if (pid <= 0) return;
    if (comptime builtin.os.tag == .macos) {
        _ = std.c.kill(-pid, .TERM);
        _ = std.c.kill(pid, .TERM);
    } else if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.kill(-pid, .TERM);
        _ = std.os.linux.kill(pid, .TERM);
    }
}

/// Reaps a direct child. False also covers a supervisor adopted from another
/// owner, since only its original parent is allowed to reap it.
pub fn reap(pid: Pid, block: bool) bool {
    if (comptime !supported) return false;
    if (comptime builtin.os.tag == .macos) {
        var status: c_int = 0;
        const flags: c_int = if (block) 0 else std.c.W.NOHANG;
        var waited = std.c.waitpid(pid, &status, flags);
        while (waited < 0 and std.c._errno().* == @backingInt(std.c.E.INTR)) {
            waited = std.c.waitpid(pid, &status, flags);
        }
        return waited == pid;
    }
    var status: i32 = 0;
    const flags: u32 = if (block) 0 else std.os.linux.W.NOHANG;
    var waited = std.os.linux.waitpid(pid, &status, flags);
    while (std.os.linux.errno(waited) == .INTR) {
        waited = std.os.linux.waitpid(pid, &status, flags);
    }
    return std.os.linux.errno(waited) == .SUCCESS and waited == @as(usize, @intCast(pid));
}

pub fn alive(pid: Pid) bool {
    if (comptime !supported) return false;
    if (pid <= 0) return false;
    if (comptime builtin.os.tag == .macos) {
        if (std.c.kill(pid, @fromBackingInt(0)) == 0) return true;
        return std.c._errno().* == @backingInt(std.c.E.PERM);
    }
    const rc = std.os.linux.kill(pid, @fromBackingInt(0));
    const err = std.os.linux.errno(rc);
    return err == .SUCCESS or err == .PERM;
}

pub fn currentPid() Pid {
    if (comptime builtin.os.tag == .macos) return std.c.getpid();
    if (comptime builtin.os.tag == .linux) return std.os.linux.getpid();
    return 0;
}

pub fn writeJsonAtomic(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    value: anytype,
) !void {
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(bytes);
    const temporary = try std.fmt.allocPrint(allocator, "{s}.tmp.{d}", .{ path, currentPid() });
    defer allocator.free(temporary);

    var file = try std.Io.Dir.createFileAbsolute(io, temporary, .{
        .permissions = .fromMode(0o600),
    });
    errdefer std.Io.Dir.deleteFileAbsolute(io, temporary) catch {};
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
    try file.sync(io);
    try std.Io.Dir.renameAbsolute(temporary, path, io);
}
