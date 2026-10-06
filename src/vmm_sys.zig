//! The calls the guest host makes that `std.posix` has not got, on both platforms.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const darwin = builtin.os.tag == .macos;

pub const Said = union(enum) { got: usize, ended, again, interrupted, broke };

pub fn read(fd: i32, into: []u8) Said {
    if (darwin) {
        const rc = std.c.read(fd, into.ptr, into.len);
        if (rc > 0) return .{ .got = @intCast(rc) };
        if (rc == 0) return .ended;
        return switch (std.c.errno(rc)) {
            .INTR => .interrupted,
            .AGAIN => .again,
            else => .broke,
        };
    }
    const rc = linux.read(fd, into.ptr, into.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => if (rc == 0) .ended else .{ .got = rc },
        .INTR => .interrupted,
        .AGAIN => .again,
        else => .broke,
    };
}

pub const Sent = union(enum) { took: usize, again, interrupted, broke };

pub fn write(fd: i32, bytes: []const u8) Sent {
    if (darwin) {
        const rc = std.c.write(fd, bytes.ptr, bytes.len);
        if (rc > 0) return .{ .took = @intCast(rc) };
        if (rc == 0) return .broke;
        return switch (std.c.errno(rc)) {
            .INTR => .interrupted,
            .AGAIN => .again,
            else => .broke,
        };
    }
    const rc = linux.write(fd, bytes.ptr, bytes.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => if (rc == 0) .broke else .{ .took = rc },
        .INTR => .interrupted,
        .AGAIN => .again,
        else => .broke,
    };
}

pub fn close(fd: i32) void {
    if (darwin) {
        _ = std.c.close(fd);
        return;
    }
    _ = linux.close(fd);
}

pub fn waiting(fd: i32, wanted: bool) bool {
    const asking: std.posix.O = .{ .NONBLOCK = true };
    const bit = @as(usize, @as(u32, @bitCast(asking)));
    if (darwin) {
        const flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(usize, 0));
        if (flags < 0) return false;
        const held = @as(usize, @intCast(flags));
        const with = if (wanted) held & ~bit else held | bit;
        return std.c.fcntl(fd, std.posix.F.SETFL, with) >= 0;
    }
    const flags = linux.fcntl(fd, std.posix.F.GETFL, 0);
    if (linux.errno(flags) != .SUCCESS) return false;
    const with = if (wanted) flags & ~bit else flags | bit;
    return linux.errno(linux.fcntl(fd, std.posix.F.SETFL, with)) == .SUCCESS;
}

pub fn sleepMs(milliseconds: u64) void {
    const sec: isize = @intCast(milliseconds / std.time.ms_per_s);
    const nsec: isize = @intCast((milliseconds % std.time.ms_per_s) * std.time.ns_per_ms);
    if (darwin) {
        const asked: std.c.timespec = .{ .sec = sec, .nsec = nsec };
        _ = std.c.nanosleep(&asked, null);
        return;
    }
    const asked: linux.timespec = .{ .sec = sec, .nsec = nsec };
    _ = linux.nanosleep(&asked, null);
}

pub fn channelPair(pair: *[2]i32) bool {
    if (darwin) {
        // macOS has no SOCK_CLOEXEC, so the flag is set afterwards on each half.
        if (std.c.socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, pair) != 0) return false;
        for (pair) |fd| {
            if (std.c.fcntl(fd, std.posix.F.SETFD, @as(usize, std.posix.FD_CLOEXEC)) < 0) {
                close(pair[0]);
                close(pair[1]);
                return false;
            }
        }
        return true;
    }
    const made = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, pair);
    return linux.errno(made) == .SUCCESS;
}

pub fn forkNow() ?i32 {
    if (darwin) {
        const pid = std.c.fork();
        return if (pid < 0) null else pid;
    }
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

pub fn dupOnto(from: i32, onto: i32) void {
    if (darwin) {
        _ = std.c.dup2(from, onto);
        return;
    }
    _ = linux.dup3(from, onto, 0);
}

pub fn ownSession() void {
    if (darwin) {
        _ = std.c.setsid();
        return;
    }
    _ = linux.setsid();
}

// Darwin has nothing that answers to PR_SET_PDEATHSIG, so the control channel covers it there: a dead parent closes its half.
pub fn endWithParent() void {
    if (darwin) return;
    _ = linux.prctl(
        @intFromEnum(linux.PR.SET_PDEATHSIG),
        @intFromEnum(linux.SIG.KILL),
        0,
        0,
        0,
    );
}

pub fn ignoreWriteSignals() void {
    if (darwin) {
        const ignore: std.c.Sigaction = .{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.mem.zeroes(std.c.sigset_t),
            .flags = 0,
        };
        _ = std.c.sigaction(.PIPE, &ignore, null);
        _ = std.c.sigaction(.IO, &ignore, null);
        return;
    }
    const ignore: linux.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.PIPE, &ignore, null);
    _ = linux.sigaction(.IO, &ignore, null);
}

fn onAlarm(_: std.posix.SIG) callconv(.c) void {}

pub fn armAlarmHandler() void {
    if (darwin) {
        const act: std.c.Sigaction = .{
            .handler = .{ .handler = onAlarm },
            .mask = std.mem.zeroes(std.c.sigset_t),
            .flags = 0,
        };
        _ = std.c.sigaction(.ALRM, &act, null);
        return;
    }
    const act: linux.Sigaction = .{
        .handler = .{ .handler = onAlarm },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.ALRM, &act, null);
}

pub const Thread = usize;

pub const no_thread: Thread = 0;

pub fn ownThread() Thread {
    if (darwin) return @intFromPtr(std.c.pthread_self());
    return @intCast(linux.gettid());
}

pub fn ownGroup() std.posix.pid_t {
    if (darwin) return std.c.getpid();
    return @intCast(linux.getpid());
}

pub fn alarmThread(group: std.posix.pid_t, thread: Thread) void {
    if (darwin) {
        _ = std.c.pthread_kill(@ptrFromInt(thread), .ALRM);
        return;
    }
    _ = linux.tgkill(group, @intCast(thread), .ALRM);
}

pub fn killNow(pid: std.posix.pid_t) void {
    if (darwin) {
        _ = std.c.kill(pid, .KILL);
        return;
    }
    _ = linux.kill(pid, .KILL);
}

pub fn reap(pid: std.posix.pid_t, wait_for_it: bool) ?u8 {
    if (darwin) {
        const options: c_int = if (wait_for_it) 0 else 1;
        var status: c_int = 0;
        var rc = std.c.wait4(pid, &status, options, null);
        while (rc < 0 and std.c.errno(rc) == .INTR) {
            rc = std.c.wait4(pid, &status, options, null);
        }
        if (rc < 0) return 1;
        if (rc == 0) return null;
        return codeFor(@bitCast(status));
    }
    const options: u32 = if (wait_for_it) 0 else linux.W.NOHANG;
    var status: u32 = 0;
    var rc = linux.wait4(pid, &status, options, null);
    while (linux.errno(rc) == .INTR) rc = linux.wait4(pid, &status, options, null);
    if (linux.errno(rc) != .SUCCESS) return 1;
    if (rc == 0) return null;
    return codeFor(status);
}

fn codeFor(status: u32) u8 {
    const W = if (darwin) std.c.W else linux.W;
    if (W.IFEXITED(status)) return W.EXITSTATUS(status);
    if (W.IFSIGNALED(status)) {
        const signal: u8 = @intCast(@intFromEnum(W.TERMSIG(status)) & 0x7f);
        return 128 + signal;
    }
    return 1;
}

test "an exit code and a signal are told apart" {
    try std.testing.expectEqual(@as(u8, 7), codeFor(7 << 8));
    try std.testing.expectEqual(@as(u8, 128 + 9), codeFor(9));
}
