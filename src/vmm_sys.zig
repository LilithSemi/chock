//! The calls the guest host makes that `std.posix` has not got, on both
//! platforms.
//!
//! **Linux goes to the kernel and Darwin goes through libSystem, and neither is
//! a choice.** `std.posix` has no `fork`, and `std.os.linux` has no Darwin half
//! at all. So the two arms are written out here once rather than at every call
//! site in `src/vmm.zig`.
//!
//! **A `sigset_t` is one word to the Linux kernel and sixteen to POSIX**, so a
//! mask built by one and given to the other is the wrong size. Each arm below
//! stays inside its own set of types for that reason.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

pub const darwin = builtin.os.tag == .macos;

/// What one read answered. `again` and `interrupted` are kept apart from `ended`
/// because a channel that said nothing is not a channel that closed.
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

/// What one write answered. A write of zero bytes is `broke`: the caller has
/// bytes left and nothing took them.
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

/// Ask a descriptor not to wait, or to wait again.
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

/// Wait this long, and never mind an interruption cutting it short: the caller
/// is counting the turns and not the time it really slept.
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

/// A connected pair of unix sockets, both closing on exec.
///
/// **Close on exec on both halves.** The parent asks for the end by closing its
/// own, and a copy left in anything it later executes would hold the channel
/// open and the guest would never be asked.
pub fn channelPair(pair: *[2]i32) bool {
    if (darwin) {
        // macOS has no `SOCK_CLOEXEC`, so the flag is set afterwards on each half.
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

/// Zero in the child, the child's id in the parent, null for a fork that failed.
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

/// A session of this process's own, so one Ctrl-C at the terminal does not take
/// the guest with it.
pub fn ownSession() void {
    if (darwin) {
        _ = std.c.setsid();
        return;
    }
    _ = linux.setsid();
}

/// End this process when its parent ends.
///
/// **Darwin has nothing that answers to `PR_SET_PDEATHSIG`, and the control
/// channel is what covers it there.** A parent that dies closes its half, which
/// the child reads as the request to stop: see `Pump.step`. The one case Linux
/// also covers is a child wedged before it reads that channel at all.
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

/// Answer a write to a peer that hung up with `EPIPE` rather than a signal.
///
/// `resetSignalState` undoes the ignore `std.Io.Threaded.init` put on these two
/// and nothing puts it back, so this is called after it and not instead of it.
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

/// Install the handler that makes a blocked hypervisor call return. **No
/// `SA_RESTART`**: the interruption is the whole point, and a restarted call
/// would never come back.
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

/// How one thread of this process is named, so it alone can be signalled.
///
/// Linux names a thread by its own id and signals it with `tgkill`. Darwin has
/// no such call and names it by its pthread handle instead. The handle is held
/// as an integer so one atomic carries either.
pub const Thread = usize;

/// The nothing a thread that has not said which one it is holds. Zero is no
/// thread id on Linux and no pthread on Darwin.
pub const no_thread: Thread = 0;

pub fn ownThread() Thread {
    if (darwin) return @intFromPtr(std.c.pthread_self());
    return @intCast(linux.gettid());
}

pub fn ownGroup() std.posix.pid_t {
    if (darwin) return std.c.getpid();
    return @intCast(linux.getpid());
}

/// Signal one thread of this process and no other.
pub fn alarmThread(group: std.posix.pid_t, thread: Thread) void {
    if (darwin) {
        // Darwin names a thread by its pthread handle, so the process it belongs
        // to is not asked for.
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

/// What a child exited with, or null for one that is still running. `waiting`
/// false asks without waiting.
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

/// An exit status as one number. A signal is not an exit code, so it is reported
/// as `128` plus the signal and never folded into one.
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
    // The shell's own convention, so a guest the parent killed is not read as a
    // guest that refused to come up and exited 1. Both platforms spell a status
    // the same way, so this runs on both.
    try std.testing.expectEqual(@as(u8, 7), codeFor(7 << 8));
    try std.testing.expectEqual(@as(u8, 128 + 9), codeFor(9));
}
