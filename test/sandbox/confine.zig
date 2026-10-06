//! Proves the boundary `chock-sandbox/vm/confine.zig` builds, from inside a
//! forked child, with no guest and no virtual machine.
//! A refused exec dies with `SIGSYS` on Linux and an errno under Seatbelt, so
//! the child reports which of the two it met.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const sandbox = @import("chock-sandbox");

const darwin = builtin.os.tag == .macos;

const E = if (darwin) std.c.E else linux.E;

/// macOS has no `/bin/true`. Its coreutils live under `/usr/bin`.
const a_program: [:0]const u8 = if (darwin) "/usr/bin/true" else "/bin/true";

/// One word on the pipe, so a short read and a full one are told apart.
const word_len = 7;

/// Linux reads it through `/proc/self/fd`. Darwin has no such directory, so
/// `F_GETPATH` fills the buffer with the resolved path instead.
fn absoluteDirPath(buffer: []u8, dir_fd: i32) ![:0]u8 {
    if (darwin) {
        std.debug.assert(buffer.len >= 1024);
        if (std.c.fcntl(dir_fd, std.c.F.GETPATH, buffer.ptr) != 0) return error.PathUnreadable;
        const len = std.mem.len(@as([*:0]u8, @ptrCast(buffer.ptr)));
        return buffer[0..len :0];
    }
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn makePipe(fds: *[2]i32) bool {
    if (darwin) return std.c.pipe(fds) == 0;
    return linux.errno(linux.pipe2(fds, .{})) == .SUCCESS;
}

/// A new process, or null when this machine would not give one.
fn forkNow() ?i32 {
    if (darwin) {
        const pid = std.c.fork();
        return if (pid < 0) null else pid;
    }
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

/// Hold standard error aside so `sandbox_init` cannot write to it on a machine
/// that refuses the profile. `restoreStderr` puts it back.
fn quietStderr() i32 {
    if (!darwin) return -1;
    const saved = std.c.dup(2);
    if (saved < 0) return -1;
    const sink = std.c.open("/dev/null", .{ .ACCMODE = .WRONLY });
    if (sink < 0) {
        _ = std.c.close(saved);
        return -1;
    }
    _ = std.c.dup2(sink, 2);
    _ = std.c.close(sink);
    return saved;
}

fn restoreStderr(saved: i32) void {
    if (darwin) {
        if (saved < 0) return;
        _ = std.c.dup2(saved, 2);
        _ = std.c.close(saved);
    }
}

fn closeFd(fd: i32) void {
    if (darwin) {
        _ = std.c.close(fd);
        return;
    }
    _ = linux.close(fd);
}

fn say(fd: i32, word: *const [word_len]u8) void {
    if (darwin) {
        _ = std.c.write(fd, word, word.len);
        return;
    }
    _ = linux.write(fd, word, word.len);
}

/// One read, folded into the three answers a caller acts on.
const Chunk = union(enum) { got: usize, interrupted, done };

fn readOnce(fd: i32, buffer: []u8) Chunk {
    if (darwin) {
        const rc = std.c.read(fd, buffer.ptr, buffer.len);
        if (rc > 0) return .{ .got = @intCast(rc) };
        if (rc == 0) return .done;
        return if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) .interrupted else .done;
    }
    const rc = linux.read(fd, buffer.ptr, buffer.len);
    const errno = linux.errno(rc);
    if (errno == .INTR) return .interrupted;
    if (errno != .SUCCESS or rc == 0) return .done;
    return .{ .got = rc };
}

/// Reads until `buffer` is full or the write end closes, and returns how many bytes arrived.
fn readAll(fd: i32, buffer: []u8) usize {
    var held: usize = 0;
    while (held < buffer.len) {
        switch (readOnce(fd, buffer[held..])) {
            .got => |count| held += count,
            .interrupted => continue,
            .done => break,
        }
    }
    return held;
}

/// Whether a directory could really be read. A real access and not a handle:
/// `O_PATH` alone does not fire either mechanism's hooks.
fn readsDirectory(path: [:0]const u8) bool {
    if (darwin) {
        const fd = std.c.openat(std.c.AT.FDCWD, path.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true });
        if (fd < 0) return false;
        _ = std.c.close(fd);
        return true;
    }
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

fn makesFile(path: [:0]const u8) bool {
    if (darwin) {
        const fd = std.c.openat(std.c.AT.FDCWD, path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true }, @as(std.c.mode_t, 0o600));
        if (fd < 0) return false;
        _ = std.c.close(fd);
        return true;
    }
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true }, 0o600);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Try to run a program, and say what came back. `execve` only ever returns on
/// a failure. On Linux the seccomp default answers with a signal instead.
fn triedToExec(path: [:0]const u8) E {
    const nothing: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    if (darwin) {
        std.c._errno().* = 0;
        _ = std.c.execve(path.ptr, nothing, nothing);
        return @enumFromInt(std.c._errno().*);
    }
    return linux.errno(linux.execve(path, nothing, nothing));
}

fn exitNow(code: u8) noreturn {
    if (darwin) std.c._exit(code);
    std.process.exit(code);
}

/// The child's wait status, or null when the wait itself failed.
fn waitFor(pid: i32) ?u32 {
    if (darwin) {
        var status: c_int = 0;
        while (std.c.waitpid(pid, &status, 0) < 0) {
            if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) return null;
        }
        return @bitCast(status);
    }
    var status: u32 = undefined;
    var rc = linux.waitpid(@intCast(pid), &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(@intCast(pid), &status, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return status;
}

/// The signal that ended the child, as a number, or null when nothing did.
fn killedBy(status: u32) ?u32 {
    if (darwin) {
        if (!std.c.W.IFSIGNALED(status)) return null;
        return @intFromEnum(std.c.W.TERMSIG(status));
    }
    if (!linux.W.IFSIGNALED(status)) return null;
    return @intFromEnum(linux.W.TERMSIG(status));
}

fn exitedWith(status: u32) ?u8 {
    if (darwin) {
        if (!std.c.W.IFEXITED(status)) return null;
        return std.c.W.EXITSTATUS(status);
    }
    if (linux.W.IFSIGNALED(status)) return null;
    return linux.W.EXITSTATUS(status);
}

test "a confined VMM cannot run a program, reach a path outside its shares, or write into a read-only one" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const share_path = try absoluteDirPath(&buffer, tmp.dir.handle);

    var tmp_ro = std.testing.tmpDir(.{});
    defer tmp_ro.cleanup();
    var ro_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const ro_share_path = try absoluteDirPath(&ro_buffer, tmp_ro.dir.handle);

    const shares = [_]sandbox.vm_shares.Share{
        .{ .name = "work", .host_path = share_path, .writable = true },
        .{ .name = "readonly", .host_path = ro_share_path, .writable = false },
    };

    var pipes: [2]i32 = undefined;
    try std.testing.expect(makePipe(&pipes));

    const child = forkNow() orelse {
        closeFd(pipes[0]);
        closeFd(pipes[1]);
        return error.SkipZigTest;
    };

    if (child == 0) {
        closeFd(pipes[0]);
        var which: ?sandbox.vm_confine.Layer = null;
        const held = quietStderr();
        sandbox.vm_confine.install(allocator, &shares, &which, null) catch {
            restoreStderr(held);
            say(pipes[1], "refused");
            exitNow(2);
        };
        restoreStderr(held);

        const inside = readsDirectory(share_path);
        const outside = readsDirectory("/etc");

        var probe_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const probe_path = std.fmt.bufPrintZ(&probe_buffer, "{s}/probe", .{ro_share_path}) catch unreachable;
        const ro_write = makesFile(probe_path);

        const fs_held = inside and !outside and !ro_write;
        say(pipes[1], if (fs_held) "fs-held" else "fs-open");

        // A refusal by the confinement and a missing program give different errnos.
        const refusal = triedToExec(a_program);
        say(pipes[1], if (refusal == .PERM) "deny-ep" else "deny-??");
        exitNow(1);
    }

    closeFd(pipes[1]);
    var said: [word_len]u8 = @splat(0);
    _ = readAll(pipes[0], &said);

    var trailing: [word_len]u8 = @splat(0);
    const trailing_held = readAll(pipes[0], &trailing);
    closeFd(pipes[0]);

    const status = waitFor(child) orelse return error.SkipZigTest;

    // A machine whose confinement will not install skips rather than failing.
    if (std.mem.eql(u8, &said, "refused")) return error.SkipZigTest;

    try std.testing.expectEqualStrings("fs-held", &said);

    if (darwin) {
        // Seatbelt answers `EPERM`, so the second word is the proof.
        try std.testing.expectEqual(@as(usize, word_len), trailing_held);
        try std.testing.expectEqualStrings("deny-ep", &trailing);
        try std.testing.expectEqual(@as(?u8, 1), exitedWith(status));
    } else {
        // A second message on the pipe would mean the filter let the exec through.
        try std.testing.expectEqual(@as(usize, 0), trailing_held);
        try std.testing.expectEqual(@as(?u32, @intFromEnum(linux.SIG.SYS)), killedBy(status));
    }
}

/// Set from inside the confined child's own thread, so the parent learns the thread really ran.
fn markRan(ran: *std.atomic.Value(bool)) void {
    ran.store(true, .release);
}

test "a confined VMM can start a thread of its own" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const share_path = try absoluteDirPath(&buffer, tmp.dir.handle);

    const shares = [_]sandbox.vm_shares.Share{
        .{ .name = "work", .host_path = share_path, .writable = true },
    };

    var pipes: [2]i32 = undefined;
    try std.testing.expect(makePipe(&pipes));

    const child = forkNow() orelse {
        closeFd(pipes[0]);
        closeFd(pipes[1]);
        return error.SkipZigTest;
    };

    if (child == 0) {
        closeFd(pipes[0]);
        var which: ?sandbox.vm_confine.Layer = null;
        const held = quietStderr();
        sandbox.vm_confine.install(allocator, &shares, &which, null) catch {
            restoreStderr(held);
            say(pipes[1], "refused");
            exitNow(2);
        };
        restoreStderr(held);

        // A Linux `vmm_calls` without `mprotect` and `sigaltstack` kills this
        // process here before it can write anything, leaving the pipe empty.
        var ran: std.atomic.Value(bool) = .init(false);
        const thread = std.Thread.spawn(.{}, markRan, .{&ran}) catch {
            say(pipes[1], "nospawn");
            exitNow(3);
        };
        thread.join();

        say(pipes[1], if (ran.load(.acquire)) "spawned" else "notheit");
        exitNow(0);
    }

    closeFd(pipes[1]);
    var said: [word_len]u8 = @splat(0);
    const held = readAll(pipes[0], &said);
    closeFd(pipes[0]);

    const status = waitFor(child) orelse return error.SkipZigTest;

    if (std.mem.eql(u8, &said, "refused")) return error.SkipZigTest;

    try std.testing.expectEqual(@as(?u32, null), killedBy(status));
    try std.testing.expectEqual(@as(usize, word_len), held);
    try std.testing.expectEqualStrings("spawned", &said);
    try std.testing.expectEqual(@as(?u8, 0), exitedWith(status));
}
