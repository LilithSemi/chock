//! Cgroup v2 resource limits: resident memory and process count.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const rlimits = @import("rlimits.zig");

const mount_points = [_][:0]const u8{ "/sys/fs/cgroup", "/sys/fs/cgroup/unified" };

const wanted_controllers = [_][]const u8{ "memory", "pids" };

const max_control_file_bytes = 4096;

pub const Support = union(enum) {
    ok,
    off,
    supplied,
    unsupported: Reason,
    unavailable: Reason,

    pub const Reason = enum {
        no_cgroup2_tree,
        no_cgroup2_mount,
        not_in_unified_hierarchy,
        cgroup_path_too_long,
        no_delegated_parent,
        create_refused,
        write_refused,

        pub fn text(self: Reason) []const u8 {
            return switch (self) {
                .no_cgroup2_tree => "this machine has no cgroup v2 tree",
                .no_cgroup2_mount => "no cgroup v2 tree is mounted where this process can see one",
                .not_in_unified_hierarchy => "this process is not in a cgroup v2 hierarchy",
                .cgroup_path_too_long => "this process's own cgroup path is too long to use",
                .no_delegated_parent => "no cgroup above this one delegates the memory and pids controllers",
                .create_refused => "a cgroup directory could not be made",
                .write_refused => "a cgroup limit file could not be written",
            };
        }
    };

    pub fn applied(self: Support) bool {
        return self == .ok;
    }

    pub fn format(self: Support, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => try writer.writeAll("the cgroup limits are on"),
            .off => try writer.writeAll("no cgroup limits were asked for"),
            .supplied => try writer.writeAll("the caller's own cgroup holds the program, and chock wrote no limit into it"),
            .unsupported => |reason| try writer.print("no cgroup limits: {s}", .{reason.text()}),
            .unavailable => |reason| try writer.print("no cgroup limits: {s}", .{reason.text()}),
        }
    }
};

pub const Vantage = enum {
    own,
    foreign,
    not_mounted,
    none,
    unknown,
};

pub fn readVantage() Vantage {
    var relative_buffer: [max_control_file_bytes]u8 = undefined;

    const root = findRoot() orelse {
        return if (readSelfCgroup(&relative_buffer) == null) .none else .not_mounted;
    };
    const relative = readSelfCgroup(&relative_buffer) orelse return .none;

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = joinPath(&path_buffer, root, relative) orelse return .unknown;

    const holds = holdsSelf(path_buffer[0..path_len]) orelse return .unknown;
    return if (holds) .own else .foreign;
}

fn holdsSelf(dir: []const u8) ?bool {
    var number: [32]u8 = undefined;
    const wanted = std.fmt.bufPrint(&number, "{d}", .{linux.getpid()}) catch return null;

    var full: [std.fs.max_path_bytes]u8 = undefined;
    const full_len = joinPath(&full, dir, "cgroup.procs") orelse return null;
    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&full_z, full[0..full_len]) orelse return null;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var line: [32]u8 = undefined;
    var line_len: usize = 0;
    var line_too_long = false;

    var buffer: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, buffer[0..].ptr, buffer.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;

        for (buffer[0..rc]) |byte| {
            if (byte != '\n') {
                if (line_len == line.len) {
                    line_too_long = true;
                } else {
                    line[line_len] = byte;
                    line_len += 1;
                }
                continue;
            }
            if (!line_too_long and std.mem.eql(u8, line[0..line_len], wanted)) return true;
            line_len = 0;
            line_too_long = false;
        }
    }

    if (line_too_long or line_len == 0) return false;
    return std.mem.eql(u8, line[0..line_len], wanted);
}

pub const Events = struct {
    oom_kills: u64 = 0,
    fork_refusals: u64 = 0,
};

pub const clone_into_cgroup_since: rlimits.Release = .{ .major = 5, .minor = 7 };

const CloneArgs = extern struct {
    flags: u64 align(8) = 0,
    pidfd: u64 align(8) = 0,
    child_tid: u64 align(8) = 0,
    parent_tid: u64 align(8) = 0,
    exit_signal: u64 align(8) = 0,
    stack: u64 align(8) = 0,
    stack_size: u64 align(8) = 0,
    tls: u64 align(8) = 0,
    set_tid: u64 align(8) = 0,
    set_tid_size: u64 align(8) = 0,
    cgroup: u64 align(8) = 0,
};

pub fn forkInto(dir_fd: i32) usize {
    if (comptime builtin.cpu.arch.isSPARC()) return refusal(.OPNOTSUPP);

    if (dir_fd < 0) return refusal(.BADF);

    var args = CloneArgs{
        .flags = linux.CLONE.INTO_CGROUP,
        .exit_signal = @intFromEnum(linux.SIG.CHLD),
        .cgroup = @intCast(dir_fd),
    };
    return linux.syscall2(.clone3, @intFromPtr(&args), @sizeOf(CloneArgs));
}

fn refusal(errno_value: linux.E) usize {
    return @bitCast(-@as(isize, @intFromEnum(errno_value)));
}

pub const Cgroup = struct {
    support: Support,
    path_buffer: [std.fs.max_path_bytes]u8 = undefined,
    path_len: usize = 0,
    procs_fd: i32 = -1,

    pub fn path(self: *const Cgroup) []const u8 {
        return self.path_buffer[0..self.path_len];
    }

    pub fn create(memory_bytes: ?u64, processes: ?u64, name_seed: u64) Cgroup {
        std.debug.assert(memory_bytes != null or processes != null);

        var self = Cgroup{ .support = .{ .unsupported = .no_cgroup2_tree } };

        const root = findRoot() orelse {
            var hierarchy_buffer: [max_control_file_bytes]u8 = undefined;
            if (readSelfCgroup(&hierarchy_buffer) != null) {
                self.support = .{ .unavailable = .no_cgroup2_mount };
            }
            return self;
        };

        var self_path_buffer: [max_control_file_bytes]u8 = undefined;
        const relative = readSelfCgroup(&self_path_buffer) orelse {
            self.support = .{ .unsupported = .not_in_unified_hierarchy };
            return self;
        };

        var parent_buffer: [std.fs.max_path_bytes]u8 = undefined;
        var parent_len = joinPath(&parent_buffer, root, relative) orelse {
            self.support = .{ .unsupported = .cgroup_path_too_long };
            return self;
        };

        var found_a_delegating_parent = false;
        while (true) {
            if (delegatesWantedControllers(parent_buffer[0..parent_len])) {
                found_a_delegating_parent = true;
                if (self.makeUnder(parent_buffer[0..parent_len], name_seed)) {
                    self.applyLimits(memory_bytes, processes);
                    return self;
                }
            }
            parent_len = parentOf(parent_buffer[0..parent_len], root.len) orelse break;
        }

        self.support = if (found_a_delegating_parent)
            .{ .unavailable = .create_refused }
        else
            .{ .unavailable = .no_delegated_parent };
        return self;
    }

    pub fn join(self: *const Cgroup) ?linux.E {
        if (self.procs_fd < 0) return null;
        const rc = linux.write(self.procs_fd, "0", 1);
        const write_errno = linux.errno(rc);
        if (write_errno != .SUCCESS) return write_errno;
        return null;
    }

    pub fn closeProcsFd(self: *Cgroup) void {
        if (self.procs_fd >= 0) _ = linux.close(self.procs_fd);
        self.procs_fd = -1;
    }

    pub fn readEvents(self: *const Cgroup) Events {
        if (!self.support.applied()) return .{};
        return .{
            .oom_kills = self.readEventField("memory.events", "oom_kill "),
            .fork_refusals = self.readEventField("pids.events", "max "),
        };
    }

    pub fn destroy(self: *Cgroup) void {
        self.closeProcsFd();
        if (!self.support.applied()) return;

        var path_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&path_z, self.path()) orelse return;

        const dir_rc = linux.open(zeroed, .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .CLOEXEC = true,
        }, 0);
        if (linux.errno(dir_rc) == .SUCCESS) {
            const dir_fd: i32 = @intCast(dir_rc);
            killMembers(dir_fd);
            _ = linux.close(dir_fd);
        }

        removeWhenEmpty(linux.AT.FDCWD, zeroed);
    }

    fn makeUnder(self: *Cgroup, parent: []const u8, name_seed: u64) bool {
        sweepStaleSiblings(parent);

        var name_buffer: [64]u8 = undefined;
        const name = std.fmt.bufPrint(
            &name_buffer,
            "{s}{d}.{d}",
            .{ name_prefix, linux.getpid(), name_seed },
        ) catch return false;

        var full: [std.fs.max_path_bytes]u8 = undefined;
        const full_len = joinPath(&full, parent, name) orelse return false;

        var full_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&full_z, full[0..full_len]) orelse return false;
        if (linux.errno(linux.mkdirat(linux.AT.FDCWD, zeroed, 0o755)) != .SUCCESS) return false;

        @memcpy(self.path_buffer[0..full_len], full[0..full_len]);
        self.path_len = full_len;
        return true;
    }

    fn applyLimits(self: *Cgroup, memory_bytes: ?u64, processes: ?u64) void {
        var number: [32]u8 = undefined;

        if (memory_bytes) |bytes| {
            const text = std.fmt.bufPrint(&number, "{d}", .{bytes}) catch return self.failWrite();
            if (!writeFileAt(self.path(), "memory.max", text)) return self.failWrite();
            _ = writeFileAt(self.path(), "memory.swap.max", "0");
        }

        if (processes) |count| {
            const text = std.fmt.bufPrint(&number, "{d}", .{count}) catch return self.failWrite();
            if (!writeFileAt(self.path(), "pids.max", text)) return self.failWrite();
        }

        var procs: [std.fs.max_path_bytes]u8 = undefined;
        const procs_len = joinPath(&procs, self.path(), "cgroup.procs") orelse return self.failWrite();
        var procs_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&procs_z, procs[0..procs_len]) orelse return self.failWrite();
        const fd_rc = linux.open(zeroed, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) return self.failWrite();
        self.procs_fd = @intCast(fd_rc);

        self.support = .ok;
    }

    fn failWrite(self: *Cgroup) void {
        self.support = .{ .unavailable = .write_refused };
    }

    fn readEventField(self: *const Cgroup, file: []const u8, key: []const u8) u64 {
        var buffer: [max_control_file_bytes]u8 = undefined;
        const contents = readFileAt(self.path(), file, &buffer) orelse return 0;
        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, key)) continue;
            return std.fmt.parseInt(u64, std.mem.trim(u8, line[key.len..], " \r"), 10) catch 0;
        }
        return 0;
    }
};

const name_prefix = "chock.";

fn sweepStaleSiblings(parent: []const u8) void {
    var parent_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&parent_z, parent) orelse return;
    const dir_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return;
    const dir_fd: i32 = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    var buffer: [4096]u8 = undefined;
    while (true) {
        const nread = linux.getdents64(dir_fd, &buffer, buffer.len);
        if (linux.errno(nread) != .SUCCESS or nread == 0) return;

        var offset: usize = 0;
        while (offset < nread) {
            const entry: *align(1) const linux.dirent64 = @ptrCast(&buffer[offset]);
            const name_offset = offset + @offsetOf(linux.dirent64, "name");
            const name_ptr: [*:0]const u8 = @ptrCast(&buffer[name_offset]);
            const name = std.mem.sliceTo(name_ptr, 0);
            offset += entry.reclen;

            if (entry.type != linux.DT.DIR) continue;
            const maker = ownedCgroupPid(name) orelse continue;
            if (processExists(maker)) continue;

            const child_rc = linux.openat(dir_fd, name_ptr, .{
                .ACCMODE = .RDONLY,
                .DIRECTORY = true,
                .CLOEXEC = true,
                .NOFOLLOW = true,
            }, 0);
            if (linux.errno(child_rc) == .SUCCESS) {
                const child_fd: i32 = @intCast(child_rc);
                killMembers(child_fd);
                _ = linux.close(child_fd);
            }

            removeWhenEmpty(dir_fd, name_ptr);
        }
    }
}

fn ownedCgroupPid(name: []const u8) ?linux.pid_t {
    if (!std.mem.startsWith(u8, name, name_prefix)) return null;
    const rest = name[name_prefix.len..];

    const dot = std.mem.indexOfScalar(u8, rest, '.') orelse return null;
    const pid_text = rest[0..dot];
    const seq_text = rest[dot + 1 ..];
    if (pid_text.len == 0 or seq_text.len == 0) return null;

    for (pid_text) |byte| if (!std.ascii.isDigit(byte)) return null;
    for (seq_text) |byte| if (!std.ascii.isDigit(byte)) return null;

    _ = std.fmt.parseInt(u64, seq_text, 10) catch return null;
    const pid = std.fmt.parseInt(linux.pid_t, pid_text, 10) catch return null;
    if (pid <= 0) return null;
    return pid;
}

fn processExists(pid: linux.pid_t) bool {
    const rc = linux.syscall2(.kill, @bitCast(@as(isize, pid)), 0);
    return linux.errno(rc) != .SRCH;
}

const max_kill_rounds = 16;

fn killMembers(dir_fd: i32) void {
    const kill_rc = linux.openat(dir_fd, "cgroup.kill", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(kill_rc) == .SUCCESS) {
        const kill_fd: i32 = @intCast(kill_rc);
        defer _ = linux.close(kill_fd);
        while (true) {
            const rc = linux.write(kill_fd, "1", 1);
            const write_errno = linux.errno(rc);
            if (write_errno == .INTR) continue;
            if (write_errno == .SUCCESS) return;
            break;
        }
    }

    var round: usize = 0;
    while (round < max_kill_rounds) : (round += 1) {
        const signalled = signalMembers(dir_fd) orelse return;
        if (signalled == 0) return;
        _ = linux.syscall0(.sched_yield);
    }
}

fn signalMembers(dir_fd: i32) ?usize {
    const fd_rc = linux.openat(dir_fd, "cgroup.procs", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const self_pid = linux.getpid();
    var signalled: usize = 0;

    var line: [32]u8 = undefined;
    var line_len: usize = 0;
    var line_too_long = false;

    var buffer: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fd, buffer[0..].ptr, buffer.len);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;

        for (buffer[0..rc]) |byte| {
            if (byte != '\n') {
                if (line_len == line.len) {
                    line_too_long = true;
                } else {
                    line[line_len] = byte;
                    line_len += 1;
                }
                continue;
            }
            if (!line_too_long and line_len > 0) {
                if (signalOne(line[0..line_len], self_pid)) signalled += 1;
            }
            line_len = 0;
            line_too_long = false;
        }
    }

    if (!line_too_long and line_len > 0) {
        if (signalOne(line[0..line_len], self_pid)) signalled += 1;
    }
    return signalled;
}

fn signalOne(text: []const u8, self_pid: linux.pid_t) bool {
    for (text) |byte| if (!std.ascii.isDigit(byte)) return false;
    const pid = std.fmt.parseInt(linux.pid_t, text, 10) catch return false;
    if (pid <= 0 or pid == self_pid) return false;
    return linux.errno(linux.kill(pid, .KILL)) == .SUCCESS;
}

const remove_pause_ns = 500 * std.time.ns_per_us;
const remove_attempts = 400;

fn removeWhenEmpty(dir_fd: i32, name: [*:0]const u8) void {
    var attempt: usize = 0;
    while (attempt < remove_attempts) : (attempt += 1) {
        const rc = linux.unlinkat(dir_fd, name, linux.AT.REMOVEDIR);
        switch (linux.errno(rc)) {
            .SUCCESS, .NOENT => return,
            else => {},
        }
        const request = linux.timespec{ .sec = 0, .nsec = remove_pause_ns };
        _ = linux.nanosleep(&request, null);
    }
}

fn findRoot() ?[:0]const u8 {
    for (&mount_points) |candidate| {
        var probe: [std.fs.max_path_bytes]u8 = undefined;
        const len = joinPath(&probe, candidate, "cgroup.controllers") orelse continue;
        var probe_z: [std.fs.max_path_bytes]u8 = undefined;
        const zeroed = nullTerminate(&probe_z, probe[0..len]) orelse continue;
        const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(fd_rc) != .SUCCESS) continue;
        _ = linux.close(@intCast(fd_rc));
        return candidate;
    }
    return null;
}

fn readSelfCgroup(buffer: []u8) ?[]const u8 {
    const contents = readWholeFile("/proc/self/cgroup", buffer) orelse return null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "0::")) continue;
        const rest = std.mem.trim(u8, line[3..], " \r");
        if (rest.len == 0) return null;
        return rest;
    }
    return null;
}

fn delegatesWantedControllers(dir: []const u8) bool {
    var buffer: [max_control_file_bytes]u8 = undefined;
    const contents = readFileAt(dir, "cgroup.subtree_control", &buffer) orelse return false;
    for (&wanted_controllers) |wanted| {
        var found = false;
        var names = std.mem.tokenizeAny(u8, contents, " \n\r\t");
        while (names.next()) |name| {
            if (std.mem.eql(u8, name, wanted)) found = true;
        }
        if (!found) return false;
    }
    return true;
}

fn parentOf(dir: []const u8, root_len: usize) ?usize {
    if (dir.len <= root_len) return null;
    const slash = std.mem.lastIndexOfScalar(u8, dir, '/') orelse return null;
    if (slash < root_len) return root_len;
    return slash;
}

fn joinPath(buffer: []u8, a: []const u8, b: []const u8) ?usize {
    const trimmed_a = if (a.len > 1 and a[a.len - 1] == '/') a[0 .. a.len - 1] else a;
    const trimmed_b = if (b.len > 0 and b[0] == '/') b[1..] else b;
    const needed = trimmed_a.len + 1 + trimmed_b.len;
    if (needed > buffer.len) return null;
    @memcpy(buffer[0..trimmed_a.len], trimmed_a);
    buffer[trimmed_a.len] = '/';
    @memcpy(buffer[trimmed_a.len + 1 ..][0..trimmed_b.len], trimmed_b);
    return needed;
}

fn nullTerminate(buffer: []u8, text: []const u8) ?[:0]const u8 {
    if (text.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

fn readFileAt(dir: []const u8, name: []const u8, buffer: []u8) ?[]const u8 {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const len = joinPath(&full, dir, name) orelse return null;
    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&full_z, full[0..len]) orelse return null;
    return readWholeFile(zeroed, buffer);
}

fn readWholeFile(path: [*:0]const u8, buffer: []u8) ?[]const u8 {
    const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS) return null;
        if (rc == 0) break;
        filled += rc;
    }
    return buffer[0..filled];
}

fn writeFileAt(dir: []const u8, name: []const u8, contents: []const u8) bool {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const len = joinPath(&full, dir, name) orelse return false;
    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&full_z, full[0..len]) orelse return false;

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const rc = linux.write(fd, contents.ptr, contents.len);
    return linux.errno(rc) == .SUCCESS and rc == contents.len;
}

test "joinPath puts exactly one separator between two parts" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/pids.max", buffer[0..joinPath(&buffer, "/sys/fs/cgroup", "pids.max").?]);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/pids.max", buffer[0..joinPath(&buffer, "/sys/fs/cgroup/", "pids.max").?]);
    try std.testing.expectEqualStrings("/sys/fs/cgroup/pids.max", buffer[0..joinPath(&buffer, "/sys/fs/cgroup", "/pids.max").?]);

    var tiny: [4]u8 = undefined;
    try std.testing.expectEqual(@as(?usize, null), joinPath(&tiny, "/sys/fs/cgroup", "pids.max"));
}

test "parentOf walks up and stops at the tree's own mount point" {
    const root = "/sys/fs/cgroup";
    const full = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/a.scope";

    var len = full.len;
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service", full[0..len]);
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/user.slice/user-1000.slice", full[0..len]);
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings("/sys/fs/cgroup/user.slice", full[0..len]);
    len = parentOf(full[0..len], root.len).?;
    try std.testing.expectEqualStrings(root, full[0..len]);

    try std.testing.expectEqual(@as(?usize, null), parentOf(full[0..len], root.len));
}

test "readSelfCgroup takes the unified line and refuses a v1 only file" {
    var buffer: [max_control_file_bytes]u8 = undefined;

    const hybrid = "8:memory:/user.slice\n4:pids:/user.slice\n0::/user.slice/user-1000.slice\n";
    @memcpy(buffer[0..hybrid.len], hybrid);
    var lines = std.mem.splitScalar(u8, buffer[0..hybrid.len], '\n');
    var found: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "0::")) found = std.mem.trim(u8, line[3..], " \r");
    }
    try std.testing.expectEqualStrings("/user.slice/user-1000.slice", found.?);

    if (builtin.os.tag != .linux) return;
    var live: [max_control_file_bytes]u8 = undefined;
    if (readSelfCgroup(&live)) |relative| {
        try std.testing.expect(relative.len > 0);
        try std.testing.expectEqual(@as(u8, '/'), relative[0]);
    }
}

test "a Support value says which of the three things happened, in words" {
    var buffer: [128]u8 = undefined;

    try std.testing.expectEqualStrings(
        "the cgroup limits are on",
        try std.fmt.bufPrint(&buffer, "{f}", .{@as(Support, .ok)}),
    );
    try std.testing.expectEqualStrings(
        "no cgroup limits: this machine has no cgroup v2 tree",
        try std.fmt.bufPrint(&buffer, "{f}", .{Support{ .unsupported = .no_cgroup2_tree }}),
    );
    try std.testing.expectEqualStrings(
        "no cgroup limits: no cgroup above this one delegates the memory and pids controllers",
        try std.fmt.bufPrint(&buffer, "{f}", .{Support{ .unavailable = .no_delegated_parent }}),
    );
    try std.testing.expectEqualStrings(
        "no cgroup limits: no cgroup v2 tree is mounted where this process can see one",
        try std.fmt.bufPrint(&buffer, "{f}", .{Support{ .unavailable = .no_cgroup2_mount }}),
    );

    try std.testing.expectEqualStrings(
        "the caller's own cgroup holds the program, and chock wrote no limit into it",
        try std.fmt.bufPrint(&buffer, "{f}", .{@as(Support, .supplied)}),
    );

    try std.testing.expect(@as(Support, .ok).applied());
    try std.testing.expect(!(Support{ .unsupported = .no_cgroup2_tree }).applied());
    try std.testing.expect(!(Support{ .unavailable = .create_refused }).applied());
    try std.testing.expect(!(@as(Support, .supplied)).applied());

    const reasons = std.enums.values(Support.Reason);
    for (reasons, 0..) |reason, i| {
        try std.testing.expect(reason.text().len > 0);
        for (reasons[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, reason.text(), other.text()));
        }
    }
}

test "the vantage tells this machine's own tree from a namespace's view of it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const here = readVantage();
    if (here == .none) return error.SkipZigTest;

    {
        var group = Cgroup.create(64 << 20, 16, 0xC06400);
        defer group.destroy();
        if (group.support == .ok) try std.testing.expectEqual(Vantage.own, here);
    }

    if (here != .own) return error.SkipZigTest;

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return error.SkipZigTest;
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        const flags = linux.CLONE.NEWUSER | linux.CLONE.NEWCGROUP;
        const record: [2]u8 = if (linux.errno(linux.unshare(flags)) == .SUCCESS)
            .{ 1, @intCast(@intFromEnum(readVantage())) }
        else
            .{ 0, 0 };
        _ = linux.write(fds[1], &record, record.len);
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var record: [2]u8 = .{ 0, 0 };
    var held: usize = 0;
    while (held < record.len) {
        const rc = linux.read(fds[0], record[held..].ptr, record.len - held);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        held += rc;
    }
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    if (held != record.len or record[0] != 1) return error.SkipZigTest;

    const inside = std.enums.fromInt(Vantage, record[1]) orelse return error.SkipZigTest;

    try std.testing.expectEqual(Vantage.foreign, inside);
}

test "a cgroup is made, holds the limits asked for, and is removed again" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var group = Cgroup.create(64 << 20, 16, 0xC0FFEE);
    defer group.destroy();

    switch (group.support) {
        .off, .supplied, .unsupported, .unavailable => {
            try std.testing.expectEqual(@as(usize, 0), group.path_len);
            try std.testing.expectEqual(@as(i32, -1), group.procs_fd);
            return;
        },
        .ok => {},
    }

    var buffer: [max_control_file_bytes]u8 = undefined;
    const memory_max = readFileAt(group.path(), "memory.max", &buffer).?;
    try std.testing.expectEqualStrings("67108864", std.mem.trim(u8, memory_max, " \n"));
    const pids_max = readFileAt(group.path(), "pids.max", &buffer).?;
    try std.testing.expectEqualStrings("16", std.mem.trim(u8, pids_max, " \n"));

    try std.testing.expect(group.procs_fd >= 0);

    var kept: [std.fs.max_path_bytes]u8 = undefined;
    const kept_path = kept[0..group.path_len];
    @memcpy(kept_path, group.path());

    group.destroy();

    var after: [max_control_file_bytes]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), readFileAt(kept_path, "pids.max", &after));
}

test "a cgroup name is read strictly, and any other shape is refused" {
    try std.testing.expectEqual(@as(?linux.pid_t, 1130789), ownedCgroupPid("chock.1130789.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, 7), ownedCgroupPid("chock.7.18446744073709551615"));

    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock."));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1."));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock..1"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.0.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chocks.1.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("session.scope"));

    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.+1.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.-1.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1_0.0"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1.0.mine"));
    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.1.0x0"));

    try std.testing.expectEqual(@as(?linux.pid_t, null), ownedCgroupPid("chock.99999999999999999999.0"));
}

fn testDelegatingAncestor(buffer: []u8) ?usize {
    const root = findRoot() orelse return null;
    var relative_buffer: [max_control_file_bytes]u8 = undefined;
    const relative = readSelfCgroup(&relative_buffer) orelse return null;

    var len = joinPath(buffer, root, relative) orelse return null;
    while (true) {
        if (delegatesWantedControllers(buffer[0..len])) return len;
        len = parentOf(buffer[0..len], root.len) orelse return null;
    }
}

fn testMakeDir(path: []const u8) bool {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return false;
    return linux.errno(linux.mkdirat(linux.AT.FDCWD, zeroed, 0o755)) == .SUCCESS;
}

fn testRemoveDir(path: []const u8) void {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return;
    _ = linux.unlinkat(linux.AT.FDCWD, zeroed, linux.AT.REMOVEDIR);
}

fn testOpenDir(path: []const u8) ?i32 {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return null;
    const rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

fn testReapedPid() ?linux.pid_t {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) std.process.exit(0);

    const pid: linux.pid_t = @intCast(rc);
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(pid, &status, 0);
    if (linux.errno(wait_rc) != .SUCCESS) return null;
    if (processExists(pid)) return null;
    return pid;
}

fn testSpawnSleeper() ?linux.pid_t {
    const rc = linux.fork();
    if (linux.errno(rc) != .SUCCESS) return null;
    if (rc == 0) {
        var left: usize = 0;
        while (left < 100) : (left += 1) {
            const request = linux.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
            _ = linux.nanosleep(&request, null);
        }
        std.process.exit(0);
    }
    return @intCast(rc);
}

fn testKillAndReap(pid: linux.pid_t) void {
    _ = linux.kill(pid, .KILL);
    var status: u32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
}

fn testReap(pid: linux.pid_t) ?u32 {
    var status: u32 = undefined;
    var rc = linux.waitpid(pid, &status, 0);
    while (linux.errno(rc) == .INTR) rc = linux.waitpid(pid, &status, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return status;
}

fn testCgroupHolds(dir: []const u8, pid: linux.pid_t) bool {
    var number: [32]u8 = undefined;
    const wanted = std.fmt.bufPrint(&number, "{d}", .{pid}) catch return false;

    var buffer: [max_control_file_bytes]u8 = undefined;
    const contents = readFileAt(dir, "cgroup.procs", &buffer) orelse return false;
    var lines = std.mem.tokenizeAny(u8, contents, "\n");
    while (lines.next()) |line| {
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r"), wanted)) return true;
    }
    return false;
}

test "a sweep kills what a stale cgroup still holds, and then removes it" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ancestor: [std.fs.max_path_bytes]u8 = undefined;
    const ancestor_len = testDelegatingAncestor(&ancestor) orelse return error.SkipZigTest;

    var outer_name: [64]u8 = undefined;
    const mine = try std.fmt.bufPrint(&outer_name, "{s}{d}.{d}", .{ name_prefix, linux.getpid(), 0xC6041 });
    var outer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outer_len = joinPath(&outer_buffer, ancestor[0..ancestor_len], mine) orelse return error.SkipZigTest;
    const outer = outer_buffer[0..outer_len];
    if (!testMakeDir(outer)) return error.SkipZigTest;
    defer testRemoveDir(outer);

    const dead_maker = testReapedPid() orelse return error.SkipZigTest;
    var stale_name: [64]u8 = undefined;
    const leaked = try std.fmt.bufPrint(&stale_name, "{s}{d}.{d}", .{ name_prefix, dead_maker, 0 });
    var stale_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const stale_len = joinPath(&stale_buffer, outer, leaked) orelse return error.SkipZigTest;
    const stale = stale_buffer[0..stale_len];
    if (!testMakeDir(stale)) return error.SkipZigTest;
    defer testRemoveDir(stale);

    const victim = testSpawnSleeper() orelse return error.SkipZigTest;
    var reaped = false;
    defer if (!reaped) testKillAndReap(victim);

    var number: [32]u8 = undefined;
    const victim_text = try std.fmt.bufPrint(&number, "{d}", .{victim});
    try std.testing.expect(writeFileAt(stale, "cgroup.procs", victim_text));

    try std.testing.expect(testCgroupHolds(stale, victim));

    sweepStaleSiblings(outer);

    const status = testReap(victim) orelse return error.SkipZigTest;
    reaped = true;
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(status));

    var after: [max_control_file_bytes]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), readFileAt(stale, "cgroup.procs", &after));
}

test "the fallback signals every pid the cgroup lists, and nothing else" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ancestor: [std.fs.max_path_bytes]u8 = undefined;
    const ancestor_len = testDelegatingAncestor(&ancestor) orelse return error.SkipZigTest;

    var outer_name: [64]u8 = undefined;
    const mine = try std.fmt.bufPrint(&outer_name, "{s}{d}.{d}", .{ name_prefix, linux.getpid(), 0xC6042 });
    var outer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outer_len = joinPath(&outer_buffer, ancestor[0..ancestor_len], mine) orelse return error.SkipZigTest;
    const outer = outer_buffer[0..outer_len];
    if (!testMakeDir(outer)) return error.SkipZigTest;
    defer testRemoveDir(outer);

    const victim = testSpawnSleeper() orelse return error.SkipZigTest;
    var reaped = false;
    defer if (!reaped) testKillAndReap(victim);

    var number: [32]u8 = undefined;
    const victim_text = try std.fmt.bufPrint(&number, "{d}", .{victim});
    try std.testing.expect(writeFileAt(outer, "cgroup.procs", victim_text));
    try std.testing.expect(testCgroupHolds(outer, victim));

    const dir_fd = testOpenDir(outer) orelse return error.SkipZigTest;
    defer _ = linux.close(dir_fd);

    try std.testing.expectEqual(@as(?usize, 1), signalMembers(dir_fd));

    const status = testReap(victim) orelse return error.SkipZigTest;
    reaped = true;
    try std.testing.expect(linux.W.IFSIGNALED(status));
    try std.testing.expectEqual(linux.SIG.KILL, linux.W.TERMSIG(status));

    const not_a_cgroup = testOpenDir("/proc/self") orelse return error.SkipZigTest;
    defer _ = linux.close(not_a_cgroup);
    try std.testing.expectEqual(@as(?usize, null), signalMembers(not_a_cgroup));
}

fn testRemoveDirWhenEmpty(path: []const u8) void {
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = nullTerminate(&path_z, path) orelse return;
    removeWhenEmpty(linux.AT.FDCWD, zeroed);
}

fn testMakeSibling(buffer: []u8, ancestor: []const u8, seq: u64) ?usize {
    var name_buffer: [64]u8 = undefined;
    const name = std.fmt.bufPrint(
        &name_buffer,
        "{s}{d}.{d}",
        .{ name_prefix, linux.getpid(), seq },
    ) catch return null;
    const len = joinPath(buffer, ancestor, name) orelse return null;
    if (!testMakeDir(buffer[0..len])) return null;
    return len;
}

test "a child is created inside the supplied cgroup, and is never charged to the one its parent is in" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var ancestor: [std.fs.max_path_bytes]u8 = undefined;
    const ancestor_len = testDelegatingAncestor(&ancestor) orelse return error.SkipZigTest;

    var parent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const parent_len = testMakeSibling(&parent_buffer, ancestor[0..ancestor_len], 0xC10E1) orelse
        return error.SkipZigTest;
    const parent = parent_buffer[0..parent_len];
    defer testRemoveDirWhenEmpty(parent);

    var target_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const target_len = testMakeSibling(&target_buffer, ancestor[0..ancestor_len], 0xC10E2) orelse
        return error.SkipZigTest;
    const target = target_buffer[0..target_len];
    defer testRemoveDirWhenEmpty(target);

    const target_fd = testOpenDir(target) orelse return error.SkipZigTest;
    defer _ = linux.close(target_fd);

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.SkipZigTest;

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return error.SkipZigTest;
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        var record: [4]u8 = .{ 0, 0, 0, 0 };

        move: {
            if (!writeFileAt(parent, "cgroup.procs", "0")) break :move;
            if (holdsSelf(parent) != true) break :move;

            var count_buffer: [max_control_file_bytes]u8 = undefined;
            const current_text = readFileAt(parent, "pids.current", &count_buffer) orelse break :move;
            const current = std.mem.trim(u8, current_text, " \n\r");
            if (!writeFileAt(parent, "pids.max", current)) break :move;

            record[0] = 1;
        }

        if (record[0] == 1) {
            const plain_rc = linux.fork();
            if (plain_rc == 0) std.process.exit(0);
            if (linux.errno(plain_rc) == .AGAIN) {
                record[1] = 1;
            } else if (linux.errno(plain_rc) == .SUCCESS) {
                var status: u32 = undefined;
                var rc = linux.waitpid(@intCast(plain_rc), &status, 0);
                while (linux.errno(rc) == .INTR) rc = linux.waitpid(@intCast(plain_rc), &status, 0);
            }

            const into_rc = forkInto(target_fd);
            if (into_rc == 0) {
                std.process.exit(if (holdsSelf(target) orelse false) 0 else 1);
            }
            if (linux.errno(into_rc) == .SUCCESS) {
                record[2] = 1;
                var status: u32 = undefined;
                var rc = linux.waitpid(@intCast(into_rc), &status, 0);
                while (linux.errno(rc) == .INTR) rc = linux.waitpid(@intCast(into_rc), &status, 0);
                if (linux.errno(rc) == .SUCCESS and linux.W.IFEXITED(status) and
                    linux.W.EXITSTATUS(status) == 0) record[3] = 1;
            }
        }

        _ = linux.write(fds[1], &record, record.len);
        std.process.exit(0);
    }

    _ = linux.close(fds[1]);
    var record: [4]u8 = .{ 0, 0, 0, 0 };
    var held: usize = 0;
    while (held < record.len) {
        const rc = linux.read(fds[0], record[held..].ptr, record.len - held);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        held += rc;
    }
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);

    if (held != record.len or record[0] != 1) return error.SkipZigTest;

    try std.testing.expectEqual(@as(u8, 1), record[1]);
    try std.testing.expectEqual(@as(u8, 1), record[2]);
    try std.testing.expectEqual(@as(u8, 1), record[3]);
}

test "a descriptor that is not a cgroup v2 directory is refused, and no process is made" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const not_a_cgroup = testOpenDir("/proc/self") orelse return error.SkipZigTest;
    defer _ = linux.close(not_a_cgroup);

    const rc = forkInto(not_a_cgroup);
    if (rc == 0) {
        std.process.exit(1);
    }

    const refused = linux.errno(rc);
    if (refused == .NOSYS) return error.SkipZigTest;
    try std.testing.expectEqual(linux.E.BADF, refused);

    const nothing = forkInto(-1);
    if (nothing == 0) std.process.exit(1);
    try std.testing.expectEqual(linux.E.BADF, linux.errno(nothing));
}
