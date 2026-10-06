//! The user, mount, and network namespaces. A user namespace is what gives an ordinary
//! user the right to make the other two.

const std = @import("std");
const linux = std.os.linux;

pub const Network = enum {
    none,
    filtered,
    host,
};

pub const Options = struct {
    network: Network = .none,
    mount: bool = true,
    helper_user: bool = false,
    map_from_parent: bool = false,
};

pub const Error = error{
    NotPermitted,
    MultiThreaded,
    MapFailed,
    Unexpected,
};

pub fn enter(options: Options, diag: ?*?Diagnostic) Error!void {
    // Read before the namespace changes: this process can only map the identity it had out here.
    const uid = linux.getuid();
    const gid = linux.getgid();

    try unshareOnly(options, diag);
    if (options.map_from_parent) return;
    try writeIdMaps(uid, gid, options.helper_user, diag);
}

pub fn unshareOnly(options: Options, diag: ?*?Diagnostic) Error!void {
    // NEWPID and NEWIPC are not optional: without them, this process stays a legal signal target and System V IPC crosses the boundary.
    var flags: usize = linux.CLONE.NEWUSER | linux.CLONE.NEWPID | linux.CLONE.NEWIPC;
    if (options.mount) flags |= linux.CLONE.NEWNS;
    switch (options.network) {
        .none, .filtered => flags |= linux.CLONE.NEWNET,
        .host => {},
    }

    switch (linux.errno(linux.unshare(flags))) {
        .SUCCESS => {},
        .PERM, .NOSPC => |err| {
            note(diag, .userns_unshare, err);
            return error.NotPermitted;
        },
        .INVAL => {
            note(diag, .userns_unshare, .INVAL);
            return error.MultiThreaded;
        },
        else => |err| {
            note(diag, .userns_unshare, err);
            return error.Unexpected;
        },
    }
}

pub const helper_id_offset: u32 = 1;

pub fn writeIdMapsFor(
    pid: linux.pid_t,
    uid: linux.uid_t,
    gid: linux.gid_t,
    helpers: bool,
    diag: ?*?Diagnostic,
) Error!void {
    var path: [64]u8 = undefined;
    var line: [64]u8 = undefined;
    const span: u32 = if (helpers) helper_id_offset + 1 else 1;

    const deny = std.fmt.bufPrintZ(&path, "/proc/{d}/setgroups", .{pid}) catch unreachable;
    try writeFile(deny.ptr, "deny", .setgroups_open, .setgroups_write, diag);

    const uid_at = std.fmt.bufPrintZ(&path, "/proc/{d}/uid_map", .{pid}) catch unreachable;
    const uid_line = std.fmt.bufPrint(&line, "{d} {d} {d}", .{ uid, uid, span }) catch unreachable;
    try writeFile(uid_at.ptr, uid_line, .uid_map_open, .uid_map_write, diag);

    const gid_at = std.fmt.bufPrintZ(&path, "/proc/{d}/gid_map", .{pid}) catch unreachable;
    const gid_line = std.fmt.bufPrint(&line, "{d} {d} {d}", .{ gid, gid, span }) catch unreachable;
    try writeFile(gid_at.ptr, gid_line, .gid_map_open, .gid_map_write, diag);
}

pub fn writeIdMaps(
    uid: linux.uid_t,
    gid: linux.gid_t,
    helpers: bool,
    diag: ?*?Diagnostic,
) Error!void {
    var buffer: [64]u8 = undefined;
    const span: u32 = if (helpers) helper_id_offset + 1 else 1;

    // setgroups must be written first, or the gid_map write fails with EPERM.
    try writeFile("/proc/self/setgroups", "deny", .setgroups_open, .setgroups_write, diag);

    const uid_line = std.fmt.bufPrint(&buffer, "{d} {d} {d}", .{ uid, uid, span }) catch unreachable;
    try writeFile("/proc/self/uid_map", uid_line, .uid_map_open, .uid_map_write, diag);

    const gid_line = std.fmt.bufPrint(&buffer, "{d} {d} {d}", .{ gid, gid, span }) catch unreachable;
    try writeFile("/proc/self/gid_map", gid_line, .gid_map_open, .gid_map_write, diag);
}

fn writeFile(
    path: [*:0]const u8,
    contents: []const u8,
    open_call: Diagnostic.Call,
    write_call: Diagnostic.Call,
    diag: ?*?Diagnostic,
) Error!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) {
        note(diag, open_call, linux.errno(fd_rc));
        return error.MapFailed;
    }
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const written = linux.write(fd, contents.ptr, contents.len);
    if (linux.errno(written) != .SUCCESS) {
        note(diag, write_call, linux.errno(written));
        return error.MapFailed;
    }
    // The kernel takes a map line whole or not at all, so a short write is reported as a fault, not a retry.
    if (written != contents.len) {
        note(diag, write_call, .IO);
        return error.MapFailed;
    }
}

pub const Availability = union(enum) {
    ok,
    unavailable: Diagnostic,
    unknown: Unknown,

    pub const Unknown = enum {
        pipe_failed,
        fork_failed,
        child_died,
        unreadable_answer,

        pub fn text(self: Unknown) []const u8 {
            return switch (self) {
                .pipe_failed => "could not make the pipe its answer comes back on",
                .fork_failed => "could not start the child that asks the kernel",
                .child_died => "lost the child that asks the kernel",
                .unreadable_answer => "got an answer it cannot read",
            };
        }
    };

    pub fn available(self: Availability) bool {
        return self == .ok;
    }

    pub fn format(self: Availability, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .ok => try writer.writeAll("this machine can enter the sandbox namespaces"),
            .unavailable => |d| try writer.print("this machine cannot enter the sandbox namespaces: {f}", .{d}),
            .unknown => |u| try writer.print("the namespaces were not measured: the probe {s}", .{u.text()}),
        }
    }
};

pub const nothing_measured_exit_status: u8 = 63;

const ProbeRecord = extern struct {
    call: u8,
    errno: i32,
};

pub fn probeAvailability() Availability {
    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{ .CLOEXEC = true })) != .SUCCESS) {
        return .{ .unknown = .pipe_failed };
    }

    const fork_rc = linux.fork();
    if (linux.errno(fork_rc) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return .{ .unknown = .fork_failed };
    }

    if (fork_rc == 0) {
        _ = linux.close(fds[0]);
        var diag: ?Diagnostic = null;
        if (enter(.{}, &diag)) |_| {
            std.process.exit(0);
        } else |_| {
            if (diag) |d| {
                const record = ProbeRecord{
                    .call = @intFromEnum(d.call),
                    .errno = @intFromEnum(d.errno),
                };
                const bytes = std.mem.asBytes(&record);
                _ = linux.write(fds[1], bytes.ptr, bytes.len);
            }
            std.process.exit(1);
        }
    }

    _ = linux.close(fds[1]);
    var buffer: [@sizeOf(ProbeRecord)]u8 = undefined;
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fds[0], buffer[filled..].ptr, buffer.len - filled);
        const read_errno = linux.errno(rc);
        if (read_errno == .INTR) continue;
        if (read_errno != .SUCCESS or rc == 0) break;
        filled += rc;
    }
    _ = linux.close(fds[0]);

    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    if (linux.errno(wait_rc) != .SUCCESS or !linux.W.IFEXITED(status)) {
        return .{ .unknown = .child_died };
    }

    return readAnswer(linux.W.EXITSTATUS(status), buffer[0..filled]);
}

fn readAnswer(exit_code: ?u32, bytes: []const u8) Availability {
    const code = exit_code orelse return .{ .unknown = .child_died };
    if (code == 0 and bytes.len == 0) return .ok;
    if (code == 0 or bytes.len != @sizeOf(ProbeRecord)) {
        return .{ .unknown = .unreadable_answer };
    }

    const record = std.mem.bytesToValue(ProbeRecord, bytes[0..@sizeOf(ProbeRecord)]);
    // fromInt, not @enumFromInt: these bytes came over a pipe, and an unknown tag is dropped rather than turned into a crash.
    const call = std.enums.fromInt(Diagnostic.Call, record.call) orelse
        return .{ .unknown = .unreadable_answer };
    const errno = std.enums.fromInt(linux.E, record.errno) orelse
        return .{ .unknown = .unreadable_answer };
    return .{ .unavailable = .{ .call = call, .errno = errno } };
}

test "the probe reads the child's answer, and never reads silence as a pass" {
    const record = ProbeRecord{
        .call = @intFromEnum(Diagnostic.Call.uid_map_write),
        .errno = @intFromEnum(linux.E.PERM),
    };
    const record_bytes = std.mem.asBytes(&record);

    try std.testing.expect(readAnswer(0, &.{}).available());

    const refused = readAnswer(1, record_bytes);
    try std.testing.expect(!refused.available());
    try std.testing.expectEqual(Diagnostic.Call.uid_map_write, refused.unavailable.call);
    try std.testing.expectEqual(linux.E.PERM, refused.unavailable.errno);

    var line_buffer: [128]u8 = undefined;
    try std.testing.expectEqualStrings(
        "this machine cannot enter the sandbox namespaces: the write to /proc/self/uid_map failed: PERM",
        try std.fmt.bufPrint(&line_buffer, "{f}", .{refused}),
    );

    const died = readAnswer(null, &.{});
    try std.testing.expect(!died.available());
    try std.testing.expectEqual(Availability.Unknown.child_died, died.unknown);

    try std.testing.expectEqual(
        Availability.Unknown.unreadable_answer,
        readAnswer(1, &.{}).unknown,
    );
    try std.testing.expectEqual(
        Availability.Unknown.unreadable_answer,
        readAnswer(0, record_bytes).unknown,
    );

    try std.testing.expectEqual(
        Availability.Unknown.unreadable_answer,
        readAnswer(1, record_bytes[0 .. record_bytes.len - 1]).unknown,
    );
    const nonsense = ProbeRecord{ .call = 250, .errno = @intFromEnum(linux.E.PERM) };
    try std.testing.expectEqual(
        Availability.Unknown.unreadable_answer,
        readAnswer(1, std.mem.asBytes(&nonsense)).unknown,
    );
}

test "the probe answers for this machine, and asks in a child that is spent by asking" {
    const first = probeAvailability();
    const second = probeAvailability();
    try std.testing.expectEqual(std.meta.activeTag(first), std.meta.activeTag(second));

    if (!first.available()) return error.SkipZigTest;
    const fork_rc = linux.fork();
    try std.testing.expectEqual(.SUCCESS, linux.errno(fork_rc));
    if (fork_rc == 0) {
        var diag: ?Diagnostic = null;
        enter(.{}, &diag) catch std.process.exit(1);
        std.process.exit(0);
    }
    var status: u32 = undefined;
    var wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    while (linux.errno(wait_rc) == .INTR) wait_rc = linux.waitpid(@intCast(fork_rc), &status, 0);
    try std.testing.expectEqual(.SUCCESS, linux.errno(wait_rc));
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u32, 0), linux.W.EXITSTATUS(status));
}

test "an id map line maps one id to itself" {
    var buffer: [64]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{d} {d} 1", .{ 1000, 1000 });
    try std.testing.expectEqualStrings("1000 1000 1", line);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    note(&diag, .mount_call, .PERM);
    note(&diag, .pivot_root, .NOENT);
    try std.testing.expectEqual(Diagnostic.Call.mount_call, diag.?.call);
    try std.testing.expectEqual(linux.E.PERM, diag.?.errno);

    note(null, .pivot_root, .NOENT);
}

test "a diagnostic names the call and the errno, and allocates nothing" {
    var buffer: [128]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{
        Diagnostic{ .call = .overlay_mount, .errno = .NODEV },
    });
    try std.testing.expectEqualStrings("the overlay mount failed: NODEV", line);

    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |call, i| {
        try std.testing.expect(call.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, call.text(), other.text()));
        }
    }
}

pub const Mount = union(enum) {
    bind: Bind,
    overlay: Overlay,
    proc: Proc,
    deny: Deny,

    pub const Bind = struct {
        source: []const u8,
        target: []const u8,
        read_only: bool = false,
    };

    pub const Overlay = struct {
        lower: []const u8,
        upper: []const u8,
        work: []const u8,
        target: []const u8,
    };

    pub const Proc = struct {
        target: []const u8 = "/proc",
    };

    pub const Deny = struct {
        target: []const u8,
    };
};

pub const deny_notice = "chock: this file is denied by the project. Its bytes are not in this sandbox.\n";

const deny_notice_source_name = ".chock-denied";

pub const Scratch = struct {
    target: []const u8,
};

pub const tmpfs_magic: u64 = 0x01021994;

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

pub const MountError = error{
    NotPermitted,
    OutOfMemory,
    SourceMissing,
    KernelTooOld,
    OverlayNotSupported,
    DenyTargetIsDirectory,
    DenyTargetIsSymlink,
    BindSourceIsSymlink,
    BindTargetIsSymlink,
    Unexpected,
};

pub const Diagnostic = struct {
    call: Call,
    errno: linux.E,
    path: ?[*:0]const u8 = null,

    pub const Call = enum {
        userns_unshare,
        setgroups_open,
        setgroups_write,
        uid_map_open,
        uid_map_write,
        gid_map_open,
        gid_map_write,
        proc_mask_file,
        proc_entry_stat,
        deny_notice_file,
        deny_notice_write,
        substitute_file,
        substitute_write,
        substitute_stat,
        substitute_link_clear,
        substitute_link,
        owned_stat,
        owned_remove,
        deny_target_stat,
        deny_target_open,
        overlay_mount,
        scratch_mount,
        scratch_open,
        mount_source_open,
        mount_source_stat,
        mount_setattr,
        mount_target_mkdir,
        mount_target_open,
        mount_call,
        pivot_root,
        chdir_after_pivot,
        old_root_umount,

        pub fn text(self: Call) []const u8 {
            return switch (self) {
                .userns_unshare => "the unshare that makes the namespaces",
                .setgroups_open => "open on /proc/self/setgroups",
                .setgroups_write => "the write to /proc/self/setgroups",
                .uid_map_open => "open on /proc/self/uid_map",
                .uid_map_write => "the write to /proc/self/uid_map",
                .gid_map_open => "open on /proc/self/gid_map",
                .gid_map_write => "the write to /proc/self/gid_map",
                .proc_mask_file => "open on the proc mask file",
                .proc_entry_stat => "statx on a proc entry",
                .deny_notice_file => "open on the deny notice file",
                .deny_notice_write => "the write of the deny notice",
                .substitute_file => "open on a substituted file",
                .substitute_write => "the write of a substituted file",
                .substitute_stat => "statx on a substituted path",
                .substitute_link_clear => "unlinkat on a substituted link's own name",
                .substitute_link => "the symlink call for a substituted link",
                .owned_stat => "statx on a directory the sandbox takes for itself",
                .owned_remove => "unlinkat on a name the sandbox takes away",
                .deny_target_stat => "statx on a denied path",
                .deny_target_open => "open on a denied path",
                .overlay_mount => "the overlay mount",
                .scratch_mount => "the scratch area mount",
                .scratch_open => "open on a scratch area",
                .mount_source_open => "open on a mount source",
                .mount_source_stat => "statx on a mount source",
                .mount_setattr => "mount_setattr",
                .mount_target_mkdir => "mkdirat on a mount target",
                .mount_target_open => "open on a mount target",
                .mount_call => "the mount call",
                .pivot_root => "pivot_root",
                .chdir_after_pivot => "chdir after pivot_root",
                .old_root_umount => "umount2 of the old root",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s} failed: {s}", .{ self.call.text(), @tagName(self.errno) });
        if (self.path) |one| try writer.print(" at {s}", .{std.mem.span(one)});
    }
};

fn note(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: linux.E) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno };
}

fn notePath(
    diag: ?*?Diagnostic,
    call: Diagnostic.Call,
    errno: linux.E,
    path: [*:0]const u8,
) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = .{ .call = call, .errno = errno, .path = path };
}

const PathKind = enum { directory, file };

pub fn buildRoot(
    allocator: std.mem.Allocator,
    root: []const u8,
    mounts: []const Mount,
    hide_other_users: bool,
    diag: ?*?Diagnostic,
) MountError!void {
    try mountCall(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0, diag);

    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    try mountCall(root_z, root_z, null, linux.MS.BIND | linux.MS.REC, 0, diag);

    for (mounts) |m| {
        switch (m) {
            .bind => |b| try buildBindMount(allocator, root, b, diag),
            .overlay => |o| try buildOverlayMount(allocator, root, o, diag),
            .proc => |p| try buildProcMount(allocator, root, p, hide_other_users, diag),
            .deny => {},
        }
    }

    try applyDenyMounts(allocator, root, mounts, diag);
}

fn applyDenyMounts(
    allocator: std.mem.Allocator,
    root: []const u8,
    mounts: []const Mount,
    diag: ?*?Diagnostic,
) MountError!void {
    var any = false;
    for (mounts) |m| {
        if (m == .deny) {
            any = true;
            break;
        }
    }
    if (!any) return;

    const source = try std.fs.path.join(allocator, &.{ root, deny_notice_source_name });
    defer allocator.free(source);

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);
    try makeNoticeFile(source_z.ptr, diag);
    defer _ = linux.unlinkat(linux.AT.FDCWD, source_z.ptr, 0);

    for (mounts) |m| {
        const deny = switch (m) {
            .deny => |d| d,
            .bind, .overlay, .proc => continue,
        };

        const fd = try pinDenyTarget(allocator, root, deny.target, diag);
        defer _ = linux.close(fd);

        var magic_buf: [64]u8 = undefined;
        const magic_z = std.fmt.bufPrintZ(&magic_buf, "/proc/self/fd/{d}", .{fd}) catch
            return error.Unexpected;

        try mountCall(source_z, magic_z, null, linux.MS.BIND, 0, diag);

        const target = try std.fs.path.join(allocator, &.{ root, deny.target });
        defer allocator.free(target);
        const target_z = try allocator.dupeZ(u8, target);
        defer allocator.free(target_z);
        try markReadOnly(target_z, diag);
    }
}

fn pinDenyTarget(
    allocator: std.mem.Allocator,
    root: []const u8,
    relative_target: []const u8,
    diag: ?*?Diagnostic,
) MountError!i32 {
    std.debug.assert(relative_target.len > 1 and relative_target[0] == '/');

    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    const root_fd_rc = linux.open(root_z.ptr, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    switch (linux.errno(root_fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .deny_target_open, err);
            return error.Unexpected;
        },
    }
    var dir_fd: i32 = @intCast(root_fd_rc);
    defer _ = linux.close(dir_fd);

    var it = std.mem.splitScalar(u8, relative_target[1..], '/');
    var component = it.next() orelse return error.Unexpected;
    while (true) {
        const next = it.next();
        const component_z = try allocator.dupeZ(u8, component);
        defer allocator.free(component_z);

        if (next == null) return openDenyLeaf(dir_fd, component_z.ptr, diag);

        const opened = try openDenyDirComponent(dir_fd, component_z.ptr, diag);
        _ = linux.close(dir_fd);
        dir_fd = opened;
        component = next.?;
    }
}

fn openDenyDirComponent(dir_fd: i32, component: [*:0]const u8, diag: ?*?Diagnostic) MountError!i32 {
    while (true) {
        const fd_rc = linux.openat(dir_fd, component, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
        switch (linux.errno(fd_rc)) {
            .SUCCESS => return @intCast(fd_rc),
            // NOTDIR as well as LOOP: with O_DIRECTORY and O_NOFOLLOW together
            // the kernel answers NOTDIR for a symlink at this component.
            .LOOP, .NOTDIR => return error.DenyTargetIsSymlink,
            .NOENT => {
                switch (linux.errno(linux.mkdirat(dir_fd, component, 0o755))) {
                    .SUCCESS, .EXIST => continue,
                    .PERM, .ACCES => return error.NotPermitted,
                    else => |err| {
                        note(diag, .mount_target_mkdir, err);
                        return error.Unexpected;
                    },
                }
            },
            .PERM, .ACCES => return error.NotPermitted,
            else => |err| {
                note(diag, .deny_target_open, err);
                return error.Unexpected;
            },
        }
    }
}

fn openDenyLeaf(dir_fd: i32, leaf: [*:0]const u8, diag: ?*?Diagnostic) MountError!i32 {
    const fd_rc = linux.openat(dir_fd, leaf, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .LOOP => return error.DenyTargetIsSymlink,
        .NOENT, .NOTDIR => return createDenyLeaf(dir_fd, leaf, diag),
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .deny_target_open, err);
            return error.Unexpected;
        },
    }
    const fd: i32 = @intCast(fd_rc);
    errdefer _ = linux.close(fd);

    var stat_buf: linux.Statx = undefined;
    const empty: [*:0]const u8 = "";
    const rc = linux.statx(fd, empty, linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat_buf);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .deny_target_stat, err);
            return error.Unexpected;
        },
    }
    if ((stat_buf.mode & linux.S.IFMT) == linux.S.IFLNK) return error.DenyTargetIsSymlink;
    if ((stat_buf.mode & linux.S.IFMT) == linux.S.IFDIR) return error.DenyTargetIsDirectory;
    return fd;
}

fn createDenyLeaf(dir_fd: i32, leaf: [*:0]const u8, diag: ?*?Diagnostic) MountError!i32 {
    const fd_rc = linux.openat(dir_fd, leaf, .{
        .ACCMODE = .RDONLY,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => return @intCast(fd_rc),
        .PERM, .ACCES => return error.NotPermitted,
        .EXIST => return error.DenyTargetIsSymlink,
        else => |err| {
            note(diag, .deny_target_open, err);
            return error.Unexpected;
        },
    }
}

fn makeNoticeFile(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .deny_notice_file, err);
            return error.Unexpected;
        },
    }
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < deny_notice.len) {
        const rc = linux.write(fd, deny_notice.ptr + written, deny_notice.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .PERM, .ACCES => return error.NotPermitted,
            else => |err| {
                note(diag, .deny_notice_write, err);
                return error.Unexpected;
            },
        }
        if (rc == 0) {
            note(diag, .deny_notice_write, .IO);
            return error.Unexpected;
        }
        written += rc;
    }
}

fn buildBindMount(allocator: std.mem.Allocator, root: []const u8, b: Mount.Bind, diag: ?*?Diagnostic) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, b.target });
    defer allocator.free(target);

    const source_z = try allocator.dupeZ(u8, b.source);
    defer allocator.free(source_z);

    const pinned = try pinBindSource(source_z.ptr, diag);
    defer _ = linux.close(pinned.fd);

    try makePath(allocator, target, pinned.kind, diag);

    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    var magic_buf: [64]u8 = undefined;
    const magic_z = std.fmt.bufPrintZ(&magic_buf, "/proc/self/fd/{d}", .{pinned.fd}) catch
        return error.Unexpected;

    try mountCall(magic_z, target_z, null, linux.MS.BIND | linux.MS.REC, 0, diag);

    if (b.read_only) try markReadOnly(target_z, diag);
}

const PinnedSource = struct {
    fd: i32,
    kind: PathKind,
};

fn pinBindSource(source: [*:0]const u8, diag: ?*?Diagnostic) MountError!PinnedSource {
    const fd_rc = linux.open(source, .{ .PATH = true, .CLOEXEC = true, .NOFOLLOW = true }, 0);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .LOOP => return error.BindSourceIsSymlink,
        .NOENT, .NOTDIR => |err| {
            notePath(diag, .mount_source_open, err, source);
            return error.SourceMissing;
        },
        .PERM, .ACCES => |err| {
            notePath(diag, .mount_source_open, err, source);
            return error.NotPermitted;
        },
        else => |err| {
            note(diag, .mount_source_open, err);
            return error.Unexpected;
        },
    }
    const fd: i32 = @intCast(fd_rc);
    errdefer _ = linux.close(fd);

    var stat_buf: linux.Statx = undefined;
    const empty: [*:0]const u8 = "";
    const rc = linux.statx(fd, empty, linux.AT.EMPTY_PATH, .{ .TYPE = true }, &stat_buf);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_source_stat, err);
            return error.Unexpected;
        },
    }
    if ((stat_buf.mode & linux.S.IFMT) == linux.S.IFLNK) return error.BindSourceIsSymlink;
    const kind: PathKind = if ((stat_buf.mode & linux.S.IFMT) == linux.S.IFDIR) .directory else .file;
    return .{ .fd = fd, .kind = kind };
}

pub const procfs_option_bytes: usize = 48;

pub fn procfsOptions(into: []u8, hide_other_users: bool, gid: linux.gid_t) ?[:0]const u8 {
    if (!hide_other_users) return null;
    return std.fmt.bufPrintZ(into, "hidepid=2,gid={d}", .{gid + helper_id_offset}) catch null;
}

fn buildProcMount(
    allocator: std.mem.Allocator,
    root: []const u8,
    p: Mount.Proc,
    hide_other_users: bool,
    diag: ?*?Diagnostic,
) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, p.target });
    defer allocator.free(target);

    try makePath(allocator, target, .directory, diag);

    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    var option_room: [procfs_option_bytes]u8 = undefined;
    const options = procfsOptions(&option_room, hide_other_users, linux.getgid());

    try mountCall(
        "proc",
        target_z,
        "proc",
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        if (options) |one| @intFromPtr(one.ptr) else 0,
        diag,
    );
    try maskProcEntries(allocator, root, target, diag);
    try markReadOnly(target_z, diag);
}

pub const masked_proc_entries: []const []const u8 = &.{
    "cmdline",
    "version",
    "kallsyms",
    "config.gz",
    "kcore",
    "modules",
    "iomem",
    "ioports",
    "mtrr",
    "sched_debug",
    "timer_list",
    "latency_stats",
    "interrupts",
    "schedstat",
    "slabinfo",
    "vmallocinfo",
    "keys",
    "key-users",
    "sysrq-trigger",
    "kmsg",
};

pub const Substitution = union(enum) {
    text: Text,
    link: Link,
    hide: []const u8,

    pub const Text = struct {
        target: []const u8,
        contents: []const u8,
    };

    pub const Link = struct {
        target: []const u8,
        link_to: []const u8,
    };
};

const substitute_source_name = ".chock-substitute";

const substitute_empty_dir_name = ".chock-empty-dir";
const substitute_empty_file_name = ".chock-empty-file";

pub fn substitute(
    allocator: std.mem.Allocator,
    root: []const u8,
    subs: []const Substitution,
    diag: ?*?Diagnostic,
) MountError!void {
    if (subs.len == 0) return;

    for (subs) |one| {
        switch (one) {
            .text => |text| try placeText(allocator, root, text, diag),
            .link => |link| try placeLink(allocator, root, link, diag),
            .hide => |target| try hidePath(allocator, root, target, diag),
        }
    }
}

fn placeText(
    allocator: std.mem.Allocator,
    root: []const u8,
    text: Substitution.Text,
    diag: ?*?Diagnostic,
) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, text.target });
    defer allocator.free(target);
    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    if (try pathIsSymlink(target_z.ptr, diag)) return error.BindTargetIsSymlink;

    switch (try existingPathKind(target_z.ptr, .substitute_stat, diag)) {
        .missing => {
            try makePath(allocator, target, .file, diag);
            try writeSubstitute(target_z.ptr, text.contents, diag);
        },
        .file, .directory => {
            const source = try std.fs.path.join(allocator, &.{ root, substitute_source_name });
            defer allocator.free(source);
            const source_z = try allocator.dupeZ(u8, source);
            defer allocator.free(source_z);
            try writeSubstitute(source_z.ptr, text.contents, diag);
            defer _ = linux.unlinkat(linux.AT.FDCWD, source_z.ptr, 0);
            try mountCall(source_z, target_z, null, linux.MS.BIND, 0, diag);
        },
    }
}

fn placeLink(
    allocator: std.mem.Allocator,
    root: []const u8,
    link: Substitution.Link,
    diag: ?*?Diagnostic,
) MountError!void {
    const link_to_full = try std.fs.path.join(allocator, &.{ root, link.link_to });
    defer allocator.free(link_to_full);
    const link_to_full_z = try allocator.dupeZ(u8, link_to_full);
    defer allocator.free(link_to_full_z);

    if (try existingPathKind(link_to_full_z.ptr, .substitute_stat, diag) == .missing) return;

    const target = try std.fs.path.join(allocator, &.{ root, link.target });
    defer allocator.free(target);
    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    if (std.fs.path.dirname(target)) |parent| {
        try makePath(allocator, parent, .directory, diag);
    }

    switch (linux.errno(linux.unlinkat(linux.AT.FDCWD, target_z.ptr, 0))) {
        .SUCCESS, .NOENT, .NOTDIR => {},
        .ISDIR => switch (linux.errno(linux.unlinkat(linux.AT.FDCWD, target_z.ptr, linux.AT.REMOVEDIR))) {
            .SUCCESS, .NOENT => {},
            .PERM, .ACCES, .ROFS, .NOTEMPTY => return error.NotPermitted,
            else => |err| {
                note(diag, .substitute_link_clear, err);
                return error.Unexpected;
            },
        },
        .PERM, .ACCES, .ROFS => return error.NotPermitted,
        else => |err| {
            note(diag, .substitute_link_clear, err);
            return error.Unexpected;
        },
    }

    const link_to_z = try allocator.dupeZ(u8, link.link_to);
    defer allocator.free(link_to_z);

    switch (linux.errno(linux.symlinkat(link_to_z.ptr, linux.AT.FDCWD, target_z.ptr))) {
        .SUCCESS => {},
        .PERM, .ACCES, .ROFS => return error.NotPermitted,
        else => |err| {
            note(diag, .substitute_link, err);
            return error.Unexpected;
        },
    }
}

fn hidePath(
    allocator: std.mem.Allocator,
    root: []const u8,
    path: []const u8,
    diag: ?*?Diagnostic,
) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, path });
    defer allocator.free(target);
    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    const kind = try existingPathKind(target_z.ptr, .substitute_stat, diag);
    if (kind == .missing) return;

    const name = if (kind == .directory) substitute_empty_dir_name else substitute_empty_file_name;
    const source = try std.fs.path.join(allocator, &.{ root, name });
    defer allocator.free(source);
    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    if (kind == .directory) {
        try makeDir(source_z.ptr, diag);
    } else {
        try makeEmptyFile(source_z.ptr, diag);
    }
    defer _ = linux.unlinkat(
        linux.AT.FDCWD,
        source_z.ptr,
        if (kind == .directory) linux.AT.REMOVEDIR else 0,
    );

    try mountCall(source_z, target_z, null, linux.MS.BIND, 0, diag);
}

fn pathIsSymlink(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!bool {
    var stat_buf: linux.Statx = undefined;
    const rc = linux.statx(
        linux.AT.FDCWD,
        path,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .TYPE = true },
        &stat_buf,
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT, .NOTDIR => return false,
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .substitute_stat, err);
            return error.Unexpected;
        },
    }
    return (stat_buf.mode & linux.S.IFMT) == linux.S.IFLNK;
}

fn writeSubstitute(path: [*:0]const u8, contents: []const u8, diag: ?*?Diagnostic) MountError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES, .ROFS => return error.NotPermitted,
        else => |err| {
            note(diag, .substitute_file, err);
            return error.Unexpected;
        },
    }
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < contents.len) {
        const rc = linux.write(fd, contents.ptr + written, contents.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => |err| {
                note(diag, .substitute_write, err);
                return error.Unexpected;
            },
        }
        if (rc == 0) {
            note(diag, .substitute_write, linux.E.IO);
            return error.Unexpected;
        }
        written += rc;
    }
}

const owned_backing_name = ".chock-owned";

const owned_backing_bytes: u64 = 1 << 20;

const mnt_detach: u32 = 2;

pub const OwnedDirectory = struct {
    target: []const u8,
    remove: []const []const u8 = &.{},
};

pub fn ownDirectory(
    allocator: std.mem.Allocator,
    root: []const u8,
    owned: OwnedDirectory,
    diag: ?*?Diagnostic,
) MountError!bool {
    const target = try std.fs.path.join(allocator, &.{ root, owned.target });
    defer allocator.free(target);
    const target_z = try allocator.dupeZ(u8, target);
    defer allocator.free(target_z);

    if (try existingPathKind(target_z.ptr, .owned_stat, diag) != .directory) return false;

    const backing = try std.fs.path.join(allocator, &.{ root, owned_backing_name });
    defer allocator.free(backing);
    const backing_z = try allocator.dupeZ(u8, backing);
    defer allocator.free(backing_z);
    try makeDir(backing_z.ptr, diag);

    var options_buffer: [32]u8 = undefined;
    const options = std.fmt.bufPrintZ(&options_buffer, "size={d}", .{owned_backing_bytes}) catch
        return error.Unexpected;
    try mountCall(
        "tmpfs",
        backing_z,
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(options.ptr),
        diag,
    );
    defer {
        _ = linux.umount2(backing_z.ptr, mnt_detach);
        _ = linux.unlinkat(linux.AT.FDCWD, backing_z.ptr, linux.AT.REMOVEDIR);
    }

    const upper = try std.fs.path.join(allocator, &.{ backing, "upper" });
    defer allocator.free(upper);
    const upper_z = try allocator.dupeZ(u8, upper);
    defer allocator.free(upper_z);
    try makeDir(upper_z.ptr, diag);

    const work = try std.fs.path.join(allocator, &.{ backing, "work" });
    defer allocator.free(work);
    const work_z = try allocator.dupeZ(u8, work);
    defer allocator.free(work_z);
    try makeDir(work_z.ptr, diag);

    try mountOverlay(allocator, .{
        .lower = target,
        .upper = upper,
        .work = work,
        .target = target,
    }, diag);

    for (owned.remove) |name| {
        const path = try std.fs.path.join(allocator, &.{ root, name });
        defer allocator.free(path);
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        switch (linux.errno(linux.unlinkat(linux.AT.FDCWD, path_z.ptr, 0))) {
            .SUCCESS, .NOENT, .NOTDIR => {},
            .PERM, .ACCES, .ROFS => return error.NotPermitted,
            else => |err| {
                note(diag, .owned_remove, err);
                return error.Unexpected;
            },
        }
    }

    return true;
}

const proc_mask_source_name = ".chock-proc-mask";

fn maskProcEntries(allocator: std.mem.Allocator, root: []const u8, proc_target: []const u8, diag: ?*?Diagnostic) MountError!void {
    const source = try std.fs.path.join(allocator, &.{ root, proc_mask_source_name });
    defer allocator.free(source);

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);
    try makeEmptyFile(source_z.ptr, diag);
    defer _ = linux.unlinkat(linux.AT.FDCWD, source_z.ptr, 0);

    for (masked_proc_entries) |name| {
        const target = try std.fs.path.join(allocator, &.{ proc_target, name });
        defer allocator.free(target);

        const target_z = try allocator.dupeZ(u8, target);
        defer allocator.free(target_z);

        switch (try existingPathKind(target_z.ptr, .proc_entry_stat, diag)) {
            .missing => continue,
            .directory => continue,
            .file => {},
        }

        try mountCall(source_z, target_z, null, linux.MS.BIND, 0, diag);
    }
}

fn makeEmptyFile(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .proc_mask_file, err);
            return error.Unexpected;
        },
    }
    _ = linux.close(@intCast(fd_rc));
}

fn existingPathKind(
    path: [*:0]const u8,
    call: Diagnostic.Call,
    diag: ?*?Diagnostic,
) MountError!enum { missing, directory, file } {
    var stat_buf: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path, 0, .{ .TYPE = true }, &stat_buf);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT, .NOTDIR => return .missing,
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, call, err);
            return error.Unexpected;
        },
    }
    if ((stat_buf.mode & linux.S.IFMT) == linux.S.IFDIR) return .directory;
    return .file;
}

fn buildOverlayMount(allocator: std.mem.Allocator, root: []const u8, o: Mount.Overlay, diag: ?*?Diagnostic) MountError!void {
    const target = try std.fs.path.join(allocator, &.{ root, o.target });
    defer allocator.free(target);

    try makePath(allocator, target, .directory, diag);

    try mountOverlay(allocator, .{
        .lower = o.lower,
        .upper = o.upper,
        .work = o.work,
        .target = target,
    }, diag);
}

pub fn mountOverlay(allocator: std.mem.Allocator, o: Mount.Overlay, diag: ?*?Diagnostic) MountError!void {
    const options = std.fmt.allocPrintSentinel(
        allocator,
        "lowerdir={s},upperdir={s},workdir={s},userxattr",
        .{ o.lower, o.upper, o.work },
        0,
    ) catch return error.OutOfMemory;
    defer allocator.free(options);

    const target_z = try allocator.dupeZ(u8, o.target);
    defer allocator.free(target_z);

    const rc = linux.mount("overlay", target_z, "overlay", 0, @intFromPtr(options.ptr));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .NODEV, .NOSYS => return error.OverlayNotSupported,
        .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .overlay_mount, err);
            return error.Unexpected;
        },
    }
}

pub fn mountScratch(
    root: []const u8,
    target: []const u8,
    size_bytes: ?u64,
    diag: ?*?Diagnostic,
) MountError!i32 {
    var full: [std.fs.max_path_bytes]u8 = undefined;
    const full_len = joinInto(&full, root, target) orelse return error.Unexpected;
    try makeDirPath(full[0..full_len], diag);

    var full_z: [std.fs.max_path_bytes]u8 = undefined;
    const zeroed = terminate(&full_z, full[0..full_len]) orelse return error.Unexpected;

    var options_buffer: [32]u8 = undefined;
    const options: [:0]const u8 = if (size_bytes) |bytes|
        std.fmt.bufPrintZ(&options_buffer, "size={d}", .{bytes}) catch return error.Unexpected
    else
        "";

    const rc = linux.mount(
        "tmpfs",
        zeroed,
        "tmpfs",
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(options.ptr),
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .scratch_mount, err);
            return error.Unexpected;
        },
    }

    const fd_rc = linux.open(zeroed, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .scratch_open, err);
            return error.Unexpected;
        },
    }
    return @intCast(fd_rc);
}

pub fn scratchIsFull(fd: i32) bool {
    var stat_buf: Statfs = undefined;
    const rc = linux.syscall2(
        .fstatfs,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(&stat_buf),
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    if (stat_buf.f_type != tmpfs_magic) return false;
    return stat_buf.f_bavail == 0;
}

fn joinInto(buffer: []u8, a: []const u8, b: []const u8) ?usize {
    const left = if (a.len > 1 and a[a.len - 1] == '/') a[0 .. a.len - 1] else a;
    const right = if (b.len > 0 and b[0] == '/') b[1..] else b;
    const needed = left.len + 1 + right.len;
    if (needed > buffer.len) return null;
    @memcpy(buffer[0..left.len], left);
    buffer[left.len] = '/';
    @memcpy(buffer[left.len + 1 ..][0..right.len], right);
    return needed;
}

fn terminate(buffer: []u8, text: []const u8) ?[:0]const u8 {
    if (text.len + 1 > buffer.len) return null;
    @memcpy(buffer[0..text.len], text);
    buffer[text.len] = 0;
    return buffer[0..text.len :0];
}

fn makeDirPath(path: []const u8, diag: ?*?Diagnostic) MountError!void {
    std.debug.assert(path.len > 0 and path[0] == '/');

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len + 1 > buffer.len) return error.Unexpected;
    @memcpy(buffer[0..path.len], path);

    var i: usize = 1;
    while (i <= path.len) : (i += 1) {
        if (i < path.len and path[i] != '/') continue;
        const kept = if (i < path.len) path[i] else 0;
        buffer[i] = 0;
        try makeDir(@ptrCast(&buffer), diag);
        buffer[i] = kept;
    }
}

const MountAttr = extern struct {
    attr_set: u64 = 0,
    attr_clr: u64 = 0,
    propagation: u64 = 0,
    userns_fd: u64 = 0,
};

const mount_attr_rdonly: u64 = 0x00000001;

const mount_attr_nosuid: u64 = 0x00000002;

const mount_attr_nodev: u64 = 0x00000004;

// mount_setattr only ever adds an attribute, never removes one, so a flag the kernel already locked is never touched and never guessed at.
fn markReadOnly(target: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    var attr = MountAttr{
        .attr_set = mount_attr_rdonly | mount_attr_nosuid | mount_attr_nodev,
    };
    const rc = linux.syscall5(
        .mount_setattr,
        @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
        @intFromPtr(target),
        @as(usize, linux.AT.RECURSIVE),
        @intFromPtr(&attr),
        @sizeOf(MountAttr),
    );
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        .NOSYS => return error.KernelTooOld,
        else => |err| {
            note(diag, .mount_setattr, err);
            return error.Unexpected;
        },
    }
}

fn makePath(allocator: std.mem.Allocator, path: []const u8, kind: PathKind, diag: ?*?Diagnostic) MountError!void {
    std.debug.assert(path.len > 0 and path[0] == '/');

    var i: usize = 1;
    while (i <= path.len) : (i += 1) {
        if (i < path.len and path[i] != '/') continue;

        const prefix = try allocator.dupeZ(u8, path[0..i]);
        defer allocator.free(prefix);

        const is_leaf = i == path.len;
        if (is_leaf and kind == .file) {
            try makeFile(prefix.ptr, diag);
        } else {
            try makeDir(prefix.ptr, diag);
        }
    }
}

fn makeDir(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, path, 0o755))) {
        .SUCCESS, .EXIST => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_target_mkdir, err);
            return error.Unexpected;
        },
    }
}

fn makeFile(path: [*:0]const u8, diag: ?*?Diagnostic) MountError!void {
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .NOFOLLOW = true }, 0o644);
    switch (linux.errno(fd_rc)) {
        .SUCCESS => {},
        .LOOP => return error.BindTargetIsSymlink,
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_target_open, err);
            return error.Unexpected;
        },
    }
    _ = linux.close(@intCast(fd_rc));
}

fn mountCall(
    source: ?[*:0]const u8,
    target: [*:0]const u8,
    fstype: ?[*:0]const u8,
    flags: u32,
    data: usize,
    diag: ?*?Diagnostic,
) MountError!void {
    const rc = linux.mount(source, target, fstype, flags, data);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .mount_call, err);
            return error.Unexpected;
        },
    }
}

pub fn pivotInto(allocator: std.mem.Allocator, root: []const u8, diag: ?*?Diagnostic) MountError!void {
    const old = try std.fs.path.join(allocator, &.{ root, ".old_root" });
    defer allocator.free(old);
    try makePath(allocator, old, .directory, diag);

    const root_z = try allocator.dupeZ(u8, root);
    defer allocator.free(root_z);
    const old_z = try allocator.dupeZ(u8, old);
    defer allocator.free(old_z);

    switch (linux.errno(linux.pivot_root(root_z, old_z))) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.NotPermitted,
        else => |err| {
            note(diag, .pivot_root, err);
            return error.Unexpected;
        },
    }

    switch (linux.errno(linux.chdir("/"))) {
        .SUCCESS => {},
        else => |err| {
            note(diag, .chdir_after_pivot, err);
            return error.Unexpected;
        },
    }

    switch (linux.errno(linux.umount2("/.old_root", mnt_detach))) {
        .SUCCESS => {},
        else => |err| {
            note(diag, .old_root_umount, err);
            return error.Unexpected;
        },
    }

    _ = linux.rmdir("/.old_root");
}

test "a resolver file the sandbox does not hold is made where it belongs and written" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(std.testing.io, &root_buffer)];

    var diag: ?Diagnostic = null;
    try substitute(gpa, root, &.{
        .{ .text = .{ .target = "/etc/resolv.conf", .contents = "nameserver 10.99.0.1\n" } },
    }, &diag);
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);

    const written = try tmp.dir.readFileAlloc(std.testing.io, "etc/resolv.conf", gpa, .limited(4096));
    defer gpa.free(written);
    try std.testing.expectEqualStrings("nameserver 10.99.0.1\n", written);

    try std.testing.expectError(error.NotPermitted, substitute(gpa, root, &.{
        .{ .text = .{ .target = "/etc/resolv.conf", .contents = "nameserver 10.99.0.1\n" } },
    }, null));
}

test "a path the sandbox does not hold is not hidden, and is not a fault either" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(std.testing.io, &root_buffer)];

    var diag: ?Diagnostic = null;
    try substitute(gpa, root, &.{.{ .hide = "/run/nscd" }}, &diag);
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);
}

test "a substitution target that is a symbolic link is refused and never followed" {
    const builtin = @import("builtin");
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(std.testing.io, &root_buffer)];

    try tmp.dir.createDir(std.testing.io, "etc", .default_dir);
    try tmp.dir.symLink(std.testing.io, "../run/systemd/resolve/stub-resolv.conf", "etc/resolv.conf", .{});
    try std.testing.expectError(error.BindTargetIsSymlink, substitute(gpa, root, &.{
        .{ .text = .{ .target = "/etc/resolv.conf", .contents = "nameserver 10.99.0.1\n" } },
    }, null));

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "etc/real", .data = "somebody else\n" });
    try tmp.dir.symLink(std.testing.io, "real", "etc/nsswitch.conf", .{});
    try std.testing.expectError(error.BindTargetIsSymlink, substitute(gpa, root, &.{
        .{ .text = .{ .target = "/etc/nsswitch.conf", .contents = "hosts: files dns\n" } },
    }, null));
    const beside = try tmp.dir.readFileAlloc(std.testing.io, "etc/real", gpa, .limited(4096));
    defer gpa.free(beside);
    try std.testing.expectEqualStrings("somebody else\n", beside);
}

test "a substitution that names nothing makes no call at all" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(std.testing.io, &root_buffer)];

    try substitute(gpa, root, &.{}, null);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(std.testing.io, substitute_source_name, .{}));
}

test "a procfs that hides other users names a group the call is not in" {
    var room: [procfs_option_bytes]u8 = undefined;

    try std.testing.expectEqual(@as(?[:0]const u8, null), procfsOptions(&room, false, 0));

    const said = procfsOptions(&room, true, 0).?;
    try std.testing.expectEqualStrings("hidepid=2,gid=1", said);
    try std.testing.expect(std.mem.indexOf(u8, said, "gid=0") == null);

    try std.testing.expectEqualStrings("hidepid=2,gid=1001", procfsOptions(&room, true, 1000).?);
}
