//! The Linux driver for `../overlay.zig`: overlayfs, for a project that is not
//! a git repository. The upper layer is the diff.

const std = @import("std");

const diagnostic = @import("../diagnostic.zig");
const Diagnostic = diagnostic.Diagnostic;
const linux = std.os.linux;

const iface = @import("../overlay.zig");
const Overlay = iface.Overlay;
const Error = iface.Error;
const ChangeKind = iface.ChangeKind;
const ChangedFile = iface.ChangedFile;
const Skip = iface.Skip;
const ChangeReport = iface.ChangeReport;
const NestedMount = iface.NestedMount;

/// `reason` is copied, not borrowed, because callers build it in a frame that
/// ends.
fn recordSkip(
    skipped: *std.ArrayList(Skip),
    allocator: std.mem.Allocator,
    path: []const u8,
    reason: []const u8,
) Error!void {
    const path_copy = allocator.dupe(u8, path) catch return error.OutOfMemory;
    errdefer allocator.free(path_copy);
    const reason_copy = allocator.dupe(u8, reason) catch return error.OutOfMemory;
    errdefer allocator.free(reason_copy);
    skipped.append(allocator, .{ .path = path_copy, .reason = reason_copy }) catch return error.OutOfMemory;
}

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    const project_owned = allocator.dupe(u8, project) catch return error.OutOfMemory;
    errdefer allocator.free(project_owned);

    const upper = std.fs.path.join(allocator, &.{ scratch, "upper" }) catch return error.OutOfMemory;
    errdefer allocator.free(upper);
    const work = std.fs.path.join(allocator, &.{ scratch, "work" }) catch return error.OutOfMemory;
    errdefer allocator.free(work);
    const merged = std.fs.path.join(allocator, &.{ scratch, "merged" }) catch return error.OutOfMemory;
    errdefer allocator.free(merged);

    try makeScratchDir(io, upper, diag);
    errdefer removeScratchDir(io, upper);
    try makeScratchDir(io, work, diag);
    errdefer removeScratchDir(io, work);
    try makeScratchDir(io, merged, diag);

    return .{ .project = project_owned, .upper = upper, .work = work, .merged = merged };
}

/// Rebuild the scratch layout of an overlay already on disk. Makes no upper
/// layer and copies nothing, so a failure leaves every file where it was.
pub fn adopt(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    const project_owned = allocator.dupe(u8, project) catch return error.OutOfMemory;
    errdefer allocator.free(project_owned);

    const upper = std.fs.path.join(allocator, &.{ scratch, "upper" }) catch return error.OutOfMemory;
    errdefer allocator.free(upper);
    const work = std.fs.path.join(allocator, &.{ scratch, "work" }) catch return error.OutOfMemory;
    errdefer allocator.free(work);
    const merged = std.fs.path.join(allocator, &.{ scratch, "merged" }) catch return error.OutOfMemory;
    errdefer allocator.free(merged);

    if (!try iface.scratchDirOnDisk(io, upper, diag)) return error.NoOverlayToAdopt;
    if (!try iface.scratchDirOnDisk(io, work, diag)) try makeScratchDir(io, work, diag);
    if (!try iface.scratchDirOnDisk(io, merged, diag)) try makeScratchDir(io, merged, diag);

    return .{ .project = project_owned, .upper = upper, .work = work, .merged = merged };
}

fn makeScratchDir(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!void {
    std.Io.Dir.createDirAbsolute(io, absolute_path, .default_dir) catch |err| {
        diagnostic.noteErr(diag, .overlay_scratch_mkdir, err);
        return error.Unexpected;
    };
}

fn removeScratchDir(io: std.Io, absolute_path: []const u8) void {
    std.Io.Dir.deleteDirAbsolute(io, absolute_path) catch {};
}

/// Read the upper layer and report every path that changed. A file the agent
/// changed and then changed back to its original bytes is still reported as
/// modified: this driver reads the upper layer and never the content.
/// A deletion is a whiteout and not a removal: overlayfs leaves a character
/// device with major and minor 0 in the upper layer. A directory that replaces
/// a deleted lower path is marked opaque instead, because a directory cannot be
/// a character device, and without that check `rm x && mkdir x` loses the
/// deletion from the diff.
pub fn changedFiles(
    self: Overlay,
    allocator: std.mem.Allocator,
    io: std.Io,
    diag: ?*?Diagnostic,
) Error!ChangeReport {
    var changed: std.ArrayList(ChangedFile) = .empty;
    errdefer {
        for (changed.items) |*item| item.deinit(allocator);
        changed.deinit(allocator);
    }
    var skipped: std.ArrayList(Skip) = .empty;
    errdefer {
        for (skipped.items) |*item| item.deinit(allocator);
        skipped.deinit(allocator);
    }

    var upper_dir = std.Io.Dir.cwd().openDir(io, self.upper, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .upper_layer_open, err);
        return error.Unexpected;
    };
    defer upper_dir.close(io);

    var walker = upper_dir.walkSelectively(allocator) catch return error.OutOfMemory;
    defer walker.deinit();

    while (true) {
        const entry = (walker.next(io) catch |err| {
            diagnostic.noteErr(diag, .upper_layer_walk, err);
            return error.Unexpected;
        }) orelse break;

        const absolute = std.fs.path.join(allocator, &.{ self.upper, entry.path }) catch return error.OutOfMemory;
        defer allocator.free(absolute);

        // entry.kind comes from the directory listing's own d_type, which
        // a filesystem may not fill in.
        const kind = resolveKind(allocator, absolute, entry.kind, diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| {
                diagnostic.noteErr(diag, .upper_entry_kind, e);
                return error.Unexpected;
            },
        };

        switch (kind) {
            .character_device => {
                // A character device that is not overlayfs's own whiteout is an
                // ordinary file the agent made.
                if (try isWhiteout(allocator, absolute, diag)) {
                    const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
                    changed.append(allocator, .{ .path = path_copy, .kind = .deleted }) catch return error.OutOfMemory;
                } else {
                    try recordSkip(&skipped, allocator, entry.path, "a character device, not overlayfs's own whiteout marker");
                }
            },
            .directory => {
                if (try isOpaqueDir(allocator, absolute, diag)) {
                    const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
                    changed.append(allocator, .{ .path = path_copy, .kind = .deleted }) catch return error.OutOfMemory;
                }
                walker.enter(io, entry) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| {
                        diagnostic.noteErr(diag, .upper_directory_enter, e);
                        return error.Unexpected;
                    },
                };
            },
            .file, .sym_link => {
                const existed_in_project = existsInProject(allocator, io, self.project, entry.path) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| {
                        diagnostic.noteErr(diag, .project_entry_check, e);
                        return error.Unexpected;
                    },
                };

                const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
                changed.append(allocator, .{
                    .path = path_copy,
                    .kind = if (existed_in_project) .modified else .added,
                }) catch return error.OutOfMemory;
            },
            else => |other| {
                const reason = std.fmt.allocPrint(
                    allocator,
                    "not a regular file, a link, a directory, or a whiteout (it is a {s})",
                    .{@tagName(other)},
                ) catch return error.OutOfMemory;
                defer allocator.free(reason);
                try recordSkip(&skipped, allocator, entry.path, reason);
            },
        }
    }

    return .{
        .changed = changed.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .skipped = skipped.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

/// Find every directory under `project` that is itself the mount point of a
/// separate filesystem, which the merged view cannot show.
/// A nested mount inside the project is invisible to the merged view, which
/// shows whatever plain directory sits at that path on the lower filesystem. An
/// agent shown an empty directory where the user has files can act on that
/// wrong belief, so a caller tells the user before the session starts.
pub fn nestedMounts(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    diag: ?*?Diagnostic,
) Error![]NestedMount {
    var list: std.ArrayList(NestedMount) = .empty;
    errdefer {
        for (list.items) |*item| item.deinit(allocator);
        list.deinit(allocator);
    }

    var project_dir = std.Io.Dir.cwd().openDir(io, project, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .project_open, err);
        return error.Unexpected;
    };
    defer project_dir.close(io);

    const project_stat = try statNoFollow(allocator, project, diag);
    const project_device = deviceNumber(project_stat);

    var walker = project_dir.walkSelectively(allocator) catch return error.OutOfMemory;
    defer walker.deinit();

    while (true) {
        const entry = (walker.next(io) catch |err| {
            diagnostic.noteErr(diag, .project_walk, err);
            return error.Unexpected;
        }) orelse break;

        const absolute = std.fs.path.join(allocator, &.{ project, entry.path }) catch return error.OutOfMemory;
        defer allocator.free(absolute);

        const entry_stat = try statNoFollow(allocator, absolute, diag);
        if ((entry_stat.mode & linux.S.IFMT) != linux.S.IFDIR) continue;

        if (deviceNumber(entry_stat) == project_device) {
            walker.enter(io, entry) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |e| {
                    diagnostic.noteErr(diag, .project_directory_enter, e);
                    return error.Unexpected;
                },
            };
            continue;
        }

        // A different device: a nested mount. Reported, not entered.
        const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
        list.append(allocator, .{ .path = path_copy }) catch return error.OutOfMemory;
    }

    return list.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn deviceNumber(stx: linux.Statx) u64 {
    return (@as(u64, stx.dev_major) << 32) | stx.dev_minor;
}

fn statNoFollow(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!linux.Statx {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path_z.ptr, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &stx);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| {
            diagnostic.noteErrno(diag, .upper_entry_stat, err);
            return error.Unexpected;
        },
    }
    return stx;
}

fn existsInProject(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    rel_path: []const u8,
) (std.Io.Dir.StatFileError || error{OutOfMemory})!bool {
    var current = allocator.dupe(u8, project) catch return error.OutOfMemory;
    defer allocator.free(current);

    var components = std.mem.tokenizeScalar(u8, rel_path, '/');
    while (components.next()) |component| {
        const joined = std.fs.path.join(allocator, &.{ current, component }) catch return error.OutOfMemory;
        allocator.free(current);
        current = joined;

        const info = std.Io.Dir.cwd().statFile(io, current, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return false,
            else => |e| return e,
        };

        if (components.peek() != null and info.kind != .directory) return false;
    }
    return true;
}

/// True if `absolute_path`, already known to be a character device, is
/// overlayfs's own whiteout: major and minor both zero.
fn isWhiteout(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!bool {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path_z.ptr, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &stx);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| {
            diagnostic.noteErrno(diag, .whiteout_stat, err);
            return error.Unexpected;
        },
    }
    if ((stx.mode & linux.S.IFMT) != linux.S.IFCHR) return false;
    return stx.rdev_major == 0 and stx.rdev_minor == 0;
}

/// `userxattr` is required, and its absence looked like a kernel fault. Without
/// it, overlayfs keeps this bookkeeping in `trusted.overlay.*`, which only
/// `CAP_SYS_ADMIN` over the host can write, so the kernel returned `EIO` for
/// `rm x && mkdir x`, for `rm -rf` of a project directory, and for replacing a
/// file with a directory. An earlier version recorded that as an unfixable
/// kernel limitation. `userxattr` moves it into `user.overlay.*`.
fn isOpaqueDir(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!bool {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var value: [1]u8 = undefined;
    const rc = linux.lgetxattr(path_z.ptr, "user.overlay.opaque", &value, value.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        // No such attribute at all: an ordinary directory.
        .NODATA => return false,
        .RANGE => return false,
        // The filesystem underneath the upper layer does not support
        // extended attributes, so it can hold no opaque marker either.
        .OPNOTSUPP => return false,
        else => |err| {
            diagnostic.noteErrno(diag, .opaque_directory_getxattr, err);
            return error.Unexpected;
        },
    }
    const len: usize = @intCast(rc);
    return len == 1 and value[0] == 'y';
}

fn resolveKind(
    allocator: std.mem.Allocator,
    absolute_path: []const u8,
    reported: std.Io.File.Kind,
    diag: ?*?Diagnostic,
) Error!std.Io.File.Kind {
    if (reported != .unknown) return reported;

    const stx = try statNoFollow(allocator, absolute_path, diag);
    return switch (stx.mode & linux.S.IFMT) {
        linux.S.IFREG => .file,
        linux.S.IFDIR => .directory,
        linux.S.IFLNK => .sym_link,
        linux.S.IFCHR => .character_device,
        linux.S.IFBLK => .block_device,
        linux.S.IFIFO => .named_pipe,
        linux.S.IFSOCK => .unix_domain_socket,
        else => .unknown,
    };
}

// Every test below builds its own project directory inside a fresh tmpDir.

const overlay_helper_path = @import("overlay_helper_path").overlay_helper_path;

const sandbox = @import("chock-sandbox");

fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    scratch_path: []u8,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(&buffer, tmp.dir.handle);

        const root_path = try std.fs.path.join(allocator, &.{ tmp_path, "project" });
        errdefer allocator.free(root_path);
        const scratch_path = try std.fs.path.join(allocator, &.{ tmp_path, "scratch" });
        errdefer allocator.free(scratch_path);

        try std.Io.Dir.createDirAbsolute(std.testing.io, root_path, .default_dir);
        try std.Io.Dir.createDirAbsolute(std.testing.io, scratch_path, .default_dir);

        return .{ .allocator = allocator, .root_path = root_path, .scratch_path = scratch_path };
    }

    fn deinit(self: *TestProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
    }

    fn writeFile(self: TestProject, name: []const u8, contents: []const u8) !void {
        const file_path = try std.fs.path.join(self.allocator, &.{ self.root_path, name });
        defer self.allocator.free(file_path);
        var file = try std.Io.Dir.createFileAbsolute(std.testing.io, file_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, contents);
    }
};

fn readProjectFile(allocator: std.mem.Allocator, project: TestProject, name: []const u8) ![]u8 {
    const file_path = try std.fs.path.join(allocator, &.{ project.root_path, name });
    defer allocator.free(file_path);
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, file_path, allocator, .limited(4096));
}

fn readUpperFile(allocator: std.mem.Allocator, ov: Overlay, name: []const u8) ![]u8 {
    const file_path = try std.fs.path.join(allocator, &.{ ov.upper, name });
    defer allocator.free(file_path);
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, file_path, allocator, .limited(4096));
}

fn allowScratchCleanup(allocator: std.mem.Allocator, ov: Overlay) void {
    const kernel_work_dir = std.fs.path.join(allocator, &.{ ov.work, "work" }) catch return;
    defer allocator.free(kernel_work_dir);
    const path_z = allocator.dupeZ(u8, kernel_work_dir) catch return;
    defer allocator.free(path_z);
    _ = linux.chmod(path_z.ptr, 0o700);
}

/// True if this process can use extended attributes on an ordinary file here.
/// A filesystem without them can hold no opaque marker.
fn xattrsSupported(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = absoluteDirPath(&buffer, tmp.dir.handle) catch return false;
    const probe_path = std.fs.path.join(allocator, &.{ tmp_path, ".xattr-probe" }) catch return false;
    defer allocator.free(probe_path);

    var file = std.Io.Dir.createFileAbsolute(std.testing.io, probe_path, .{}) catch return false;
    file.close(std.testing.io);

    const path_z = allocator.dupeZ(u8, probe_path) catch return false;
    defer allocator.free(path_z);
    const rc = linux.setxattr(path_z.ptr, "user.chock_probe", "y", 1, 0);
    return linux.errno(rc) == .SUCCESS;
}

fn runOverlayHelper(allocator: std.mem.Allocator, ov: Overlay, ops: []const []const u8) !std.process.Child.Term {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, overlay_helper_path);
    try argv.append(allocator, ov.project);
    try argv.append(allocator, ov.upper);
    try argv.append(allocator, ov.work);
    try argv.append(allocator, ov.merged);
    try argv.appendSlice(allocator, ops);

    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const term = try child.wait(std.testing.io);
    allowScratchCleanup(allocator, ov);
    // A boundary that was never reached is not a boundary that held.
    if (term == .exited and term.exited == sandbox.namespace.nothing_measured_exit_status) {
        return error.SkipZigTest;
    }
    return term;
}

test "a write inside the overlay does not change the file in the project" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("tracked.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"W:tracked.txt:changed by the agent\n"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const project_contents = try readProjectFile(allocator, project, "tracked.txt");
    defer allocator.free(project_contents);
    try std.testing.expectEqualStrings("original\n", project_contents);

    const upper_contents = try readUpperFile(allocator, ov, "tracked.txt");
    defer allocator.free(upper_contents);
    try std.testing.expectEqualStrings("changed by the agent\n", upper_contents);
}

test "the upper layer holds only the files that changed" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("a.txt", "a\n");
    try project.writeFile("b.txt", "b\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"W:a.txt:a, changed\n"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var upper_dir = try std.Io.Dir.cwd().openDir(std.testing.io, ov.upper, .{ .iterate = true });
    defer upper_dir.close(std.testing.io);
    var it = upper_dir.iterate();
    var entry_count: usize = 0;
    var saw_a = false;
    while (try it.next(std.testing.io)) |entry| {
        entry_count += 1;
        try std.testing.expect(!std.mem.eql(u8, entry.name, "b.txt"));
        if (std.mem.eql(u8, entry.name, "a.txt")) saw_a = true;
    }
    try std.testing.expectEqual(@as(usize, 1), entry_count);
    try std.testing.expect(saw_a);
}

test "a file deleted in the overlay is still in the project" {
    // overlayfs marks a deletion with a whiteout. Prove the original survives.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("todelete.txt", "keep me\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"D:todelete.txt"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const project_contents = try readProjectFile(allocator, project, "todelete.txt");
    defer allocator.free(project_contents);
    try std.testing.expectEqualStrings("keep me\n", project_contents);

    const upper_path = try std.fs.path.join(allocator, &.{ ov.upper, "todelete.txt" });
    defer allocator.free(upper_path);
    try std.testing.expect(try isWhiteout(allocator, upper_path, null));
}

test "changedFiles lists a new file, a changed file, and a deleted one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("changed.txt", "before\n");
    try project.writeFile("deleted.txt", "gone soon\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{
        "W:new.txt:brand new\n",
        "W:changed.txt:after\n",
        "D:deleted.txt",
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), report.changed.len);

    var found_new = false;
    var found_changed = false;
    var found_deleted = false;
    for (report.changed) |change| {
        if (std.mem.eql(u8, change.path, "new.txt")) {
            try std.testing.expectEqual(ChangeKind.added, change.kind);
            found_new = true;
        } else if (std.mem.eql(u8, change.path, "changed.txt")) {
            try std.testing.expectEqual(ChangeKind.modified, change.kind);
            found_changed = true;
        } else if (std.mem.eql(u8, change.path, "deleted.txt")) {
            try std.testing.expectEqual(ChangeKind.deleted, change.kind);
            found_deleted = true;
        }
    }
    try std.testing.expect(found_new);
    try std.testing.expect(found_changed);
    try std.testing.expect(found_deleted);
}

test "a symbolic link made inside the overlay does not touch the project, and changedFiles reports it as added" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"L:link.txt:/somewhere/outside"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var project_dir = try std.Io.Dir.cwd().openDir(std.testing.io, project.root_path, .{ .iterate = true });
    defer project_dir.close(std.testing.io);
    var project_it = project_dir.iterate();
    try std.testing.expectEqual(null, try project_it.next(std.testing.io));

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("link.txt", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.added, report.changed[0].kind);
}

test "a new directory the agent made is not reported on its own, only the file inside it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "M:sub", "W:sub/inside.txt:nested\n" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var project_dir = try std.Io.Dir.cwd().openDir(std.testing.io, project.root_path, .{ .iterate = true });
    defer project_dir.close(std.testing.io);
    var project_it = project_dir.iterate();
    try std.testing.expectEqual(null, try project_it.next(std.testing.io));

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("sub/inside.txt", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.added, report.changed[0].kind);
}

test "mounts describes an overlay onto the project's own path, with project as the lower layer" {
    // A reviewer swapped the mount target to prove the test was really
    // reading the merged view.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const list = try ov.mounts(allocator);
    defer allocator.free(list);

    try std.testing.expectEqual(@as(usize, 1), list.len);
    const entry = switch (list[0]) {
        .overlay => |o| o,
        .bind, .proc, .deny => return error.ExpectedAnOverlayEntry,
    };
    try std.testing.expectEqualStrings(project.root_path, entry.lower);
    try std.testing.expectEqualStrings(ov.upper, entry.upper);
    try std.testing.expectEqualStrings(ov.work, entry.work);
    try std.testing.expectEqualStrings(project.root_path, entry.target);
}

test "regression: a directory that replaces a deleted file is reported as a deletion, not lost" {
    // The case that made `userxattr` necessary.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("x", "a file, soon a directory\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "D:x", "M:x", "W:x/inside.txt:new content\n" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);

    // Whether "x" itself is reported deleted depends on reading the opaque
    // marker, which needs extended attribute support underneath.
    const check_opaque_marker = xattrsSupported(allocator, tmp);

    var found_deleted_x = false;
    var found_added_inside = false;
    for (report.changed) |change| {
        if (std.mem.eql(u8, change.path, "x")) {
            if (check_opaque_marker) try std.testing.expectEqual(ChangeKind.deleted, change.kind);
            found_deleted_x = true;
        } else if (std.mem.eql(u8, change.path, "x/inside.txt")) {
            try std.testing.expectEqual(ChangeKind.added, change.kind);
            found_added_inside = true;
        }
    }
    if (check_opaque_marker) try std.testing.expect(found_deleted_x);
    try std.testing.expect(found_added_inside);
}

test "regression: a project symlink does not let existsInProject see through a replaced directory" {
    // `existsInProject` used to resolve rel_path in a way that followed a
    // symbolic link out of the project.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const other_dir_path = try std.fs.path.join(allocator, &.{ project.root_path, "other" });
    defer allocator.free(other_dir_path);
    try std.Io.Dir.createDirAbsolute(std.testing.io, other_dir_path, .default_dir);
    const other_file_path = try std.fs.path.join(allocator, &.{ other_dir_path, "existing.txt" });
    defer allocator.free(other_file_path);
    var other_file = try std.Io.Dir.createFileAbsolute(std.testing.io, other_file_path, .{});
    try other_file.writeStreamingAll(std.testing.io, "unrelated content\n");
    other_file.close(std.testing.io);

    const link_path = try std.fs.path.join(allocator, &.{ project.root_path, "x" });
    defer allocator.free(link_path);
    try std.Io.Dir.cwd().symLink(std.testing.io, "other", link_path, .{});

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "D:x", "M:x", "W:x/existing.txt:brand new\n" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);

    const check_opaque_marker = xattrsSupported(allocator, tmp);

    var found_x_deleted = false;
    var found_inside_added = false;
    for (report.changed) |change| {
        if (std.mem.eql(u8, change.path, "x")) {
            if (check_opaque_marker) try std.testing.expectEqual(ChangeKind.deleted, change.kind);
            found_x_deleted = true;
        } else if (std.mem.eql(u8, change.path, "x/existing.txt")) {
            try std.testing.expectEqual(ChangeKind.added, change.kind);
            found_inside_added = true;
        }
    }
    if (check_opaque_marker) try std.testing.expect(found_x_deleted);
    try std.testing.expect(found_inside_added);
}

test "an entire project directory removed in the overlay is reported as one deletion" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const olddir_path = try std.fs.path.join(allocator, &.{ project.root_path, "olddir" });
    defer allocator.free(olddir_path);
    try std.Io.Dir.createDirAbsolute(std.testing.io, olddir_path, .default_dir);
    const inside_path = try std.fs.path.join(allocator, &.{ olddir_path, "inside.txt" });
    defer allocator.free(inside_path);
    var inside_file = try std.Io.Dir.createFileAbsolute(std.testing.io, inside_path, .{});
    try inside_file.writeStreamingAll(std.testing.io, "bye\n");
    inside_file.close(std.testing.io);

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "D:olddir/inside.txt", "R:olddir" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("olddir", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.deleted, report.changed[0].kind);
}

test "a fifo made inside the overlay is recorded as a skip, not silently dropped" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"F:pipe1"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.changed.len);
    try std.testing.expectEqual(@as(usize, 1), report.skipped.len);
    try std.testing.expectEqualStrings("pipe1", report.skipped[0].path);
}

test "resolveKind falls back to statx when the caller reports unknown" {
    // A filesystem with no d_type reports every entry as unknown, so the walk
    // must stat rather than trust the listing.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try absoluteDirPath(&buffer, tmp.dir.handle);
    const file_path = try std.fs.path.join(allocator, &.{ tmp_path, "plain.txt" });
    defer allocator.free(file_path);
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, file_path, .{});
    file.close(std.testing.io);

    const kind = try resolveKind(allocator, file_path, .unknown, null);
    try std.testing.expectEqual(std.Io.File.Kind.file, kind);
}

fn writeUpper(allocator: std.mem.Allocator, ov: Overlay, relative: []const u8, contents: []const u8) !void {
    const file_path = try std.fs.path.join(allocator, &.{ ov.upper, relative });
    defer allocator.free(file_path);
    if (std.fs.path.dirname(file_path)) |parent| {
        try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);
    }
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, file_path, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, contents);
}

/// Make the whiteout overlayfs makes for a deleted path: a character device
/// with major and minor both zero.
fn makeWhiteout(allocator: std.mem.Allocator, ov: Overlay, relative: []const u8) !void {
    const file_path = try std.fs.path.join(allocator, &.{ ov.upper, relative });
    defer allocator.free(file_path);
    if (std.fs.path.dirname(file_path)) |parent| {
        try std.Io.Dir.cwd().createDirPath(std.testing.io, parent);
    }
    const path_z = try allocator.dupeZ(u8, file_path);
    defer allocator.free(path_z);
    const rc = linux.mknod(path_z.ptr, linux.S.IFCHR | 0o600, 0);
    // A failure fails the test and never skips it. A machine that cannot make
    // a whiteout would otherwise pass this silently.
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(rc));
    try std.testing.expect(try isWhiteout(allocator, file_path, null));
}

fn readCarried(allocator: std.mem.Allocator, destination: []const u8, relative: []const u8) ![]u8 {
    const file_path = try std.fs.path.join(allocator, &.{ destination, relative });
    defer allocator.free(file_path);
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, file_path, allocator, .limited(4096));
}

test "adopt rebuilds every path create built, over the work that is already there" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("tracked.txt", "original\n");

    var made = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer made.deinit(allocator);
    try writeUpper(allocator, made, "tracked.txt", "the agent changed this\n");

    var taken = try adopt(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer taken.deinit(allocator);

    try std.testing.expectEqualStrings(made.project, taken.project);
    try std.testing.expectEqualStrings(made.upper, taken.upper);
    try std.testing.expectEqualStrings(made.work, taken.work);
    try std.testing.expectEqualStrings(made.merged, taken.merged);

    const kept = try readUpperFile(allocator, taken, "tracked.txt");
    defer allocator.free(kept);
    try std.testing.expectEqualStrings("the agent changed this\n", kept);
}

test "adopt refuses a scratch directory with no upper layer, and a symbolic link where one should be" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    try std.testing.expectError(error.NoOverlayToAdopt, adopt(
        allocator,
        std.testing.io,
        project.root_path,
        project.scratch_path,
        null,
    ));

    const upper_path = try std.fs.path.join(allocator, &.{ project.scratch_path, "upper" });
    defer allocator.free(upper_path);
    try std.Io.Dir.symLinkAbsolute(std.testing.io, project.root_path, upper_path, .{});
    try std.testing.expectError(error.NoOverlayToAdopt, adopt(
        allocator,
        std.testing.io,
        project.root_path,
        project.scratch_path,
        null,
    ));
}

test "carryOut brings a changed file and a new one out, and changes nothing in the project" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("tracked.txt", "original\n");
    try project.writeFile("untouched.txt", "leave me\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUpper(allocator, ov, "tracked.txt", "the agent changed this\n");
    try writeUpper(allocator, ov, "notes/new.md", "the agent made this\n");

    const destination = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted" });
    defer allocator.free(destination);

    const carried = try ov.carryOut(allocator, std.testing.io, destination, null);
    try std.testing.expectEqual(@as(usize, 2), carried.files);
    try std.testing.expectEqual(@as(usize, 0), carried.deleted);
    try std.testing.expectEqual(@as(usize, 0), carried.skipped);

    const changed = try readCarried(allocator, destination, "files/tracked.txt");
    defer allocator.free(changed);
    try std.testing.expectEqualStrings("the agent changed this\n", changed);
    const added = try readCarried(allocator, destination, "files/notes/new.md");
    defer allocator.free(added);
    try std.testing.expectEqualStrings("the agent made this\n", added);

    // Nothing of the person's moved.
    const still_there = try readProjectFile(allocator, project, "tracked.txt");
    defer allocator.free(still_there);
    try std.testing.expectEqualStrings("original\n", still_there);
    const untouched = try readProjectFile(allocator, project, "untouched.txt");
    defer allocator.free(untouched);
    try std.testing.expectEqualStrings("leave me\n", untouched);
}

test "a path the session deleted is named in the deleted file and is still in the project" {
    // A deletion is work, and it is carried as a name.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("gone.txt", "the agent deleted me\n");
    try project.writeFile("kept.txt", "still here\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try makeWhiteout(allocator, ov, "gone.txt");

    const destination = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted" });
    defer allocator.free(destination);

    const carried = try ov.carryOut(allocator, std.testing.io, destination, null);
    try std.testing.expectEqual(@as(usize, 0), carried.files);
    try std.testing.expectEqual(@as(usize, 1), carried.deleted);

    const named = try readCarried(allocator, destination, "deleted");
    defer allocator.free(named);
    try std.testing.expectEqualStrings("gone.txt\n", named);

    const survivor = try readProjectFile(allocator, project, "gone.txt");
    defer allocator.free(survivor);
    try std.testing.expectEqualStrings("the agent deleted me\n", survivor);
    const other = try readProjectFile(allocator, project, "kept.txt");
    defer allocator.free(other);
    try std.testing.expectEqualStrings("still here\n", other);
}

test "the deleted and skipped files are written even when nothing was deleted or skipped" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const destination = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted" });
    defer allocator.free(destination);

    const carried = try ov.carryOut(allocator, std.testing.io, destination, null);
    try std.testing.expectEqual(@as(usize, 0), carried.files);

    const deleted = try readCarried(allocator, destination, "deleted");
    defer allocator.free(deleted);
    try std.testing.expectEqualStrings("", deleted);
    const skipped = try readCarried(allocator, destination, "skipped");
    defer allocator.free(skipped);
    try std.testing.expectEqualStrings("", skipped);
}

test "carryOut refuses a destination that already holds something, and reads nothing out of the upper layer" {
    // Not silent, and not a merge. A destination that is already there may
    // hold files a person edited, and there is no telling those apart.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("tracked.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUpper(allocator, ov, "tracked.txt", "the agent changed this\n");

    const destination = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted" });
    defer allocator.free(destination);
    try std.Io.Dir.createDirAbsolute(std.testing.io, destination, .default_dir);
    const in_the_way = try std.fs.path.join(allocator, &.{ destination, "files" });
    defer allocator.free(in_the_way);
    var handle = try std.Io.Dir.createFileAbsolute(std.testing.io, in_the_way, .{});
    try handle.writeStreamingAll(std.testing.io, "a person put this here\n");
    handle.close(std.testing.io);

    try std.testing.expectError(
        error.WorkAlreadyCarriedOut,
        ov.carryOut(allocator, std.testing.io, destination, null),
    );

    const still_there = try readCarried(allocator, destination, "files");
    defer allocator.free(still_there);
    try std.testing.expectEqualStrings("a person put this here\n", still_there);

    const second = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted-again" });
    defer allocator.free(second);
    const carried = try ov.carryOut(allocator, std.testing.io, second, null);
    try std.testing.expectEqual(@as(usize, 1), carried.files);
}

test "a symbolic link the session made is carried as a link, and an executable file keeps its mode" {
    // Following the link would copy a file the session never wrote.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUpper(allocator, ov, "build.sh", "#!/bin/sh\necho hello\n");

    const script_path = try std.fs.path.join(allocator, &.{ ov.upper, "build.sh" });
    defer allocator.free(script_path);
    const script_z = try allocator.dupeZ(u8, script_path);
    defer allocator.free(script_z);
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.chmod(script_z.ptr, 0o755)));

    const link_path = try std.fs.path.join(allocator, &.{ ov.upper, "latest" });
    defer allocator.free(link_path);
    // A relative target, which is what an agent makes.
    try std.Io.Dir.cwd().symLink(std.testing.io, "build.sh", link_path, .{});

    const destination = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted" });
    defer allocator.free(destination);
    const carried = try ov.carryOut(allocator, std.testing.io, destination, null);
    try std.testing.expectEqual(@as(usize, 2), carried.files);

    const carried_link = try std.fs.path.join(allocator, &.{ destination, "files", "latest" });
    defer allocator.free(carried_link);
    const link_stat = try std.Io.Dir.cwd().statFile(std.testing.io, carried_link, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, link_stat.kind);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try std.Io.Dir.readLinkAbsolute(std.testing.io, carried_link, &buffer);
    try std.testing.expectEqualStrings("build.sh", buffer[0..length]);

    const carried_script = try std.fs.path.join(allocator, &.{ destination, "files", "build.sh" });
    defer allocator.free(carried_script);
    const carried_script_z = try allocator.dupeZ(u8, carried_script);
    defer allocator.free(carried_script_z);
    var stx: linux.Statx = undefined;
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.statx(
        linux.AT.FDCWD,
        carried_script_z.ptr,
        linux.AT.SYMLINK_NOFOLLOW,
        .{ .MODE = true },
        &stx,
    )));
    try std.testing.expectEqual(@as(u32, 0o755), stx.mode & 0o777);
}

test "a fifo the session made is named in the skipped file rather than dropped" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const fifo_path = try std.fs.path.join(allocator, &.{ ov.upper, "pipe" });
    defer allocator.free(fifo_path);
    const fifo_z = try allocator.dupeZ(u8, fifo_path);
    defer allocator.free(fifo_z);
    // A fifo needs no privilege at all, so a failure here fails the test.
    try std.testing.expectEqual(linux.E.SUCCESS, linux.errno(linux.mknod(fifo_z.ptr, linux.S.IFIFO | 0o600, 0)));

    const destination = try std.fs.path.join(allocator, &.{ project.scratch_path, "adopted" });
    defer allocator.free(destination);
    const carried = try ov.carryOut(allocator, std.testing.io, destination, null);
    try std.testing.expectEqual(@as(usize, 0), carried.files);
    try std.testing.expectEqual(@as(usize, 1), carried.skipped);

    const named = try readCarried(allocator, destination, "skipped");
    defer allocator.free(named);
    try std.testing.expect(std.mem.startsWith(u8, named, "pipe: "));
}

test "nestedMounts finds nothing under a project with no mounts of its own" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("a.txt", "a\n");
    const sub_path = try std.fs.path.join(allocator, &.{ project.root_path, "sub" });
    defer allocator.free(sub_path);
    try std.Io.Dir.createDirAbsolute(std.testing.io, sub_path, .default_dir);

    const found = try nestedMounts(allocator, std.testing.io, project.root_path, null);
    defer iface.freeNestedMounts(allocator, found);
    try std.testing.expectEqual(@as(usize, 0), found.len);
}
