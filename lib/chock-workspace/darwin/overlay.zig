//! The Darwin driver for `../overlay.zig`, for a project that has no git of its
//! own. Not a port of `linux/overlay.zig`: this clones the project with
//! `clonefile(2)` and compares the clone against it entry by entry.

const std = @import("std");

const diagnostic = @import("../diagnostic.zig");
const Diagnostic = diagnostic.Diagnostic;
const builtin = @import("builtin");
const iface = @import("../overlay.zig");

const Overlay = iface.Overlay;
const Error = iface.Error;
const ChangeKind = iface.ChangeKind;
const ChangedFile = iface.ChangedFile;
const Skip = iface.Skip;
const ChangeReport = iface.ChangeReport;
const NestedMount = iface.NestedMount;

/// Declared here because `std` does not carry it.
extern "c" fn clonefile(src: [*:0]const u8, dst: [*:0]const u8, flags: u32) c_int;

extern "c" fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

extern "c" fn lstat(path: [*:0]const u8, out: *DeviceStat) c_int;

/// Darwin's own `struct stat`, with only the first field named. `st_dev` sits
/// first, and the rest is never read.
const DeviceStat = extern struct {
    device: i32,
    rest: [260]u8 align(8),
};

const compare_chunk_bytes: usize = 64 * 1024;

/// Clone `project` into a fresh directory under `scratch`, and describe the
/// result the way `../overlay.zig` expects.
/// `clonefile` refuses two ways. The two paths must be on the same volume, and
/// another volume gives `EXDEV`, reported as `error.ScratchOnAnotherVolume`
/// rather than moving the scratch directory into the user's project. The
/// destination must not exist, and `EEXIST` becomes
/// `error.ScratchAlreadyExists`. A volume with no copy on write clone at all,
/// such as HFS+, gives `ENOTSUP`.
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

    // The clone comes first, and nothing makes `upper` beforehand: clonefile
    // refuses a destination that already exists.
    try cloneTree(allocator, project_owned, upper, diag);
    errdefer removeScratchTree(io, upper);

    try makeScratchDir(io, work, diag);
    errdefer removeScratchDir(io, work);
    try makeScratchDir(io, merged, diag);

    return .{ .project = project_owned, .upper = upper, .work = work, .merged = merged };
}

/// Rebuild the scratch layout of an overlay already on disk. Copies nothing, so
/// a failure leaves every file where it was.
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

fn cloneTree(
    allocator: std.mem.Allocator,
    source: []const u8,
    destination: []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    const source_z = allocator.dupeZ(u8, source) catch return error.OutOfMemory;
    defer allocator.free(source_z);
    const destination_z = allocator.dupeZ(u8, destination) catch return error.OutOfMemory;
    defer allocator.free(destination_z);

    const result = clonefile(source_z.ptr, destination_z.ptr, 0);
    if (result == 0) return;

    switch (std.posix.errno(result)) {
        .XDEV => return error.ScratchOnAnotherVolume,
        .EXIST => return error.ScratchAlreadyExists,
        .OPNOTSUPP => return error.NoOverlayFilesystem,
        else => |errno| {
            diagnostic.noteErrno(diag, .project_clone, errno);
            return error.Unexpected;
        },
    }
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

fn removeScratchTree(io: std.Io, absolute_path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, absolute_path) catch {};
}

const PendingDir = struct {
    relative: []u8,
    in_project: bool,
};

/// Compare the clone against the project and report every path that changed.
/// Two passes: the clone's own entries, then everything the project holds that
/// the clone no longer does.
/// A timestamp cannot recover the changed set. `clonefile` copies each file's
/// `mtime` from the original and gives every cloned file a fresh `ctime`, so
/// this reads content where the two agree on size.
///
/// One deliberate difference from `linux/overlay.zig` follows: a file the agent
/// changed and then changed back is reported here as unchanged.
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

    const left = allocator.alloc(u8, compare_chunk_bytes) catch return error.OutOfMemory;
    defer allocator.free(left);
    const right = allocator.alloc(u8, compare_chunk_bytes) catch return error.OutOfMemory;
    defer allocator.free(right);

    var pending: std.ArrayList(PendingDir) = .empty;
    defer {
        for (pending.items) |item| allocator.free(item.relative);
        pending.deinit(allocator);
    }

    const root_relative = allocator.dupe(u8, "") catch return error.OutOfMemory;
    pending.append(allocator, .{ .relative = root_relative, .in_project = true }) catch {
        allocator.free(root_relative);
        return error.OutOfMemory;
    };

    while (pending.pop()) |dir| {
        defer allocator.free(dir.relative);

        const clone_path = try joinAbsolute(allocator, self.upper, dir.relative);
        defer allocator.free(clone_path);

        var clone_dir = try openIterable(io, clone_path, diag);
        defer clone_dir.close(io);

        var project_dir: ?std.Io.Dir = null;
        defer if (project_dir) |d| d.close(io);
        if (dir.in_project) {
            const project_path = try joinAbsolute(allocator, self.project, dir.relative);
            defer allocator.free(project_path);
            project_dir = try openIterable(io, project_path, diag);
        }

        var clone_names: std.StringHashMapUnmanaged(void) = .empty;
        defer {
            var it = clone_names.keyIterator();
            while (it.next()) |key| allocator.free(key.*);
            clone_names.deinit(allocator);
        }

        var clone_it = clone_dir.iterate();
        while (true) {
            const entry = (clone_it.next(io) catch |err| {
                diagnostic.noteErr(diag, .clone_read, err);
                return error.Unexpected;
            }) orelse break;

            const name = allocator.dupe(u8, entry.name) catch return error.OutOfMemory;
            clone_names.put(allocator, name, {}) catch {
                allocator.free(name);
                return error.OutOfMemory;
            };

            // The kind comes from a stat of the clone, never from the
            // directory listing's own d_type.
            const clone_stat = (try statNoFollow(io, clone_dir, name, diag)) orelse continue;
            const project_stat = if (project_dir) |d| try statNoFollow(io, d, name, diag) else null;

            const relative = try joinRelative(allocator, dir.relative, name);
            var relative_owned = true;
            defer if (relative_owned) allocator.free(relative);

            switch (clone_stat.kind) {
                .directory => {
                    const replaced_something = if (project_stat) |ps| ps.kind != .directory else false;
                    if (replaced_something) {
                        changed.append(allocator, .{ .path = relative, .kind = .deleted }) catch return error.OutOfMemory;
                        relative_owned = false;
                    }
                    const still_in_project = if (project_stat) |ps| ps.kind == .directory else false;
                    const pushed = if (relative_owned) relative else (allocator.dupe(u8, relative) catch return error.OutOfMemory);
                    pending.append(allocator, .{ .relative = pushed, .in_project = still_in_project }) catch {
                        if (!relative_owned) allocator.free(pushed);
                        return error.OutOfMemory;
                    };
                    relative_owned = false;
                },
                .file, .sym_link => {
                    const kind = try classifyFile(
                        io,
                        clone_dir,
                        project_dir,
                        name,
                        clone_stat,
                        project_stat,
                        left,
                        right,
                        diag,
                    );
                    if (kind) |k| {
                        changed.append(allocator, .{ .path = relative, .kind = k }) catch return error.OutOfMemory;
                        relative_owned = false;
                    }
                },
                else => |other| {
                    const reason = std.fmt.allocPrint(
                        allocator,
                        "not a regular file, a link, or a directory (it is a {s})",
                        .{@tagName(other)},
                    ) catch return error.OutOfMemory;
                    defer allocator.free(reason);
                    try recordSkip(&skipped, allocator, relative, reason);
                },
            }
        }

        // The second pass: everything the project holds here that the clone
        // does not.
        if (project_dir) |d| {
            var project_it = d.iterate();
            while (true) {
                const entry = (project_it.next(io) catch |err| {
                    diagnostic.noteErr(diag, .project_read, err);
                    return error.Unexpected;
                }) orelse break;
                if (clone_names.contains(entry.name)) continue;

                const relative = try joinRelative(allocator, dir.relative, entry.name);
                changed.append(allocator, .{ .path = relative, .kind = .deleted }) catch {
                    allocator.free(relative);
                    return error.OutOfMemory;
                };
            }
        }
    }

    return .{
        .changed = changed.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .skipped = skipped.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

fn classifyFile(
    io: std.Io,
    clone_dir: std.Io.Dir,
    project_dir: ?std.Io.Dir,
    name: []const u8,
    clone_stat: std.Io.File.Stat,
    project_stat: ?std.Io.File.Stat,
    left: []u8,
    right: []u8,
    diag: ?*?Diagnostic,
) Error!?ChangeKind {
    const project = project_stat orelse return .added;
    const other = project_dir orelse return .added;

    if (project.kind != clone_stat.kind) return .modified;

    if (clone_stat.kind == .sym_link) {
        return if (try sameLinkTarget(io, clone_dir, other, name, diag)) null else .modified;
    }

    // Different lengths cannot hold the same bytes, and this costs no read.
    if (project.size != clone_stat.size) return .modified;

    return if (try sameContent(io, clone_dir, other, name, left, right, diag)) null else .modified;
}

fn sameLinkTarget(
    io: std.Io,
    left_dir: std.Io.Dir,
    right_dir: std.Io.Dir,
    name: []const u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var left_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var right_buffer: [std.fs.max_path_bytes]u8 = undefined;

    const left_len = left_dir.readLink(io, name, &left_buffer) catch |err| {
        diagnostic.noteErr(diag, .clone_link_read, err);
        return error.Unexpected;
    };
    const right_len = right_dir.readLink(io, name, &right_buffer) catch |err| {
        diagnostic.noteErr(diag, .project_link_read, err);
        return error.Unexpected;
    };
    return std.mem.eql(u8, left_buffer[0..left_len], right_buffer[0..right_len]);
}

/// Whether the two files of the same name hold the same bytes. Both are read,
/// because a timestamp cannot answer this after a clone.
fn sameContent(
    io: std.Io,
    left_dir: std.Io.Dir,
    right_dir: std.Io.Dir,
    name: []const u8,
    left: []u8,
    right: []u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var left_file = left_dir.openFile(io, name, .{}) catch |err| {
        diagnostic.noteErr(diag, .clone_file_open, err);
        return error.Unexpected;
    };
    defer left_file.close(io);
    var right_file = right_dir.openFile(io, name, .{}) catch |err| {
        diagnostic.noteErr(diag, .project_file_open, err);
        return error.Unexpected;
    };
    defer right_file.close(io);

    while (true) {
        const left_len = try readChunk(io, left_file, left, diag);
        const right_len = try readChunk(io, right_file, right, diag);
        if (left_len != right_len) return false;
        if (left_len == 0) return true;
        if (!std.mem.eql(u8, left[0..left_len], right[0..right_len])) return false;
    }
}

fn readChunk(io: std.Io, file: std.Io.File, buffer: []u8, diag: ?*?Diagnostic) Error!usize {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const count = file.readStreaming(io, &.{buffer[filled..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| {
                diagnostic.noteErr(diag, .compared_file_read, e);
                return error.Unexpected;
            },
        };
        if (count == 0) break;
        filled += count;
    }
    return filled;
}

fn statNoFollow(
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    diag: ?*?Diagnostic,
) Error!?std.Io.File.Stat {
    return dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => |e| {
            diagnostic.noteErr(diag, .entry_metadata_read, e);
            return error.Unexpected;
        },
    };
}

fn openIterable(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!std.Io.Dir {
    return std.Io.Dir.cwd().openDir(io, absolute_path, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .directory_open, err);
        return error.Unexpected;
    };
}

fn joinAbsolute(allocator: std.mem.Allocator, root: []const u8, relative: []const u8) Error![]u8 {
    if (relative.len == 0) return allocator.dupe(u8, root) catch return error.OutOfMemory;
    return std.fs.path.join(allocator, &.{ root, relative }) catch return error.OutOfMemory;
}

fn joinRelative(allocator: std.mem.Allocator, prefix: []const u8, name: []const u8) Error![]u8 {
    if (prefix.len == 0) return allocator.dupe(u8, name) catch return error.OutOfMemory;
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name }) catch return error.OutOfMemory;
}

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

/// Find every directory under `project` that is itself the mount point of a
/// separate filesystem.
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

    const root_device = try deviceOf(allocator, project, diag);

    var pending: std.ArrayList([]u8) = .empty;
    defer {
        for (pending.items) |item| allocator.free(item);
        pending.deinit(allocator);
    }

    const root_relative = allocator.dupe(u8, "") catch return error.OutOfMemory;
    pending.append(allocator, root_relative) catch {
        allocator.free(root_relative);
        return error.OutOfMemory;
    };

    while (pending.pop()) |relative| {
        defer allocator.free(relative);

        const absolute = try joinAbsolute(allocator, project, relative);
        defer allocator.free(absolute);

        var dir = try openIterable(io, absolute, diag);
        defer dir.close(io);

        var it = dir.iterate();
        while (true) {
            const entry = (it.next(io) catch |err| {
                diagnostic.noteErr(diag, .project_read, err);
                return error.Unexpected;
            }) orelse break;

            const stat = (try statNoFollow(io, dir, entry.name, diag)) orelse continue;
            if (stat.kind != .directory) continue;

            const child_relative = try joinRelative(allocator, relative, entry.name);
            var owned = true;
            defer if (owned) allocator.free(child_relative);

            const child_absolute = try joinAbsolute(allocator, project, child_relative);
            defer allocator.free(child_absolute);

            if ((try deviceOf(allocator, child_absolute, diag)) != root_device) {
                list.append(allocator, .{ .path = child_relative }) catch return error.OutOfMemory;
                owned = false;
                continue;
            }

            pending.append(allocator, child_relative) catch return error.OutOfMemory;
            owned = false;
        }
    }

    return list.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

fn deviceOf(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!i32 {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var stat: DeviceStat = undefined;
    const result = lstat(path_z.ptr, &stat);
    if (result != 0) {
        diagnostic.noteErrno(diag, .entry_device_read, std.posix.errno(result));
        return error.Unexpected;
    }
    return stat.device;
}

/// A project and a scratch directory side by side under one `tmpDir`, so both
/// are on the same volume.
const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    scratch_path: []u8,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(std.testing.io, &buffer);
        const tmp_path = buffer[0..length];

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
        self.* = undefined;
    }

    fn writeFile(self: TestProject, relative: []const u8, contents: []const u8) !void {
        try writeUnder(self.allocator, self.root_path, relative, contents);
    }

    fn makeDir(self: TestProject, relative: []const u8) !void {
        const path = try std.fs.path.join(self.allocator, &.{ self.root_path, relative });
        defer self.allocator.free(path);
        try std.Io.Dir.createDirAbsolute(std.testing.io, path, .default_dir);
    }
};

fn writeUnder(allocator: std.mem.Allocator, root: []const u8, relative: []const u8, contents: []const u8) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, contents);
}

fn deleteUnder(allocator: std.mem.Allocator, root: []const u8, relative: []const u8) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    try std.Io.Dir.deleteFileAbsolute(std.testing.io, path);
}

fn readUnder(allocator: std.mem.Allocator, root: []const u8, relative: []const u8) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    var buffer: [4096]u8 = undefined;
    const length = try readChunk(std.testing.io, file, &buffer, null);
    return allocator.dupe(u8, buffer[0..length]);
}

fn changeFor(report: ChangeReport, path: []const u8) ?ChangeKind {
    for (report.changed) |item| {
        if (std.mem.eql(u8, item.path, path)) return item.kind;
    }
    return null;
}

test "create clones the project, and the clone carries the project's own content" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeDir("sub");
    try project.writeFile("sub/kept.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const cloned = try readUnder(allocator, ov.upper, "sub/kept.txt");
    defer allocator.free(cloned);
    try std.testing.expectEqualStrings("original\n", cloned);
}

test "a file the agent created is reported as added" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "new.txt", "brand new\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "new.txt").?);
}

test "a file the agent changed is reported as modified" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("changed.txt", "before\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "changed.txt", "after\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.modified, changeFor(report, "changed.txt").?);

    // The project's own copy is untouched: the clone is where the write went.
    const original = try readUnder(allocator, project.root_path, "changed.txt");
    defer allocator.free(original);
    try std.testing.expectEqualStrings("before\n", original);
}

test "a file the agent deleted is reported as deleted" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("gone.txt", "goodbye\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try deleteUnder(allocator, ov.upper, "gone.txt");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.deleted, changeFor(report, "gone.txt").?);
}

test "a file nobody touched is reported as unchanged, though clonefile copies its timestamps" {
    if (builtin.os.tag != .macos) return;
    // The case a timestamp comparison gets wrong. clonefile copies each file's
    // mtime from the original.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("untouched.txt", "same bytes\n");
    try project.makeDir("sub");
    try project.writeFile("sub/also-untouched.txt", "same bytes too\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    try writeUnder(allocator, ov.upper, "written.txt", "the only change\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "written.txt").?);
    try std.testing.expectEqual(@as(?ChangeKind, null), changeFor(report, "untouched.txt"));
    try std.testing.expectEqual(@as(?ChangeKind, null), changeFor(report, "sub/also-untouched.txt"));
}

test "a file changed and then changed back to its own bytes is reported as unchanged" {
    if (builtin.os.tag != .macos) return;
    // The one place this driver is stricter than linux/overlay.zig.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("round-trip.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "round-trip.txt", "different\n");
    try writeUnder(allocator, ov.upper, "round-trip.txt", "original\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.changed.len);
}

test "a file of the same length with different bytes is still reported as modified" {
    if (builtin.os.tag != .macos) return;
    // The size check is a shortcut for files of different lengths, never the
    // whole answer.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("same-length.txt", "aaaa\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "same-length.txt", "bbbb\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.modified, changeFor(report, "same-length.txt").?);
}

test "a whole project directory the agent removed is reported as one deletion" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeDir("olddir");
    try project.writeFile("olddir/inside.txt", "bye\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    const olddir = try std.fs.path.join(allocator, &.{ ov.upper, "olddir" });
    defer allocator.free(olddir);
    try std.Io.Dir.cwd().deleteTree(std.testing.io, olddir);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("olddir", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.deleted, report.changed[0].kind);
}

test "a new directory the agent made is not reported on its own, only the file inside it" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    const newdir = try std.fs.path.join(allocator, &.{ ov.upper, "newdir" });
    defer allocator.free(newdir);
    try std.Io.Dir.createDirAbsolute(std.testing.io, newdir, .default_dir);
    try writeUnder(allocator, ov.upper, "newdir/inside.txt", "hello\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "newdir/inside.txt").?);
}

test "a symbolic link the agent made is reported as added, and the project keeps none" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("target.txt", "pointed at\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    // A relative target, so the link means the same thing in the clone.
    var clone_dir = try std.Io.Dir.cwd().openDir(std.testing.io, ov.upper, .{});
    defer clone_dir.close(std.testing.io);
    try clone_dir.symLink(std.testing.io, "target.txt", "link", .{});

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "link").?);

    const project_link = try std.fs.path.join(allocator, &.{ project.root_path, "link" });
    defer allocator.free(project_link);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, project_link, .{ .follow_symlinks = false }),
    );
}

test "a symbolic link the agent repointed is modified, and one it left alone is not" {
    if (builtin.os.tag != .macos) return;
    // A link is compared by its own target, never by what the target holds.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("first.txt", "one\n");
    try project.writeFile("second.txt", "two\n");

    var project_dir = try std.Io.Dir.cwd().openDir(std.testing.io, project.root_path, .{});
    defer project_dir.close(std.testing.io);
    try project_dir.symLink(std.testing.io, "first.txt", "moved", .{});
    try project_dir.symLink(std.testing.io, "first.txt", "kept", .{});

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    var clone_dir = try std.Io.Dir.cwd().openDir(std.testing.io, ov.upper, .{});
    defer clone_dir.close(std.testing.io);
    try clone_dir.deleteFile(std.testing.io, "moved");
    try clone_dir.symLink(std.testing.io, "second.txt", "moved", .{});

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.modified, changeFor(report, "moved").?);
    try std.testing.expectEqual(@as(?ChangeKind, null), changeFor(report, "kept"));
}

test "a fifo the agent made is recorded as a skip, not silently dropped" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    const fifo_path = try std.fs.path.joinZ(allocator, &.{ ov.upper, "pipe1" });
    defer allocator.free(fifo_path);
    try std.testing.expectEqual(@as(c_int, 0), mkfifo(fifo_path.ptr, 0o600));

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.changed.len);
    try std.testing.expectEqual(@as(usize, 1), report.skipped.len);
    try std.testing.expectEqualStrings("pipe1", report.skipped[0].path);
}

test "create refuses a scratch directory that already holds a clone, and names the path" {
    if (builtin.os.tag != .macos) return;
    // clonefile refuses a destination that exists.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const stale = try std.fs.path.join(allocator, &.{ project.scratch_path, "upper" });
    defer allocator.free(stale);
    try std.Io.Dir.createDirAbsolute(std.testing.io, stale, .default_dir);

    try std.testing.expectError(
        error.ScratchAlreadyExists,
        create(allocator, std.testing.io, project.root_path, project.scratch_path, null),
    );
}

test "create refuses a scratch directory on another volume, and names the volume problem" {
    if (builtin.os.tag != .macos) return;
    // clonefile cannot clone across a volume. This needs a second writable
    // volume, so it is skipped where there is none.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const project_device = try deviceOf(allocator, project.root_path, null);

    const candidates = [_][]const u8{ "/nix", "/System/Volumes/VM", "/System/Volumes/Data" };
    var other_volume: ?[]const u8 = null;
    for (candidates) |candidate| {
        const device = deviceOf(allocator, candidate, null) catch continue;
        if (device != project_device) {
            other_volume = candidate;
            break;
        }
    }
    const scratch = other_volume orelse return error.SkipZigTest;

    try std.testing.expectError(
        error.ScratchOnAnotherVolume,
        create(allocator, std.testing.io, project.root_path, scratch, null),
    );
}

test "nestedMounts finds nothing under a project with no mounts of its own" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeDir("sub");
    try project.writeFile("sub/file.txt", "plain\n");

    const mounts = try nestedMounts(allocator, std.testing.io, project.root_path, null);
    defer iface.freeNestedMounts(allocator, mounts);
    try std.testing.expectEqual(@as(usize, 0), mounts.len);
}
