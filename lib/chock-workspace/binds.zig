//! Brings the paths the `workspace` block names into the workspace: a mount
//! for the two modes that bind, and a copy for the two that copy. The block
//! itself is read by `chock-policy`, and every path here is already resolved.

const std = @import("std");

const policy = @import("chock-policy");
const sandbox = @import("chock-sandbox");
const worktree_mod = @import("worktree.zig");

pub const Mount = sandbox.namespace.Mount;
pub const Resolved = policy.workspace.Resolved;
pub const Mode = policy.workspace.Mode;
pub const Report = worktree_mod.ImportReport;

pub const Error = worktree_mod.Error;

/// One bind, with the path the sandbox sees it at. The strings belong to this value.
pub const Attached = struct {
    bind: Resolved,
    /// Under the sandbox root and the work directory, at the same relative path.
    target: []u8,
    work_path: []u8,

    pub fn deinit(self: *Attached, gpa: std.mem.Allocator) void {
        self.bind.deinit(gpa);
        gpa.free(self.target);
        gpa.free(self.work_path);
        self.* = undefined;
    }
};

pub fn free(gpa: std.mem.Allocator, list: []Attached) void {
    for (list) |*one| one.deinit(gpa);
    gpa.free(list);
}

/// `copy_in` is false for a workspace another session already filled, so
/// copying again does not overwrite its agent's work.
pub fn attach(
    gpa: std.mem.Allocator,
    io: std.Io,
    work_dir: []const u8,
    sandbox_root: []const u8,
    resolved: []const Resolved,
    copy_in: bool,
    report: *Report,
) Error![]Attached {
    var out: std.ArrayList(Attached) = .empty;
    errdefer {
        for (out.items) |*one| one.deinit(gpa);
        out.deinit(gpa);
    }

    for (resolved) |one| {
        var attached = Attached{
            .bind = .{
                .name = try gpa.dupe(u8, one.name),
                .relative = try gpa.dupe(u8, one.relative),
                .host_path = try gpa.dupe(u8, one.host_path),
                .mode = one.mode,
                .is_directory = one.is_directory,
                .read_only = one.read_only,
                .write_back = one.write_back,
            },
            .target = try std.fs.path.join(gpa, &.{ sandbox_root, one.relative }),
            .work_path = try std.fs.path.join(gpa, &.{ work_dir, one.relative }),
        };
        errdefer attached.deinit(gpa);

        switch (one.mode) {
            .read_only, .write => {},
            .copy, .temp_copy => if (copy_in) try copyIn(gpa, io, attached, report),
        }
        try out.append(gpa, attached);
    }

    return out.toOwnedSlice(gpa);
}

/// `read_only` relies on the kernel's own refusal to write.
pub fn appendMounts(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(Mount),
    attached: []const Attached,
) std.mem.Allocator.Error!void {
    for (attached) |one| {
        switch (one.bind.mode) {
            .copy, .temp_copy => continue,
            .read_only, .write => try list.append(gpa, .{ .bind = .{
                .source = one.bind.host_path,
                .target = one.target,
                .read_only = one.bind.read_only,
            } }),
        }
    }
}

pub const WriteBack = struct {
    files: usize = 0,
    binds: usize = 0,
};

/// Never removes a file, so a file the agent deleted stays on the user's disk.
pub fn writeBack(
    gpa: std.mem.Allocator,
    io: std.Io,
    attached: []const Attached,
    report: *Report,
) Error!WriteBack {
    var done = WriteBack{};
    for (attached) |one| {
        if (one.bind.mode != .copy or !one.bind.write_back) continue;
        const before = report.total();
        try copyOut(gpa, io, one, report);
        done.files += report.total() - before;
        done.binds += 1;
    }
    return done;
}

fn copyIn(gpa: std.mem.Allocator, io: std.Io, one: Attached, report: *Report) Error!void {
    if (!one.bind.is_directory) {
        return worktree_mod.Worktree.copyRegularFile(
            gpa,
            io,
            one.bind.relative,
            one.bind.host_path,
            one.work_path,
            true,
            report,
        );
    }
    return copyTree(gpa, io, one.bind.host_path, one.work_path, one.bind.relative, report);
}

fn copyOut(gpa: std.mem.Allocator, io: std.Io, one: Attached, report: *Report) Error!void {
    if (!one.bind.is_directory) {
        return worktree_mod.Worktree.copyRegularFile(
            gpa,
            io,
            one.bind.relative,
            one.work_path,
            one.bind.host_path,
            false,
            report,
        );
    }
    return copyTree(gpa, io, one.work_path, one.bind.host_path, one.bind.relative, report);
}

/// A directory this cannot open is one skip, not a failed session.
fn copyTree(
    gpa: std.mem.Allocator,
    io: std.Io,
    from: []const u8,
    to: []const u8,
    named: []const u8,
    report: *Report,
) Error!void {
    var dir = std.Io.Dir.openDirAbsolute(io, from, .{ .iterate = true }) catch |err| {
        const reason = try std.fmt.allocPrint(gpa, "opening {s} failed: {t}", .{ from, err });
        return worktree_mod.Worktree.recordSkip(report, gpa, named, reason);
    };
    defer dir.close(io);

    std.Io.Dir.cwd().createDirPath(io, to) catch |err| {
        const reason = try std.fmt.allocPrint(gpa, "making {s} failed: {t}", .{ to, err });
        return worktree_mod.Worktree.recordSkip(report, gpa, named, reason);
    };

    var walker = dir.walk(gpa) catch |err| {
        const reason = try std.fmt.allocPrint(gpa, "reading {s} failed: {t}", .{ from, err });
        return worktree_mod.Worktree.recordSkip(report, gpa, named, reason);
    };
    defer walker.deinit();

    // A walk that fails must be reported, not read as the end of the tree.
    while (true) {
        const next = walker.next(io) catch |err| {
            const reason = try std.fmt.allocPrint(
                gpa,
                "reading {s} stopped partway: {t}. What was copied before this is incomplete.",
                .{ from, err },
            );
            return worktree_mod.Worktree.recordSkip(report, gpa, named, reason);
        };
        const entry = next orelse break;
        const shown = try std.fs.path.join(gpa, &.{ named, entry.path });
        defer gpa.free(shown);
        const source = try std.fs.path.join(gpa, &.{ from, entry.path });
        defer gpa.free(source);
        const target = try std.fs.path.join(gpa, &.{ to, entry.path });
        defer gpa.free(target);

        switch (entry.kind) {
            .directory => std.Io.Dir.cwd().createDirPath(io, target) catch |err| {
                const reason = try std.fmt.allocPrint(gpa, "making {s} failed: {t}", .{ target, err });
                try worktree_mod.Worktree.recordSkip(report, gpa, shown, reason);
            },
            .file => try worktree_mod.Worktree.copyRegularFile(gpa, io, shown, source, target, true, report),
            .sym_link => try worktree_mod.Worktree.recreateSymlink(gpa, io, shown, source, target, true, report),
            else => |kind| {
                const reason = try std.fmt.allocPrint(
                    gpa,
                    "not a regular file, a link or a directory, and not carried across (it is a {t})",
                    .{kind},
                );
                try worktree_mod.Worktree.recordSkip(report, gpa, shown, reason);
            },
        }
    }
}

const testing = std.testing;

fn realPathOf(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const length = try dir.realPath(testing.io, buffer);
    return buffer[0..length];
}

test "a read_only bind and a write bind become one mount each, and the copies become none" {
    const gpa = testing.allocator;

    const attached = [_]Attached{
        .{
            .bind = .{
                .name = "config.local.*",
                .relative = "config.local.json",
                .host_path = "/p/config.local.json",
                .mode = .read_only,
                .is_directory = false,
            },
            .target = @constCast("/w/config.local.json"),
            .work_path = @constCast("/s/config.local.json"),
        },
        .{
            .bind = .{
                .name = "out",
                .relative = "out",
                .host_path = "/p/out",
                .mode = .write,
                .is_directory = true,
                .read_only = false,
            },
            .target = @constCast("/w/out"),
            .work_path = @constCast("/s/out"),
        },
        .{
            .bind = .{
                .name = "scripts/release",
                .relative = "scripts/release",
                .host_path = "/p/scripts/release",
                .mode = .copy,
                .is_directory = true,
            },
            .target = @constCast("/w/scripts/release"),
            .work_path = @constCast("/s/scripts/release"),
        },
    };

    var list: std.ArrayList(Mount) = .empty;
    defer list.deinit(gpa);
    try appendMounts(gpa, &list, &attached);

    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expectEqualStrings("/p/config.local.json", list.items[0].bind.source);
    try testing.expectEqualStrings("/w/config.local.json", list.items[0].bind.target);
    try testing.expect(list.items[0].bind.read_only);
    try testing.expectEqualStrings("/w/out", list.items[1].bind.target);
    try testing.expect(!list.items[1].bind.read_only);
}

test "a copy bind lands in the workspace, and a temp_copy does too" {
    const gpa = testing.allocator;

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var work = testing.tmpDir(.{});
    defer work.cleanup();

    try project.dir.createDirPath(testing.io, "scripts/release");
    {
        var file = try project.dir.createFile(testing.io, "scripts/release/run.sh", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "echo hello\n");
    }
    {
        var file = try project.dir.createFile(testing.io, "generated.conf", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "a=1\n");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try realPathOf(&project_buffer, project.dir);
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const work_root = try realPathOf(&work_buffer, work.dir);

    const tree = try std.fs.path.join(gpa, &.{ project_root, "scripts/release" });
    defer gpa.free(tree);
    const one_file = try std.fs.path.join(gpa, &.{ project_root, "generated.conf" });
    defer gpa.free(one_file);

    const resolved = [_]Resolved{
        .{
            .name = "scripts/release",
            .relative = "scripts/release",
            .host_path = tree,
            .mode = .copy,
            .is_directory = true,
            .write_back = true,
        },
        .{
            .name = "generated.conf",
            .relative = "generated.conf",
            .host_path = one_file,
            .mode = .temp_copy,
            .is_directory = false,
        },
    };

    var report = Report{};
    defer report.deinit(gpa);
    const attached = try attach(gpa, testing.io, work_root, "/project", &resolved, true, &report);
    defer free(gpa, attached);

    try testing.expectEqual(@as(usize, 0), report.skipped.items.len);
    try testing.expectEqualStrings("/project/scripts/release", attached[0].target);

    const copied = try work.dir.readFileAlloc(testing.io, "scripts/release/run.sh", gpa, .limited(64));
    defer gpa.free(copied);
    try testing.expectEqualStrings("echo hello\n", copied);

    const temp = try work.dir.readFileAlloc(testing.io, "generated.conf", gpa, .limited(64));
    defer gpa.free(temp);
    try testing.expectEqualStrings("a=1\n", temp);

    var list: std.ArrayList(Mount) = .empty;
    defer list.deinit(gpa);
    try appendMounts(gpa, &list, attached);
    try testing.expectEqual(@as(usize, 0), list.items.len);
}

test "a copy is written back and a temp_copy is not" {
    const gpa = testing.allocator;

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var work = testing.tmpDir(.{});
    defer work.cleanup();

    try project.dir.createDirPath(testing.io, "scripts/release");
    {
        var file = try project.dir.createFile(testing.io, "scripts/release/run.sh", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "echo hello\n");
    }
    {
        var file = try project.dir.createFile(testing.io, "generated.conf", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "a=1\n");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try realPathOf(&project_buffer, project.dir);
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const work_root = try realPathOf(&work_buffer, work.dir);

    const tree = try std.fs.path.join(gpa, &.{ project_root, "scripts/release" });
    defer gpa.free(tree);
    const one_file = try std.fs.path.join(gpa, &.{ project_root, "generated.conf" });
    defer gpa.free(one_file);

    const resolved = [_]Resolved{
        .{
            .name = "scripts/release",
            .relative = "scripts/release",
            .host_path = tree,
            .mode = .copy,
            .is_directory = true,
            .write_back = true,
        },
        .{
            .name = "generated.conf",
            .relative = "generated.conf",
            .host_path = one_file,
            .mode = .temp_copy,
            .is_directory = false,
        },
    };

    var report = Report{};
    defer report.deinit(gpa);
    const attached = try attach(gpa, testing.io, work_root, "/project", &resolved, true, &report);
    defer free(gpa, attached);

    {
        var file = try work.dir.createFile(testing.io, "scripts/release/run.sh", .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "echo changed\n");
    }
    {
        var file = try work.dir.createFile(testing.io, "generated.conf", .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "a=2\n");
    }

    var back_report = Report{};
    defer back_report.deinit(gpa);
    const done = try writeBack(gpa, testing.io, attached, &back_report);
    try testing.expectEqual(@as(usize, 1), done.binds);

    const landed = try project.dir.readFileAlloc(testing.io, "scripts/release/run.sh", gpa, .limited(64));
    defer gpa.free(landed);
    try testing.expectEqualStrings("echo changed\n", landed);

    const untouched = try project.dir.readFileAlloc(testing.io, "generated.conf", gpa, .limited(64));
    defer gpa.free(untouched);
    try testing.expectEqualStrings("a=1\n", untouched);
}

test "a copy the caller did not permit is left in the workspace" {
    const gpa = testing.allocator;

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var work = testing.tmpDir(.{});
    defer work.cleanup();

    {
        var file = try project.dir.createFile(testing.io, "generated.conf", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "a=1\n");
    }

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try realPathOf(&project_buffer, project.dir);
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const work_root = try realPathOf(&work_buffer, work.dir);

    const one_file = try std.fs.path.join(gpa, &.{ project_root, "generated.conf" });
    defer gpa.free(one_file);

    const resolved = [_]Resolved{.{
        .name = "generated.conf",
        .relative = "generated.conf",
        .host_path = one_file,
        .mode = .copy,
        .is_directory = false,
        .write_back = false,
    }};

    var report = Report{};
    defer report.deinit(gpa);
    const attached = try attach(gpa, testing.io, work_root, "/project", &resolved, true, &report);
    defer free(gpa, attached);

    {
        var file = try work.dir.createFile(testing.io, "generated.conf", .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "a=2\n");
    }

    var back_report = Report{};
    defer back_report.deinit(gpa);
    const done = try writeBack(gpa, testing.io, attached, &back_report);
    try testing.expectEqual(@as(usize, 0), done.binds);

    const untouched = try project.dir.readFileAlloc(testing.io, "generated.conf", gpa, .limited(64));
    defer gpa.free(untouched);
    try testing.expectEqualStrings("a=1\n", untouched);

    const kept = try work.dir.readFileAlloc(testing.io, "generated.conf", gpa, .limited(64));
    defer gpa.free(kept);
    try testing.expectEqualStrings("a=2\n", kept);
}

test "a copy that stops partway says so, and does not report an incomplete tree as done" {
    const gpa = testing.allocator;

    var project = testing.tmpDir(.{});
    defer project.cleanup();
    var work = testing.tmpDir(.{});
    defer work.cleanup();

    try project.dir.createDirPath(testing.io, "tree/readable");
    {
        var file = try project.dir.createFile(testing.io, "tree/readable/kept.txt", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "this one is fine\n");
    }
    try project.dir.createDirPath(testing.io, "tree/closed");
    {
        var file = try project.dir.createFile(testing.io, "tree/closed/hidden.txt", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "unreachable\n");
    }
    // `iterate` is required: without it Linux opens with O_PATH, and fchmod
    // on that descriptor answers EBADF, which panics in a debug build.
    var closed = try project.dir.openDir(testing.io, "tree/closed", .{ .iterate = true });
    defer closed.close(testing.io);
    closed.setPermissions(testing.io, .fromMode(0o000)) catch return error.SkipZigTest;
    defer closed.setPermissions(testing.io, .fromMode(0o755)) catch {};

    if (project.dir.openDir(testing.io, "tree/closed", .{ .iterate = true })) |*open| {
        @constCast(open).close(testing.io);
        return error.SkipZigTest;
    } else |_| {}

    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try realPathOf(&project_buffer, project.dir);
    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const work_root = try realPathOf(&work_buffer, work.dir);

    const tree = try std.fs.path.join(gpa, &.{ project_root, "tree" });
    defer gpa.free(tree);

    const resolved = [_]Resolved{.{
        .name = "tree",
        .relative = "tree",
        .host_path = tree,
        .mode = .temp_copy,
        .is_directory = true,
    }};

    var report = Report{};
    defer report.deinit(gpa);
    const attached = try attach(gpa, testing.io, work_root, "/project", &resolved, true, &report);
    defer {
        for (attached) |*one| @constCast(one).deinit(gpa);
        gpa.free(attached);
    }

    try testing.expect(report.skipped.items.len > 0);

    var said_partway = false;
    for (report.skipped.items) |one| {
        if (std.mem.indexOf(u8, one.reason, "stopped partway") != null) said_partway = true;
        if (std.mem.indexOf(u8, one.reason, "incomplete") != null) said_partway = true;
    }
    try testing.expect(said_partway);
}
