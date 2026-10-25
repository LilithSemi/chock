//! Durable workspace images for transcript forks.
//!
//! A checkpoint belongs to a `session.end` event. Git workspaces include the
//! visible checkout, the private object store, and the private HEAD/index, so
//! commits and staged changes survive a fork. Overlay workspaces are not yet
//! checkpointed: on Linux their upper directory is not a standalone tree.

const std = @import("std");

const Workspace = @import("Workspace.zig").Workspace;

pub const restore_leaf = "fork-restore";
const checkpoints_leaf = "checkpoints";
const tree_leaf = "tree";
const objects_leaf = "objects";
const meta_leaf = "meta";
const base_leaf = "base";

pub fn save(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: *const Workspace,
    work_dir: []const u8,
    event_id: u64,
) !bool {
    const wt = switch (workspace.kind) {
        .worktree => |*one| one,
        .overlay => return false,
    };

    const parent = try std.fs.path.join(allocator, &.{ work_dir, checkpoints_leaf });
    defer allocator.free(parent);
    try std.Io.Dir.cwd().createDirPath(io, parent);

    const name = try std.fmt.allocPrint(allocator, "{d}", .{event_id});
    defer allocator.free(name);
    const final = try std.fs.path.join(allocator, &.{ parent, name });
    defer allocator.free(final);
    const temporary = try std.fmt.allocPrint(allocator, "{s}.tmp", .{final});
    defer allocator.free(temporary);
    std.Io.Dir.cwd().deleteTree(io, temporary) catch {};
    errdefer std.Io.Dir.cwd().deleteTree(io, temporary) catch {};
    try std.Io.Dir.cwd().createDirPath(io, temporary);

    const tree = try std.fs.path.join(allocator, &.{ temporary, tree_leaf });
    defer allocator.free(tree);
    try copyTree(allocator, io, wt.path, tree, true);

    const objects = try std.fs.path.join(allocator, &.{ temporary, objects_leaf });
    defer allocator.free(objects);
    try copyTree(allocator, io, wt.object_store_source, objects, false);

    const meta = try std.fs.path.join(allocator, &.{ temporary, meta_leaf });
    defer allocator.free(meta);
    try std.Io.Dir.cwd().createDirPath(io, meta);
    const live_head = try std.fs.path.join(allocator, &.{ wt.worktree_meta_bind_source, "HEAD" });
    defer allocator.free(live_head);
    const saved_head = try std.fs.path.join(allocator, &.{ meta, "HEAD" });
    defer allocator.free(saved_head);
    try std.Io.Dir.copyFileAbsolute(live_head, saved_head, io, .{ .make_path = true });
    const live_index = try std.fs.path.join(allocator, &.{ wt.worktree_meta_bind_source, "index" });
    defer allocator.free(live_index);
    const saved_index = try std.fs.path.join(allocator, &.{ meta, "index" });
    defer allocator.free(saved_index);
    try std.Io.Dir.copyFileAbsolute(live_index, saved_index, io, .{ .make_path = true });

    const base = try std.fs.path.join(allocator, &.{ temporary, base_leaf });
    defer allocator.free(base);
    var base_file = try std.Io.Dir.createFileAbsolute(io, base, .{ .exclusive = true });
    defer base_file.close(io);
    try base_file.writeStreamingAll(io, wt.base_commit);
    try base_file.sync(io);

    std.Io.Dir.cwd().deleteTree(io, final) catch {};
    try std.Io.Dir.renameAbsolute(temporary, final, io);
    return true;
}

/// Give the child its own copy. The source session may be removed before the
/// child is next run, so a reference back to the source is not sufficient.
pub fn copyForFork(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_work: []const u8,
    child_work: []const u8,
    event_id: u64,
) !bool {
    const name = try std.fmt.allocPrint(allocator, "{d}", .{event_id});
    defer allocator.free(name);
    const source_root = try std.fs.path.join(allocator, &.{ source_work, checkpoints_leaf });
    defer allocator.free(source_root);
    const source = try std.fs.path.join(allocator, &.{ source_root, name });
    defer allocator.free(source);
    var source_dir = std.Io.Dir.openDirAbsolute(io, source, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    source_dir.close(io);

    // The copied log prefix still offers all of its earlier turn boundaries.
    // Keep their immutable workspace images with the child so a nested fork
    // remains self-contained even after the original session is removed.
    const inherited = try std.fs.path.join(allocator, &.{ child_work, checkpoints_leaf });
    defer allocator.free(inherited);
    const inherited_temporary = try std.fmt.allocPrint(allocator, "{s}.tmp", .{inherited});
    defer allocator.free(inherited_temporary);
    std.Io.Dir.cwd().deleteTree(io, inherited) catch {};
    std.Io.Dir.cwd().deleteTree(io, inherited_temporary) catch {};
    errdefer std.Io.Dir.cwd().deleteTree(io, inherited_temporary) catch {};
    try std.Io.Dir.cwd().createDirPath(io, inherited_temporary);
    var checkpoints = try std.Io.Dir.openDirAbsolute(io, source_root, .{ .iterate = true });
    defer checkpoints.close(io);
    var entries = checkpoints.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind != .directory) continue;
        const inherited_event = std.fmt.parseInt(u64, entry.name, 10) catch continue;
        if (inherited_event > event_id) continue;
        const from = try std.fs.path.join(allocator, &.{ source_root, entry.name });
        defer allocator.free(from);
        const to = try std.fs.path.join(allocator, &.{ inherited_temporary, entry.name });
        defer allocator.free(to);
        try copyTree(allocator, io, from, to, false);
    }
    try std.Io.Dir.renameAbsolute(inherited_temporary, inherited, io);

    const target = try std.fs.path.join(allocator, &.{ child_work, restore_leaf });
    defer allocator.free(target);
    const temporary = try std.fmt.allocPrint(allocator, "{s}.tmp", .{target});
    defer allocator.free(temporary);
    std.Io.Dir.cwd().deleteTree(io, target) catch {};
    std.Io.Dir.cwd().deleteTree(io, temporary) catch {};
    errdefer std.Io.Dir.cwd().deleteTree(io, temporary) catch {};
    const inherited_source = try std.fs.path.join(allocator, &.{ inherited, name });
    defer allocator.free(inherited_source);
    try copyTree(allocator, io, inherited_source, temporary, false);
    try std.Io.Dir.renameAbsolute(temporary, target, io);
    return true;
}

/// Restore into a newly-created worktree. Returns false when the session has
/// no checkpoint or when its backing is an overlay.
pub fn restore(
    allocator: std.mem.Allocator,
    io: std.Io,
    workspace: *Workspace,
    work_dir: []const u8,
) !bool {
    const wt = switch (workspace.kind) {
        .worktree => |*one| one,
        .overlay => return false,
    };
    const restore_root = try std.fs.path.join(allocator, &.{ work_dir, restore_leaf });
    defer allocator.free(restore_root);
    var restore_dir = std.Io.Dir.openDirAbsolute(io, restore_root, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    restore_dir.close(io);

    const base_path = try std.fs.path.join(allocator, &.{ restore_root, base_leaf });
    defer allocator.free(base_path);
    const base = try std.Io.Dir.readFileAlloc(.cwd(), io, base_path, allocator, .limited(256));
    defer allocator.free(base);
    if ((base.len != 40 and base.len != 64) or !allHex(base)) return error.InvalidCheckpoint;

    try clearTree(allocator, io, wt.path, true);
    const tree = try std.fs.path.join(allocator, &.{ restore_root, tree_leaf });
    defer allocator.free(tree);
    try copyTree(allocator, io, tree, wt.path, true);

    try clearTree(allocator, io, wt.object_store_source, false);
    const objects = try std.fs.path.join(allocator, &.{ restore_root, objects_leaf });
    defer allocator.free(objects);
    try copyTree(allocator, io, objects, wt.object_store_source, false);

    const saved_head = try std.fs.path.join(allocator, &.{ restore_root, meta_leaf, "HEAD" });
    defer allocator.free(saved_head);
    const live_head = try std.fs.path.join(allocator, &.{ wt.worktree_meta_bind_source, "HEAD" });
    defer allocator.free(live_head);
    try std.Io.Dir.copyFileAbsolute(saved_head, live_head, io, .{});
    const saved_index = try std.fs.path.join(allocator, &.{ restore_root, meta_leaf, "index" });
    defer allocator.free(saved_index);
    const live_index = try std.fs.path.join(allocator, &.{ wt.worktree_meta_bind_source, "index" });
    defer allocator.free(live_index);
    try std.Io.Dir.copyFileAbsolute(saved_index, live_index, io, .{});

    const owned_base = try allocator.dupe(u8, base);
    allocator.free(wt.base_commit);
    wt.base_commit = owned_base;
    return true;
}

pub fn discardRestore(allocator: std.mem.Allocator, io: std.Io, work_dir: []const u8) void {
    const path = std.fs.path.join(allocator, &.{ work_dir, restore_leaf }) catch return;
    defer allocator.free(path);
    std.Io.Dir.cwd().deleteTree(io, path) catch {};
}

fn allHex(bytes: []const u8) bool {
    for (bytes) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

fn clearTree(allocator: std.mem.Allocator, io: std.Io, path: []const u8, keep_dot_git: bool) !void {
    var dir = try std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true });
    defer dir.close(io);
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (keep_dot_git and std.mem.eql(u8, entry.name, ".git")) continue;
        const name = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(name);
        try names.append(allocator, name);
    }
    for (names.items) |name| try dir.deleteTree(io, name);
}

fn copyTree(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    destination: []const u8,
    skip_dot_git: bool,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, destination);
    var source_dir = try std.Io.Dir.openDirAbsolute(io, source, .{ .iterate = true });
    defer source_dir.close(io);
    var destination_dir = try std.Io.Dir.openDirAbsolute(io, destination, .{});
    defer destination_dir.close(io);
    var walker = try source_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (skip_dot_git and (std.mem.eql(u8, entry.path, ".git") or
            std.mem.startsWith(u8, entry.path, ".git/"))) continue;
        switch (entry.kind) {
            .directory => try destination_dir.createDirPath(io, entry.path),
            .file => try entry.dir.copyFile(entry.basename, destination_dir, entry.path, io, .{ .make_path = true }),
            .sym_link => {
                var target_buffer: [std.fs.max_path_bytes]u8 = undefined;
                const source_path = try std.fs.path.join(allocator, &.{ source, entry.path });
                defer allocator.free(source_path);
                const target_len = try std.Io.Dir.readLinkAbsolute(io, source_path, &target_buffer);
                const target_path = try std.fs.path.join(allocator, &.{ destination, entry.path });
                defer allocator.free(target_path);
                if (std.fs.path.dirname(target_path)) |parent| try std.Io.Dir.cwd().createDirPath(io, parent);
                try std.Io.Dir.cwd().symLink(io, target_buffer[0..target_len], target_path, .{});
            },
            else => return error.UnsupportedWorkspaceEntry,
        }
    }
}

const testing = std.testing;

test "workspace tree copy preserves links and omits the worktree pointer" {
    const allocator = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "source/empty");
    try tmp.dir.writeFile(io, .{ .sub_path = "source/file.txt", .data = "work\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/.git", .data = "gitdir: elsewhere\n" });
    try tmp.dir.symLink(io, "file.txt", "source/link", .{});

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &buffer);
    const source = try std.fs.path.join(allocator, &.{ buffer[0..root_len], "source" });
    defer allocator.free(source);
    const target = try std.fs.path.join(allocator, &.{ buffer[0..root_len], "target" });
    defer allocator.free(target);
    try copyTree(allocator, io, source, target, true);

    const copied = try std.fs.path.join(allocator, &.{ target, "file.txt" });
    defer allocator.free(copied);
    const contents = try std.Io.Dir.readFileAlloc(.cwd(), io, copied, allocator, .limited(32));
    defer allocator.free(contents);
    try testing.expectEqualStrings("work\n", contents);

    const dot_git = try std.fs.path.join(allocator, &.{ target, ".git" });
    defer allocator.free(dot_git);
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, dot_git, .{}));

    const link = try std.fs.path.join(allocator, &.{ target, "link" });
    defer allocator.free(link);
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = try std.Io.Dir.readLinkAbsolute(io, link, &link_buffer);
    try testing.expectEqualStrings("file.txt", link_buffer[0..link_len]);

    const empty = try std.fs.path.join(allocator, &.{ target, "empty" });
    defer allocator.free(empty);
    var empty_dir = try std.Io.Dir.openDirAbsolute(io, empty, .{});
    empty_dir.close(io);
}

test "a fork checkpoint restores the Git tree objects HEAD and index" {
    const allocator = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "source/tree");
    try tmp.dir.createDirPath(io, "source/objects/aa");
    try tmp.dir.createDirPath(io, "source/meta");
    try tmp.dir.createDirPath(io, "source-work");
    try tmp.dir.createDirPath(io, "child-work");
    try tmp.dir.writeFile(io, .{ .sub_path = "source/tree/file.txt", .data = "at the fork\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/tree/.git", .data = "source pointer\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/objects/aa/object", .data = "object" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/meta/HEAD", .data = "cccccccccccccccccccccccccccccccccccccccc\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "source/meta/index", .data = "index" });

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buffer);
    const root = root_buffer[0..root_len];
    const source_tree = try std.fs.path.join(allocator, &.{ root, "source/tree" });
    defer allocator.free(source_tree);
    const source_objects = try std.fs.path.join(allocator, &.{ root, "source/objects" });
    defer allocator.free(source_objects);
    const source_meta = try std.fs.path.join(allocator, &.{ root, "source/meta" });
    defer allocator.free(source_meta);
    const source_work = try std.fs.path.join(allocator, &.{ root, "source-work" });
    defer allocator.free(source_work);
    const child_work = try std.fs.path.join(allocator, &.{ root, "child-work" });
    defer allocator.free(child_work);

    const source_base = try allocator.dupe(u8, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    defer allocator.free(source_base);
    var source_wt: @import("worktree.zig").Worktree = undefined;
    source_wt.path = source_tree;
    source_wt.object_store_source = source_objects;
    source_wt.worktree_meta_bind_source = source_meta;
    source_wt.base_commit = source_base;
    const source = Workspace{
        .kind = .{ .worktree = source_wt },
        .chock_zon_source = null,
        .chock_zon_target = null,
        .deny_paths = &.{},
    };
    try testing.expect(try save(allocator, io, &source, source_work, 42));
    const earlier = try std.fs.path.join(allocator, &.{ source_work, checkpoints_leaf, "7" });
    defer allocator.free(earlier);
    try std.Io.Dir.cwd().createDirPath(io, earlier);
    const earlier_marker = try std.fs.path.join(allocator, &.{ earlier, "earlier" });
    defer allocator.free(earlier_marker);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = earlier_marker, .data = "kept" });
    const later = try std.fs.path.join(allocator, &.{ source_work, checkpoints_leaf, "99" });
    defer allocator.free(later);
    try std.Io.Dir.cwd().createDirPath(io, later);
    try testing.expect(try copyForFork(allocator, io, source_work, child_work, 42));
    const inherited_earlier = try std.fs.path.join(allocator, &.{ child_work, checkpoints_leaf, "7/earlier" });
    defer allocator.free(inherited_earlier);
    _ = try std.Io.Dir.cwd().statFile(io, inherited_earlier, .{});
    const excluded_later = try std.fs.path.join(allocator, &.{ child_work, checkpoints_leaf, "99" });
    defer allocator.free(excluded_later);
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, excluded_later, .{}));

    try tmp.dir.createDirPath(io, "child/tree");
    try tmp.dir.createDirPath(io, "child/objects");
    try tmp.dir.createDirPath(io, "child/meta");
    try tmp.dir.writeFile(io, .{ .sub_path = "child/tree/.git", .data = "child pointer\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "child/tree/stale", .data = "remove me" });
    try tmp.dir.writeFile(io, .{ .sub_path = "child/objects/stale", .data = "remove me" });
    try tmp.dir.writeFile(io, .{ .sub_path = "child/meta/HEAD", .data = "old head" });
    try tmp.dir.writeFile(io, .{ .sub_path = "child/meta/index", .data = "old index" });
    const child_tree = try std.fs.path.join(allocator, &.{ root, "child/tree" });
    defer allocator.free(child_tree);
    const child_objects = try std.fs.path.join(allocator, &.{ root, "child/objects" });
    defer allocator.free(child_objects);
    const child_meta = try std.fs.path.join(allocator, &.{ root, "child/meta" });
    defer allocator.free(child_meta);

    var child_wt: @import("worktree.zig").Worktree = undefined;
    child_wt.path = child_tree;
    child_wt.object_store_source = child_objects;
    child_wt.worktree_meta_bind_source = child_meta;
    child_wt.base_commit = try allocator.dupe(u8, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    var child = Workspace{
        .kind = .{ .worktree = child_wt },
        .chock_zon_source = null,
        .chock_zon_target = null,
        .deny_paths = &.{},
    };
    defer allocator.free(child.kind.worktree.base_commit);
    try testing.expect(try restore(allocator, io, &child, child_work));
    try testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", child.kind.worktree.base_commit);

    try expectFile(allocator, io, child_tree, "file.txt", "at the fork\n");
    try expectFile(allocator, io, child_tree, ".git", "child pointer\n");
    try expectFile(allocator, io, child_objects, "aa/object", "object");
    try expectFile(allocator, io, child_meta, "HEAD", "cccccccccccccccccccccccccccccccccccccccc\n");
    try expectFile(allocator, io, child_meta, "index", "index");
    const stale = try std.fs.path.join(allocator, &.{ child_tree, "stale" });
    defer allocator.free(stale);
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(io, stale, .{}));
}

fn expectFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    relative: []const u8,
    expected: []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    const bytes = try std.Io.Dir.readFileAlloc(.cwd(), io, path, allocator, .limited(256));
    defer allocator.free(bytes);
    try testing.expectEqualStrings(expected, bytes);
}
