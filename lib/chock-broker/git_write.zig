//! Writing git state: the index a commit is built from, the commit itself, and the
//! push that sends it. The agent reaches none of this directly. A tool call does.

const std = @import("std");
const ziggit = @import("ziggit");

/// The index a commit is built from. With no paths this is every change in the
/// worktree. With paths it is HEAD, with only the named paths taken from the
/// worktree, which is what `git add <paths>` writes.
pub fn commitIndex(
    gpa: std.mem.Allocator,
    io: std.Io,
    repo: *ziggit.Repository,
    head_tree: ?ziggit.Oid,
    paths: ?[]const []const u8,
) !ziggit.WorktreeIndex {
    const work_tree = repo.layout.work_tree orelse return error.IndexNotClean;
    const named = paths orelse
        return ziggit.stageWorktree(gpa, io, work_tree, &repo.odb, repo.format, .{});

    var base = ziggit.WorktreeIndex.open(gpa, io, repo.layout.git_dir, repo.format) catch |err| switch (err) {
        error.IndexNotFound => ziggit.WorktreeIndex{ .gpa = gpa, .entries = &.{} },
        else => |e| return e,
    };
    defer base.deinit();
    try refuseADirtyIndex(gpa, repo, base, head_tree);

    var work = try ziggit.stageWorktree(gpa, io, work_tree, &repo.odb, repo.format, .{});
    defer work.deinit();

    var entries: std.ArrayList(ziggit.IndexEntry) = .empty;
    errdefer {
        for (entries.items) |*one| one.deinit(gpa);
        entries.deinit(gpa);
    }
    // A named path that is gone from the worktree is a deletion, so it is simply
    // never copied across.
    for (base.entries) |one| {
        if (under(one.path, named)) continue;
        try entries.append(gpa, try dupeEntry(gpa, one));
    }
    for (work.entries) |one| {
        if (!under(one.path, named)) continue;
        try entries.append(gpa, try dupeEntry(gpa, one));
    }
    std.mem.sort(ziggit.IndexEntry, entries.items, {}, lessByPath);
    return .{ .gpa = gpa, .entries = try entries.toOwnedSlice(gpa) };
}

/// The agent edits through `write_file` and never runs `git add`, so an index that
/// disagrees with HEAD holds somebody else's staged work, and a commit of named paths
/// would carry it. Writing the tree is the comparison, which needs no entry by entry
/// walk and no tree reader, neither of which ziggit exposes.
fn refuseADirtyIndex(
    gpa: std.mem.Allocator,
    repo: *ziggit.Repository,
    base: ziggit.WorktreeIndex,
    head_tree: ?ziggit.Oid,
) !void {
    const expected = head_tree orelse {
        if (base.entries.len != 0) return error.IndexNotClean;
        return;
    };
    const written = ziggit.writeTreeFromIndex(gpa, &repo.odb, base, null) catch return error.IndexNotClean;
    if (!written.eql(expected)) return error.IndexNotClean;
}

/// What a commit object holds. Both dates are given, because the landing keeps the
/// author date of the commit it replays and takes the committer date from now.
pub const Commit = struct {
    tree: ziggit.Oid,
    parents: []const ziggit.Oid,
    message: []const u8,
    author: ziggit.Identity,
    committer: ziggit.Identity,
};

/// Writes the commit object and answers its id. The message gets the newline that
/// completes its last line, which is what `git commit-tree` writes and which the
/// object id covers.
pub fn writeCommit(gpa: std.mem.Allocator, repo: *ziggit.Repository, what: Commit) !ziggit.Oid {
    var payload: std.Io.Writer.Allocating = .init(gpa);
    defer payload.deinit();
    const object: ziggit.Commit = .{
        .tree = what.tree,
        .parents = what.parents,
        .author = what.author,
        .committer = what.committer,
        .extra_headers = &.{},
        .message = what.message,
    };
    try object.write(&payload.writer);
    if (!std.mem.endsWith(u8, what.message, "\n")) try payload.writer.writeAll("\n");
    return repo.odb.write(.commit, payload.written(), null);
}

/// A named path matches itself and, when it names a directory, everything beneath it.
fn under(path: []const u8, named: []const []const u8) bool {
    for (named) |one| {
        if (std.mem.eql(u8, path, one)) return true;
        if (path.len > one.len and path[one.len] == '/' and std.mem.startsWith(u8, path, one)) return true;
    }
    return false;
}

fn dupeEntry(gpa: std.mem.Allocator, one: ziggit.IndexEntry) std.mem.Allocator.Error!ziggit.IndexEntry {
    var copy = one;
    copy.path = try gpa.dupe(u8, one.path);
    return copy;
}

fn lessByPath(_: void, a: ziggit.IndexEntry, b: ziggit.IndexEntry) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

const testing = std.testing;
const chock_workspace = @import("chock-workspace");

const Scene = struct {
    gpa: std.mem.Allocator,
    root: [:0]const u8,
    env: std.process.Environ.Map,

    fn init(gpa: std.mem.Allocator, tmp: std.testing.TmpDir) !Scene {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        buffer[len] = 0;
        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root = try std.fmt.bufPrintSentinel(&root_buffer, "{s}/project", .{buffer[0..len]}, 0);
        try std.Io.Dir.createDirAbsolute(testing.io, root, .default_dir);

        var env = try std.testing.environ.createMap(gpa);
        errdefer env.deinit();
        try env.put("GIT_CEILING_DIRECTORIES", buffer[0..len]);

        var scene: Scene = .{ .gpa = gpa, .root = try gpa.dupeSentinel(u8, root, 0), .env = env };
        try scene.git(&.{ "init", "-b", "main" });
        try scene.git(&.{ "config", "user.email", "test@example.com" });
        try scene.git(&.{ "config", "user.name", "Test" });
        return scene;
    }

    fn deinit(self: *Scene) void {
        self.gpa.free(self.root);
        self.env.deinit();
    }

    fn git(self: *const Scene, argv: []const []const u8) !void {
        var out = try chock_workspace.git.run(self.gpa, testing.io, &self.env, self.root, argv, null);
        defer out.deinit(self.gpa);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, out.term);
    }

    fn gitOut(self: *const Scene, gpa: std.mem.Allocator, argv: []const []const u8) ![]u8 {
        var out = try chock_workspace.git.run(gpa, testing.io, &self.env, self.root, argv, null);
        defer out.deinit(gpa);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, out.term);
        return gpa.dupe(u8, std.mem.trimEnd(u8, out.stdout, "\n"));
    }

    fn write(self: *const Scene, gpa: std.mem.Allocator, name: []const u8, contents: []const u8) !void {
        const path = try std.fs.path.join(gpa, &.{ self.root, name });
        defer gpa.free(path);
        if (std.fs.path.dirname(path)) |dir| try std.Io.Dir.cwd().createDirPath(testing.io, dir);
        var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, contents);
    }

    fn remove(self: *const Scene, gpa: std.mem.Allocator, name: []const u8) !void {
        const path = try std.fs.path.join(gpa, &.{ self.root, name });
        defer gpa.free(path);
        try std.Io.Dir.deleteFileAbsolute(testing.io, path);
    }

    fn open(self: *const Scene, arena: std.mem.Allocator) !ziggit.Repository {
        var start = try std.Io.Dir.openDirAbsolute(testing.io, self.root, .{ .iterate = true });
        defer start.close(testing.io);
        const layout = try ziggit.discover(arena, testing.io, start, .{}, null);
        return ziggit.Repository.open(arena, testing.io, layout, .{}, null);
    }

    fn headTree(self: *const Scene, gpa: std.mem.Allocator, repo: *ziggit.Repository) !ziggit.Oid {
        const text = try self.gitOut(gpa, &.{ "rev-parse", "HEAD^{tree}" });
        defer gpa.free(text);
        return ziggit.Oid.parse(repo.format, text);
    }

    /// `git commit-tree` with the dates given, so a test can compare object ids.
    fn commitTree(
        self: *Scene,
        gpa: std.mem.Allocator,
        tree: []const u8,
        parents: []const []const u8,
        message: []const u8,
    ) ![]u8 {
        try self.env.put("GIT_AUTHOR_NAME", test_author.name);
        try self.env.put("GIT_AUTHOR_EMAIL", test_author.email);
        try self.env.put("GIT_AUTHOR_DATE", "1700000000 +0100");
        try self.env.put("GIT_COMMITTER_NAME", test_committer.name);
        try self.env.put("GIT_COMMITTER_EMAIL", test_committer.email);
        try self.env.put("GIT_COMMITTER_DATE", "1700000500 -0430");

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{ "commit-tree", tree });
        for (parents) |parent| try argv.appendSlice(gpa, &.{ "-p", parent });
        try argv.appendSlice(gpa, &.{ "-m", message });
        return self.gitOut(gpa, argv.items);
    }
};

/// `path<TAB>oid` for every blob in the tree the index writes, which is what the
/// caller actually wants to assert: which content each path ended up at.
fn treeText(gpa: std.mem.Allocator, scene: *const Scene, repo: *ziggit.Repository, index: ziggit.WorktreeIndex) ![]u8 {
    const oid = try ziggit.writeTreeFromIndex(gpa, &repo.odb, index, null);
    var buffer: [64]u8 = undefined;
    const hex = try std.fmt.bufPrint(&buffer, "{f}", .{oid});
    return scene.gitOut(gpa, &.{ "ls-tree", "-r", "--format=%(path) %(objectname)", hex });
}

fn setUp(scene: *const Scene, gpa: std.mem.Allocator) !void {
    try scene.write(gpa, "a.txt", "a one\n");
    try scene.write(gpa, "b.txt", "b one\n");
    try scene.write(gpa, "other.txt", "other one\n");
    try scene.write(gpa, "dir/one.txt", "one one\n");
    try scene.write(gpa, "dir/two.txt", "two one\n");
    // Three deep on purpose. writeTreeFromIndex wrote a zero oid for a parent of a
    // parent before ziggit 05e658b, and a one deep fixture would not have noticed.
    try scene.write(gpa, "deep/one/two/three.txt", "three one\n");
    try scene.git(&.{ "add", "-A" });
    try scene.git(&.{ "commit", "-m", "setup" });
}

test "a named path is taken from the worktree and every other path stays at HEAD" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);
    const before = try treeTextOfHead(arena, &scene);

    try scene.write(arena, "a.txt", "a two\n");
    try scene.write(arena, "b.txt", "b two\n");

    var repo = try scene.open(arena);
    defer repo.deinit();
    const head = try scene.headTree(arena, &repo);
    var index = try commitIndex(arena, testing.io, &repo, head, &.{"a.txt"});
    defer index.deinit();

    const after = try treeText(arena, &scene, &repo, index);
    try testing.expect(!sameLine(before, after, "a.txt"));
    try testing.expect(sameLine(before, after, "b.txt"));
}

test "a named directory takes everything beneath it and leaves a sibling alone" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);
    const before = try treeTextOfHead(arena, &scene);

    try scene.write(arena, "dir/one.txt", "one two\n");
    try scene.write(arena, "dir/two.txt", "two two\n");
    try scene.write(arena, "other.txt", "other two\n");

    var repo = try scene.open(arena);
    defer repo.deinit();
    const head = try scene.headTree(arena, &repo);
    var index = try commitIndex(arena, testing.io, &repo, head, &.{"dir"});
    defer index.deinit();

    const after = try treeText(arena, &scene, &repo, index);
    try testing.expect(!sameLine(before, after, "dir/one.txt"));
    try testing.expect(!sameLine(before, after, "dir/two.txt"));
    try testing.expect(sameLine(before, after, "other.txt"));
}

test "a path three directories deep is written with a readable tree" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);
    const before = try treeTextOfHead(arena, &scene);

    try scene.write(arena, "deep/one/two/three.txt", "three two\n");

    var repo = try scene.open(arena);
    defer repo.deinit();
    const head = try scene.headTree(arena, &repo);
    var index = try commitIndex(arena, testing.io, &repo, head, &.{"deep"});
    defer index.deinit();

    // ls-tree reading the result at all is half the assertion: a tree holding a zero
    // oid for a parent is one git refuses.
    const after = try treeText(arena, &scene, &repo, index);
    try testing.expect(!sameLine(before, after, "deep/one/two/three.txt"));
    try testing.expect(sameLine(before, after, "dir/one.txt"));
}

test "a deletion lands only when the path is named" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);

    try scene.remove(arena, "a.txt");
    try scene.remove(arena, "b.txt");

    var repo = try scene.open(arena);
    defer repo.deinit();
    const head = try scene.headTree(arena, &repo);
    var index = try commitIndex(arena, testing.io, &repo, head, &.{"a.txt"});
    defer index.deinit();

    const after = try treeText(arena, &scene, &repo, index);
    try testing.expect(std.mem.indexOf(u8, after, "a.txt") == null);
    try testing.expect(std.mem.indexOf(u8, after, "b.txt") != null);
}

test "no paths takes every change, an untracked file included" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);

    try scene.write(arena, "a.txt", "a two\n");
    try scene.write(arena, "fresh.txt", "brand new\n");

    var repo = try scene.open(arena);
    defer repo.deinit();
    const head = try scene.headTree(arena, &repo);
    var index = try commitIndex(arena, testing.io, &repo, head, null);
    defer index.deinit();

    const after = try treeText(arena, &scene, &repo, index);
    try testing.expect(std.mem.indexOf(u8, after, "fresh.txt") != null);
}

test "a staged change that is not HEAD refuses a commit of named paths" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);

    try scene.write(arena, "other.txt", "staged by someone else\n");
    try scene.git(&.{ "add", "other.txt" });
    try scene.write(arena, "a.txt", "a two\n");

    var repo = try scene.open(arena);
    defer repo.deinit();
    const head = try scene.headTree(arena, &repo);
    try testing.expectError(error.IndexNotClean, commitIndex(arena, testing.io, &repo, head, &.{"a.txt"}));
}

fn treeTextOfHead(gpa: std.mem.Allocator, scene: *const Scene) ![]u8 {
    return scene.gitOut(gpa, &.{ "ls-tree", "-r", "--format=%(path) %(objectname)", "HEAD" });
}

/// True when `path` carries the same object id in both listings.
fn sameLine(before: []const u8, after: []const u8, path: []const u8) bool {
    const one = lineFor(before, path) orelse return false;
    const two = lineFor(after, path) orelse return false;
    return std.mem.eql(u8, one, two);
}

fn lineFor(text: []const u8, path: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, path) and line.len > path.len and line[path.len] == ' ') return line;
    }
    return null;
}

const test_author: ziggit.Identity = .{
    .name = "Chock",
    .email = "chock@example.com",
    .when = 1700000000,
    .tz_offset_minutes = 60,
};

/// A different moment from the author's, and a negative offset that is not a whole
/// hour, because both halves of the offset are bytes the object id covers.
const test_committer: ziggit.Identity = .{
    .name = "Chock",
    .email = "chock@example.com",
    .when = 1700000500,
    .tz_offset_minutes = -270,
};

test "a commit of two parents has the object id git commit-tree gives it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);
    try scene.write(arena, "a.txt", "a two\n");
    try scene.git(&.{ "add", "-A" });
    try scene.git(&.{ "commit", "-m", "second" });

    const tree_hex = try scene.gitOut(arena, &.{ "rev-parse", "HEAD^{tree}" });
    const ours_hex = try scene.gitOut(arena, &.{ "rev-parse", "HEAD" });
    const theirs_hex = try scene.gitOut(arena, &.{ "rev-parse", "HEAD~1" });
    const message =
        "Merge chock/session\n\nThe work of one chock session, carried into main.\n\n" ++
        "Claimed-Author: A U Thor <author@example.com>\n";
    const expected_hex = try scene.commitTree(arena, tree_hex, &.{ ours_hex, theirs_hex }, message);

    var repo = try scene.open(arena);
    defer repo.deinit();
    const written = try writeCommit(arena, &repo, .{
        .tree = try ziggit.Oid.parse(repo.format, tree_hex),
        .parents = &.{
            try ziggit.Oid.parse(repo.format, ours_hex),
            try ziggit.Oid.parse(repo.format, theirs_hex),
        },
        .message = message,
        .author = test_author,
        .committer = test_committer,
    });

    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(expected_hex, try std.fmt.bufPrint(&buffer, "{f}", .{written}));
}

test "a message with no trailing newline gets the one git would add" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var scene = try Scene.init(testing.allocator, tmp);
    defer scene.deinit();
    try setUp(&scene, arena);

    const tree_hex = try scene.gitOut(arena, &.{ "rev-parse", "HEAD^{tree}" });
    const parent_hex = try scene.gitOut(arena, &.{ "rev-parse", "HEAD" });
    // The replay landing trims its body, so this is the shape it writes.
    const message = "one replayed commit";
    const expected_hex = try scene.commitTree(arena, tree_hex, &.{parent_hex}, message);

    var repo = try scene.open(arena);
    defer repo.deinit();
    const written = try writeCommit(arena, &repo, .{
        .tree = try ziggit.Oid.parse(repo.format, tree_hex),
        .parents = &.{try ziggit.Oid.parse(repo.format, parent_hex)},
        .message = message,
        .author = test_author,
        .committer = test_committer,
    });

    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(expected_hex, try std.fmt.bufPrint(&buffer, "{f}", .{written}));
}
