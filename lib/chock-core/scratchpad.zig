//! The session scratchpad: a working directory for files that are not the
//! project, and the read only directory beside it where background task
//! output lands.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
pub const Sink = diagnostic.Sink;
pub const sinkOf = diagnostic.sinkOf;
const cache = @import("cache.zig");

pub const sandbox_dir = "/run/chock/scratch";

pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

// A tmpfs mounted for one tool call; no host directory answers to this path.
pub const tmp_sandbox_dir = "/run/chock/tmp";

pub const scratch_leaf = "scratch";
pub const tasks_leaf = "tasks";
pub const agents_leaf = "agents";
pub const stage_leaf = "stage";

pub fn stageDir(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, stage_leaf });
}

pub const TempArea = enum {
    capped,
    scratchpad,
};

pub fn tempAreaFor(limits: sandbox.Sandbox.Limits) TempArea {
    if (!sandbox.expresses.scratch_area) return .scratchpad;
    return if (limits.scratchFitsUnderMemory()) .capped else .scratchpad;
}

pub const variable_names = [_][]const u8{ "TMPDIR", "CHOCK_SCRATCHPAD" };

pub const dropped_variable_names = [_][]const u8{ "TMP", "TEMP", "TEMPDIR", "NIX_BUILD_TOP" };

pub fn tempDirFor(area: TempArea, dir: []const u8) []const u8 {
    return switch (area) {
        .capped => tmp_sandbox_dir,
        .scratchpad => dir,
    };
}

pub const max_bytes: u64 = 512 * 1024 * 1024;

pub const Size = cache.Size;

pub const Verdict = enum {
    keep,
    empty,
};

pub fn verdictFor(size: Size) Verdict {
    return if (size.bytes > max_bytes) .empty else .keep;
}

pub const Agent = union(enum) {
    main,
    child: []const u8,
};

pub fn mayRead(viewer: Agent, owner: Agent) bool {
    return switch (viewer) {
        .main => true,
        .child => |viewer_id| switch (owner) {
            .main => false,
            .child => |owner_id| std.mem.eql(u8, viewer_id, owner_id),
        },
    };
}

pub const LeafError = error{
    BadChildId,
};

pub fn leafFor(
    allocator: std.mem.Allocator,
    agent: Agent,
) (std.mem.Allocator.Error || LeafError)![]u8 {
    return switch (agent) {
        .main => allocator.dupe(u8, scratch_leaf),
        .child => |id| {
            if (!isPlainName(id)) return error.BadChildId;
            return std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ agents_leaf, id, scratch_leaf });
        },
    };
}

fn isPlainName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |character| {
        const ok = std.ascii.isAlphanumeric(character) or character == '-' or character == '_';
        if (!ok) return false;
    }
    return true;
}

pub fn environment(
    allocator: std.mem.Allocator,
    base: []const []const u8,
    area: TempArea,
    dir: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (entries.items) |entry| allocator.free(entry);
        entries.deinit(allocator);
    }

    for (base) |entry| {
        if (namesAScratchVariable(entry)) continue;
        try entries.append(allocator, try allocator.dupe(u8, entry));
    }
    try entries.append(allocator, try std.fmt.allocPrint(
        allocator,
        "TMPDIR={s}",
        .{tempDirFor(area, dir)},
    ));
    try entries.append(allocator, try std.fmt.allocPrint(allocator, "CHOCK_SCRATCHPAD={s}", .{dir}));
    return entries.toOwnedSlice(allocator);
}

pub const freeEnvironment = cache.freeEnvironment;

fn namesAScratchVariable(entry: []const u8) bool {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return false;
    const key = entry[0..equals];
    for (variable_names ++ dropped_variable_names) |name| {
        if (std.mem.eql(u8, key, name)) return true;
    }
    return false;
}

pub const LayoutError = error{
    ScratchpadDirectoryUnwritable,
};

pub fn makeLayout(io: std.Io, dir_path: []const u8, diag: ?Sink) LayoutError!void {
    try makeDirAll(io, dir_path, diag);
    inline for (.{ scratch_leaf, tasks_leaf, agents_leaf, stage_leaf }) |leaf| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, leaf }) catch
            return error.ScratchpadDirectoryUnwritable;
        try makeDirAll(io, path, diag);
    }
}

pub fn exists(io: std.Io, dir_path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{}) catch return false;
    dir.close(io);
    return true;
}

pub fn measureScratch(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    stop_at: u64,
) Size {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, scratch_leaf }) catch return .{};
    return cache.measure(allocator, io, path, stop_at);
}

pub fn clearScratch(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    diag: ?Sink,
) LayoutError!Size {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, scratch_leaf }) catch
        return error.ScratchpadDirectoryUnwritable;

    const went = cache.measure(allocator, io, path, std.math.maxInt(u64));

    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch return went;
    {
        defer dir.close(io);

        // List names first; deleting while iterating a directory is undefined on some filesystems.
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| allocator.free(name);
            names.deinit(allocator);
        }

        var it = dir.iterate();
        while (it.next(io) catch null) |entry| {
            const owned = allocator.dupe(u8, entry.name) catch continue;
            names.append(allocator, owned) catch {
                allocator.free(owned);
                continue;
            };
        }
        for (names.items) |name| dir.deleteTree(io, name) catch continue;
    }

    try makeDirAll(io, path, diag);
    return went;
}

pub fn remove(io: std.Io, dir_path: []const u8) void {
    var parent_dir = std.Io.Dir.openDirAbsolute(io, std.fs.path.dirname(dir_path) orelse return, .{}) catch return;
    defer parent_dir.close(io);
    parent_dir.deleteTree(io, std.fs.path.basename(dir_path)) catch {};
}

fn makeDirAll(io: std.Io, path: []const u8, diag: ?Sink) LayoutError!void {
    makeDirAllInner(io, path) catch |err| {
        diagnostic.notePath(diag, .scratchpad_directory_not_made, path, err);
        return error.ScratchpadDirectoryUnwritable;
    };
}

fn makeDirAllInner(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAllInner(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

const testing = std.testing;
const tasks = @import("tasks.zig");

test "the scratchpad environment points TMPDIR at a path the sandbox mounts" {
    const allocator = testing.allocator;

    const built = try environment(allocator, &.{}, .capped, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 2), built.len);
    try testing.expectEqualStrings("TMPDIR=/run/chock/tmp", built[0]);
    try testing.expectEqualStrings("CHOCK_SCRATCHPAD=/run/chock/scratch", built[1]);
}

test "a scratchpad appears under the runtime prefix, or at its own path where no path can move" {
    const allocator = testing.allocator;
    const host_dir = "/somewhere/on/the/host/scratch";

    if (sandbox.expresses.moved_paths) {
        try testing.expectEqualStrings(sandbox_dir, sandboxDirFor(host_dir));
    } else {
        try testing.expectEqualStrings(host_dir, sandboxDirFor(host_dir));
    }

    const inside = sandboxDirFor(host_dir);
    const built = try environment(allocator, &.{}, .scratchpad, inside);
    defer freeEnvironment(allocator, built);

    var expected: [256]u8 = undefined;
    try testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected, "TMPDIR={s}", .{inside}),
        built[0],
    );
    var expected_note: [256]u8 = undefined;
    try testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected_note, "CHOCK_SCRATCHPAD={s}", .{inside}),
        built[1],
    );
}

test "a build with no cap mechanism asks for no capped area, and says so rather than pretending" {
    if (!sandbox.expresses.scratch_area) {
        try testing.expectEqual(TempArea.scratchpad, tempAreaFor(.{}));
        try testing.expectEqual(
            TempArea.scratchpad,
            tempAreaFor((sandbox.Sandbox.Limits{}).narrow(.{})),
        );
        try testing.expectEqualStrings("/a/host/scratch", tempDirFor(.scratchpad, "/a/host/scratch"));
    } else {
        try testing.expectEqual(TempArea.capped, tempAreaFor(.{}));
        try testing.expectEqualStrings(tmp_sandbox_dir, tempDirFor(.capped, "/a/host/scratch"));
    }
}

test "TMPDIR names the capped area and CHOCK_SCRATCHPAD names the notes, and they are two paths" {
    try testing.expect(!std.mem.eql(u8, sandbox_dir, tmp_sandbox_dir));
    try testing.expect(!std.mem.startsWith(u8, tmp_sandbox_dir, sandbox_dir ++ "/"));
    try testing.expect(!std.mem.startsWith(u8, sandbox_dir, tmp_sandbox_dir ++ "/"));
    try testing.expect(std.mem.startsWith(u8, tmp_sandbox_dir, "/run/chock/"));

    try testing.expect(!std.mem.eql(u8, tmp_sandbox_dir, tasks.sandbox_dir));
    try testing.expect(!std.mem.startsWith(u8, tasks.sandbox_dir, tmp_sandbox_dir ++ "/"));
}

test "a call whose limits cannot carry a cap keeps TMPDIR on the scratchpad" {
    const allocator = testing.allocator;

    if (sandbox.expresses.scratch_area) {
        try testing.expectEqual(TempArea.capped, tempAreaFor(.{}));
        try testing.expectEqual(
            TempArea.scratchpad,
            tempAreaFor((sandbox.Sandbox.Limits{}).narrow(.{ .memory_bytes = 1 << 20 })),
        );
    }

    const built = try environment(allocator, &.{}, .scratchpad, sandbox_dir);
    defer freeEnvironment(allocator, built);
    try testing.expectEqual(@as(usize, 2), built.len);
    try testing.expectEqualStrings("TMPDIR=" ++ sandbox_dir, built[0]);
    try testing.expectEqualStrings("CHOCK_SCRATCHPAD=" ++ sandbox_dir, built[1]);
}

test "a TMPDIR the dev shell states is replaced and never left beside Chock's own" {
    const allocator = testing.allocator;

    const base = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/run/chock/git/objects",
        "TMPDIR=/tmp/nix-shell.qHnEsN",
        "KEEP=me",
        "CHOCK_SCRATCHPAD=/tmp/somewhere-else",
    };
    const built = try environment(allocator, &base, .capped, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 4), built.len);
    try testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try testing.expectEqualStrings("KEEP=me", built[1]);
    try testing.expectEqualStrings("TMPDIR=" ++ tmp_sandbox_dir, built[2]);
    try testing.expectEqualStrings("CHOCK_SCRATCHPAD=" ++ sandbox_dir, built[3]);

    for (variable_names) |name| {
        var seen: usize = 0;
        for (built) |entry| {
            const equals = std.mem.indexOfScalar(u8, entry, '=').?;
            if (std.mem.eql(u8, entry[0..equals], name)) seen += 1;
        }
        try testing.expectEqual(@as(usize, 1), seen);
    }
}

test "the other four names a dev shell exports for a temporary directory reach no tool call" {
    const allocator = testing.allocator;

    const base = [_][]const u8{
        "TMP=/tmp/nix-shell.qHnEsN",
        "TEMP=/tmp/nix-shell.qHnEsN",
        "TEMPDIR=/tmp/nix-shell.qHnEsN",
        "NIX_BUILD_TOP=/tmp/nix-shell.qHnEsN",
        "KEEP=me",
    };
    const built = try environment(allocator, &base, .capped, sandbox_dir);
    defer freeEnvironment(allocator, built);

    for (built) |entry| {
        const equals = std.mem.indexOfScalar(u8, entry, '=').?;
        for (dropped_variable_names) |name| {
            try testing.expect(!std.mem.eql(u8, entry[0..equals], name));
        }
    }
    try testing.expectEqual(@as(usize, 3), built.len);
    try testing.expectEqualStrings("KEEP=me", built[0]);
}

test "the scratchpad and the task directory are siblings, both inside Chock's own runtime prefix" {
    try testing.expect(std.mem.startsWith(u8, sandbox_dir, "/run/chock/"));
    try testing.expect(std.mem.startsWith(u8, tasks.sandbox_dir, "/run/chock/"));
    try testing.expect(!std.mem.startsWith(u8, tasks.sandbox_dir, sandbox_dir ++ "/"));
    try testing.expect(!std.mem.startsWith(u8, sandbox_dir, tasks.sandbox_dir ++ "/"));
    try testing.expect(!std.mem.eql(u8, sandbox_dir, tasks.sandbox_dir));

    try testing.expect(!std.mem.startsWith(u8, sandbox_dir, cache.sandbox_dir ++ "/"));
    try testing.expect(!std.mem.eql(u8, sandbox_dir, "/run/chock/memory"));
}

test "a subagent sees its own scratchpad, the parent sees all, and siblings see nothing of each other" {
    const first: Agent = .{ .child = "01CHILDA" };
    const second: Agent = .{ .child = "01CHILDB" };

    try testing.expect(mayRead(first, first));
    try testing.expect(!mayRead(first, second));
    try testing.expect(!mayRead(second, first));

    try testing.expect(mayRead(.main, first));
    try testing.expect(mayRead(.main, second));
    try testing.expect(mayRead(.main, .main));

    try testing.expect(!mayRead(first, .main));
}

test "a child identifier that is not a plain name never reaches a path" {
    const allocator = testing.allocator;

    try testing.expectError(error.BadChildId, leafFor(allocator, .{ .child = "../../etc" }));
    try testing.expectError(error.BadChildId, leafFor(allocator, .{ .child = "a/b" }));
    try testing.expectError(error.BadChildId, leafFor(allocator, .{ .child = "" }));

    const child = try leafFor(allocator, .{ .child = "01CHILDA" });
    defer allocator.free(child);
    try testing.expectEqualStrings("agents/01CHILDA/scratch", child);

    const main = try leafFor(allocator, .main);
    defer allocator.free(main);
    try testing.expectEqualStrings(scratch_leaf, main);
    try testing.expect(!std.mem.eql(u8, main, agents_leaf));
}

test "the layout holds the directory the environment names, and the three beside it" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const session_dir = try std.fmt.allocPrint(allocator, "{s}/chock/01SESSION", .{path_buffer[0..path_len]});
    defer allocator.free(session_dir);

    try testing.expect(!exists(testing.io, session_dir));
    try makeLayout(testing.io, session_dir, null);
    try testing.expect(exists(testing.io, session_dir));

    inline for (.{ scratch_leaf, tasks_leaf, agents_leaf, stage_leaf }) |leaf| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ session_dir, leaf });
        defer allocator.free(path);
        try testing.expect(exists(testing.io, path));
    }

    const staging = try stageDir(allocator, session_dir);
    defer allocator.free(staging);
    try testing.expect(exists(testing.io, staging));

    try makeLayout(testing.io, session_dir, null);
    try testing.expect(exists(testing.io, session_dir));
}

test "a scratchpad over the bound is emptied, one under it is kept, and the task records survive both" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const session_dir = try std.fmt.allocPrint(allocator, "{s}/chock/01SESSION", .{path_buffer[0..path_len]});
    defer allocator.free(session_dir);
    try makeLayout(testing.io, session_dir, null);

    try testing.expectEqual(Verdict.keep, verdictFor(.{}));
    try testing.expectEqual(Verdict.keep, verdictFor(.{ .bytes = max_bytes, .files = 1 }));
    try testing.expectEqual(Verdict.empty, verdictFor(.{ .bytes = max_bytes + 1, .files = 2 }));

    const scratch_file = try std.fmt.allocPrint(allocator, "{s}/{s}/deep/notes.txt", .{ session_dir, scratch_leaf });
    defer allocator.free(scratch_file);
    try makeLayout(testing.io, std.fs.path.dirname(scratch_file).?, null);
    try writeBytes(scratch_file, "s" ** 300);

    const task_file = try std.fmt.allocPrint(allocator, "{s}/{s}/01.out", .{ session_dir, tasks_leaf });
    defer allocator.free(task_file);
    try writeBytes(task_file, "t" ** 90);

    const measured = measureScratch(allocator, testing.io, session_dir, max_bytes);
    try testing.expectEqual(@as(u64, 300), measured.bytes);
    try testing.expectEqual(@as(usize, 1), measured.files);

    const went = try clearScratch(allocator, testing.io, session_dir, null);
    try testing.expectEqual(@as(u64, 300), went.bytes);

    try testing.expectEqual(@as(u64, 0), measureScratch(allocator, testing.io, session_dir, max_bytes).bytes);
    const scratch_dir_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ session_dir, scratch_leaf });
    defer allocator.free(scratch_dir_path);
    try testing.expect(exists(testing.io, scratch_dir_path));
    try testing.expect(!exists(testing.io, std.fs.path.dirname(scratch_file).?));
    try testing.expect(fileSize(task_file) == 90);
}

test "removing the scratchpad takes the whole session directory, records and all" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const session_dir = try std.fmt.allocPrint(allocator, "{s}/chock/01SESSION", .{path_buffer[0..path_len]});
    defer allocator.free(session_dir);
    try makeLayout(testing.io, session_dir, null);

    const task_file = try std.fmt.allocPrint(allocator, "{s}/{s}/01.out", .{ session_dir, tasks_leaf });
    defer allocator.free(task_file);
    try writeBytes(task_file, "kept while the session runs");

    remove(testing.io, session_dir);
    try testing.expect(!exists(testing.io, session_dir));

    remove(testing.io, session_dir);
}

fn writeBytes(path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, contents);
}

fn fileSize(path: []const u8) u64 {
    const stat = std.Io.Dir.cwd().statFile(testing.io, path, .{}) catch return 0;
    return stat.size;
}

test "the directory a failed layout could not make reaches the caller" {
    const under_a_file = "/dev/null/chock-scratchpad";
    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(testing.allocator);

    try testing.expectError(
        error.ScratchpadDirectoryUnwritable,
        makeLayout(testing.io, under_a_file, sinkOf(testing.allocator, &diag)),
    );
    try testing.expectEqualStrings(
        under_a_file,
        diag.?.scratchpad_directory_not_made.path,
    );

    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "making the scratchpad directory "));

    try testing.expectError(
        error.ScratchpadDirectoryUnwritable,
        makeLayout(testing.io, under_a_file, null),
    );
}

test "the directory named is one this file built, and it is read after that frame ended" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &path_buffer);

    const blocker = try std.fmt.allocPrint(gpa, "{s}/scratchpad", .{path_buffer[0..len]});
    defer gpa.free(blocker);
    {
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, blocker, .{});
        handle.close(testing.io);
    }

    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);

    try testing.expectError(
        error.ScratchpadDirectoryUnwritable,
        makeLayout(testing.io, blocker, sinkOf(gpa, &diag)),
    );
    std.mem.doNotOptimizeAway(dirtyTheFrame());

    var line_buffer: [std.fs.max_path_bytes + 256]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, line, blocker) != null);
    try testing.expect(std.mem.endsWith(u8, diag.?.scratchpad_directory_not_made.path, "/" ++ scratch_leaf));
}

fn dirtyTheFrame() u64 {
    var scratch: [2 * std.fs.max_path_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}
