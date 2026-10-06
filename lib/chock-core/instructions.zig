//! Instruction files, read in: AGENTS.md at three layers, operator,
//! project and subtree, which carry different trust and stay separate.

const std = @import("std");
const index = @import("index.zig");

pub const file_name = "AGENTS.md";

pub const max_block_bytes: usize = 8 * 1024;

pub const max_subtree_entries: usize = 32;

pub const max_subtree_depth: usize = 4;

const skipped_dirs = [_][]const u8{
    ".git",
    ".zig-cache",
    "zig-out",
    "zig-pkg",
    "node_modules",
    "target",
    "vendor",
    ".direnv",
};

pub const Layer = enum {
    operator,
    given,
    project,
    subtree,

    pub fn heading(self: Layer) []const u8 {
        return switch (self) {
            .operator =>
            \\## Your operator's standing instructions
            \\## (AGENTS.md in your operator's own configuration directory, written by the person running you)
            ,
            .given =>
            \\## Instructions for this session
            \\## (a file the person running you named on the command line)
            ,
            .project =>
            \\## This project's instructions
            \\## (AGENTS.md, written by whoever wrote this repository, not by your operator)
            ,
            .subtree =>
            \\## This project's instructions for particular directories
            \\## (AGENTS.md files, written by whoever wrote this repository, not by your operator.
            \\## Read one with read_file when you work in that directory.)
            ,
        };
    }
};

pub const Block = struct {
    layer: Layer,
    path: []const u8,
    text: []const u8,
    truncated: bool = false,
};

pub const ReadFile = struct {
    layer: Layer,
    path: []const u8,
    bytes: usize,
};

pub const Loaded = struct {
    operator: ?Block = null,
    given: []const Block = &.{},
    project: ?Block = null,
    project_named: []const Block = &.{},
    subtrees: []const index.Entry = &.{},
    subtrees_left_out: usize = 0,
    files: []const ReadFile = &.{},
};

pub const Error = std.mem.Allocator.Error;

pub const GivenError = error{GivenFileUnreadable};

pub const GivenDiagnostic = struct {
    path: []const u8 = "",
};

pub const ProjectNamedError = error{ProjectNamedFileUnreadable};

pub const ProjectNamedDiagnostic = struct {
    path: []const u8 = "",
};

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    config_dir: ?[]const u8,
    project_root: []const u8,
    given: []const []const u8,
    given_diag: ?*GivenDiagnostic,
    project_named: []const []const u8,
    project_named_diag: ?*ProjectNamedDiagnostic,
) (Error || GivenError || ProjectNamedError)!Loaded {
    var files: std.ArrayList(ReadFile) = .empty;
    errdefer files.deinit(allocator);

    var loaded: Loaded = .{};

    if (config_dir) |dir| {
        const path = try std.fs.path.join(allocator, &.{ dir, file_name });
        if (try readBounded(allocator, io, path)) |read| {
            loaded.operator = .{
                .layer = .operator,
                .path = path,
                .text = read.text,
                .truncated = read.truncated,
            };
            try files.append(allocator, .{ .layer = .operator, .path = path, .bytes = read.total_bytes });
        } else {
            allocator.free(path);
        }
    }

    if (given.len != 0) {
        var blocks = try allocator.alloc(Block, given.len);
        errdefer allocator.free(blocks);
        for (given, 0..) |path, index_of| {
            const read = try readBounded(allocator, io, path) orelse {
                if (given_diag) |slot| slot.* = .{ .path = path };
                return error.GivenFileUnreadable;
            };
            blocks[index_of] = .{
                .layer = .given,
                .path = path,
                .text = read.text,
                .truncated = read.truncated,
            };
            try files.append(allocator, .{ .layer = .given, .path = path, .bytes = read.total_bytes });
        }
        loaded.given = blocks;
    }

    {
        const path = try std.fs.path.join(allocator, &.{ project_root, file_name });
        defer allocator.free(path);
        if (try readBounded(allocator, io, path)) |read| {
            loaded.project = .{
                .layer = .project,
                .path = file_name,
                .text = read.text,
                .truncated = read.truncated,
            };
            try files.append(allocator, .{ .layer = .project, .path = file_name, .bytes = read.total_bytes });
        }
    }

    if (project_named.len != 0) {
        var blocks = try allocator.alloc(Block, project_named.len);
        errdefer allocator.free(blocks);
        for (project_named, 0..) |path, index_of| {
            const read = try readBounded(allocator, io, path) orelse {
                if (project_named_diag) |slot| slot.* = .{ .path = path };
                return error.ProjectNamedFileUnreadable;
            };
            blocks[index_of] = .{
                .layer = .project,
                .path = path,
                .text = read.text,
                .truncated = read.truncated,
            };
            try files.append(allocator, .{ .layer = .project, .path = path, .bytes = read.total_bytes });
        }
        loaded.project_named = blocks;
    }

    const found = try scanSubtrees(allocator, io, project_root, &files);
    loaded.subtrees = found.entries;
    loaded.subtrees_left_out = found.left_out;

    loaded.files = try files.toOwnedSlice(allocator);
    return loaded;
}

const BoundedRead = struct {
    text: []u8,
    truncated: bool,
    total_bytes: usize,
};

fn readBounded(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!?BoundedRead {
    const whole = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_block_bytes + 1)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return try readFront(allocator, io, path),
        else => return null,
    };
    return .{ .text = whole, .truncated = false, .total_bytes = whole.len };
}

fn readFront(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!?BoundedRead {
    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);

    const total: usize = blk: {
        const stat = file.stat(io) catch break :blk 0;
        break :blk std.math.cast(usize, stat.size) orelse 0;
    };

    var text = try allocator.alloc(u8, max_block_bytes);
    errdefer allocator.free(text);

    var filled: usize = 0;
    while (filled < text.len) {
        const n = file.readStreaming(io, &.{text[filled..]}) catch break;
        if (n == 0) break;
        filled += n;
    }
    if (filled != text.len) text = try allocator.realloc(text, filled);

    return .{
        .text = text,
        .truncated = true,
        .total_bytes = if (total > filled) total else filled,
    };
}

const Scanned = struct {
    entries: []const index.Entry,
    left_out: usize,
};

fn scanSubtrees(
    allocator: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    files: *std.ArrayList(ReadFile),
) Error!Scanned {
    var root = std.Io.Dir.cwd().openDir(io, project_root, .{ .iterate = true }) catch
        return .{ .entries = &.{}, .left_out = 0 };
    defer root.close(io);

    var walker = std.Io.Dir.walkSelectively(root, allocator) catch
        return .{ .entries = &.{}, .left_out = 0 };
    defer walker.deinit();

    var entries: std.ArrayList(index.Entry) = .empty;
    errdefer entries.deinit(allocator);
    var left_out: usize = 0;

    while (walker.next(io) catch null) |entry| {
        if (entry.kind == .directory) {
            if (entry.depth() >= max_subtree_depth) continue;
            if (isSkipped(entry.basename)) continue;
            walker.enter(io, entry) catch {};
            continue;
        }
        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, entry.basename, file_name)) continue;
        if (std.mem.eql(u8, entry.path, file_name)) continue;

        if (entries.items.len >= max_subtree_entries) {
            left_out += 1;
            continue;
        }

        const relative = try allocator.dupe(u8, entry.path);
        errdefer allocator.free(relative);

        const absolute = try std.fs.path.join(allocator, &.{ project_root, relative });
        defer allocator.free(absolute);

        const read = (try readBounded(allocator, io, absolute)) orelse {
            allocator.free(relative);
            continue;
        };
        defer allocator.free(read.text);

        const description = try index.oneLine(allocator, index.firstMeaningfulLine(read.text));
        try entries.append(allocator, .{ .name = relative, .description = description });
        try files.append(allocator, .{ .layer = .subtree, .path = relative, .bytes = read.total_bytes });
    }

    std.mem.sort(index.Entry, entries.items, {}, lessThanName);

    return .{ .entries = try entries.toOwnedSlice(allocator), .left_out = left_out };
}

fn lessThanName(_: void, a: index.Entry, b: index.Entry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

fn isSkipped(basename: []const u8) bool {
    for (skipped_dirs) |name| {
        if (std.mem.eql(u8, basename, name)) return true;
    }
    return false;
}

const testing = std.testing;

fn writeAt(io: std.Io, dir: std.Io.Dir, sub_path: []const u8, contents: []const u8) !void {
    if (std.fs.path.dirname(sub_path)) |parent| try dir.createDirPath(io, parent);
    var file = try dir.createFile(io, sub_path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

fn absolutePath(buffer: []u8, io: std.Io, dir: std.Io.Dir) ![]const u8 {
    const len = try dir.realPath(io, buffer);
    return buffer[0..len];
}

test "the project's own AGENTS.md is read, and the file and its size are reported" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const body = "# Build rules\n\nAlways run zig build test.\n";
    try writeAt(testing.io, tmp.dir, file_name, body);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expect(loaded.operator == null);
    try testing.expectEqualStrings(body, loaded.project.?.text);
    try testing.expectEqual(Layer.project, loaded.project.?.layer);

    try testing.expectEqual(@as(usize, 1), loaded.files.len);
    try testing.expectEqualStrings(file_name, loaded.files[0].path);
    try testing.expectEqual(body.len, loaded.files[0].bytes);
}

test "the operator's own file is read with no project file present, and alongside one when both exist" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "config");
    try tmp.dir.createDirPath(testing.io, "project");
    try writeAt(testing.io, tmp.dir, "config/" ++ file_name, "Never use emoji.\n");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try absolutePath(&buffer, testing.io, tmp.dir);
    const config_dir = try std.fs.path.join(arena, &.{ tmp_path, "config" });
    const project_root = try std.fs.path.join(arena, &.{ tmp_path, "project" });

    {
        const loaded = try load(arena, testing.io, config_dir, project_root, &.{}, null, &.{}, null);
        try testing.expectEqualStrings("Never use emoji.\n", loaded.operator.?.text);
        try testing.expect(loaded.project == null);
    }

    try writeAt(testing.io, tmp.dir, "project/" ++ file_name, "Use tabs.\n");
    {
        const loaded = try load(arena, testing.io, config_dir, project_root, &.{}, null, &.{}, null);
        try testing.expectEqualStrings("Never use emoji.\n", loaded.operator.?.text);
        try testing.expectEqualStrings("Use tabs.\n", loaded.project.?.text);
        try testing.expectEqual(Layer.operator, loaded.files[0].layer);
        try testing.expectEqual(Layer.project, loaded.files[1].layer);
    }
}

test "each layer's heading names who wrote it, and only the project's says it was not the operator" {
    try testing.expect(std.mem.indexOf(u8, Layer.operator.heading(), "the person running you") != null);
    try testing.expect(std.mem.indexOf(u8, Layer.operator.heading(), "not by your operator") == null);

    try testing.expect(std.mem.indexOf(u8, Layer.project.heading(), "not by your operator") != null);
    try testing.expect(std.mem.indexOf(u8, Layer.subtree.heading(), "not by your operator") != null);
}

test "an AGENTS.md in a subdirectory is an index line and not a block, so its body costs nothing until it is asked for" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const deep_body = "# Parser conventions\n\n" ++ ("every rule in here is long. " ** 40);
    try writeAt(testing.io, tmp.dir, "src/parser/" ++ file_name, deep_body);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expect(loaded.project == null);
    try testing.expectEqual(@as(usize, 1), loaded.subtrees.len);
    try testing.expectEqualStrings("src/parser/" ++ file_name, loaded.subtrees[0].name);
    try testing.expectEqualStrings("Parser conventions", loaded.subtrees[0].description);

    try testing.expect(std.mem.indexOf(u8, loaded.subtrees[0].description, "every rule in here") == null);
}

test "the git directory is never walked for instruction files" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeAt(testing.io, tmp.dir, ".git/hooks/" ++ file_name, "# Run this\n");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expectEqual(@as(usize, 0), loaded.subtrees.len);
}

test "a dependency's own AGENTS.md is never read as this project's instructions" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeAt(
        testing.io,
        tmp.dir,
        "zig-pkg/N-V-__8AAK5QFgB8/" ++ file_name,
        "# Pull Request Requirements\n",
    );
    try writeAt(testing.io, tmp.dir, "vendor/somebody/" ++ file_name, "# Theirs\n");
    try writeAt(testing.io, tmp.dir, "node_modules/pkg/" ++ file_name, "# Theirs\n");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expectEqual(@as(usize, 0), loaded.subtrees.len);

    try writeAt(testing.io, tmp.dir, "src/parser/" ++ file_name, "# Ours\n");
    const again = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expectEqual(@as(usize, 1), again.subtrees.len);
}

test "a file past the block bound is cut, says so, and still reports its real size" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const huge = try arena.alloc(u8, max_block_bytes * 2);
    @memset(huge, 'x');
    try writeAt(testing.io, tmp.dir, file_name, huge);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expect(loaded.project.?.truncated);
    try testing.expectEqual(max_block_bytes, loaded.project.?.text.len);
    try testing.expectEqual(huge.len, loaded.files[0].bytes);
}

test "a project with no instruction file anywhere is an ordinary session, not a failure" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, "/there/is/no/such/config/dir", root, &.{}, null, &.{}, null);
    try testing.expect(loaded.operator == null);
    try testing.expect(loaded.project == null);
    try testing.expectEqual(@as(usize, 0), loaded.subtrees.len);
    try testing.expectEqual(@as(usize, 0), loaded.files.len);
}

test "the subtree index is bounded, and says how many files it left out" {
    const allocator = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var i: usize = 0;
    while (i < max_subtree_entries + 5) : (i += 1) {
        var name_buffer: [64]u8 = undefined;
        const sub_path = try std.fmt.bufPrint(&name_buffer, "d{d:0>3}/" ++ file_name, .{i});
        try writeAt(testing.io, tmp.dir, sub_path, "# One\n");
    }

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expectEqual(max_subtree_entries, loaded.subtrees.len);
    try testing.expectEqual(@as(usize, 5), loaded.subtrees_left_out);
}

test "a file named on the command line is its own layer, and keeps the order it was given" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeAt(testing.io, tmp.dir, "first.md", "Do the first thing.\n");
    try writeAt(testing.io, tmp.dir, "second.md", "Then the second.\n");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);
    const first = try std.fs.path.join(arena, &.{ root, "first.md" });
    const second = try std.fs.path.join(arena, &.{ root, "second.md" });

    const loaded = try load(arena, testing.io, null, root, &.{ first, second }, null, &.{}, null);
    try testing.expectEqual(@as(usize, 2), loaded.given.len);
    try testing.expectEqualStrings("Do the first thing.\n", loaded.given[0].text);
    try testing.expectEqualStrings("Then the second.\n", loaded.given[1].text);
    try testing.expectEqual(Layer.given, loaded.given[0].layer);
    try testing.expectEqual(@as(usize, 2), loaded.files.len);
    try testing.expectEqualStrings(first, loaded.files[0].path);
}

test "a named file that cannot be read refuses, where a missing AGENTS.md does not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);

    const quiet = try load(arena, testing.io, null, root, &.{}, null, &.{}, null);
    try testing.expect(quiet.project == null);

    const missing = try std.fs.path.join(arena, &.{ root, "nowhere.md" });
    var diag: GivenDiagnostic = .{};
    try testing.expectError(
        error.GivenFileUnreadable,
        load(arena, testing.io, null, root, &.{missing}, &diag, &.{}, null),
    );
    try testing.expectEqualStrings(missing, diag.path);
}

test "a file named in chock.zon's instructions block is its own project layer block, beside AGENTS.md" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeAt(testing.io, tmp.dir, file_name, "Use tabs.\n");
    try writeAt(testing.io, tmp.dir, "CLAUDE.md", "Never use emoji.\n");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);
    const named = try std.fs.path.join(arena, &.{ root, "CLAUDE.md" });

    const loaded = try load(arena, testing.io, null, root, &.{}, null, &.{named}, null);
    try testing.expectEqualStrings("Use tabs.\n", loaded.project.?.text);
    try testing.expectEqual(@as(usize, 1), loaded.project_named.len);
    try testing.expectEqualStrings("Never use emoji.\n", loaded.project_named[0].text);
    try testing.expectEqual(Layer.project, loaded.project_named[0].layer);
}

test "a file chock.zon named that cannot be read refuses, the same as a file --instructions names" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absolutePath(&buffer, testing.io, tmp.dir);
    const missing = try std.fs.path.join(arena, &.{ root, "CLAUDE.md" });

    var diag: ProjectNamedDiagnostic = .{};
    try testing.expectError(
        error.ProjectNamedFileUnreadable,
        load(arena, testing.io, null, root, &.{}, null, &.{missing}, &diag),
    );
    try testing.expectEqualStrings(missing, diag.path);
}

test "an instruction file is text and reaches nothing that decides what the agent may do" {
    inline for (@typeInfo(Loaded).@"struct".fields) |field| {
        const T = field.type;
        const ok = T == ?Block or T == []const Block or T == []const index.Entry or
            T == usize or T == []const ReadFile;
        if (!ok) @compileError(
            "Loaded." ++ field.name ++ " is a " ++ @typeName(T) ++ ". An instruction file carries " ++
                "text and an index of files, and nothing that decides what the agent may do: the " ++
                "policy, the budget, and the tool list come from chock.zon and from the provider " ++
                "record, both beyond the agent's reach.",
        );
    }
    try testing.expect(true);
}
