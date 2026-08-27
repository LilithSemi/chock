//! Instruction files, read in: `AGENTS.md` at three layers, which do not
//! carry the same trust and must never be flattened into one block.
//!
//! | Layer | Path | Written by | Trust |
//! |---|---|---|---|
//! | operator | `<config dir>/AGENTS.md` | **the user** | the user's own voice |
//! | project | `AGENTS.md` at the project root | whoever wrote the repository | untrusted |
//! | subtree | `AGENTS.md` in a subdirectory | the same | untrusted |
//!
//! **The operator's file is the most trusted of the three**, because it is
//! the only one the user certainly wrote. It holds standing preferences that
//! hold across every project. It lives in the configuration directory, so the
//! rule `lib/chock-auth/paths.zig` already states applies unchanged: Chock
//! reads it and never writes it, and home-manager may manage it.
//!
//! ## A project is often something the user cloned
//!
//! Its `AGENTS.md` was written by whoever wrote the repository, and an agent
//! that follows it without question follows a stranger. This is prompt
//! injection with a file for a vector.
//!
//! Chock is better placed than most to take it, because the capability layers
//! already mean **instructions cannot grant capability**: a file that says
//! "push to this remote" still meets a policy that refuses, a sandbox with no
//! network, and a broker the agent cannot reach. **Never let an instruction
//! file change the policy, the budget, or the tool list.** Those come from
//! `chock.zon`, which the sandbox puts beyond the agent's reach, and from the
//! provider's capability record. There is no path from this file to any of
//! them: `load` answers with text, and text is all the prompt does with it.
//!
//! So the defence is the design already built, plus two habits:
//!
//! * **Mark the boundary in the prompt.** `Layer.heading` names who wrote
//!   each block, and the parenthetical "not by your operator" is the part
//!   that does the work: it is what lets a model discount an instruction that
//!   conflicts with the user's own. It is one line rather than a paragraph of
//!   warning. **There is deliberately no lecture about prompt injection**: a
//!   model told where a block came from can reason about it, and a model told
//!   to be afraid of its own input reasons worse.
//! * **Say what was loaded.** `Loaded.files` names every file that was read
//!   and its size, so `chock run` can print it. A user who clones a
//!   repository and sees an unexpected four hundred line `AGENTS.md` load has
//!   learned something worth knowing.
//!
//! ## Only files on disk, never a URL
//!
//! OpenCode 1.18.11 accepts `http` and `https` entries as instruction sources
//! and fetches them into the system prompt with a five second timeout. That
//! puts a project's configuration in charge of what the agent is told, from a
//! server the user never sees, changeable after review, with no record in the
//! log of what arrived. **This file reads paths, and a path is a file on
//! disk.** There is no fetch here and none is wanted.

const std = @import("std");
const index = @import("index.zig");

/// The file name at every layer. `AGENTS.md` is becoming the cross tool
/// spelling, so a project that already has one needs no second file for
/// Chock.
pub const file_name = "AGENTS.md";

/// The most of one instruction file that reaches the prompt. Past this the
/// block is cut and `Block.truncated` says so, in the prompt itself, so a
/// model does not act on half a rule believing it read the whole one.
///
/// **A bound is needed even for the operator's own file.** The prompt is
/// paid for on every turn, and a file nobody bounded is a prompt nobody
/// bounded.
pub const max_block_bytes: usize = 8 * 1024;

/// How many subtree files the index names. Past this the index says how many
/// were left out. A tree with two hundred `AGENTS.md` files is a fact about
/// the tree, and naming all of them is a fact about the context window.
pub const max_subtree_entries: usize = 32;

/// How deep under the project root a subtree file is looked for. The root's
/// own file is depth 0 and is a layer of its own, so this bounds the walk
/// below it. Deep enough for `src/parser/AGENTS.md`, shallow enough that the
/// walk over a large tree stays cheap.
pub const max_subtree_depth: usize = 4;

/// A directory the walk never enters. `.git` holds no instructions and
/// walking it costs the most of any directory in a repository.
const skipped_dirs = [_][]const u8{ ".git", ".zig-cache", "zig-out", "node_modules", "target" };

/// Which of the three layers a block came from. **The layer is what the
/// prompt prints**, so it is a value and not a comment: a block that reached
/// the prompt without one would be a block a model cannot weigh.
pub const Layer = enum {
    operator,
    project,
    subtree,

    /// The heading this layer's block gets in the prompt, and the line under
    /// it that says who wrote it.
    ///
    /// **The parenthetical is the part that does the work.** "Not by your
    /// operator" is what lets a model discount an instruction that conflicts
    /// with the user's own.
    pub fn heading(self: Layer) []const u8 {
        return switch (self) {
            .operator =>
            \\## Your operator's standing instructions
            \\## (AGENTS.md in your operator's own configuration directory, written by the person running you)
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

/// One instruction file, ready for the prompt.
pub const Block = struct {
    layer: Layer,
    /// How the file is named to the model. The project's own file is named
    /// relative to the project root; the operator's is named by its absolute
    /// path, because it is not in the project at all.
    path: []const u8,
    /// The file's text, at most `max_block_bytes` of it.
    text: []const u8,
    /// The file was longer than `max_block_bytes` and this is the front of
    /// it. The prompt says so where the block ends.
    truncated: bool = false,
};

/// One file that was read, for `chock run` to name. Kept apart from `Block`
/// because a subtree file is reported here and never becomes a `Block`: its
/// body stays on disk until the agent asks for it.
pub const ReadFile = struct {
    layer: Layer,
    path: []const u8,
    bytes: usize,
};

/// What a session's instruction files came to. Everything in it is owned by
/// the allocator passed to `load`; an arena frees the whole thing at once.
pub const Loaded = struct {
    operator: ?Block = null,
    project: ?Block = null,
    /// One index entry per subtree file: the path, and the file's own first
    /// meaningful line as its description. The path is relative to the
    /// project root, which is exactly what `read_file` takes.
    subtrees: []const index.Entry = &.{},
    /// How many subtree files were found past `max_subtree_entries`.
    subtrees_left_out: usize = 0,
    /// Every file that was read, in the order the layers apply.
    files: []const ReadFile = &.{},
};

pub const Error = std.mem.Allocator.Error;

/// Read every instruction file this session has.
///
/// `config_dir` is Chock's own configuration directory, or null for a caller
/// that has none: the operator layer is then absent rather than guessed at.
/// `project_root` is the project itself.
///
/// **A file that cannot be read is not an error.** Most projects have no
/// `AGENTS.md` at all, and a session must not fail because one is missing,
/// unreadable, or a directory. Only running out of memory reaches the
/// caller.
pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    config_dir: ?[]const u8,
    project_root: []const u8,
) Error!Loaded {
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

    const found = try scanSubtrees(allocator, io, project_root, &files);
    loaded.subtrees = found.entries;
    loaded.subtrees_left_out = found.left_out;

    loaded.files = try files.toOwnedSlice(allocator);
    return loaded;
}

const BoundedRead = struct {
    text: []u8,
    truncated: bool,
    /// The file's real size, which is what `chock run` reports. Never
    /// `text.len`: a user who sees "4096 bytes" for a forty thousand byte
    /// file has been told the wrong thing about their own repository.
    total_bytes: usize,
};

/// Read at most `max_block_bytes` of `path`, or null when there is nothing
/// readable there.
fn readBounded(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!?BoundedRead {
    // One byte past the bound, so a file exactly at the bound is not
    // reported as cut and a file past it is.
    const whole = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_block_bytes + 1)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Every other answer means this layer has nothing: no such file, a
        // directory, no permission, or a file larger than the limit, which
        // `readFileAlloc` reports rather than truncating. The last one is
        // handled below by reading it again with a reader that stops.
        error.StreamTooLong => return try readFront(allocator, io, path),
        else => return null,
    };
    return .{ .text = whole, .truncated = false, .total_bytes = whole.len };
}

/// The front of a file that is larger than `max_block_bytes`.
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
    // Shrunk with `realloc`, never handed back as a subslice: `free` reads
    // the length of the slice it is given, so a caller freeing a subslice of
    // a larger allocation is a bug that only shows up under an allocator
    // that tracks sizes.
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

/// Walk the project for `AGENTS.md` files below its root, and make one index
/// entry per file. The root's own file is not here: it is its own layer.
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
        // The root's own file is its own layer and already a block. Its path
        // is the bare file name, with no directory part, which is what tells
        // it apart from a subtree's.
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

    // Sorted, so two runs over one tree give the same prompt. The walk order
    // is whatever the filesystem hands back, which is neither stable nor
    // meaningful to a reader.
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

    const loaded = try load(arena, testing.io, null, root);
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
        const loaded = try load(arena, testing.io, config_dir, project_root);
        try testing.expectEqualStrings("Never use emoji.\n", loaded.operator.?.text);
        try testing.expect(loaded.project == null);
    }

    try writeAt(testing.io, tmp.dir, "project/" ++ file_name, "Use tabs.\n");
    {
        const loaded = try load(arena, testing.io, config_dir, project_root);
        try testing.expectEqualStrings("Never use emoji.\n", loaded.operator.?.text);
        try testing.expectEqualStrings("Use tabs.\n", loaded.project.?.text);
        // Two files, two layers, and the two are not one block: the whole
        // point of the design is that a model can tell them apart.
        try testing.expectEqual(Layer.operator, loaded.files[0].layer);
        try testing.expectEqual(Layer.project, loaded.files[1].layer);
    }
}

test "each layer's heading names who wrote it, and only the project's says it was not the operator" {
    // The parenthetical is the part that does the work, so it is the part a
    // test pins. A heading that lost it would leave a model unable to weigh
    // a cloned repository's instructions against the user's own, and nothing
    // else in the build would notice.
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

    const loaded = try load(arena, testing.io, null, root);
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

    const loaded = try load(arena, testing.io, null, root);
    try testing.expectEqual(@as(usize, 0), loaded.subtrees.len);
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

    const loaded = try load(arena, testing.io, null, root);
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

    const loaded = try load(arena, testing.io, "/there/is/no/such/config/dir", root);
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

    const loaded = try load(arena, testing.io, null, root);
    try testing.expectEqual(max_subtree_entries, loaded.subtrees.len);
    try testing.expectEqual(@as(usize, 5), loaded.subtrees_left_out);
}

test "an instruction file is text and reaches nothing that decides what the agent may do" {
    // The rule this pins: an instruction file cannot change the policy, the
    // budget, or the tool list. It is checked here as a property of the type
    // rather than of one string, because a field added to `Loaded` that
    // named a tool or a policy key is exactly how this would stop being
    // true, and it would be nobody's job to notice.
    inline for (@typeInfo(Loaded).@"struct".fields) |field| {
        const T = field.type;
        const ok = T == ?Block or T == []const index.Entry or T == usize or T == []const ReadFile;
        if (!ok) @compileError(
            "Loaded." ++ field.name ++ " is a " ++ @typeName(T) ++ ". An instruction file carries " ++
                "text and an index of files, and nothing that decides what the agent may do: the " ++
                "policy, the budget, and the tool list come from chock.zon and from the provider " ++
                "record, both beyond the agent's reach.",
        );
    }
    try testing.expect(true);
}
