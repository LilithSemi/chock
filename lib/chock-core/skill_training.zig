//! The optional training contract beside an Agent Skill. It names evaluation
//! suites; it grants no runtime tool, policy, network, or filesystem access.

const std = @import("std");

pub const file_name = "training.zon";
pub const max_file_bytes: usize = 64 * 1024;
pub const max_suite_bytes: usize = 1024 * 1024;

pub const Mode = enum { runtime, trainable, hybrid };

pub const Suites = struct {
    train: []const u8 = "",
    validation: []const u8 = "",
    @"test": []const u8 = "",
};

pub const Manifest = struct {
    schema: []const u8 = "chock.skill-training",
    version: u32 = 1,
    skill: []const u8,
    mode: Mode,
    adapter: []const u8 = "",
    suites: Suites = .{},
};

pub const Suite = struct {
    path: []const u8,
    sha256: []const u8,
};

pub const ResolvedSuites = struct {
    train: ?Suite = null,
    validation: ?Suite = null,
    @"test": ?Suite = null,
};

pub const Inspection = struct {
    schema: []const u8 = "chock.skill-training-inspection",
    version: u32 = 1,
    skill: []const u8,
    mode: Mode,
    adapter: []const u8,
    manifest: []const u8,
    manifest_sha256: []const u8,
    suites: ResolvedSuites,
};

pub const ContractError = error{
    BadSchema,
    SkillNameMismatch,
    RuntimeHasTraining,
    TrainingIncomplete,
    UnsafePath,
};

pub fn inspect(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    skill_dir: []const u8,
) !Inspection {
    const root = try realPath(arena, io, skill_dir);
    const manifest_path = try std.fs.path.join(arena, &.{ root, file_name });
    const source = try std.Io.Dir.cwd().readFileAlloc(io, manifest_path, arena, .limited(max_file_bytes));
    const source_z = try arena.dupeSentinel(u8, source, 0);
    var diagnostics: std.zon.parse.Diagnostics = undefined;
    const manifest = try std.zon.parse.fromSlice(Manifest, .{
        .gpa = gpa,
        .arena = arena,
        .source = source_z,
        .diagnostics = &diagnostics,
    });

    if (!std.mem.eql(u8, manifest.schema, "chock.skill-training") or manifest.version != 1)
        return error.BadSchema;
    if (!std.mem.eql(u8, manifest.skill, std.fs.path.basename(root)))
        return error.SkillNameMismatch;

    const has_training = manifest.adapter.len != 0 or
        manifest.suites.train.len != 0 or
        manifest.suites.validation.len != 0 or
        manifest.suites.@"test".len != 0;
    switch (manifest.mode) {
        .runtime => if (has_training) return error.RuntimeHasTraining,
        .trainable, .hybrid => if (manifest.adapter.len == 0 or
            manifest.suites.train.len == 0 or
            manifest.suites.validation.len == 0 or
            manifest.suites.@"test".len == 0)
            return error.TrainingIncomplete,
    }

    return .{
        .skill = manifest.skill,
        .mode = manifest.mode,
        .adapter = manifest.adapter,
        .manifest = manifest_path,
        .manifest_sha256 = try sha256(arena, source),
        .suites = .{
            .train = try resolveSuite(arena, io, root, manifest.suites.train),
            .validation = try resolveSuite(arena, io, root, manifest.suites.validation),
            .@"test" = try resolveSuite(arena, io, root, manifest.suites.@"test"),
        },
    };
}

fn resolveSuite(
    arena: std.mem.Allocator,
    io: std.Io,
    skill_dir: []const u8,
    relative: []const u8,
) !?Suite {
    if (relative.len == 0) return null;
    if (!safeRelative(relative)) return error.UnsafePath;
    const joined = try std.fs.path.join(arena, &.{ skill_dir, relative });
    const path = try fileRealPath(arena, io, joined);
    if (!underneath(path, skill_dir)) return error.UnsafePath;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_suite_bytes));
    return .{ .path = path, .sha256 = try sha256(arena, bytes) };
}

fn realPath(arena: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    return arena.dupe(u8, buffer[0..try dir.realPath(io, &buffer)]);
}

fn fileRealPath(arena: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    return arena.dupe(u8, buffer[0..try std.Io.Dir.cwd().realPathFile(io, path, &buffer)]);
}

fn underneath(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    return path[root.len] == std.fs.path.sep;
}

fn safeRelative(path: []const u8) bool {
    if (path.len == 0 or std.fs.path.isAbsolute(path)) return false;
    var parts = std.fs.path.componentIterator(path);
    while (parts.next()) |part| if (std.mem.eql(u8, part.name, "..")) return false;
    return true;
}

fn sha256(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

const testing = std.testing;

fn writeTrainingFixture(io: std.Io, dir: std.Io.Dir, manifest: []const u8) !void {
    try dir.writeFile(io, .{ .sub_path = file_name, .data = manifest });
    try dir.createDirPath(io, "evals");
    try dir.writeFile(io, .{ .sub_path = "evals/train.zon", .data = ".{ .name = \"train\" }\n" });
    try dir.writeFile(io, .{ .sub_path = "evals/validation.zon", .data = ".{ .name = \"validation\" }\n" });
    try dir.writeFile(io, .{ .sub_path = "evals/test.zon", .data = ".{ .name = \"test\" }\n" });
}

test "a hybrid skill binds all three suites and their bytes" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "rtl");
    var skill = try tmp.dir.openDir(io, "rtl", .{});
    defer skill.close(io);
    try writeTrainingFixture(io, skill,
        \\.{
        \\    .schema = "chock.skill-training",
        \\    .version = 1,
        \\    .skill = "rtl",
        \\    .mode = .hybrid,
        \\    .adapter = "haruka-rtl",
        \\    .suites = .{
        \\        .train = "evals/train.zon",
        \\        .validation = "evals/validation.zon",
        \\        .@"test" = "evals/test.zon",
        \\    },
        \\}
    );

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const skill_dir = try std.fs.path.join(arena, &.{ root, "rtl" });
    const found = try inspect(arena, testing.allocator, io, skill_dir);
    try testing.expectEqual(Mode.hybrid, found.mode);
    try testing.expectEqualStrings("haruka-rtl", found.adapter);
    try testing.expectEqual(@as(usize, 64), found.manifest_sha256.len);
    try testing.expect(found.suites.train != null);
    try testing.expect(found.suites.validation != null);
    try testing.expect(found.suites.@"test" != null);
}

test "a training skill cannot omit held-out suites or leave its directory" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "nix");
    var skill = try tmp.dir.openDir(io, "nix", .{});
    defer skill.close(io);
    try skill.writeFile(io, .{ .sub_path = file_name, .data =
        \\.{ .skill = "nix", .mode = .trainable, .adapter = "haruka-nix", .suites = .{ .train = "train.zon" } }
    });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const skill_dir = try std.fs.path.join(arena, &.{ root, "nix" });
    try testing.expectError(error.TrainingIncomplete, inspect(arena, testing.allocator, io, skill_dir));
}

test "a suite cannot escape its skill through a symbolic link" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "rtl/evals");
    try tmp.dir.writeFile(io, .{ .sub_path = "outside.zon", .data = ".{ .name = \"outside\" }\n" });
    try tmp.dir.symLink(io, "../../outside.zon", "rtl/evals/test.zon", .{});
    var skill = try tmp.dir.openDir(io, "rtl", .{});
    defer skill.close(io);
    try skill.writeFile(io, .{ .sub_path = file_name, .data =
        \\.{
        \\    .skill = "rtl",
        \\    .mode = .trainable,
        \\    .adapter = "rtl",
        \\    .suites = .{
        \\        .train = "evals/test.zon",
        \\        .validation = "evals/test.zon",
        \\        .@"test" = "evals/test.zon",
        \\    },
        \\}
    });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const skill_dir = try std.fs.path.join(arena, &.{ root, "rtl" });
    try testing.expectError(error.UnsafePath, inspect(arena, testing.allocator, io, skill_dir));
}
