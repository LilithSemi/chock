//! What a project's Nix dev shell states: the environment every tool call

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const dev_env = @import("dev_env.zig");
const proc = @import("proc.zig");
const store = @import("store.zig");

const DevShell = @This();

pub const Error = dev_env.Error || store.Error || error{
    CacheUnusable,
};

arena: *std.heap.ArenaAllocator,
variables: []const []const u8,
store_paths: []const []const u8,
evaluated: bool,

pub fn deinit(self: *DevShell) void {
    const gpa = self.arena.child_allocator;
    self.arena.deinit();
    gpa.destroy(self.arena);
    self.* = undefined;
}

pub const Options = struct {
    project_root: []const u8,
    cache_dir: []const u8,
    shell_name: ?[]const u8 = null,
    host_env: *const std.process.Environ.Map,
    on_evaluate: ?*const fn (project_root: []const u8) void = null,
    staging_dir: ?[]const u8 = null,
    diag: ?*?Diagnostic = null,
};

pub fn load(gpa: std.mem.Allocator, io: std.Io, options: Options) Error!?DevShell {
    if (!try hasFlake(io, options.project_root)) return null;

    // The message is held by gpa and the answer by the arena below: load destroys the arena on the way out when it fails, so a message living in the arena would be a read of freed memory after that.
    const sink = diagnostic.sinkOf(gpa, options.diag);

    const stamp = try stampOf(gpa, io, options.project_root, options.shell_name, options.staging_dir);

    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    if (try readCache(arena.allocator(), io, options.cache_dir, &stamp)) |cached| {
        return .{
            .arena = arena,
            .variables = cached.variables,
            .store_paths = cached.store_paths,
            .evaluated = false,
        };
    }

    if (options.on_evaluate) |report| report(options.project_root);

    const allocator = arena.allocator();
    const nix_program = try proc.resolve(allocator, io, options.host_env, "nix");
    const env_program = try proc.resolve(allocator, io, options.host_env, "env");

    const script = try dev_env.printDevEnv(
        allocator,
        io,
        nix_program,
        options.project_root,
        options.shell_name,
        options.host_env,
        sink,
    );
    const script_path = try std.fs.path.join(allocator, &.{ options.cache_dir, script_name });
    try writeFile(io, script_path, script);

    const bash_program = try dev_env.bashFor(allocator, io, script, options.host_env);

    const variables = try dev_env.read(allocator, io, .{
        .diag = sink,
        .bash_program = bash_program,
        .env_program = env_program,
        .script_path = script_path,
        .cwd = options.project_root,
        .host_env = options.host_env,
        .staging_dir = options.staging_dir,
    });

    const roots = try store.pathsIn(allocator, io, variables);
    const store_paths = try store.closureOf(allocator, io, nix_program, options.host_env, roots, sink);

    rootPaths(allocator, io, options, roots) catch |err| {
        _ = diagnostic.note(sink, .{ .toolchain_not_rooted = err });
    };

    writeCache(allocator, io, options.cache_dir, &stamp, variables, store_paths) catch |err| {
        diagnostic.noteNamed(sink, .cache_not_written, options.cache_dir, err) catch {};
    };

    removeOldStaging(allocator, io, options.staging_dir, variables);

    return .{
        .arena = arena,
        .variables = variables,
        .store_paths = store_paths,
        .evaluated = true,
    };
}

fn removeOldStaging(
    allocator: std.mem.Allocator,
    io: std.Io,
    staging_dir: ?[]const u8,
    variables: []const []const u8,
) void {
    const where = staging_dir orelse return;
    const keep = std.fs.path.basename(valueOf(variables, "NIX_BUILD_TOP") orelse return);

    var dir = std.Io.Dir.openDirAbsolute(io, where, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.startsWith(u8, entry.name, staging_prefix)) continue;
        if (std.mem.eql(u8, entry.name, keep)) continue;
        const copy = allocator.dupe(u8, entry.name) catch return;
        names.append(allocator, copy) catch {
            allocator.free(copy);
            return;
        };
    }

    for (names.items) |name| dir.deleteTree(io, name) catch continue;
}

const staging_prefix = "nix-shell.";

fn valueOf(variables: []const []const u8, key: []const u8) ?[]const u8 {
    for (variables) |record| {
        const split = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (!std.mem.eql(u8, record[0..split], key)) continue;
        return record[split + 1 ..];
    }
    return null;
}

fn rootPaths(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    roots: []const []const u8,
) Error!void {
    const nix_store_program = try proc.resolve(allocator, io, options.host_env, "nix-store");
    const link_prefix = try std.fs.path.join(allocator, &.{ options.cache_dir, root_link_name });

    removeOldRoots(allocator, io, options.cache_dir);

    try store.addRoots(allocator, io, nix_store_program, options.host_env, link_prefix, roots, null);
}

fn removeOldRoots(allocator: std.mem.Allocator, io: std.Io, cache_dir: []const u8) void {
    var dir = std.Io.Dir.openDirAbsolute(io, cache_dir, .{ .iterate = true }) catch return;
    defer dir.close(io);

    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| allocator.free(name);
        names.deinit(allocator);
    }

    var it = dir.iterate();
    while (it.next(io) catch null) |entry| {
        if (!std.mem.startsWith(u8, entry.name, root_link_name)) continue;
        const copy = allocator.dupe(u8, entry.name) catch return;
        names.append(allocator, copy) catch {
            allocator.free(copy);
            return;
        };
    }

    // Removed after the walk, never during it: a directory iterator that outlives an entry it deleted is reading a tree that changed under it.
    for (names.items) |name| dir.deleteFile(io, name) catch continue;
}

const script_name = "dev-env.sh";

pub const root_link_name = "gcroot";
const stamp_name = "stamp";
const variables_name = "env";
const paths_name = "store-paths";

const stamp_hex_length = 2 * std.crypto.hash.sha2.Sha256.digest_length;

pub fn hasFlake(io: std.Io, project_root: []const u8) Error!bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/flake.nix", .{project_root}) catch return false;
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

fn stampOf(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    shell_name: ?[]const u8,
    staging_dir: ?[]const u8,
) Error![stamp_hex_length]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("chock dev shell 3\n");

    hash.update(shell_name orelse "");
    hash.update("\n");

    hash.update(staging_dir orelse "");
    hash.update("\n");

    for ([_][]const u8{ "flake.nix", "flake.lock" }) |name| {
        const path = try std.fs.path.join(gpa, &.{ project_root, name });
        defer gpa.free(path);

        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_flake_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => "",
        };
        defer if (bytes.len != 0) gpa.free(bytes);

        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, bytes.len, .little);
        hash.update(name);
        hash.update(&length);
        hash.update(bytes);
    }

    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

const max_flake_bytes: usize = 16 * 1024 * 1024;

const Cached = struct {
    variables: []const []const u8,
    store_paths: []const []const u8,
};

fn readCache(
    arena: std.mem.Allocator,
    io: std.Io,
    cache_dir: []const u8,
    stamp: *const [stamp_hex_length]u8,
) Error!?Cached {
    const written = (try readCacheFile(arena, io, cache_dir, stamp_name, stamp_hex_length + 1)) orelse return null;
    if (!std.mem.eql(u8, std.mem.trimEnd(u8, written, "\n"), stamp)) return null;

    const variables_blob = (try readCacheFile(arena, io, cache_dir, variables_name, max_cache_bytes)) orelse return null;
    const paths_blob = (try readCacheFile(arena, io, cache_dir, paths_name, max_cache_bytes)) orelse return null;

    const variables = try splitBlob(arena, variables_blob, 0);
    const store_paths = try splitBlob(arena, paths_blob, '\n');

    for (store_paths) |path| {
        _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;
    }

    return .{ .variables = variables, .store_paths = store_paths };
}

const max_cache_bytes: usize = 16 * 1024 * 1024;

fn readCacheFile(
    arena: std.mem.Allocator,
    io: std.Io,
    cache_dir: []const u8,
    name: []const u8,
    limit: usize,
) Error!?[]u8 {
    const path = try std.fs.path.join(arena, &.{ cache_dir, name });
    return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(limit)) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

fn splitBlob(arena: std.mem.Allocator, blob: []const u8, separator: u8) Error![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, blob, separator);
    while (it.next()) |part| {
        if (part.len == 0) continue;
        try list.append(arena, part);
    }
    return list.toOwnedSlice(arena);
}

fn writeCache(
    allocator: std.mem.Allocator,
    io: std.Io,
    cache_dir: []const u8,
    stamp: *const [stamp_hex_length]u8,
    variables: []const []const u8,
    store_paths: []const []const u8,
) Error!void {
    const stamp_path = try std.fs.path.join(allocator, &.{ cache_dir, stamp_name });
    // Removed first, so a failure to write either of the two files below cannot leave the old stamp standing over new contents.
    std.Io.Dir.deleteFileAbsolute(io, stamp_path) catch {};

    try writeJoined(allocator, io, cache_dir, variables_name, variables, 0);
    try writeJoined(allocator, io, cache_dir, paths_name, store_paths, '\n');
    try writeFile(io, stamp_path, stamp);
}

fn writeJoined(
    allocator: std.mem.Allocator,
    io: std.Io,
    cache_dir: []const u8,
    name: []const u8,
    parts: []const []const u8,
    separator: u8,
) Error!void {
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(allocator);
    for (parts) |part| {
        try blob.appendSlice(allocator, part);
        try blob.append(allocator, separator);
    }

    const path = try std.fs.path.join(allocator, &.{ cache_dir, name });
    defer allocator.free(path);
    try writeFile(io, path, blob.items);
}

fn writeFile(io: std.Io, path: []const u8, bytes: []const u8) Error!void {
    var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch return error.CacheUnusable;
    defer file.close(io);
    file.writeStreamingAll(io, bytes) catch return error.CacheUnusable;
}

test "a project with no flake has no dev shell to read" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    var host_env = try std.testing.environ.createMap(allocator);
    defer host_env.deinit();

    const loaded = try load(allocator, std.testing.io, .{
        .project_root = dir_path,
        .cache_dir = dir_path,
        .host_env = &host_env,
    });
    try std.testing.expectEqual(@as(?DevShell, null), loaded);
}

test "a fault outlives the arena that load throws away" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer std.testing.expect(debug.deinit() == .ok) catch @panic("this test leaked");
    const gpa = debug.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.nix", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ outputs = _: {}; }\n");
    }

    try tmp.dir.createDir(std.testing.io, "bin", .default_dir);
    var bin = try tmp.dir.openDir(std.testing.io, "bin", .{});
    defer bin.close(std.testing.io);
    {
        var file = try bin.createFile(std.testing.io, "nix", .{
            .permissions = .fromMode(0o755),
        });
        defer file.close(std.testing.io);
        try file.writeStreamingAll(
            std.testing.io,
            "#!/bin/sh\necho 'error: this flake does not evaluate' >&2\nexit 1\n",
        );
    }

    var host_env = try std.testing.environ.createMap(gpa);
    defer host_env.deinit();
    const path = try std.fmt.allocPrint(gpa, "{s}/bin:{s}", .{
        dir_path,
        host_env.get("PATH") orelse "",
    });
    defer gpa.free(path);
    try host_env.put("PATH", path);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    if (load(gpa, std.testing.io, .{
        .project_root = dir_path,
        .cache_dir = dir_path,
        .host_env = &host_env,
        .diag = &diag,
    })) |loaded| {
        if (loaded) |shell| {
            var owned = shell;
            owned.deinit();
        }
        return error.SkipZigTest;
    } else |err| {
        if (err == error.ProgramNotFound) return error.SkipZigTest;
        try std.testing.expectEqual(@as(anyerror, error.EvalFailed), err);
    }

    var line: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "{f}", .{&diag.?});
    try std.testing.expect(std.mem.indexOf(u8, text, "nix print-dev-env failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "this flake does not evaluate") != null);
}

test "the stamp follows both flake files" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.nix", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ outputs = _: {}; }\n");
    }
    const first = try stampOf(allocator, std.testing.io, dir_path, null, null);

    const again = try stampOf(allocator, std.testing.io, dir_path, null, null);
    try std.testing.expectEqualStrings(&first, &again);

    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.lock", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ \"nodes\": {} }\n");
    }
    const with_lock = try stampOf(allocator, std.testing.io, dir_path, null, null);
    try std.testing.expect(!std.mem.eql(u8, &first, &with_lock));

    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.nix", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ outputs = _: { changed = true; }; }\n");
    }
    const changed = try stampOf(allocator, std.testing.io, dir_path, null, null);
    try std.testing.expect(!std.mem.eql(u8, &with_lock, &changed));
}

test "the dev shell name is part of the stamp, so two names never share a cache" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.nix", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ outputs = _: {}; }\n");
    }

    const unnamed = try stampOf(allocator, std.testing.io, dir_path, null, null);
    const named = try stampOf(allocator, std.testing.io, dir_path, "ci", null);
    const other = try stampOf(allocator, std.testing.io, dir_path, "release", null);

    try std.testing.expect(!std.mem.eql(u8, &unnamed, &named));
    try std.testing.expect(!std.mem.eql(u8, &named, &other));

    const again = try stampOf(allocator, std.testing.io, dir_path, "ci", null);
    try std.testing.expectEqualStrings(&named, &again);

    const staged = try stampOf(allocator, std.testing.io, dir_path, "ci", "/var/chock/tmp");
    try std.testing.expect(!std.mem.eql(u8, &named, &staged));
}

test "a cache is read back whole, and a stamp that does not match is not read at all" {
    const allocator = std.testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    const variables = [_][]const u8{ "MULTI=one\ntwo", "PATH=/usr/bin" };
    const paths = [_][]const u8{dir_path};

    const stamp: [stamp_hex_length]u8 = ("a" ** stamp_hex_length).*;
    try writeCache(arena, std.testing.io, dir_path, &stamp, &variables, &paths);

    const read_back = (try readCache(arena, std.testing.io, dir_path, &stamp)).?;
    try std.testing.expectEqual(@as(usize, 2), read_back.variables.len);
    try std.testing.expectEqualStrings("MULTI=one\ntwo", read_back.variables[0]);
    try std.testing.expectEqualStrings("PATH=/usr/bin", read_back.variables[1]);
    try std.testing.expectEqual(@as(usize, 1), read_back.store_paths.len);

    const other: [stamp_hex_length]u8 = ("b" ** stamp_hex_length).*;
    try std.testing.expectEqual(
        @as(?Cached, null),
        try readCache(arena, std.testing.io, dir_path, &other),
    );
}

test "a cache whose paths are gone is not used" {
    const allocator = std.testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &buffer);
    const dir_path = buffer[0..len];

    const variables = [_][]const u8{"PATH=/usr/bin"};
    const paths = [_][]const u8{"/nix/store/00000000000000000000000000000000-not-here"};

    const stamp: [stamp_hex_length]u8 = ("c" ** stamp_hex_length).*;
    try writeCache(arena, std.testing.io, dir_path, &stamp, &variables, &paths);

    try std.testing.expectEqual(
        @as(?Cached, null),
        try readCache(arena, std.testing.io, dir_path, &stamp),
    );
}

test "an evaluation takes off the staging directories the ones before it left" {
    const allocator = std.testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const staging = buffer[0..len];

    try tmp.dir.createDirPath(io, "nix-shell.old111");
    try tmp.dir.createDirPath(io, "nix-shell.old222/inside");
    try tmp.dir.createDirPath(io, "nix-shell.new333");
    try tmp.dir.createDirPath(io, "stamp.d");

    const kept = try std.fs.path.join(arena, &.{ staging, "nix-shell.new333" });
    const variables = [_][]const u8{
        try std.fmt.allocPrint(arena, "NIX_BUILD_TOP={s}", .{kept}),
        "PATH=/usr/bin",
    };

    removeOldStaging(allocator, io, staging, &variables);

    try std.testing.expect(exists(io, kept));
    try std.testing.expect(exists(io, try std.fs.path.join(arena, &.{ staging, "stamp.d" })));
    for ([_][]const u8{ "nix-shell.old111", "nix-shell.old222" }) |gone| {
        try std.testing.expect(!exists(io, try std.fs.path.join(arena, &.{ staging, gone })));
    }
}

fn exists(io: std.Io, path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}
