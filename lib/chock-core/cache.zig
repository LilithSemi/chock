//! The toolchain cache: a writable directory for the compiler, kept out
//! of the project and kept across sessions.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
pub const Sink = diagnostic.Sink;
pub const sinkOf = diagnostic.sinkOf;

pub const sandbox_dir = "/run/chock/cache";

pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

pub const home_dir = sandbox_dir ++ "/home";

pub const xdg_cache_dir = home_dir ++ "/.cache";

pub fn homeIn(allocator: std.mem.Allocator, dir: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, home_leaf });
}

pub fn xdgCacheIn(allocator: std.mem.Allocator, dir: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, xdg_cache_leaf });
}

pub const home_leaf = "home";
pub const xdg_cache_leaf = "home/.cache";

pub const variables = [_][]const u8{
    "HOME=" ++ home_dir,
    "XDG_CACHE_HOME=" ++ xdg_cache_dir,
};

pub const variable_names = [_][]const u8{ "HOME", "XDG_CACHE_HOME" };

pub const max_bytes: u64 = 2 * 1024 * 1024 * 1024;

pub const Size = struct {
    bytes: u64 = 0,
    files: usize = 0,
    stopped_early: bool = false,
};

pub const Verdict = enum {
    keep,
    empty,
};

pub fn verdictFor(size: Size) Verdict {
    return if (size.bytes > max_bytes) .empty else .keep;
}

pub fn environment(
    allocator: std.mem.Allocator,
    base: []const []const u8,
    dir: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (entries.items) |entry| allocator.free(entry);
        entries.deinit(allocator);
    }

    for (base) |entry| {
        if (namesACacheVariable(entry)) continue;
        try entries.append(allocator, try allocator.dupe(u8, entry));
    }

    const home = try homeIn(allocator, dir);
    defer allocator.free(home);
    try entries.append(allocator, try std.fmt.allocPrint(allocator, "HOME={s}", .{home}));

    const xdg = try xdgCacheIn(allocator, dir);
    defer allocator.free(xdg);
    try entries.append(allocator, try std.fmt.allocPrint(allocator, "XDG_CACHE_HOME={s}", .{xdg}));

    return entries.toOwnedSlice(allocator);
}

pub fn freeEnvironment(allocator: std.mem.Allocator, entries: []const []const u8) void {
    for (entries) |entry| allocator.free(entry);
    allocator.free(entries);
}

fn namesACacheVariable(entry: []const u8) bool {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return false;
    const key = entry[0..equals];
    for (variable_names) |name| {
        if (std.mem.eql(u8, key, name)) return true;
    }
    return false;
}

pub const LayoutError = error{
    CacheDirectoryUnwritable,
};

pub fn makeLayout(io: std.Io, dir_path: []const u8, diag: ?Sink) LayoutError!void {
    try makeDirAll(io, dir_path, diag);

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const home = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ dir_path, home_leaf }) catch
        return error.CacheDirectoryUnwritable;
    try makeDirAll(io, home, diag);

    var cache_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const xdg = std.fmt.bufPrint(&cache_buffer, "{s}/{s}", .{ dir_path, xdg_cache_leaf }) catch
        return error.CacheDirectoryUnwritable;
    try makeDirAll(io, xdg, diag);
}

pub fn exists(io: std.Io, dir_path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{}) catch return false;
    dir.close(io);
    return true;
}

pub fn measure(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    stop_at: u64,
) Size {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return .{};
    defer dir.close(io);

    var walker = dir.walk(allocator) catch return .{};
    defer walker.deinit();

    var total: Size = .{};
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        const stat = entry.dir.statFile(io, entry.basename, .{ .follow_symlinks = false }) catch continue;
        total.bytes += stat.size;
        total.files += 1;
        if (total.bytes > stop_at) {
            total.stopped_early = true;
            return total;
        }
    }
    return total;
}

pub fn clear(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
    diag: ?Sink,
) LayoutError!Size {
    const went = measure(allocator, io, dir_path, std.math.maxInt(u64));

    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return went;
    {
        defer dir.close(io);

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

    try makeLayout(io, dir_path, diag);
    return went;
}

fn makeDirAll(io: std.Io, path: []const u8, diag: ?Sink) LayoutError!void {
    makeDirAllInner(io, path) catch |err| {
        diagnostic.notePath(diag, .cache_directory_not_made, path, err);
        return error.CacheDirectoryUnwritable;
    };
}

fn makeDirAllInner(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    if (!std.fs.path.isAbsolute(path)) return error.NotAbsolute;
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

test "the cache environment names HOME and XDG_CACHE_HOME inside the sandbox, and XDG below HOME" {
    const allocator = testing.allocator;

    const built = try environment(allocator, &.{}, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 2), built.len);
    try testing.expectEqualStrings("HOME=/run/chock/cache/home", built[0]);
    try testing.expectEqualStrings("XDG_CACHE_HOME=/run/chock/cache/home/.cache", built[1]);

    try testing.expect(std.mem.startsWith(u8, xdg_cache_dir, home_dir ++ "/"));
    try testing.expectEqualStrings(home_dir ++ "/.cache", xdg_cache_dir);
}

test "a cache appears under the runtime prefix, or at its own path where no path can move" {
    const allocator = testing.allocator;
    const host_dir = "/somewhere/on/the/host/cache";

    if (sandbox.expresses.moved_paths) {
        try testing.expectEqualStrings(sandbox_dir, sandboxDirFor(host_dir));
    } else {
        try testing.expectEqualStrings(host_dir, sandboxDirFor(host_dir));
    }

    const inside = sandboxDirFor(host_dir);
    const built = try environment(allocator, &.{}, inside);
    defer freeEnvironment(allocator, built);

    const home = try homeIn(allocator, inside);
    defer allocator.free(home);
    const xdg = try xdgCacheIn(allocator, inside);
    defer allocator.free(xdg);

    var expected_home: [256]u8 = undefined;
    try testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected_home, "HOME={s}", .{home}),
        built[0],
    );
    var expected_xdg: [256]u8 = undefined;
    try testing.expectEqualStrings(
        try std.fmt.bufPrint(&expected_xdg, "XDG_CACHE_HOME={s}", .{xdg}),
        built[1],
    );
    try testing.expect(std.mem.startsWith(u8, xdg, home));
}

test "the cache is outside the workspace and inside Chock's own runtime prefix" {
    try testing.expect(std.mem.startsWith(u8, sandbox_dir, "/run/chock/"));
    try testing.expect(std.mem.startsWith(u8, home_dir, sandbox_dir ++ "/"));
    try testing.expect(!std.mem.eql(u8, sandbox_dir, "/run/chock/memory"));
}

test "a HOME the dev shell states is replaced and never left beside Chock's own" {
    const allocator = testing.allocator;

    const base = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/run/chock/git/objects",
        "HOME=/nix/store/aaa-fake-home",
        "XDG_CACHE_HOME=/nix/store/bbb-cache",
        "KEEP=me",
    };
    const built = try environment(allocator, &base, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 4), built.len);
    try testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try testing.expectEqualStrings("KEEP=me", built[1]);
    try testing.expectEqualStrings("HOME=" ++ home_dir, built[2]);
    try testing.expectEqualStrings("XDG_CACHE_HOME=" ++ xdg_cache_dir, built[3]);

    var homes: usize = 0;
    for (built) |entry| {
        if (std.mem.startsWith(u8, entry, "HOME=")) homes += 1;
    }
    try testing.expectEqual(@as(usize, 1), homes);
}

test "the layout holds the two directories the environment names" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const dir_path = path_buffer[0..path_len];
    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{dir_path});
    defer allocator.free(cache_dir);

    try testing.expect(!exists(testing.io, cache_dir));
    try makeLayout(testing.io, cache_dir, null);
    try testing.expect(exists(testing.io, cache_dir));

    const home = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, home_leaf });
    defer allocator.free(home);
    const xdg = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, xdg_cache_leaf });
    defer allocator.free(xdg);
    try testing.expect(exists(testing.io, home));
    try testing.expect(exists(testing.io, xdg));

    try makeLayout(testing.io, cache_dir, null);
    try testing.expect(exists(testing.io, xdg));
}

test "measure counts the bytes below the cache, and stops early when it passes the bound" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const dir_path = path_buffer[0..path_len];
    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{dir_path});
    defer allocator.free(cache_dir);
    try makeLayout(testing.io, cache_dir, null);

    const empty = measure(allocator, testing.io, cache_dir, max_bytes);
    try testing.expectEqual(@as(u64, 0), empty.bytes);
    try testing.expectEqual(@as(usize, 0), empty.files);

    const shallow = try std.fmt.allocPrint(allocator, "{s}/shallow.bin", .{cache_dir});
    defer allocator.free(shallow);
    const deep = try std.fmt.allocPrint(allocator, "{s}/{s}/deep.bin", .{ cache_dir, xdg_cache_leaf });
    defer allocator.free(deep);
    try writeBytes(shallow, "a" ** 100);
    try writeBytes(deep, "b" ** 250);

    const filled = measure(allocator, testing.io, cache_dir, max_bytes);
    try testing.expectEqual(@as(u64, 350), filled.bytes);
    try testing.expectEqual(@as(usize, 2), filled.files);
    try testing.expect(!filled.stopped_early);

    const over = measure(allocator, testing.io, cache_dir, 100);
    try testing.expect(over.stopped_early);
    try testing.expect(over.bytes > 100);
    try testing.expect(over.bytes <= filled.bytes);
}

test "a cache over the bound is emptied, and one under it is kept" {
    try testing.expectEqual(Verdict.keep, verdictFor(.{}));
    try testing.expectEqual(Verdict.keep, verdictFor(.{ .bytes = max_bytes, .files = 1000 }));
    try testing.expectEqual(Verdict.empty, verdictFor(.{ .bytes = max_bytes + 1, .files = 1001 }));

    const stopped = Size{ .bytes = max_bytes + 1, .files = 5, .stopped_early = true };
    try testing.expectEqual(Verdict.empty, verdictFor(stopped));
}

test "clearing empties the cache, keeps the layout, and answers what went" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const dir_path = path_buffer[0..path_len];
    const cache_dir = try std.fmt.allocPrint(allocator, "{s}/cache", .{dir_path});
    defer allocator.free(cache_dir);
    try makeLayout(testing.io, cache_dir, null);

    const deep = try std.fmt.allocPrint(allocator, "{s}/{s}/zig/o/deadbeef/main.o", .{ cache_dir, xdg_cache_leaf });
    defer allocator.free(deep);
    try makeLayout(testing.io, std.fs.path.dirname(deep).?, null);
    try writeBytes(deep, "c" ** 64);

    const went = try clear(allocator, testing.io, cache_dir, null);
    try testing.expectEqual(@as(u64, 64), went.bytes);
    try testing.expectEqual(@as(usize, 1), went.files);

    const after = measure(allocator, testing.io, cache_dir, max_bytes);
    try testing.expectEqual(@as(u64, 0), after.bytes);
    const xdg = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, xdg_cache_leaf });
    defer allocator.free(xdg);
    try testing.expect(exists(testing.io, xdg));
    try testing.expect(!exists(testing.io, std.fs.path.dirname(deep).?));
}

fn writeBytes(path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, contents);
}

test "the directory named is one this file built, and it is read after that frame ended" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);

    const blocker = try std.fmt.allocPrint(gpa, "{s}/cache", .{path_buffer[0..path_len]});
    defer gpa.free(blocker);
    {
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, blocker, .{});
        handle.close(testing.io);
    }

    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);

    try testing.expectError(
        error.CacheDirectoryUnwritable,
        makeLayout(testing.io, blocker, sinkOf(gpa, &diag)),
    );
    std.mem.doNotOptimizeAway(dirtyTheFrame());

    var line_buffer: [std.fs.max_path_bytes + 256]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, line, blocker) != null);
    try testing.expect(std.mem.endsWith(u8, diag.?.cache_directory_not_made.path, "/" ++ home_leaf));
}

fn dirtyTheFrame() u64 {
    var scratch: [2 * std.fs.max_path_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}

test "a relative path is refused by name rather than asserting inside the standard library" {
    try testing.expectError(error.NotAbsolute, makeDirAllInner(testing.io, "relative/path"));
    try testing.expectError(error.NotAbsolute, makeDirAllInner(testing.io, "."));
    try makeDirAllInner(testing.io, "");

    var noted: ?Diagnostic = null;
    defer if (noted) |*one| one.deinit(testing.allocator);
    try testing.expectError(error.CacheDirectoryUnwritable, makeDirAll(
        testing.io,
        "relative/path",
        Sink{ .allocator = testing.allocator, .slot = &noted },
    ));
    try testing.expect(noted != null);
}
