//! Where a session lives on disk, and what its identifier is.
//! Both `chock run` and `chock daemon` use this, so the two agree on where a log is.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_core = @import("chock-core");
const tty = @import("tty.zig");

pub const id_length = 26;

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn newId(io: std.Io) [id_length]u8 {
    const time_ms: u64 = @intCast(@max(0, std.Io.Timestamp.now(io, .real).toMilliseconds()));

    var out: [id_length]u8 = undefined;
    var remaining = time_ms;
    var index: usize = 10;
    while (index > 0) {
        index -= 1;
        out[index] = crockford[@intCast(remaining & 0x1f)];
        remaining >>= 5;
    }

    var random: [16]u8 = undefined;
    io.random(&random);
    for (random, 10..) |byte, position| out[position] = crockford[byte & 0x1f];
    return out;
}

const timestamp_length = 10;

pub fn startedMs(id: []const u8) u64 {
    std.debug.assert(isValidId(id));
    var value: u64 = 0;
    for (id[0..timestamp_length]) |character| {
        const digit = std.mem.indexOfScalar(u8, crockford, character).?;
        value = (value << 5) | @as(u64, @intCast(digit));
    }
    return value;
}

pub fn isValidId(text: []const u8) bool {
    if (text.len != id_length) return false;
    for (text) |character| {
        if (std.mem.indexOfScalar(u8, crockford, character) == null) return false;
    }
    return true;
}

pub const Error = std.mem.Allocator.Error || chock_auth.paths.DirError;

pub fn projectDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Error![]u8 {
    const state = try chock_auth.paths.stateDir(gpa, env);
    defer gpa.free(state);

    const key = try projectKey(gpa, project_root);
    defer gpa.free(key);

    return std.fs.path.join(gpa, &.{ state, "sessions", key });
}

pub fn memoryDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Error![]u8 {
    const data = try chock_auth.paths.dataDir(gpa, env);
    defer gpa.free(data);

    const key = try projectKey(gpa, project_root);
    defer gpa.free(key);

    return std.fs.path.join(gpa, &.{ data, "memory", key });
}

pub fn createMemoryDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

pub fn cacheDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Error![]u8 {
    const data = try chock_auth.paths.dataDir(gpa, env);
    defer gpa.free(data);

    const key = try projectKey(gpa, project_root);
    defer gpa.free(key);

    return std.fs.path.join(gpa, &.{ data, "cache", key });
}

pub fn createCacheDir(
    io: std.Io,
    path: []const u8,
    diag: ?chock_core.cache.Sink,
) chock_core.cache.LayoutError!bool {
    const had_one = chock_core.cache.exists(io, path);
    try chock_core.cache.makeLayout(io, path, diag);
    return !had_one;
}

pub fn scratchpadDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    id: []const u8,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(isValidId(id));
    const temp = env.get("TMPDIR") orelse "/tmp";
    return std.fs.path.join(gpa, &.{ temp, "chock", id });
}

pub fn devShellDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Error![]u8 {
    const state = try chock_auth.paths.stateDir(gpa, env);
    defer gpa.free(state);

    const key = try projectKey(gpa, project_root);
    defer gpa.free(key);

    return std.fs.path.join(gpa, &.{ state, "dev-shell", key });
}

pub fn createDevShellDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

pub fn devShellStagingDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Error![]u8 {
    const dir = try devShellDir(gpa, env, project_root);
    defer gpa.free(dir);

    return std.fs.path.join(gpa, &.{ dir, staging_leaf });
}

pub const staging_leaf = "tmp";

pub fn createDevShellStagingDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

pub fn createDirAll(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

pub fn imagesDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) Error![]u8 {
    const state = try chock_auth.paths.stateDir(gpa, env);
    defer gpa.free(state);

    return std.fs.path.join(gpa, &.{ state, "images" });
}

pub fn imageDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    name: []const u8,
) Error![]u8 {
    const state = try chock_auth.paths.stateDir(gpa, env);
    defer gpa.free(state);

    return std.fs.path.join(gpa, &.{ state, "images", name });
}

pub fn createImageDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

pub fn projectKey(gpa: std.mem.Allocator, project_root: []const u8) std.mem.Allocator.Error![]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(project_root, &digest, .{});

    const raw = std.fs.path.basename(project_root);
    const name = if (raw.len == 0) "project" else raw;

    var safe: std.ArrayList(u8) = .empty;
    defer safe.deinit(gpa);
    for (name) |character| {
        // A project directory named ".." would otherwise build a path that
        // climbs out of the state directory.
        const ok = std.ascii.isAlphanumeric(character) or character == '-' or character == '_';
        try safe.append(gpa, if (ok) character else '_');
    }

    const hex = std.fmt.bytesToHex(digest[0..4].*, .lower);
    return std.fmt.allocPrint(gpa, "{s}-{s}", .{ safe.items, &hex });
}

pub const Paths = struct {
    gpa: std.mem.Allocator,
    dir: []u8,
    log: [:0]u8,
    work: []u8,
    root: []u8,

    pub fn deinit(self: *Paths) void {
        self.gpa.free(self.dir);
        self.gpa.free(self.log);
        self.gpa.free(self.work);
        self.gpa.free(self.root);
        self.* = undefined;
    }
};

pub fn pathsFor(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    id: []const u8,
) Error!Paths {
    std.debug.assert(isValidId(id));

    const dir = try projectDir(gpa, env, project_root);
    errdefer gpa.free(dir);

    const log = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    errdefer gpa.free(log);
    const work = try std.fmt.allocPrint(gpa, "{s}/{s}.work", .{ dir, id });
    errdefer gpa.free(work);
    const root = try std.fmt.allocPrint(gpa, "{s}/{s}.root", .{ dir, id });

    return .{ .gpa = gpa, .dir = dir, .log = log, .work = work, .root = root };
}

pub const CreateError = error{
    SessionDirectoryUnwritable,
};

pub fn create(io: std.Io, self: Paths) CreateError!void {
    try makeDirAll(io, self.dir);
    try makeDirAll(io, self.work);
    try makeDirAll(io, self.root);
}

fn makeDirAll(io: std.Io, path: []const u8) CreateError!void {
    makeDirAllInner(io, path) catch |err| {
        tty.print(.err, "making the session directory {s} failed: {s}\n", .{ path, @errorName(err) });
        return error.SessionDirectoryUnwritable;
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

pub fn newestId(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) Error!?[id_length]u8 {
    const dir_path = try projectDir(gpa, env, project_root);
    defer gpa.free(dir_path);

    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return null;
    defer dir.close(io);

    var newest: ?[id_length]u8 = null;
    var walker = dir.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;
        const stem = entry.name[0 .. entry.name.len - ".jsonl".len];
        if (!isValidId(stem)) continue;
        if (newest) |current| {
            if (std.mem.order(u8, stem, &current) != .gt) continue;
        }
        newest = stem[0..id_length].*;
    }
    return newest;
}

const testing = std.testing;

test "a session identifier sorts by the time it was made, so the newest is the last by name" {
    const first = newId(testing.io);
    var later = first;
    later[9] = crockford[(std.mem.indexOfScalar(u8, crockford, first[9]).? + 1) % crockford.len];

    try testing.expectEqual(@as(usize, id_length), first.len);
    try testing.expect(isValidId(&first));
    if (first[9] != crockford[crockford.len - 1]) {
        try testing.expectEqual(std.math.Order.lt, std.mem.order(u8, &first, &later));
    }
}

test "the time an identifier carries reads back out of it, and the random half does not change it" {
    try testing.expectEqual(@as(u64, 0), startedMs("0000000000" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 1), startedMs("0000000001" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 1755000000000), startedMs("01K2F2DKG0" ++ "A" ** 16));

    try testing.expectEqual(@as(u64, (1 << 50) - 1), startedMs("ZZZZZZZZZZ" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 1 << 45), startedMs("1000000000" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 31), startedMs("000000000Z" ++ "A" ** 16));

    const one = "01K2F2DKG0" ++ "A" ** 16;
    const other = "01K2F2DKG0" ++ "Z" ** 16;
    try testing.expect(!std.mem.eql(u8, one, other));
    try testing.expectEqual(startedMs(one), startedMs(other));

    try testing.expectEqual(std.math.Order.lt, std.mem.order(u8, one, "01K3CW3600" ++ "A" ** 16));
    try testing.expect(startedMs(one) < startedMs("01K3CW3600" ++ "A" ** 16));
}

test "an identifier that is not one this build made is refused before it reaches a path" {
    try testing.expect(!isValidId(""));
    try testing.expect(!isValidId("../../../etc/passwd"));
    try testing.expect(!isValidId("01JQ")); // too short
    try testing.expect(!isValidId("01JQ" ++ "A" ** 30)); // too long
    try testing.expect(!isValidId("01JQIIIIIIIIIIIIIIIIIIIIII"));
    try testing.expect(isValidId("01JQ" ++ "A" ** 22));
}

test "a project key carries the project's own name and a hash, so two projects of one name differ" {
    const gpa = testing.allocator;

    const first = try projectKey(gpa, "/home/somebody/work/parser");
    defer gpa.free(first);
    const second = try projectKey(gpa, "/home/somebody/spike/parser");
    defer gpa.free(second);

    try testing.expect(std.mem.startsWith(u8, first, "parser-"));
    try testing.expect(std.mem.startsWith(u8, second, "parser-"));
    try testing.expect(!std.mem.eql(u8, first, second));

    const again = try projectKey(gpa, "/home/somebody/work/parser");
    defer gpa.free(again);
    try testing.expectEqualStrings(first, again);
}

test "a project directory named .. cannot build a path that climbs out of the state directory" {
    const gpa = testing.allocator;
    const key = try projectKey(gpa, "/home/somebody/..");
    defer gpa.free(key);
    try testing.expect(std.mem.indexOf(u8, key, "..") == null);
    try testing.expect(std.mem.indexOfScalar(u8, key, '/') == null);
}

test "a toolchain cache is keyed by project, sits in Chock's own data directory, and is never in the project" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");

    const project = "/home/somebody/work/parser";
    const first = try cacheDir(gpa, &env, project);
    defer gpa.free(first);

    const data = try chock_auth.paths.dataDir(gpa, &env);
    defer gpa.free(data);
    try testing.expect(std.mem.startsWith(u8, first, data));
    try testing.expect(!std.mem.startsWith(u8, first, project));

    const other = try cacheDir(gpa, &env, "/home/somebody/spike/parser");
    defer gpa.free(other);
    try testing.expect(!std.mem.eql(u8, first, other));

    const again = try cacheDir(gpa, &env, project);
    defer gpa.free(again);
    try testing.expectEqualStrings(first, again);

    const memory = try memoryDir(gpa, &env, project);
    defer gpa.free(memory);
    try testing.expect(!std.mem.eql(u8, first, memory));
    try testing.expect(!std.mem.startsWith(u8, first, memory));
    try testing.expect(!std.mem.startsWith(u8, memory, first));
}

test "making a cache says whether this project had one already" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const path = try std.fmt.allocPrint(gpa, "{s}/cache/parser-0011aabb", .{buffer[0..len]});
    defer gpa.free(path);

    try testing.expect(try createCacheDir(testing.io, path, null));
    try testing.expect(!try createCacheDir(testing.io, path, null));
}

test "a cache that cannot be made names the directory inside it and the reason" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const blocked = try std.fmt.allocPrint(gpa, "{s}/blocked", .{buffer[0..len]});
    defer gpa.free(blocked);
    {
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, blocked, .{});
        handle.close(testing.io);
    }

    var diag: ?chock_core.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    try testing.expectError(
        error.CacheDirectoryUnwritable,
        createCacheDir(testing.io, blocked, chock_core.cache.sinkOf(gpa, &diag)),
    );

    try testing.expect(diag != null);
    const named = try std.fmt.allocPrint(
        gpa,
        "{s}/{s}",
        .{ blocked, chock_core.cache.home_leaf },
    );
    defer gpa.free(named);
    try testing.expectEqualStrings(named, diag.?.cache_directory_not_made.path);
    try testing.expectEqual(error.NotDir, diag.?.cache_directory_not_made.err);

    var line: [std.fs.max_path_bytes + 256]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, text, named) != null);
    try testing.expect(std.mem.indexOf(u8, text, "NotDir") != null);
}

test "a session log goes under the state directory and never beside the credential store" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");

    var paths = try pathsFor(gpa, &env, "/home/somebody/work/parser", "01JQ" ++ "A" ** 22);
    defer paths.deinit();

    const data = try chock_auth.paths.dataDir(gpa, &env);
    defer gpa.free(data);
    const config = try chock_auth.paths.configDir(gpa, &env);
    defer gpa.free(config);

    try testing.expect(std.mem.startsWith(u8, paths.log, "/home/somebody/.local/state/chock/sessions/"));
    try testing.expect(std.mem.endsWith(u8, paths.log, ".jsonl"));
    try testing.expect(!std.mem.startsWith(u8, paths.log, data));
    try testing.expect(!std.mem.startsWith(u8, paths.log, config));
    try testing.expect(std.mem.startsWith(u8, paths.work, paths.dir));
    try testing.expect(std.mem.startsWith(u8, paths.root, paths.dir));
}

test "a scratchpad is in the temp directory, keyed by session, and never beside anything that persists" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");
    try env.put("TMPDIR", "/tmp/nix-shell.qHnEsN");

    const project = "/home/somebody/work/parser";
    const first_id = "01JQ" ++ "A" ** 22;
    const second_id = "01JQ" ++ "B" ** 22;

    const first = try scratchpadDir(gpa, &env, first_id);
    defer gpa.free(first);
    try testing.expectEqualStrings("/tmp/nix-shell.qHnEsN/chock/" ++ first_id, first);

    const second = try scratchpadDir(gpa, &env, second_id);
    defer gpa.free(second);
    try testing.expect(!std.mem.eql(u8, first, second));

    const cache = try cacheDir(gpa, &env, project);
    defer gpa.free(cache);
    const memory = try memoryDir(gpa, &env, project);
    defer gpa.free(memory);
    const state = try chock_auth.paths.stateDir(gpa, &env);
    defer gpa.free(state);
    try testing.expect(!std.mem.startsWith(u8, first, project));
    try testing.expect(!std.mem.startsWith(u8, first, cache));
    try testing.expect(!std.mem.startsWith(u8, first, memory));
    try testing.expect(!std.mem.startsWith(u8, first, state));

    var bare = std.process.Environ.Map.init(gpa);
    defer bare.deinit();
    const fallback = try scratchpadDir(gpa, &bare, first_id);
    defer gpa.free(fallback);
    try testing.expectEqualStrings("/tmp/chock/" ++ first_id, fallback);
}
