//! Where a session lives on disk, and what its identifier is.
//! Both `chock run` and `chock daemon` use this, so the two agree on where a log is.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");
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

/// The file in a project's directory that says which directory it is for.
///
/// `projectKey` hashes the path, so the directory name cannot be read back
/// into a path. Without this, nothing can list the projects a person has.
pub const project_marker = "project";

pub fn create(io: std.Io, self: Paths) CreateError!void {
    try makeDirAll(io, self.dir);
    try makeDirAll(io, self.work);
    try makeDirAll(io, self.root);
}

/// Write down which directory this session directory belongs to.
///
/// Separate from `create` because it needs the project root, and `Paths` has
/// already turned that into a hashed directory name. A failure is dropped: the
/// marker only makes a listing nicer, and a session runs without it.
pub fn markProject(io: std.Io, self: Paths, project_root: []const u8) void {
    const path = std.fmt.allocPrint(self.gpa, "{s}/{s}", .{ self.dir, project_marker }) catch return;
    defer self.gpa.free(path);

    const file = std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true }) catch return;
    defer file.close(io);
    file.writeStreamingAll(io, project_root) catch {};
}

/// One project a person has worked in.
pub const Project = struct {
    /// The directory the sessions are in. Always known.
    dir: []const u8,
    /// The project this is for, as the marker says, or empty when a directory
    /// predates the marker and nothing wrote one.
    root: []const u8,
    /// A name to show. The marker's basename, or the directory's own name with
    /// the hash taken off.
    name: []const u8,
    sessions: usize,
    /// The identifier of the newest session in it. Identifiers sort by the time
    /// they were made, so this orders projects by when each was last worked in.
    newest: [id_length]u8 = @splat('0'),
};

/// Every project under the state directory, newest name order left to the
/// caller. A directory with no sessions in it is left out.
pub fn listProjects(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) Error![]Project {
    const state = try chock_auth.paths.stateDir(gpa, env);
    defer gpa.free(state);

    const root = try std.fmt.allocPrint(gpa, "{s}/sessions", .{state});
    defer gpa.free(root);

    var dir = std.Io.Dir.openDirAbsolute(io, root, .{ .iterate = true }) catch return &.{};
    defer dir.close(io);

    var out: std.ArrayList(Project) = .empty;
    var walker = dir.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ root, entry.name });
        const found = sessionsIn(io, path);
        if (found.count == 0) {
            gpa.free(path);
            continue;
        }
        const said = markerIn(gpa, io, path) orelse recoverRoot(gpa, io, path, entry.name);
        // `entry.name` points into the walker's own buffer, which the next step
        // writes over, so a name kept past this iteration has to be copied.
        const name = if (said) |one|
            std.fs.path.basename(one)
        else
            try gpa.dupe(u8, nameOf(entry.name));
        try out.append(gpa, .{
            .dir = path,
            .root = said orelse "",
            .name = name,
            .sessions = found.count,
            .newest = found.newest,
        });
    }

    // Newest first, so the project a person is working in is at the top.
    std.mem.sort(Project, out.items, {}, newerFirst);
    return out.toOwnedSlice(gpa);
}

fn newerFirst(_: void, left: Project, right: Project) bool {
    return std.mem.order(u8, &left.newest, &right.newest) == .gt;
}

const Counted = struct {
    count: usize = 0,
    newest: [id_length]u8 = @splat('0'),
};

fn sessionsIn(io: std.Io, path: []const u8) Counted {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch return .{};
    defer dir.close(io);

    var out: Counted = .{};
    var walker = dir.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".jsonl")) continue;
        const stem = entry.name[0 .. entry.name.len - ".jsonl".len];
        if (!isValidId(stem)) continue;
        out.count += 1;
        if (std.mem.order(u8, stem, &out.newest) == .gt) out.newest = stem[0..id_length].*;
    }
    return out;
}

fn markerIn(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ?[]const u8 {
    const file_path = std.fmt.allocPrint(gpa, "{s}/{s}", .{ path, project_marker }) catch return null;
    defer gpa.free(file_path);

    const said = std.Io.Dir.readFileAlloc(.cwd(), io, file_path, gpa, .limited(std.fs.max_path_bytes)) catch
        return null;
    const kept = std.mem.trim(u8, said, " \t\r\n");
    if (kept.len == 0 or !std.fs.path.isAbsolute(kept)) {
        gpa.free(said);
        return null;
    }
    return kept;
}

/// Work out a project's directory from a worktree it left behind, for a
/// directory made before anything wrote a marker.
///
/// A git worktree's `.git` is a file naming the repository it came from, so a
/// kept workspace still points home. The answer is only taken when hashing it
/// reproduces the directory's own name, so a wrong guess is never written down.
fn recoverRoot(gpa: std.mem.Allocator, io: std.Io, path: []const u8, entry: []const u8) ?[]const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch return null;
    defer dir.close(io);

    var walker = dir.iterate();
    while (walker.next(io) catch null) |one| {
        if (one.kind != .directory) continue;
        if (!std.mem.endsWith(u8, one.name, ".work")) continue;

        const work = std.fmt.allocPrint(gpa, "{s}/{s}", .{ path, one.name }) catch return null;
        defer gpa.free(work);

        if (rootUnder(gpa, io, work, entry)) |found| {
            // Write it down, so the next listing reads a marker.
            const marker = std.fmt.allocPrint(gpa, "{s}/{s}", .{ path, project_marker }) catch return found;
            defer gpa.free(marker);
            if (std.Io.Dir.createFileAbsolute(io, marker, .{ .truncate = true })) |file| {
                defer file.close(io);
                file.writeStreamingAll(io, found) catch {};
            } else |_| {}
            return found;
        }
    }
    return null;
}

/// The project behind any one attempt under a `.work` directory.
fn rootUnder(gpa: std.mem.Allocator, io: std.Io, work: []const u8, entry: []const u8) ?[]const u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, work, .{ .iterate = true }) catch return null;
    defer dir.close(io);

    var walker = dir.iterate();
    while (walker.next(io) catch null) |one| {
        if (one.kind != .directory) continue;
        const link = std.fmt.allocPrint(gpa, "{s}/{s}/.git", .{ work, one.name }) catch continue;
        defer gpa.free(link);

        const said = std.Io.Dir.readFileAlloc(.cwd(), io, link, gpa, .limited(4096)) catch continue;
        defer gpa.free(said);

        const root = rootOfGitLink(said) orelse continue;
        const key = projectKey(gpa, root) catch continue;
        defer gpa.free(key);
        if (!std.mem.eql(u8, key, entry)) continue;

        return gpa.dupe(u8, root) catch null;
    }
    return null;
}

/// `gitdir: /home/ross/chock/.git/worktrees/<name>` names `/home/ross/chock`.
fn rootOfGitLink(said: []const u8) ?[]const u8 {
    const prefix = "gitdir:";
    if (!std.mem.startsWith(u8, said, prefix)) return null;
    const path = std.mem.trim(u8, said[prefix.len..], " \t\r\n");
    const at = std.mem.lastIndexOf(u8, path, "/.git/") orelse return null;
    if (at == 0) return null;
    return path[0..at];
}

/// A directory name is `<basename>-<eight hex>`, so the name is what comes
/// before the last dash.
fn nameOf(entry: []const u8) []const u8 {
    const cut = std.mem.lastIndexOfScalar(u8, entry, '-') orelse return entry;
    if (entry.len - cut - 1 != 8) return entry;
    return entry[0..cut];
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

test "a project is listed by the path its marker names, and by its directory when nothing wrote one" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var room: [std.fs.max_path_bytes]u8 = undefined;
    const state = try chock_proto.log.absoluteDirPath(io, &room, tmp.dir);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("XDG_STATE_HOME", state);

    const project = "/home/somebody/work/parser";
    const id = "01JQ" ++ "A" ** 22;

    var paths = try pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try create(io, paths);
    markProject(io, paths, project);

    // A directory holding no session is not a project anybody can open, so a
    // log goes in beside the marker.
    const log = try std.fmt.allocPrint(gpa, "{s}/{s}.jsonl", .{ paths.dir, id });
    defer gpa.free(log);
    const file = try std.Io.Dir.createFileAbsolute(io, log, .{ .truncate = true });
    file.close(io);

    const found = try listProjects(gpa, io, &env);
    defer {
        for (found) |one| {
            gpa.free(one.dir);
            if (one.root.len != 0) gpa.free(one.root);
        }
        gpa.free(found);
    }

    try testing.expectEqual(@as(usize, 1), found.len);
    try testing.expectEqualStrings(project, found[0].root);
    try testing.expectEqualStrings("parser", found[0].name);
    try testing.expectEqual(@as(usize, 1), found[0].sessions);
}

test "a directory name carries the project's own name with the hash taken off" {
    try testing.expectEqualStrings("chock", nameOf("chock-e6146e21"));
    try testing.expectEqualStrings("chock-website", nameOf("chock-website-40e39acb"));
    // Not eight hex after the last dash, so the whole name stands.
    try testing.expectEqualStrings("no-hash-here", nameOf("no-hash-here"));
}

test "a worktree left behind names its project, and a name that does not hash back is refused" {
    try testing.expectEqualStrings(
        "/home/ross/chock",
        rootOfGitLink("gitdir: /home/ross/chock/.git/worktrees/01M0TMATKBZE7HQPXTQZ3CWAR6\n").?,
    );
    // Nothing to cut at, so nothing is claimed.
    try testing.expectEqual(@as(?[]const u8, null), rootOfGitLink("gitdir: /home/ross/chock\n"));
    try testing.expectEqual(@as(?[]const u8, null), rootOfGitLink("ref: refs/heads/master\n"));
    try testing.expectEqual(@as(?[]const u8, null), rootOfGitLink(""));
}

test "a recovered project is only taken when hashing it gives the directory back" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var room: [std.fs.max_path_bytes]u8 = undefined;
    const state = try chock_proto.log.absoluteDirPath(io, &room, tmp.dir);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("XDG_STATE_HOME", state);

    const project = "/home/somebody/work/parser";
    const id = "01JQ" ++ "A" ** 22;

    var paths = try pathsFor(gpa, &env, project, id);
    defer paths.deinit();
    try create(io, paths);

    // A session, and a worktree still pointing at where it came from. No
    // marker: this is a directory made before markers existed.
    const log = try std.fmt.allocPrint(gpa, "{s}/{s}.jsonl", .{ paths.dir, id });
    defer gpa.free(log);
    (try std.Io.Dir.createFileAbsolute(io, log, .{ .truncate = true })).close(io);

    const attempt = try std.fmt.allocPrint(gpa, "{s}/01JQB", .{paths.work});
    defer gpa.free(attempt);
    try std.Io.Dir.createDirAbsolute(io, attempt, .default_dir);

    const link = try std.fmt.allocPrint(gpa, "{s}/.git", .{attempt});
    defer gpa.free(link);
    const file = try std.Io.Dir.createFileAbsolute(io, link, .{ .truncate = true });
    try file.writeStreamingAll(io, "gitdir: " ++ project ++ "/.git/worktrees/01JQB\n");
    file.close(io);

    const found = try listProjects(gpa, io, &env);
    defer {
        for (found) |one| {
            gpa.free(one.dir);
            if (one.root.len != 0) gpa.free(one.root);
        }
        gpa.free(found);
    }

    try testing.expectEqual(@as(usize, 1), found.len);
    try testing.expectEqualStrings(project, found[0].root);

    // Written down, so the next listing reads it rather than walking again.
    const marker = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ paths.dir, project_marker });
    defer gpa.free(marker);
    const said = try std.Io.Dir.readFileAlloc(.cwd(), io, marker, gpa, .limited(4096));
    defer gpa.free(said);
    try testing.expectEqualStrings(project, said);
}
