//! Where a session lives on disk, and what its identifier is. Shared by
//! `chock run` and `chock daemon`, so the two can never disagree about where
//! to look for a log.
//!
//! **A session is a file, and a user has to be able to find it again.** The log
//! is the truth of a session, and `chockd` serves that same log to other
//! clients, so its path is part of what Chock promises and not an
//! implementation detail.
//!
//! ```
//! $XDG_STATE_HOME/chock/sessions/<project key>/<session id>.jsonl   the log
//! $XDG_STATE_HOME/chock/sessions/<project key>/<session id>.work/   the workspace scratch
//! $XDG_STATE_HOME/chock/sessions/<project key>/<session id>.root/   the sandbox root
//! ```
//!
//! `~/.local/state/chock` by default. **The state directory, not the data
//! one**: a session log is state a program rebuilds and a user throws away,
//! and it must not sit beside the credential store, which is the one
//! directory in this project with a mode rule on it.
//!
//! The **project key** is the project's own directory name, plus eight hex
//! digits of a hash of its absolute path. The name is there so a person
//! reading `ls` knows which project a directory belongs to, and the hash is
//! there because two projects can share a name. Neither alone is enough.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_core = @import("chock-core");
const tty = @import("tty.zig");

/// How many characters a session identifier has. A ULID in Crockford base32:
/// ten characters of millisecond timestamp and sixteen of randomness.
pub const id_length = 26;

/// Crockford base32, which is the alphabet a ULID uses: no `I`, `L`, `O`, or
/// `U`, so a person reading an identifier aloud cannot turn one character
/// into another.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A fresh session identifier, sortable by the time it was made.
///
/// A ULID and not a random UUID, for one reason: `ls` in the session
/// directory then lists a user's sessions oldest first with no extra index to
/// keep, and `--continue` picks the last one by name rather than by a
/// timestamp the filesystem may not have kept.
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

/// How many characters of a session identifier hold its timestamp. The
/// remaining `id_length - timestamp_length` are the random half.
const timestamp_length = 10;

/// The moment `id` was made, in milliseconds since the epoch, read back out of
/// the identifier itself.
///
/// **The inverse of `newId`, and it lives beside it for that reason.** The
/// alphabet is spelled once in this file, so a reading of an identifier cannot
/// drift from the writing of one. A second copy of `crockford` in a command
/// that wanted a date is how two readings of one identifier quietly start
/// disagreeing.
///
/// This is what lets `chock sessions` say when a session started without
/// reading a file's modification time, which a copy or a restore changes, and
/// without a clock, which no test may depend on.
///
/// `id` must be one `isValidId` accepts, which is asserted: every character has
/// to be in the alphabet for the digits below to mean anything.
pub fn startedMs(id: []const u8) u64 {
    std.debug.assert(isValidId(id));
    var value: u64 = 0;
    for (id[0..timestamp_length]) |character| {
        const digit = std.mem.indexOfScalar(u8, crockford, character).?;
        value = (value << 5) | @as(u64, @intCast(digit));
    }
    return value;
}

/// True when `text` could be a session identifier this build made. Checked
/// before any path is built from it: a session identifier arrives from a
/// command line and, through `chock daemon`, from a socket, and a value that
/// reached a path unchecked is a path traversal.
pub fn isValidId(text: []const u8) bool {
    if (text.len != id_length) return false;
    for (text) |character| {
        if (std.mem.indexOfScalar(u8, crockford, character) == null) return false;
    }
    return true;
}

pub const Error = std.mem.Allocator.Error || chock_auth.paths.DirError;

/// The directory that holds every session of one project. Caller owns the
/// result.
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

/// Where a project's knowledgebase lives:
/// `<data dir>/memory/<project key>`. Caller owns the result.
///
/// **The data directory, not the state directory and never the project.** The
/// project belongs to the user and a note in it would pollute a diff. The
/// data directory is the one `lib/chock-auth/paths.zig` already calls Chock's
/// own, which home-manager does not manage.
///
/// Keyed the same way a session log is, by `projectKey`, so two projects with
/// the same directory name keep separate knowledgebases and one project keeps
/// the same one across runs.
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

/// Make the knowledgebase directory. Called before a session starts, because
/// the two memory tools bind it into the sandbox and a mount source that is
/// not there is a mount that fails.
pub fn createMemoryDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

/// Where this project's toolchain cache lives:
/// `<data dir>/cache/<project key>`. Caller owns the result.
///
/// **The data directory, beside the knowledgebase, and never the project.** A
/// cache in the project would land in the diff, reach `workspace.apply`, and
/// turn up in the user's repository.
///
/// It is beside the knowledgebase and not beside the dev shell cache in the
/// state directory, though both hold something Chock can rebuild, because the
/// two are different in the way that matters here: the dev shell cache is
/// written by Chock from `flake.nix`, and this one is **written by the agent's
/// own tool calls and read by every session after**. That is the class
/// `lib/chock-core/memory.zig` describes, so it gets that class's treatment
/// and that class's home: bounded, inspectable with `chock cache`, and
/// clearable in one step.
///
/// Keyed by `projectKey`, the same way a session log and a knowledgebase are,
/// so one project keeps one cache across runs and two projects of one name
/// keep separate ones.
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

/// Make the toolchain cache and everything in it that the sandbox
/// environment names, and say whether this project had one already.
///
/// **The answer is what `chock run` says on screen the first time**, so a
/// persistent directory of Chock's is never one a user finds later and cannot
/// explain. The layout itself belongs to `lib/chock-core/cache.zig`, which is
/// the file the sandbox environment is written in: a second spelling of the
/// layout here is how two paths quietly stop agreeing.
///
/// `diag` carries the directory that could not be made and the reason. The
/// caller names `path` and only the layout knows the three directories below
/// it, so without this a person is told the cache failed and never which part
/// of it or why. Give an allocator that outlives the message: see
/// `chock-core/diagnostic.zig`.
pub fn createCacheDir(
    io: std.Io,
    path: []const u8,
    diag: ?chock_core.cache.Sink,
) chock_core.cache.LayoutError!bool {
    const had_one = chock_core.cache.exists(io, path);
    try chock_core.cache.makeLayout(io, path, diag);
    return !had_one;
}

/// Where this session's scratchpad lives: `<temp>/chock/<session id>`. Caller
/// owns the result.
///
/// **The temp directory, and keyed by session and not by project.** Everything
/// else Chock keeps is keyed by project and outlives the run: a session log, a
/// knowledgebase, a toolchain cache, a dev shell evaluation. This one must not.
/// It exists for the run and no longer, so nothing an agent leaves in it
/// reaches the next session, which is what makes it the right home for
/// anything with no reason to persist. See
/// `lib/chock-core/scratchpad.zig`'s own top comment.
///
/// `TMPDIR` when the environment states one, and `/tmp` when it does not,
/// which is the same rule every program that wants a temporary directory
/// already follows. **This is the host's own `TMPDIR`, which is a different
/// thing from the one a tool call gets**: the sandbox's is a constant of
/// `scratchpad.zig` and names a path inside the mount tree.
pub fn scratchpadDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    id: []const u8,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(isValidId(id));
    const temp = env.get("TMPDIR") orelse "/tmp";
    return std.fs.path.join(gpa, &.{ temp, "chock", id });
}

/// Where this project's Nix dev shell evaluation is kept:
/// `<state dir>/dev-shell/<project key>`. Caller owns the result.
///
/// **The state directory, and never the project.** The cache is something
/// Chock rebuilds from `flake.nix` whenever it has to, which is the
/// definition this file's own top comment gives for state, and a directory
/// of Chock's inside the user's tree would show up in their `git status`.
///
/// It holds the garbage collector root links as well as the cache, so
/// removing it releases the toolchain Chock was holding: see
/// `lib/chock-nix/DevShell.zig`.
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

/// Make the dev shell directory. Called before the evaluation, which writes
/// its cache and its garbage collector roots there.
pub fn createDevShellDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

/// Where the tree of one container image is kept:
/// `<state dir>/images/<image directory name>`. Caller owns the result.
///
/// **Keyed by the image and not by the project**, which is the one place this
/// differs from the dev shell cache next door. A dev shell is one project's
/// own toolchain. An image is a named thing on a registry, so two projects
/// that name `debian:stable-slim` want the same tree, and extracting it twice
/// would cost a person the same minutes twice and the same disk twice. The
/// stamp inside the directory still holds the digest and the runtime, so a
/// tree that is no longer the image reads as missing: see
/// `lib/chock-container/Image.zig`.
///
/// **The state directory, and never the project.** The tree is something Chock
/// rebuilds from the runtime whenever it has to, which is the definition this
/// file's own top comment gives for state.
///
/// `name` is `chock_container.reference.directoryName`, which is what makes a
/// reference safe to put in a path.
pub fn imageDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    name: []const u8,
) Error![]u8 {
    const state = try chock_auth.paths.stateDir(gpa, env);
    defer gpa.free(state);

    return std.fs.path.join(gpa, &.{ state, "images", name });
}

/// Make the image directory. Called before the extraction, which writes the
/// tree and the stamp there.
pub fn createImageDir(io: std.Io, path: []const u8) CreateError!void {
    try makeDirAll(io, path);
}

/// The project's own directory name, plus eight hex digits of a hash of its
/// absolute path: see this file's own top comment. Caller owns the result.
pub fn projectKey(gpa: std.mem.Allocator, project_root: []const u8) std.mem.Allocator.Error![]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(project_root, &digest, .{});

    const raw = std.fs.path.basename(project_root);
    const name = if (raw.len == 0) "project" else raw;

    var safe: std.ArrayList(u8) = .empty;
    defer safe.deinit(gpa);
    for (name) |character| {
        // Anything that is not a plain name character becomes an underscore.
        // A project directory called `..` would otherwise build a path that
        // climbs out of the state directory.
        const ok = std.ascii.isAlphanumeric(character) or character == '-' or character == '_';
        try safe.append(gpa, if (ok) character else '_');
    }

    const hex = std.fmt.bytesToHex(digest[0..4].*, .lower);
    return std.fmt.allocPrint(gpa, "{s}-{s}", .{ safe.items, &hex });
}

/// The three paths one session owns. Every field is owned by this value.
pub const Paths = struct {
    gpa: std.mem.Allocator,
    dir: []u8,
    /// The session log, which is the session.
    log: [:0]u8,
    /// Scratch for the workspace: a linked git worktree, or an overlay's own
    /// upper and work layers.
    work: []u8,
    /// The directory that becomes the root of the sandbox.
    root: []u8,

    pub fn deinit(self: *Paths) void {
        self.gpa.free(self.dir);
        self.gpa.free(self.log);
        self.gpa.free(self.work);
        self.gpa.free(self.root);
        self.* = undefined;
    }
};

/// Where the session `id` of the project at `project_root` lives. Builds no
/// directory: see `create`.
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
    /// A directory this session needs could not be made. `create` says which
    /// one and why on standard error before this is returned. This file is
    /// part of the command and not of a library, so writing the reason here
    /// is this layer's own decision to make.
    SessionDirectoryUnwritable,
};

/// Make every directory the session needs. The log itself is made by
/// `chock_proto.log.Log.open`.
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

/// The identifier of the newest session of this project, or null when the
/// project has none. Newest by name, which is newest by time because a
/// session identifier starts with its own timestamp: see `newId`.
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
    // `--continue` picks the newest session by name. That only works if a
    // later identifier compares greater than an earlier one, which is the
    // whole reason the timestamp is at the front.
    const first = newId(testing.io);
    // A ULID's own resolution is one millisecond, so two made in the same
    // millisecond differ only in their random half. Compare the timestamp
    // halves of one made now against one built from a later time by hand.
    var later = first;
    later[9] = crockford[(std.mem.indexOfScalar(u8, crockford, first[9]).? + 1) % crockford.len];

    try testing.expectEqual(@as(usize, id_length), first.len);
    try testing.expect(isValidId(&first));
    if (first[9] != crockford[crockford.len - 1]) {
        try testing.expectEqual(std.math.Order.lt, std.mem.order(u8, &first, &later));
    }
}

test "the time an identifier carries reads back out of it, and the random half does not change it" {
    // What `chock sessions` prints for "when did this start". It has to come
    // out of the identifier, because a file's modification time is changed by
    // a copy, a restore, or an append, and because no test may read a clock.
    //
    // The vectors are fixed on purpose. A test that made an identifier and
    // compared it against the clock would be the wall clock assertion this
    // suite has none of.
    try testing.expectEqual(@as(u64, 0), startedMs("0000000000" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 1), startedMs("0000000001" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 1755000000000), startedMs("01K2F2DKG0" ++ "A" ** 16));

    // All ten characters count, and each one is five bits. Every identifier of
    // this era begins with a zero, so a reader that dropped the first digit, or
    // the last, or read four bits, would be right about today's identifiers and
    // wrong about the arithmetic. This pins the arithmetic.
    try testing.expectEqual(@as(u64, (1 << 50) - 1), startedMs("ZZZZZZZZZZ" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 1 << 45), startedMs("1000000000" ++ "A" ** 16));
    try testing.expectEqual(@as(u64, 31), startedMs("000000000Z" ++ "A" ** 16));

    // Only the first ten characters are the timestamp. Two identifiers made in
    // the same millisecond differ in their random half alone, and they must
    // still read as the same moment.
    const one = "01K2F2DKG0" ++ "A" ** 16;
    const other = "01K2F2DKG0" ++ "Z" ** 16;
    try testing.expect(!std.mem.eql(u8, one, other));
    try testing.expectEqual(startedMs(one), startedMs(other));

    // And the order by name is the order by time, which is the property the
    // whole listing rests on: see `newId`.
    try testing.expectEqual(std.math.Order.lt, std.mem.order(u8, one, "01K3CW3600" ++ "A" ** 16));
    try testing.expect(startedMs(one) < startedMs("01K3CW3600" ++ "A" ** 16));
}

test "an identifier that is not one this build made is refused before it reaches a path" {
    // A session identifier arrives from a command line and, through
    // `chock daemon`, from a socket. A value that reached a path unchecked is
    // a path traversal.
    try testing.expect(!isValidId(""));
    try testing.expect(!isValidId("../../../etc/passwd"));
    try testing.expect(!isValidId("01JQ")); // too short
    try testing.expect(!isValidId("01JQ" ++ "A" ** 30)); // too long
    // `I`, `L`, `O` and `U` are not in Crockford base32.
    try testing.expect(!isValidId("01JQIIIIIIIIIIIIIIIIIIIIII"));
    try testing.expect(isValidId("01JQ" ++ "A" ** 22));
}

test "a project key carries the project's own name and a hash, so two projects of one name differ" {
    const gpa = testing.allocator;

    const first = try projectKey(gpa, "/home/somebody/work/parser");
    defer gpa.free(first);
    const second = try projectKey(gpa, "/home/somebody/spike/parser");
    defer gpa.free(second);

    // The name is there so `ls` is readable.
    try testing.expect(std.mem.startsWith(u8, first, "parser-"));
    try testing.expect(std.mem.startsWith(u8, second, "parser-"));
    // The hash is there because the name alone collides. Without it these
    // two projects would share one session directory.
    try testing.expect(!std.mem.eql(u8, first, second));

    // The same path twice gives the same key, or `--continue` would never
    // find yesterday's session.
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
    // The three facts the whole feature rests on. A cache inside the project
    // would reach `workspace.apply` and turn up in the user's repository, and
    // a cache that is not keyed by project would be shared by every project
    // on the machine.
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

    // Two projects of one name keep separate caches, and one project keeps
    // the same one across runs, which is what makes a second session reuse
    // what the first built.
    const other = try cacheDir(gpa, &env, "/home/somebody/spike/parser");
    defer gpa.free(other);
    try testing.expect(!std.mem.eql(u8, first, other));

    const again = try cacheDir(gpa, &env, project);
    defer gpa.free(again);
    try testing.expectEqualStrings(first, again);

    // Beside the knowledgebase and not inside it: two writable directories,
    // two paths, so a `chock memory clear` cannot empty a cache and a cache
    // that grows cannot bury the notes.
    const memory = try memoryDir(gpa, &env, project);
    defer gpa.free(memory);
    try testing.expect(!std.mem.eql(u8, first, memory));
    try testing.expect(!std.mem.startsWith(u8, first, memory));
    try testing.expect(!std.mem.startsWith(u8, memory, first));
}

test "making a cache says whether this project had one already" {
    // What `chock run` prints the first time a project gets a cache, and what
    // keeps it quiet every time after.
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
    // The caller knows the name it passed and nothing else. **The layout below
    // it belongs to `chock_core.cache`**, so the part that really failed can
    // only reach a person through the sink, and nothing under `lib/` prints.
    // Measured before this was threaded: `chock run` said the cache "could not
    // be made" and named neither `home` nor `NotDir`.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    // An ordinary file where the cache belongs. The top level is then not one
    // this has to make, and the first directory inside it cannot be made.
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

    // And the line a person reads carries both, which is what the caller
    // prints with `{f}`.
    var line: [std.fs.max_path_bytes + 256]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, text, named) != null);
    try testing.expect(std.mem.indexOf(u8, text, "NotDir") != null);
}

test "a session log goes under the state directory and never beside the credential store" {
    // The credential store is the one directory in this project with a mode
    // rule on it. A session log is state a program rebuilds and a user throws
    // away, so it must not land there.
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
    // The workspace scratch and the sandbox root sit beside the log, in the
    // same session directory, so removing that one directory removes the
    // whole session.
    try testing.expect(std.mem.startsWith(u8, paths.work, paths.dir));
    try testing.expect(std.mem.startsWith(u8, paths.root, paths.dir));
}

test "a scratchpad is in the temp directory, keyed by session, and never beside anything that persists" {
    // The three facts the whole feature rests on. Ephemeral is a security
    // property here: the cache and the knowledgebase are channels that outlive
    // the sandbox, and this one is not.
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

    // Keyed by session, so two sessions of one project share nothing here.
    // Every other directory Chock keeps is keyed by project on purpose.
    const second = try scratchpadDir(gpa, &env, second_id);
    defer gpa.free(second);
    try testing.expect(!std.mem.eql(u8, first, second));

    // Not in the project, which would put it in the diff, and not in either
    // directory that survives the run.
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

    // A machine that states no TMPDIR still gets one, at the path every
    // program that wants a temporary directory already computes for itself.
    var bare = std.process.Environ.Map.init(gpa);
    defer bare.deinit();
    const fallback = try scratchpadDir(gpa, &bare, first_id);
    defer gpa.free(fallback);
    try testing.expectEqualStrings("/tmp/chock/" ++ first_id, fallback);
}
