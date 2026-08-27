//! What a project's Nix dev shell states: the environment every tool call
//! runs with, and the store paths the sandbox mounts for it.
//!
//! If the project has a `flake.nix` with a dev shell, every tool call runs
//! with the environment of that dev shell, which removes toolchain drift.
//! Before this existed, that only worked by accident.
//! `lib/chock-core/tools.zig` resolves a tool call's `argv[0]` against the
//! host's own `PATH`, so a `chock run` typed inside `nix develop` inherited
//! the toolchain and one typed outside it did not, and neither one ever got a
//! variable a flake's `shellHook` sets.
//!
//! ## One evaluation answers both questions
//!
//! The environment and the mount set come from the same `nix print-dev-env`,
//! and that is the point rather than an economy. Red team finding 1 of
//! 2026-08-21 asked for the store mount to be narrowed and the project owner
//! decided the shape: **do not filter the store by guessing what to exclude,
//! read the dev shell and provide what the dev shell says.** A mount set
//! derived from the same evaluation as the environment cannot drift from it.
//! A hand written list would be correct on the day it was written and wrong
//! for the next project.
//!
//! ## A project with no dev shell, decided rather than left to happen
//!
//! **A project with no `flake.nix` gets the whole store, read only, exactly
//! as before, and `chock run` says so out loud.** `load` answers null, and
//! `lib/chock-core/tools.zig`'s own `Context.store_paths` default is the
//! whole store.
//!
//! That is a decision and not a fallback nobody chose. The alternative on
//! the table was the host toolchain's own closure, and it was measured
//! before it was refused: on a NixOS machine the host's `PATH` reaches the
//! system profile, whose closure is most of the store **and includes the
//! home-manager generated files the finding names**. It would cost a Nix
//! query on every session of every project that has no flake, and it would
//! not close the finding for those projects. Narrowing is a property of a
//! project that states its toolchain. A project that states nothing gets no
//! derived answer, and the honest thing is to say that where the user can
//! see it.
//!
//! ## The cache, and what invalidates it
//!
//! Chock caches the environment, and rebuilds it when `flake.nix` or
//! `flake.lock` changes. The mount set is a property of the same evaluation,
//! so it caches with it. `stamp` is a hash of those two files.
//!
//! **A dev shell defined in another file that `flake.nix` imports is not
//! seen by that stamp.** This project's own shell is one: it lives in
//! `pkgs/chock/default.nix`. Editing such a file and keeping `flake.nix`
//! byte for byte the same leaves a stale cache, and the way out is to touch
//! `flake.nix` or remove the cache directory. The honest alternative is a
//! full evaluation on every session, which is the cost the cache exists to
//! avoid.
//!
//! A cache hit still checks that every path it names is still on disk. The
//! garbage collector root makes that hard to break, and "hard" is not
//! "cannot": a user who removes Chock's state directory releases the root,
//! and the next `nix-collect-garbage` takes the toolchain. Finding that at
//! mount time, one tool call into a session, is the confusing failure the
//! root exists to prevent.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why a `nix` call did not give an answer. One type for the whole module:
/// see `chock-nix/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const dev_env = @import("dev_env.zig");
const proc = @import("proc.zig");
const store = @import("store.zig");

const DevShell = @This();

pub const Error = dev_env.Error || store.Error || error{
    /// The cache directory could not be read or written. The session can
    /// still run: `load`'s caller reports this and takes the fallback.
    CacheUnusable,
};

/// Owns every string in `variables` and `store_paths`.
arena: *std.heap.ArenaAllocator,
/// The variables the dev shell states, as `KEY=VALUE`, sorted by name.
/// **`PATH` is one of them**, and it is the one a tool call's `argv[0]` is
/// resolved against.
variables: []const []const u8,
/// Every store path the mount set covers: what the dev shell refers to, and
/// what those refer to, transitively. Sorted.
store_paths: []const []const u8,
/// True when this load evaluated the flake, false when it read the cache.
/// A caller says so on screen, because an evaluation is slow enough that a
/// user deserves to know it is happening.
evaluated: bool,

pub fn deinit(self: *DevShell) void {
    const gpa = self.arena.child_allocator;
    self.arena.deinit();
    gpa.destroy(self.arena);
    self.* = undefined;
}

pub const Options = struct {
    /// The project. `flake.nix` is looked for directly inside it.
    project_root: []const u8,
    /// Chock's own directory for this project's dev shell: the cache and
    /// the garbage collector root links. **It must already exist**, the
    /// same requirement every other directory a session needs already
    /// carries, and `src/session.zig` makes it.
    cache_dir: []const u8,
    /// The environment `nix` itself runs with, and where `dev_env`'s own
    /// small base comes from. This process's own.
    host_env: *const std.process.Environ.Map,
    /// Called once, before a slow evaluation starts, and never on a cache
    /// hit.
    on_evaluate: ?*const fn (project_root: []const u8) void = null,
    /// Where a fault past what `Error` can say is left, **and where the
    /// notices go**: a toolchain that could not be rooted, a cache that could
    /// not be written, and store paths left out of the mount set all leave a
    /// session that runs, so they land here and `load` still answers. A
    /// caller that reads its slot after a `load` that succeeded finds one of
    /// those three, or nothing.
    ///
    /// **What it points at is held by `load`'s own `gpa` argument, and the
    /// caller releases it with the same one.** Never by the arena `load`
    /// works in: that arena is destroyed the moment `load` fails, and the
    /// message is read after that. See `chock-nix/diagnostic.zig`.
    diag: ?*?Diagnostic = null,
};

/// Read this project's dev shell, from the cache when it is current and
/// from Nix when it is not. Answers null when the project has no
/// `flake.nix`, which is the case `load`'s caller reports and takes the
/// fallback for.
pub fn load(gpa: std.mem.Allocator, io: std.Io, options: Options) Error!?DevShell {
    if (!try hasFlake(io, options.project_root)) return null;

    // **The message is held by `gpa`, and the answer by the arena below.**
    // The two allocators are not interchangeable here. A `load` that fails
    // destroys the arena on the way out, and its caller formats the message
    // after that, so a message in the arena is a read of freed memory. That
    // is what this sink exists to state.
    const sink = diagnostic.sinkOf(gpa, options.diag);

    const stamp = try stampOf(gpa, io, options.project_root);

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
        options.host_env,
        sink,
    );
    const script_path = try std.fs.path.join(allocator, &.{ options.cache_dir, script_name });
    try writeFile(io, script_path, script);

    // After the script and not before it, because the script says which bash
    // can read it. See `dev_env.bashFor`.
    const bash_program = try dev_env.bashFor(allocator, io, script, options.host_env);

    const variables = try dev_env.read(allocator, io, .{
        .diag = sink,
        .bash_program = bash_program,
        .env_program = env_program,
        .script_path = script_path,
        .cwd = options.project_root,
        .host_env = options.host_env,
    });

    const roots = try store.pathsIn(allocator, io, variables);
    const store_paths = try store.closureOf(allocator, io, nix_program, options.host_env, roots, sink);

    // Before the cache is written, so a cache that exists is a cache whose
    // paths are held. A failure here is said out loud and is not fatal: a
    // session without a root still works, and only a `nix-collect-garbage`
    // during that session would find it out.
    rootPaths(allocator, io, options, roots) catch |err| {
        _ = diagnostic.note(sink, .{ .toolchain_not_rooted = err });
    };

    // Not fatal: the evaluation in hand is correct whether or not it can be
    // written down. A session that cannot cache pays for the evaluation
    // again next time, and it still gets its own toolchain now.
    writeCache(allocator, io, options.cache_dir, &stamp, variables, store_paths) catch |err| {
        diagnostic.noteNamed(sink, .cache_not_written, options.cache_dir, err) catch {};
    };

    return .{
        .arena = arena,
        .variables = variables,
        .store_paths = store_paths,
        .evaluated = true,
    };
}

/// Make the garbage collector roots, replacing whatever an earlier
/// evaluation of this project left. The old links are removed first: a link
/// left behind holds a toolchain nothing uses any more, and an indirect root
/// stops being a root as soon as its link is gone.
fn rootPaths(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    roots: []const []const u8,
) Error!void {
    const nix_store_program = try proc.resolve(allocator, io, options.host_env, "nix-store");
    const link_prefix = try std.fs.path.join(allocator, &.{ options.cache_dir, root_link_name });

    removeOldRoots(allocator, io, options.cache_dir);

    // No diagnostic here: `load` turns a fault of this whole function into
    // the `toolchain_not_rooted` notice, which is the one a person acts on.
    try store.addRoots(allocator, io, nix_store_program, options.host_env, link_prefix, roots, null);
}

/// Take off every garbage collector root link this project's cache
/// directory holds. Best effort by design: a link that will not come off is
/// a link that still holds a store path, which costs disk and breaks
/// nothing.
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

    // Removed after the walk, never during it: a directory iterator that
    // outlives an entry it deleted is reading a tree that changed under it.
    for (names.items) |name| dir.deleteFile(io, name) catch continue;
}

const script_name = "dev-env.sh";

/// What every garbage collector root link in this directory is called, or
/// starts with.
///
/// **Public because a second writer puts links here.** A provisioned program
/// is held against the collector too, and its links go beside these.
/// `removeOldRoots` takes off everything that starts with this word, so a
/// provisioned program is released by the same thing that releases the dev
/// shell, which is a new evaluation of the flake or a user who removes this
/// directory. A second spelling of the word in the other writer would quietly
/// stop that from happening.
pub const root_link_name = "gcroot";
const stamp_name = "stamp";
const variables_name = "env";
const paths_name = "store-paths";

const stamp_hex_length = 2 * std.crypto.hash.sha2.Sha256.digest_length;

fn hasFlake(io: std.Io, project_root: []const u8) Error!bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/flake.nix", .{project_root}) catch return false;
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

/// A hash of the two files above, length prefixed so that moving a byte from
/// one file to the other changes the answer.
fn stampOf(gpa: std.mem.Allocator, io: std.Io, project_root: []const u8) Error![stamp_hex_length]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    // A version of this file's own format. A stamp written by an older
    // Chock, whose cache holds fields this one does not read, must not
    // read as current.
    hash.update("chock dev shell 1\n");

    for ([_][]const u8{ "flake.nix", "flake.lock" }) |name| {
        const path = try std.fs.path.join(gpa, &.{ project_root, name });
        defer gpa.free(path);

        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_flake_bytes)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // A missing `flake.lock` is ordinary: a flake with no inputs
            // never gets one. It is hashed as a file of no bytes, which is
            // a different stamp from the same flake once it has a lock.
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

/// The largest `flake.nix` or `flake.lock` this hashes. A lock file for a
/// flake with many inputs is a few hundred kilobytes.
const max_flake_bytes: usize = 16 * 1024 * 1024;

const Cached = struct {
    variables: []const []const u8,
    store_paths: []const []const u8,
};

/// The cached evaluation, when the stamp matches and every path it names is
/// still on disk. Anything else answers null, and the caller evaluates.
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

/// Write the evaluation down, the stamp last. A reader takes the stamp as
/// its proof that the other two files are whole, so a crash halfway through
/// leaves a cache that reads as missing rather than as current.
fn writeCache(
    allocator: std.mem.Allocator,
    io: std.Io,
    cache_dir: []const u8,
    stamp: *const [stamp_hex_length]u8,
    variables: []const []const u8,
    store_paths: []const []const u8,
) Error!void {
    const stamp_path = try std.fs.path.join(allocator, &.{ cache_dir, stamp_name });
    // Removed first, so a failure to write either of the two files below
    // cannot leave the old stamp standing over new contents.
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

    // Null, and no `nix` was run to find that out: the answer is a fact
    // about the project, and Chock only claims a dev shell for a project that
    // has a flake.
    const loaded = try load(allocator, std.testing.io, .{
        .project_root = dir_path,
        .cache_dir = dir_path,
        .host_env = &host_env,
    });
    try std.testing.expectEqual(@as(?DevShell, null), loaded);
}

test "a fault outlives the arena that load throws away" {
    // **This is the shape that made `chock doctor` segfault.** `load` builds
    // its answer in an arena and destroys that arena the moment it fails.
    // Its caller reads the message after that. A message that pointed into
    // the arena was a read of freed memory, and the first project with a
    // flake that does not evaluate found it.
    //
    // The debug allocator underneath is what makes this a test and not a
    // hope. A message the arena held is released by the arena and then given
    // to `deinit` below, and this allocator refuses that free instead of
    // taking it. `chock-nix/diagnostic.zig` pins the other half, the read of
    // a string the caller never owned.
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

    // A `nix` that refuses, so this test needs no Nix daemon and no network
    // at all. The line it writes is the one the message must still hold
    // after the arena is gone.
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
    // The fake `nix` first, and the host's own path after it, because `load`
    // resolves `env` before it runs anything.
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
        // A host that ran the fake `nix` and still succeeded has no fault
        // here to pin.
        return error.SkipZigTest;
    } else |err| {
        // A host with no `env` never reaches the fake `nix`.
        if (err == error.ProgramNotFound) return error.SkipZigTest;
        try std.testing.expectEqual(@as(anyerror, error.EvalFailed), err);
    }

    // Read only now, which is the whole point: the arena `load` worked in
    // is already gone.
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
    const first = try stampOf(allocator, std.testing.io, dir_path);

    // The same tree hashes the same, or a cache would never hit at all.
    const again = try stampOf(allocator, std.testing.io, dir_path);
    try std.testing.expectEqualStrings(&first, &again);

    // A lock file that appears is a different dev shell: it pins different
    // inputs, and the stamp names it for exactly this reason.
    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.lock", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ \"nodes\": {} }\n");
    }
    const with_lock = try stampOf(allocator, std.testing.io, dir_path);
    try std.testing.expect(!std.mem.eql(u8, &first, &with_lock));

    {
        var file = try tmp.dir.createFile(std.testing.io, "flake.nix", .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "{ outputs = _: { changed = true; }; }\n");
    }
    const changed = try stampOf(allocator, std.testing.io, dir_path);
    try std.testing.expect(!std.mem.eql(u8, &with_lock, &changed));
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

    // A variable holding a newline, which is why the environment is stored
    // separated by a zero byte and the paths by a newline: a `shellHook`
    // that exports a multi line value is ordinary.
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

    // The `nix-collect-garbage` case: the stamp still matches, because the
    // flake did not change, and the toolchain the cache names is not there
    // any more. Reading it would build a sandbox whose mounts fail one tool
    // call into the session.
    const variables = [_][]const u8{"PATH=/usr/bin"};
    const paths = [_][]const u8{"/nix/store/00000000000000000000000000000000-not-here"};

    const stamp: [stamp_hex_length]u8 = ("c" ** stamp_hex_length).*;
    try writeCache(arena, std.testing.io, dir_path, &stamp, &variables, &paths);

    try std.testing.expectEqual(
        @as(?Cached, null),
        try readCache(arena, std.testing.io, dir_path, &stamp),
    );
}
