//! The toolchain cache: a writable directory for the compiler, kept out of
//! the project and kept across sessions.
//!
//! ## Why this exists
//!
//! **The sandbox was writable in the workspace and nowhere else, so no real
//! toolchain could build.** Measured on 2026-08-21, inside a real tool call:
//!
//! ```
//! zig build-exe m.zig
//! error: unable to resolve zig cache directory: AppDataDirUnavailable
//! ```
//!
//! `lib/chock-nix/dev_env.zig` puts `HOME` in the base set that both of its
//! shells start from, so the subtraction removes it again and the host's
//! `HOME` never reaches the sandbox. **That is correct and it stays**: it is
//! what keeps an API key in the user's own shell away from the agent. The
//! fault was that nothing was put in its place.
//!
//! This is not a fact about Zig. Cargo wants `CARGO_HOME`, Go wants a build
//! cache, and npm, pip and ccache each want a writable place that is not the
//! project. Every one of them finds it below `HOME` or below
//! `XDG_CACHE_HOME`.
//!
//! ## The two variables, and why there are only two
//!
//! `HOME` and `XDG_CACHE_HOME`, and no toolchain specific variable at all.
//! Each of the four compilers above reads one of these two:
//!
//! | Toolchain | What it reads | Where it lands |
//! |---|---|---|
//! | Zig | `ZIG_GLOBAL_CACHE_DIR`, then `XDG_CACHE_HOME` | `<cache>/zig` |
//! | Cargo | `CARGO_HOME`, which defaults to `$HOME/.cargo` | `<home>/.cargo` |
//! | Go | `GOCACHE`, which defaults to the user cache directory | `<cache>/go-build` |
//! | npm, pip, ccache | the same two | `<home>` or `<cache>` |
//!
//! **`XDG_CACHE_HOME` is set below `HOME`**, at the path a program that reads
//! neither still computes for itself. So the two answers agree, and a
//! toolchain that reads `HOME` and one that reads `XDG_CACHE_HOME` write into
//! one tree.
//!
//! ## The hazard, which is wider than the knowledgebase
//!
//! `lib/chock-core/memory.zig` describes a writable directory that is also a
//! channel out of the sandbox. This one is wider in two ways, and both are
//! deliberate:
//!
//! * The knowledgebase is mounted for exactly two tool calls. **This is
//!   mounted for every `run_command`**, because the compiler is what writes
//!   it.
//! * A note has a bound of `memory.max_body_bytes` and a shape a reader can
//!   check. **Cache content is opaque bytes** that only the toolchain reads.
//!
//! The mount is still only `run_command`. A `read_file`, a `write_file`, or a
//! `grep` call is built with a mount tree that has no cache in it, so those
//! calls cannot read or write one byte of it.

const std = @import("std");
const sandbox = @import("chock-sandbox");

const diagnostic = @import("diagnostic.zig");
/// Why a piece of the loop's own scaffolding could not be made or kept. One
/// type for the whole module: see `chock-core/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
/// Where a fault goes, and who owns the path it names. **Every path this file
/// puts in a message is built in a stack buffer of the frame that built it**,
/// so the message keeps a copy and the caller says who holds it.
pub const Sink = diagnostic.Sink;
/// Build a `Sink` from an allocator and the slot a caller passed. Release the
/// message with that same allocator: see `Diagnostic.deinit`.
pub const sinkOf = diagnostic.sinkOf;

/// Where the cache is mounted inside the sandbox **on a build that can move a
/// path**. See `sandboxDirFor`, which is what a caller asks.
///
/// Under `/run/chock`, which `lib/chock-sandbox/Sandbox.zig` names
/// `runtime_prefix` and keeps for Chock's own paths, so the project keeps the
/// root to itself. Written out here, the way `memory.zig` writes out its own
/// `sandbox_dir`, because this library states the path and the sandbox
/// library only carries it.
pub const sandbox_dir = "/run/chock/cache";

/// Where a cache that lives at `host_dir` appears inside the sandbox.
///
/// **Two answers, one per platform, and the second is not a lesser one.** A
/// build that moves a path puts the cache at `sandbox_dir`, so the path is the
/// same in every session and can be a constant. macOS moves no path at all, so
/// the cache appears where it really is and the mount becomes a rule. See
/// `lib/chock-workspace/layout.zig`, which is the same decision for the
/// workspace, and see `environment` for what a person loses.
pub fn sandboxDirFor(host_dir: []const u8) []const u8 {
    return if (sandbox.expresses.moved_paths) sandbox_dir else host_dir;
}

/// What `HOME` is inside the sandbox on a build that can move a path. See
/// `homeIn`, which answers for a cache at any directory.
pub const home_dir = sandbox_dir ++ "/home";

/// What `XDG_CACHE_HOME` is inside the sandbox on such a build. Below
/// `home_dir`, at the path a program that reads neither variable computes for
/// itself: see this file's own top comment.
pub const xdg_cache_dir = home_dir ++ "/.cache";

/// What `HOME` is for a cache that appears at `dir` inside the sandbox.
/// Caller owns the result.
pub fn homeIn(allocator: std.mem.Allocator, dir: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, home_leaf });
}

/// What `XDG_CACHE_HOME` is for a cache that appears at `dir`. Caller owns the
/// result.
pub fn xdgCacheIn(allocator: std.mem.Allocator, dir: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, xdg_cache_leaf });
}

/// The same two directories, relative to the host directory this cache lives
/// in. `makeLayout` builds them, and nothing else may build a path below the
/// cache from parts.
pub const home_leaf = "home";
pub const xdg_cache_leaf = "home/.cache";

/// The environment a `run_command` call gets for a cache at `sandbox_dir`, as
/// `KEY=VALUE`. What `environment` builds when this build moves paths.
pub const variables = [_][]const u8{
    "HOME=" ++ home_dir,
    "XDG_CACHE_HOME=" ++ xdg_cache_dir,
};

/// The names in `variables`, so `environment` can take an earlier answer out
/// of the list rather than leave two entries of one name behind.
pub const variable_names = [_][]const u8{ "HOME", "XDG_CACHE_HOME" };

/// How much one project's cache may hold before `src/run.zig` empties it.
///
/// Two gibibytes. A Zig global cache for a project of this size is a few
/// hundred mebibytes, and a Cargo registry with a large dependency tree is
/// about a gibibyte, so this holds an ordinary project's whole toolchain
/// state and still names a limit a user can act on. **A number, and not "no
/// limit"**: the directory is written by a program the agent chooses and
/// nothing else would ever remove it.
pub const max_bytes: u64 = 2 * 1024 * 1024 * 1024;

/// What one cache directory holds.
pub const Size = struct {
    bytes: u64 = 0,
    files: usize = 0,
    /// True when `measure` stopped at its own `stop_at` and the real total is
    /// larger than `bytes`. A caller that only asks whether the cache is over
    /// the bound does not have to walk the rest of it.
    stopped_early: bool = false,
};

/// What a session start does about a cache of this size. See `verdictFor`.
pub const Verdict = enum {
    /// Under the bound: the session reuses what is there, which is the whole
    /// point of keeping it.
    keep,
    /// Over the bound: the session empties it and says so, and then builds
    /// from nothing.
    empty,
};

/// Whether a cache this size is kept or emptied.
///
/// **Emptying is the answer, and it is a decision.** A cache grows without
/// limit by nature, and nothing else would ever remove it, so a bound with no
/// action behind it is only a number in a document. Removing the oldest
/// entries instead would need Chock to understand a layout every toolchain
/// writes differently, and the cost of being wrong about that is a cache the
/// compiler reads as valid and is not. Emptying costs the time to build again
/// and nothing else, because a cache is rebuildable by definition.
pub fn verdictFor(size: Size) Verdict {
    return if (size.bytes > max_bytes) .empty else .keep;
}

/// The environment `base` becomes for a call whose cache appears at `dir`
/// inside the sandbox: every entry of `base` that does not name one of
/// `variable_names`, and then `HOME` and `XDG_CACHE_HOME` below `dir`.
///
/// **Every entry of the result is owned by `allocator`**, the copied ones as
/// well as the two this builds, so a caller frees the whole thing one way. On
/// a build that moves no path the two are built from a session's own directory
/// and cannot be constants, and a result where some entries were owned and
/// others were not is how a caller frees the wrong half.
///
/// **Chock's own answer wins.** Two entries of one name is undefined in
/// POSIX, and "whichever libc reads first" is not a rule to build on. A dev
/// shell that exports `HOME` in a `shellHook` would otherwise point the
/// compiler at a path that is not mounted in the sandbox at all, which is the
/// same failure this whole file exists to end.
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

/// Free what `environment` answered, here or in `lib/chock-core/scratchpad.zig`.
/// Every entry is owned, so this frees every entry and then the slice.
///
/// **One spelling for both builders**, because a caller that has a cache and a
/// scratchpad holds two of these results and must not free them two different
/// ways.
pub fn freeEnvironment(allocator: std.mem.Allocator, entries: []const []const u8) void {
    for (entries) |entry| allocator.free(entry);
    allocator.free(entries);
}

/// True when this `KEY=VALUE` entry names one of `variable_names`.
fn namesACacheVariable(entry: []const u8) bool {
    const equals = std.mem.indexOfScalar(u8, entry, '=') orelse return false;
    const key = entry[0..equals];
    for (variable_names) |name| {
        if (std.mem.eql(u8, key, name)) return true;
    }
    return false;
}

pub const LayoutError = error{
    /// A directory this cache needs could not be made. Pass a `Diagnostic`
    /// to learn which one and why, because a caller can act on "read only
    /// filesystem" and cannot act on this name alone.
    CacheDirectoryUnwritable,
};

/// Build `dir_path` and the two directories inside it that `variables` name.
///
/// **One owner of the layout.** `src/session.zig` decides where the cache
/// lives, and this decides what is in it, so a directory the environment
/// names can never be missing from the tree the sandbox mounts. A compiler
/// given a `HOME` that does not exist fails in the same way as one with no
/// `HOME` at all.
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

/// True when `dir_path` is already a directory on the host. `src/run.zig`
/// asks before `makeLayout`, so it can say on screen the first time a project
/// gets a cache and stay quiet every time after.
pub fn exists(io: std.Io, dir_path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{}) catch return false;
    dir.close(io);
    return true;
}

/// How much `dir_path` holds, counting every ordinary file below it.
///
/// **Stops as soon as the total passes `stop_at`**, and says so in
/// `Size.stopped_early`. A caller that only asks whether the cache is over
/// `max_bytes` therefore pays for the walk only until the answer is decided,
/// and a caller that wants the real total gives `std.math.maxInt(u64)`.
///
/// A directory that cannot be read at all answers zero rather than an error.
/// This runs at the start of every session, and a cache that cannot be
/// measured is not a reason to refuse to work: the session then behaves like
/// one with an empty cache, which is slow and correct.
///
/// A symbolic link is counted as the link and is never followed, so a link
/// into the Nix store does not count the store.
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

/// Empty the cache and answer what went. The directory itself stays, with the
/// layout `makeLayout` builds, so the next tool call has somewhere to write.
///
/// **Clearing is one step**, the same rule `memory.clear` follows: a cache a
/// user cannot clear is a cache a user cannot trust. Unlike a knowledgebase
/// this removes everything below the directory, whatever its name: cache
/// content is written by a compiler and has no extension Chock can recognise.
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

        // The names first, then the deletes: deleting while a directory is
        // walked is undefined on more than one filesystem. The same shape
        // `memory.clear` uses, for the same reason.
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

/// **`path` is borrowed for the length of this call only.** Every caller
/// builds it in a buffer of its own frame, so `notePath` copies it into the
/// sink's own allocator.
fn makeDirAll(io: std.Io, path: []const u8, diag: ?Sink) LayoutError!void {
    makeDirAllInner(io, path) catch |err| {
        diagnostic.notePath(diag, .cache_directory_not_made, path, err);
        return error.CacheDirectoryUnwritable;
    };
}

/// The same recursive create `src/session.zig` makes for a session directory.
/// Here rather than there because this file owns the layout, and a second
/// spelling of the layout is how two paths quietly stop agreeing.
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

test "the cache environment names HOME and XDG_CACHE_HOME inside the sandbox, and XDG below HOME" {
    // The whole fix in one assertion: a tool call gets a `HOME`, and it names
    // a path the sandbox mounts. Before this, `HOME` was absent and
    // `zig build-exe` answered `AppDataDirUnavailable`.
    const allocator = testing.allocator;

    const built = try environment(allocator, &.{}, sandbox_dir);
    defer freeEnvironment(allocator, built);

    try testing.expectEqual(@as(usize, 2), built.len);
    try testing.expectEqualStrings("HOME=/run/chock/cache/home", built[0]);
    try testing.expectEqualStrings("XDG_CACHE_HOME=/run/chock/cache/home/.cache", built[1]);

    // The second is below the first. A program that reads `XDG_CACHE_HOME`
    // and one that computes `$HOME/.cache` for itself must land in one tree,
    // or a toolchain that reads the wrong one caches into a place the next
    // session's measurement never sees.
    try testing.expect(std.mem.startsWith(u8, xdg_cache_dir, home_dir ++ "/"));
    try testing.expectEqualStrings(home_dir ++ "/.cache", xdg_cache_dir);
}

test "a cache appears under the runtime prefix, or at its own path where no path can move" {
    // **The macOS blocker, in one assertion.** A bind whose target differs from
    // its source is what `darwin/driver.zig`'s own `expressibleOn` refuses, and
    // a session that asked for one had every tool call refused with
    // `NoMountNamespace`. Measured on 2026-08-25 on the Darwin box, before this
    // existed: `chock doctor` named `/run/chock/scratch` as the reason.
    //
    // Mutation check: answer `sandbox_dir` in both arms and the second half
    // fails on Darwin; answer `host_dir` in both and the first half fails on
    // Linux, and with it every path Linux keeps constant.
    const allocator = testing.allocator;
    const host_dir = "/somewhere/on/the/host/cache";

    if (sandbox.expresses.moved_paths) {
        try testing.expectEqualStrings(sandbox_dir, sandboxDirFor(host_dir));
    } else {
        try testing.expectEqualStrings(host_dir, sandboxDirFor(host_dir));
    }

    // Whatever the platform answers, the two variables are built below it, so a
    // compiler finds its own `HOME` inside the directory the mount really
    // carries.
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
    // A cache inside the project would land in the diff, reach
    // `workspace.apply`, and turn up in the user's repository. Both paths
    // below sit under `/run/chock`, which is the prefix
    // `lib/chock-sandbox/Sandbox.zig` keeps for Chock's own directories.
    try testing.expect(std.mem.startsWith(u8, sandbox_dir, "/run/chock/"));
    try testing.expect(std.mem.startsWith(u8, home_dir, sandbox_dir ++ "/"));
    // And it is not the knowledgebase's own directory: two writable mounts,
    // two paths, so one cannot be read through the other.
    try testing.expect(!std.mem.eql(u8, sandbox_dir, "/run/chock/memory"));
}

test "a HOME the dev shell states is replaced and never left beside Chock's own" {
    // Two entries of one name is undefined in POSIX. A `shellHook` that
    // exports `HOME` would otherwise point the compiler at a path that is not
    // mounted in the sandbox at all.
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
    // A compiler given a `HOME` that does not exist fails the same way as one
    // with no `HOME` at all, so the two paths in `variables` must be real
    // directories before the first tool call runs.
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

    // Named from `home_leaf` and `xdg_cache_leaf`, not typed out again, so a
    // layout that moves moves this test with it.
    const home = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, home_leaf });
    defer allocator.free(home);
    const xdg = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cache_dir, xdg_cache_leaf });
    defer allocator.free(xdg);
    try testing.expect(exists(testing.io, home));
    try testing.expect(exists(testing.io, xdg));

    // Called a second time on a directory that already exists, because every
    // session after the first calls it exactly that way.
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

    // An empty cache is zero, which is what a project's first session sees.
    const empty = measure(allocator, testing.io, cache_dir, max_bytes);
    try testing.expectEqual(@as(u64, 0), empty.bytes);
    try testing.expectEqual(@as(usize, 0), empty.files);

    // Two files, one of them below the directory `XDG_CACHE_HOME` names, so
    // the walk is a real walk and not a listing of the top level.
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

    // Over a bound of 100 bytes the walk stops as soon as the answer is
    // decided, so the total it reports is short of the real one on purpose.
    const over = measure(allocator, testing.io, cache_dir, 100);
    try testing.expect(over.stopped_early);
    try testing.expect(over.bytes > 100);
    try testing.expect(over.bytes <= filled.bytes);
}

test "a cache over the bound is emptied, and one under it is kept" {
    try testing.expectEqual(Verdict.keep, verdictFor(.{}));
    try testing.expectEqual(Verdict.keep, verdictFor(.{ .bytes = max_bytes, .files = 1000 }));
    try testing.expectEqual(Verdict.empty, verdictFor(.{ .bytes = max_bytes + 1, .files = 1001 }));

    // A measurement that stopped early is over the bound by construction:
    // `measure` only stops once the total has passed its own stopping point,
    // so a session start that measures against `max_bytes` still decides
    // correctly on the short answer.
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

    // Nothing is left, and the directories the environment names are still
    // there: the next tool call must have somewhere to write.
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
    // `chock cache clear` is the command a person reaches this on. The top
    // level directory is the caller's own slice and never dangled. **The two
    // below it are built in a `[std.fs.max_path_bytes]u8` buffer of
    // `makeLayout`'s own frame**, and the message used to point at that
    // buffer. `dirtyTheFrame` writes over it, which is what a printer does by
    // accident.
    //
    // The debug allocator underneath is what makes this a test and not a
    // hope, and it also fails on a message nobody released.
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(testing.io, &path_buffer);

    // An ordinary file where the cache belongs. The top level is then made
    // without a fault, because a name that is already there is not one this
    // has to make, and the first directory inside it cannot be made.
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

/// Write known bytes over the frame `makeLayout` used. A printer does this by
/// accident, which is why a borrowed path printed a row of whatever byte the
/// last call left.
fn dirtyTheFrame() u64 {
    var scratch: [2 * std.fs.max_path_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}
