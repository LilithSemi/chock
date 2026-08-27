//! What a container image states: the environment every tool call runs with,
//! and the directories the sandbox mounts for it.
//!
//! ## What the extraction refuses, and why that is worth having
//!
//! `std.tar.extract` is pure Zig, so the rules are this project's own rather
//! than a system `tar`'s defaults:
//!
//! * **A path that leaves the tree is refused.** An entry whose name walks out
//!   of the target directory is not written.
//! * **Only the executable bit is kept.** `ExtractOptions.mode_mode` is
//!   `.executable_bit_only`, so a set-user-id bit in the image is dropped and
//!   never reaches the disk. `std.tar.ExtractOptions.ModeMode` has two members
//!   and neither one can write that bit, so this is a property of the
//!   mechanism and not only of the option chosen. A system `tar -p` run as
//!   root would write it, which is one more reason the extraction is pure Zig.
//!   A read only bind mount in `chock-sandbox` also carries `NOSUID`, so this
//!   is the second of two answers, not the only one. Measured on 2026-08-25:
//!   `debian:stable-slim` ships seven set-user-id programs in its tar, and
//!   none of them reaches the disk with the bit on.
//! * **A device node is not written.** `std.tar` has no file kind for one, so
//!   it lands in the diagnostics and the rest of the tree is still written.
//!   Measured on 2026-08-25: `docker export` writes `/dev/console` as an empty
//!   ordinary file, so a base image produces none of these.
//!
//! **A hard link is refused the same way a device node is**, because `std.tar`
//! has no file kind for one either. An image that uses hard links loses those
//! entries. `Diagnostic.entry_refused` says how many were lost and names the
//! first, because a program that needs one of them fails inside the sandbox
//! and the reason would otherwise be very hard to find.
//!
//! ## A moved tag waits for the sessions that are running
//!
//! One directory holds the tree for one image reference, and every session on
//! that reference shares it. A session keeps a shared lock on that directory
//! from `load` to `deinit`, and the session that wants to replace the tree has
//! to take the same lock exclusively first. See `lock.zig`.
//!
//! **So a tag that moves is not picked up until the last session using the old
//! tree ends.** That is a real cost and it was chosen rather than assumed. The
//! alternative is worse: a tree removed under a running session takes every
//! tool call of it with no warning, an hour into the work, and the session
//! cannot recover, while a session that starts on yesterday's tag is refused at
//! its first second with a sentence saying exactly what to do.
//!
//! A tree named after the digest would avoid the wait, because two digests
//! would then be two directories. It is not what this does, for one reason: a
//! tree nothing removes grows without bound, and the reaper that would remove
//! one needs this very lock to know that no session is on it. The wait is the
//! smaller thing to carry.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
/// The rule for an image reference. Named `ref` here because this struct has
/// its own `reference` field, which is the value the rule is applied to.
const ref = @import("reference.zig");
const lock = @import("lock.zig");
const Runtime = @import("Runtime.zig");

const Image = @This();

pub const Error = Runtime.Error || error{
    /// The image inspection could not be read. The runtime answered something
    /// this file does not understand.
    InspectUnreadable,
    /// The root filesystem could not be written to the cache directory.
    ExtractFailed,
    /// The cache directory could not be read or written.
    CacheUnusable,
};

/// One directory of the image, and where it belongs inside the sandbox.
pub const Mount = struct {
    /// The path on the host, inside the extracted tree.
    source: []const u8,
    /// The path inside the sandbox. An image root filesystem is a whole `/`,
    /// so a target is not its source. **That is why this arrangement is Linux
    /// only**: `lib/chock-sandbox/darwin/driver.zig` refuses a bind whose
    /// target is not its source, and that gap is permanent.
    target: []const u8,
    /// Always true. The extracted tree is shared by every session that uses
    /// this image, so no tool call may write into it.
    read_only: bool = true,
    /// Whether the source is a directory or a regular file.
    ///
    /// **A caller needs this to pick a Landlock rule.** The kernel refuses
    /// `AccessFs.read_only` over a path that is not a directory, and answers
    /// `EINVAL`. `lib/chock-sandbox/linux/landlock.zig` carries the
    /// measurement: a Nix dev shell whose mount set held a single file broke
    /// every tool call in the session. An image has such entries too, and a
    /// real one was measured on 2026-08-25: `docker export` writes
    /// `.dockerenv` as a regular file at the top of a Debian tree.
    kind: Kind,

    pub const Kind = enum { directory, file };
};

/// Whether `load` may fetch an image it does not find.
pub const Pull = enum {
    /// Never fetch. An image that is not on the disk is a refusal that names
    /// the command to run. **The default**, because a session must not depend
    /// on a network reaching a registry.
    never,
    /// Fetch an image that is not on the disk. Still on the host, still before
    /// any sandbox exists.
    if_missing,
};

/// Owns every string below.
arena: *std.heap.ArenaAllocator,
kind: Runtime.Kind,
/// What privilege that runtime holds. Carried here so that a caller which
/// reports an image reports the trust position with it. See `Runtime.Trust`.
trust: Runtime.Trust,
reference: []const u8,
/// The image's own identifier, which is a content hash. The cache stamp.
digest: []const u8,
/// The variables the image states, as `KEY=VALUE`. **`PATH` is normally one
/// of them**, and it is the one a tool call's `argv[0]` is resolved against.
/// An image that states none gives an empty list, and the caller decides what
/// a tool call gets then.
variables: []const []const u8,
/// The image's own `WorkingDir`, or `/` when it states none.
workdir: []const u8,
/// The extracted tree on the host.
rootfs: []const u8,
/// What the sandbox binds. Sorted by target.
mounts: []const Mount,
/// True when this load extracted the image, false when it read the cache. A
/// caller says so on screen, because an extraction is slow enough that a user
/// deserves to know it is happening.
extracted: bool,
/// The shared lock that says this session is using `rootfs` right now, held
/// from `load` until `deinit`. See `lock.use_file_name`.
///
/// **This is why an `Image` has a lifetime and not only a value.** The mount
/// set above names paths in a directory every session on this image shares.
/// Without this lock, a second session whose digest differs would take the
/// extract lock legitimately, remove the tree, and write another one, and every
/// tool call of this session would then bind a path that is gone.
in_use: lock.Held,

/// Release the tree and every string of this image.
///
/// **`io`, because this releases a lock.** A session holds the image's tree for
/// its whole length and lets go here, and until it does, no other session may
/// replace that tree. See `in_use`.
///
/// A session that never reaches this still lets go. `flock` belongs to an open
/// file description and the kernel drops it when the process ends, however it
/// ends, so a crash, an interrupt or a `SIGKILL` frees the image as surely as
/// this function does.
pub fn deinit(self: *Image, io: std.Io) void {
    self.in_use.release(io);
    const gpa = self.arena.child_allocator;
    self.arena.deinit();
    gpa.destroy(self.arena);
    self.* = undefined;
}

/// What one `load` produced: an image, or one sentence saying why not.
///
/// **A refusal is not an `Error`.** It is a fact about the request that a
/// person reads and can act on. Only a fault that says nothing about the
/// request reaches the caller as an error. The same rule
/// `lib/chock-nix/provision.zig` states for its own `Answer`.
pub const Answer = union(enum) {
    /// Owns its own arena **and a lock on the extracted tree**. The caller
    /// releases both with `Image.deinit`, and holds it for the whole session:
    /// see `Image.in_use`.
    provided: Image,
    /// **Owned by the `gpa` `load` was given**, and released with
    /// `gpa.free`. It cannot come from the image's own arena, because that
    /// arena is destroyed on the way out of every refusing branch.
    refused: []const u8,
};

pub const Options = struct {
    /// The image. **From the project's own configuration, never from the
    /// model**: see `chock-container/reference.zig`.
    reference: []const u8,
    /// Chock's own directory for this image: the stamp and the extracted tree.
    /// **It must already exist**, the same requirement `DevShell.Options`
    /// carries. One directory per image, and `reference.directoryName` is what
    /// names it.
    cache_dir: []const u8,
    /// Which runtime, and what privilege it holds. From `Runtime.detect`.
    kind: Runtime.Kind,
    trust: Runtime.Trust,
    runner: Runtime.Runner,
    pull: Pull = .never,
    /// Called once, before a slow extraction starts, and never on a cache hit.
    on_extract: ?*const fn (reference: []const u8) void = null,
    /// Called once, when another session is already extracting this image and
    /// this one is about to wait for it. **Before the wait, never after**: a
    /// session that goes quiet for a minute with nothing on screen reads as a
    /// hang.
    on_wait: ?*const fn (reference: []const u8) void = null,
    /// How long this session waits for the one that holds the cache. See
    /// `lock.default_wait_ns`. Running out of it is a refusal and not an error.
    wait_ns: u64 = lock.default_wait_ns,
    /// Where a fault past what `Error` can say is left, **and where the two
    /// notices go**. A cache that could not be written and a refused root
    /// filesystem entry both leave a session that works, so they land here and
    /// `load` still answers.
    ///
    /// **A `Sink`, so the message never comes from this file's own arena.**
    /// `load` builds a private arena and destroys it on every error path, and a
    /// message that pointed into it was read after the free by the very next
    /// line of the caller. Build one with `diagnostic.sinkOf` and the caller's
    /// own allocator, never with the arena.
    diag: ?diagnostic.Sink = null,
};

/// Read this image, from the cache when it is current and from the runtime
/// when it is not.
///
/// **Give this an arena's parent allocator.** `load` makes an arena of its own
/// and every string of the answer comes out of it, the same convention
/// `DevShell.load` follows.
///
/// **What it hands back has a lifetime.** The answer holds a shared lock on the
/// extracted tree until `Image.deinit`, so the caller must keep the image for
/// as long as any tool call binds its mount set. See `Image.in_use` and this
/// file's own top comment for the trade that choice makes.
pub fn load(gpa: std.mem.Allocator, io: std.Io, options: Options) Error!Answer {
    ref.check(options.reference) catch |err| {
        return .{ .refused = try ref.refusalText(gpa, options.reference, err) };
    };

    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    const inspected = switch (try inspect(allocator, io, options)) {
        .refused => |text| {
            // The refusal outlives the arena, because the arena goes away with
            // this branch.
            const copy = try gpa.dupe(u8, text);
            arena.deinit();
            gpa.destroy(arena);
            return .{ .refused = copy };
        },
        .read => |value| value,
    };

    const rootfs = try std.fs.path.join(allocator, &.{ options.cache_dir, rootfs_name });

    // **Held over the check, the extraction and the reading of the tree.** An
    // image cache is shared on purpose, so two cold sessions on one image each
    // removed and rebuilt what the other was reading. Measured on 2026-08-25,
    // before this lock: 54 of 100 four way runs failed outright on
    // `alpine:3.20`, and four way on `debian:bookworm-slim` extracted the image
    // four times into one directory. See `lock.zig`.
    var guard = switch (takeCacheLock(io, options)) {
        .held => |held| held,
        .busy => |seconds| return refuse(
            gpa,
            arena,
            "another session is writing the files of {s} to disk, and it did not finish inside " ++
                "{d} seconds. Chock waits for that session rather than extracting the same image " ++
                "twice into {s}. Run this again once it has finished.",
            .{ options.reference, seconds, options.cache_dir },
        ),
        .unusable => |err| return refuse(
            gpa,
            arena,
            "the file {s}/{s} could not be used ({s}). Chock takes a lock there so that two " ++
                "sessions do not write the files of {s} into one directory at the same time.",
            .{ options.cache_dir, lock.file_name, @errorName(err), options.reference },
        ),
    };
    defer guard.release(io);

    const current = try isCurrent(io, options.cache_dir, options.kind, inspected.digest, rootfs);

    // **Taken before anything is removed, and kept for the whole session.** The
    // extract lock above covers this moment. This one covers the hour after it.
    // Shared when the tree on the disk is already the wanted one, exclusive
    // when this session is about to replace it, and every session that reads
    // the tree keeps its shared hold until `Image.deinit`. See `lock.zig` for
    // why the two are separate files.
    var in_use = switch (takeUseLock(io, options, current)) {
        .held => |held| held,
        .busy => return refuse(
            gpa,
            arena,
            "the files of {s} in {s} are not the ones this session needs, and another session " ++
                "is using them right now. That happens when the tag has moved, or when the other " ++
                "session used a different container runtime. Chock never replaces an image tree " ++
                "under a session that is running, because every tool call of that session binds " ++
                "it. Run this again once those sessions have ended.",
            .{ options.reference, options.cache_dir },
        ),
        .unusable => |err| return refuse(
            gpa,
            arena,
            "the file {s}/{s} could not be used ({s}). Chock takes a lock there for the length " ++
                "of a session, so that no other session removes the files of {s} while this one " ++
                "is running.",
            .{ options.cache_dir, lock.use_file_name, @errorName(err), options.reference },
        ),
    };
    errdefer in_use.release(io);

    if (!current) {
        if (options.on_extract) |report| report(options.reference);
        try extract(allocator, io, options, rootfs);
        // Written after the tree, so a stamp that exists is a stamp over a
        // tree that is whole. A crash halfway through leaves a cache that
        // reads as missing rather than as current. Not fatal: the tree in hand
        // is correct whether or not the stamp can be written, and a session
        // that cannot write one pays for the extraction again next time.
        writeStamp(allocator, io, options.cache_dir, options.kind, inspected.digest) catch |err| {
            diagnostic.noteNamed(options.diag, .cache_not_written, options.cache_dir, err) catch {};
        };
        // From here this session is an ordinary reader of the tree it just
        // wrote. Holding the use lock exclusively any longer would refuse every
        // other session on this image for as long as this one runs.
        in_use.downgrade(io) catch |err| {
            in_use.release(io);
            return refuse(
                gpa,
                arena,
                "the files of {s} were written to {s} and the lock on them could not be shared " ++
                    "with other sessions ({s}). Run this again: the files are on the disk now, " ++
                    "so the next session reads them without extracting anything.",
                .{ options.reference, options.cache_dir, @errorName(err) },
            );
        };
    }

    return .{ .provided = .{
        .arena = arena,
        .kind = options.kind,
        .trust = options.trust,
        .reference = try allocator.dupe(u8, options.reference),
        .digest = inspected.digest,
        .variables = inspected.variables,
        .workdir = inspected.workdir,
        .rootfs = rootfs,
        .mounts = try mountsIn(allocator, io, rootfs, options.diag),
        .extracted = !current,
        .in_use = in_use,
    } };
}

/// Take the lock that says this session is using the tree, in the mode this
/// load needs.
///
/// **It never waits, and that is the difference between this lock and the
/// other one.** The extract lock waits minutes, because what it waits for is an
/// extraction that finishes in seconds. This one would be waiting for a whole
/// session, which lasts as long as a person is working, so a bound of any size
/// would be a session that stands still and then refuses anyway. It refuses at
/// once and says what to do.
///
/// **The shared ask cannot really be busy.** The exclusive mode is taken only
/// by a caller that holds the extract lock, and this caller holds it, so no
/// other process can be in that state. It is still answered rather than
/// asserted, because a refusal a person can read is worth more than a crash.
fn takeUseLock(io: std.Io, options: Options, current: bool) lock.Answer {
    return lock.take(io, options.cache_dir, .{
        .name = lock.use_file_name,
        .mode = if (current) .shared else .exclusive,
        .wait_ns = 0,
    });
}

/// Take the cache lock, and tell the caller before any waiting starts.
///
/// **Two asks, and the first one does not wait.** A session that is about to
/// stand still for a minute has to say so first, and a lock that took a
/// callback of its own would have to carry the caller's context for one line of
/// text.
fn takeCacheLock(io: std.Io, options: Options) lock.Answer {
    const first = lock.take(io, options.cache_dir, .{ .wait_ns = 0 });
    switch (first) {
        .busy => {},
        .held, .unusable => return first,
    }

    if (options.on_wait) |report| report(options.reference);
    return lock.take(io, options.cache_dir, .{ .wait_ns = options.wait_ns });
}

/// A refusal built with the caller's own allocator, releasing the arena on the
/// way out. **The message is built first**, because its arguments can point
/// into the arena this destroys.
fn refuse(
    gpa: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    comptime fmt: []const u8,
    args: anytype,
) Error!Answer {
    const text = try std.fmt.allocPrint(gpa, fmt, args);
    arena.deinit();
    gpa.destroy(arena);
    return .{ .refused = text };
}

/// True when this image is already on the disk, so a session that names it
/// would start.
///
/// **It inspects and never extracts, and it never fetches.** One `image
/// inspect` and nothing else, so a report can ask the question without paying
/// for the answer `load` produces. `Options.cache_dir`, `Options.pull` and
/// `Options.on_extract` are not read at all.
///
/// A reference that breaks the rule answers false rather than an error: a name
/// nothing may run is a name no image is on the disk under. The caller states
/// the rule itself, with `reference.check`, where a person can act on it.
pub fn present(allocator: std.mem.Allocator, io: std.Io, options: Options) Error!bool {
    ref.check(options.reference) catch return false;

    var output = try runInspect(allocator, io, options);
    defer output.deinit(allocator);
    return output.succeeded();
}

const Inspected = struct {
    digest: []const u8,
    variables: []const []const u8,
    workdir: []const u8,
};

const Inspection = union(enum) {
    read: Inspected,
    refused: []const u8,
};

fn inspect(allocator: std.mem.Allocator, io: std.Io, options: Options) Error!Inspection {
    var first = try runInspect(allocator, io, options);
    defer first.deinit(allocator);

    if (first.succeeded()) return .{ .read = try parseInspect(allocator, first.stdout) };

    if (options.pull == .never) {
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "the image {s} is not on this machine. Run `{s} pull {s}` before the session. " ++
                "Chock never fetches an image during a session, because a tool call has no network.",
            .{ options.reference, options.kind.program(), options.reference },
        ) };
    }

    var pulled = try options.runner.run(allocator, io, &.{ "pull", "--", options.reference });
    defer pulled.deinit(allocator);
    if (!pulled.succeeded()) {
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "the image {s} could not be fetched: {s}",
            .{ options.reference, tailOf(pulled.stderr) },
        ) };
    }

    var second = try runInspect(allocator, io, options);
    defer second.deinit(allocator);
    if (!second.succeeded()) {
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "the image {s} was fetched and still cannot be read: {s}",
            .{ options.reference, tailOf(second.stderr) },
        ) };
    }

    return .{ .read = try parseInspect(allocator, second.stdout) };
}

fn runInspect(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
) Error!@import("proc.zig").Output {
    return options.runner.run(allocator, io, &.{
        "image",
        "inspect",
        "--format",
        "{{json .}}",
        // Every runtime here takes this, measured on 2026-08-25. It is a
        // second bound and not the only one: `reference.check` already refuses
        // a value that could be read as an option.
        "--",
        options.reference,
    });
}

/// The shape this file reads out of an image inspection. Every other field is
/// ignored, which is what `ignore_unknown_fields` is for: a runtime that adds
/// a field must not break a session.
const InspectJson = struct {
    Id: []const u8,
    Config: ?ConfigJson = null,

    const ConfigJson = struct {
        Env: ?[]const []const u8 = null,
        WorkingDir: ?[]const u8 = null,
    };
};

/// Read an image inspection. `allocator` must be an arena: the parse is leaky
/// on purpose, because every string of it is held for the length of a session.
fn parseInspect(allocator: std.mem.Allocator, text: []const u8) Error!Inspected {
    const parsed = std.json.parseFromSliceLeaky(InspectJson, allocator, text, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InspectUnreadable;

    if (parsed.Id.len == 0) return error.InspectUnreadable;

    const config = parsed.Config orelse InspectJson.ConfigJson{};
    const workdir = if (config.WorkingDir) |dir|
        (if (dir.len == 0) "/" else dir)
    else
        "/";

    return .{
        .digest = parsed.Id,
        .variables = config.Env orelse &.{},
        .workdir = workdir,
    };
}

/// The tail of what a runtime said, which is the part a person acts on.
fn tailOf(stderr: []const u8) []const u8 {
    const said = std.mem.trim(u8, stderr, " \t\r\n");
    if (said.len <= max_said_bytes) return said;
    return said[said.len - max_said_bytes ..];
}

const max_said_bytes: usize = 512;

const rootfs_name = "rootfs";
const stamp_name = "stamp";
const tar_name = "image.tar";

/// A version of this file's own cache format. A stamp written by an older
/// Chock, whose tree was built by rules this one does not have, must not read
/// as current.
const stamp_version = "chock container image 1";

/// Turn the image into a tree under `rootfs`. Replaces whatever is there.
fn extract(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    rootfs: []const u8,
) Error!void {
    var cache = std.Io.Dir.openDirAbsolute(io, options.cache_dir, .{}) catch return error.CacheUnusable;
    defer cache.close(io);

    // The stamp goes first, so a run that dies partway through cannot leave an
    // old stamp standing over a tree that is half replaced.
    cache.deleteFile(io, stamp_name) catch {};
    cache.deleteTree(io, rootfs_name) catch return error.CacheUnusable;
    cache.deleteFile(io, tar_name) catch {};

    const tar_path = try std.fs.path.join(allocator, &.{ options.cache_dir, tar_name });
    // The tar is large and is never needed again. It comes off the disk on
    // every path out of this function, including a failure.
    defer cache.deleteFile(io, tar_name) catch {};

    const container = try create(allocator, io, options);
    try exportRootfs(allocator, io, options, container, tar_path);
    // Best effort. A container that will not come off costs a little disk and
    // breaks nothing, and the tar is already written.
    remove(allocator, io, options, container) catch {};

    cache.createDirPath(io, rootfs_name) catch return error.CacheUnusable;
    var tree = cache.openDir(io, rootfs_name, .{}) catch return error.CacheUnusable;
    defer tree.close(io);

    try unpack(allocator, io, tar_path, tree, options.diag);
    _ = rootfs;
}

/// Make a container that is never started, and answer its identifier.
///
/// The command it is given never runs. `create` records it and stops. Naming
/// one anyway is what lets this work on an image that states no command of its
/// own, which would otherwise be refused.
fn create(allocator: std.mem.Allocator, io: std.Io, options: Options) Error![]const u8 {
    var output = try options.runner.run(allocator, io, &.{
        "create",
        "--",
        options.reference,
        never_run_command,
    });
    defer output.deinit(allocator);

    if (!output.succeeded()) {
        try diagnostic.noteRefusal(options.diag, .container_create, output.stderr);
        return error.ExtractFailed;
    }

    const id = std.mem.trim(u8, output.stdout, " \t\r\n");
    if (id.len == 0) return error.ExtractFailed;
    return allocator.dupe(u8, id);
}

const never_run_command = "/chock-container-never-runs";

fn exportRootfs(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    container: []const u8,
    tar_path: []const u8,
) Error!void {
    // `--output`, so the runtime writes the tar itself. A root filesystem is
    // gigabytes for a real image, and reading one through a pipe into this
    // process's memory would be the wrong shape at any size.
    var output = try options.runner.run(allocator, io, &.{
        "export",
        "--output",
        tar_path,
        "--",
        container,
    });
    defer output.deinit(allocator);

    if (!output.succeeded()) {
        try diagnostic.noteRefusal(options.diag, .container_export, output.stderr);
        return error.ExtractFailed;
    }
}

fn remove(allocator: std.mem.Allocator, io: std.Io, options: Options, container: []const u8) Error!void {
    var output = try options.runner.run(allocator, io, &.{ "rm", "--", container });
    defer output.deinit(allocator);
    if (!output.succeeded()) return error.ExtractFailed;
}

/// Write the tar into `tree`. See this file's own top comment for every rule
/// this extraction applies and the reason for each.
fn unpack(
    allocator: std.mem.Allocator,
    io: std.Io,
    tar_path: []const u8,
    tree: std.Io.Dir,
    diag: ?diagnostic.Sink,
) Error!void {
    var file = std.Io.Dir.openFileAbsolute(io, tar_path, .{}) catch return error.ExtractFailed;
    defer file.close(io);

    const buffer = try allocator.alloc(u8, read_buffer_bytes);
    defer allocator.free(buffer);
    var file_reader = file.reader(io, buffer);

    var diagnostics = std.tar.Diagnostics{ .allocator = allocator };
    defer diagnostics.deinit();

    std.tar.extract(io, tree, &file_reader.interface, .{
        // Every entry of an exported root filesystem is already at the top of
        // the tar. Nothing is stripped.
        .strip_components = 0,
        // The set-user-id bit never reaches the disk. See this file's own top
        // comment.
        .mode_mode = .executable_bit_only,
        .diagnostics = &diagnostics,
    }) catch return error.ExtractFailed;

    if (diagnostics.errors.items.len != 0) {
        try diagnostic.noteEntry(
            diag,
            firstRefusedName(diagnostics.errors.items[0]),
            diagnostics.errors.items.len,
        );
    }
}

/// How much of the tar is read at a time. A tar block is 512 bytes and a real
/// image holds millions of them, so a small buffer costs a great many reads.
const read_buffer_bytes: usize = 256 * 1024;

fn firstRefusedName(err: std.tar.Diagnostics.Error) []const u8 {
    return switch (err) {
        .unable_to_create_sym_link => |value| value.file_name,
        .unable_to_create_file => |value| value.file_name,
        .unsupported_file_type => |value| value.file_name,
        .components_outside_stripped_prefix => |value| value.file_name,
    };
}

/// True when the cache holds this exact image, from this runtime, and the tree
/// is still on the disk.
fn isCurrent(
    io: std.Io,
    cache_dir: []const u8,
    kind: Runtime.Kind,
    digest: []const u8,
    rootfs: []const u8,
) Error!bool {
    var cache = std.Io.Dir.openDirAbsolute(io, cache_dir, .{}) catch return error.CacheUnusable;
    defer cache.close(io);

    var buffer: [max_stamp_bytes]u8 = undefined;
    const file = cache.openFile(io, stamp_name, .{}) catch return false;
    defer file.close(io);

    var reader = file.reader(io, &buffer);
    const written = reader.interface.allocRemaining(std.heap.page_allocator, .limited(max_stamp_bytes)) catch return false;
    defer std.heap.page_allocator.free(written);

    var wanted_buffer: [max_stamp_bytes]u8 = undefined;
    const wanted = stampText(&wanted_buffer, kind, digest) catch return false;
    if (!std.mem.eql(u8, written, wanted)) return false;

    // The stamp still matching does not mean the tree is there. A user who
    // clears a temporary directory leaves exactly this state, and finding it
    // at mount time, one tool call into a session, is the confusing failure
    // this check prevents.
    _ = std.Io.Dir.cwd().statFile(io, rootfs, .{}) catch return false;
    return true;
}

/// Write the stamp for this runtime and this digest.
///
/// **A half written stamp cannot read as current.** The write truncates first,
/// so a torn one leaves a prefix of the text, and `isCurrent` compares the whole
/// content against the text it expects rather than a prefix of it. The lock
/// closes that window as well, and the property is worth stating without it: a
/// stamp is the one thing a cold session trusts.
fn writeStamp(
    allocator: std.mem.Allocator,
    io: std.Io,
    cache_dir: []const u8,
    kind: Runtime.Kind,
    digest: []const u8,
) Error!void {
    var buffer: [max_stamp_bytes]u8 = undefined;
    const text = stampText(&buffer, kind, digest) catch return error.CacheUnusable;

    const path = try std.fs.path.join(allocator, &.{ cache_dir, stamp_name });
    defer allocator.free(path);

    var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch return error.CacheUnusable;
    defer file.close(io);
    file.writeStreamingAll(io, text) catch return error.CacheUnusable;
}

/// The stamp carries the runtime as well as the digest. Two runtimes can hold
/// an image with the same identifier and export a tree that differs, and a
/// person who moves from one to the other must get a fresh extraction rather
/// than the other runtime's tree.
fn stampText(buffer: []u8, kind: Runtime.Kind, digest: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}\n{s}\n{s}\n", .{ stamp_version, kind.program(), digest });
}

const max_stamp_bytes: usize = 512;

/// Every top level entry of the extracted tree, and where it belongs inside
/// the sandbox. Sorted by target.
///
/// **A top level symbolic link is followed, and the thing it names is mounted
/// at the link's own path.** This is not a detail of one image. Measured on
/// 2026-08-25: in `debian:stable-slim`, `/bin`, `/lib` and `/sbin` are all
/// symbolic links into `/usr`. A bind mount cannot be a symbolic link, so
/// without this a Debian image would give a sandbox with no `/bin` at all, and
/// nothing in it would start. See `linkMount` for how the link is resolved and
/// why it is never resolved against the host.
fn mountsIn(
    allocator: std.mem.Allocator,
    io: std.Io,
    rootfs: []const u8,
    diag: ?diagnostic.Sink,
) Error![]const Mount {
    var dir = std.Io.Dir.openDirAbsolute(io, rootfs, .{ .iterate = true }) catch return error.CacheUnusable;
    defer dir.close(io);

    var found: std.ArrayList(Mount) = .empty;
    errdefer found.deinit(allocator);

    var it = dir.iterate();
    while (it.next(io) catch return error.CacheUnusable) |entry| {
        if (sandboxOwns(entry.name)) continue;

        const kind: Mount.Kind = switch (entry.kind) {
            .directory => .directory,
            .file => .file,
            .sym_link => {
                if (try linkMount(allocator, io, dir, rootfs, entry.name, diag)) |mount| {
                    try found.append(allocator, mount);
                }
                continue;
            },
            // A socket, a fifo, or a device node. `std.tar` writes none of
            // these, so an entry here came from somewhere else and is not a
            // thing a tool call needs.
            else => {
                try diagnostic.noteSkipped(diag, entry.name, .not_a_file_or_directory);
                continue;
            },
        };

        try found.append(allocator, .{
            .source = try std.fs.path.join(allocator, &.{ rootfs, entry.name }),
            .target = try std.fmt.allocPrint(allocator, "/{s}", .{entry.name}),
            .kind = kind,
        });
    }

    const result = try found.toOwnedSlice(allocator);
    std.mem.sort(Mount, result, {}, lessThanTarget);
    return result;
}

/// The mount a top level symbolic link stands for, or null when there is none.
///
/// **The link is resolved inside the tree and never against the host.** An
/// absolute link in an image means the image's own root, not this machine's.
/// So `/lib -> /usr/lib` becomes `<rootfs>/usr/lib`, and a `statFile` on the
/// link's own path is never used, because the kernel would resolve that
/// absolute target against the host and hand back a mount source somewhere in
/// `/usr` on the real machine.
///
/// A link that still leaves the tree after that, such as `/etc -> ../../..`,
/// is left out and noted. So is a link that names another link:
/// `follow_symlinks` is false, so a chain is refused rather than walked, and
/// there is then no depth at which a second absolute target could escape.
fn linkMount(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    rootfs: []const u8,
    name: []const u8,
    diag: ?diagnostic.Sink,
) Error!?Mount {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = dir.readLink(io, name, &buffer) catch {
        try diagnostic.noteSkipped(diag, name, .link_unreadable);
        return null;
    };
    const link = buffer[0..length];
    if (link.len == 0) {
        try diagnostic.noteSkipped(diag, name, .link_names_nothing);
        return null;
    }

    const inside = if (link[0] == '/') link[1..] else link;
    const source = try std.fs.path.resolve(allocator, &.{ rootfs, inside });

    if (!isUnder(source, rootfs)) {
        allocator.free(source);
        try diagnostic.noteSkipped(diag, name, .link_leaves_the_image);
        return null;
    }

    const stat = std.Io.Dir.cwd().statFile(io, source, .{ .follow_symlinks = false }) catch {
        allocator.free(source);
        try diagnostic.noteSkipped(diag, name, .link_points_at_nothing);
        return null;
    };

    const kind: Mount.Kind = switch (stat.kind) {
        .directory => .directory,
        .file => .file,
        else => {
            allocator.free(source);
            try diagnostic.noteSkipped(diag, name, .link_points_at_a_link);
            return null;
        },
    };

    return .{
        .source = source,
        .target = try std.fmt.allocPrint(allocator, "/{s}", .{name}),
        .kind = kind,
    };
}

/// True when `path` is `root` itself or something inside it. The separator
/// check is what stops `/a/rootfs-other` reading as being under `/a/rootfs`.
fn isUnder(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    return path[root.len] == '/';
}

fn lessThanTarget(_: void, a: Mount, b: Mount) bool {
    return std.mem.lessThan(u8, a.target, b.target);
}

/// The paths the sandbox creates itself, which an image must not cover.
///
/// * `proc` is a procfs of the sandbox's own, showing the sandbox's own
///   processes. See `chock-sandbox`'s `Mount.Proc`.
/// * `dev` holds `/dev/null`, which the sandbox binds itself. An exported
///   image writes empty ordinary files there, and one of those over
///   `/dev/null` would break every program that opens it.
/// * `tmp` is the sandbox's own capped scratch area. See `Config.scratch`.
/// * `sys` is a window on the host that nothing in a tool call needs.
/// * `run` holds every path Chock invents inside a sandbox, because
///   `chock_sandbox.runtime_prefix` is `/run/chock`: the git object store, the
///   program a call runs, and the file a write tool stages. **Measured on
///   2026-08-25 with a real `alpine:3.20`**: the image's own `/run` is bound
///   read only, and the mount that puts the git object store at
///   `/run/chock/objects` then cannot make its own target, or is hidden by the
///   image and leaves a Landlock rule naming a path that is not there. Every
///   base image has an empty `/run`, because a real one is a tmpfs the runtime
///   makes at start.
pub const sandbox_owns: []const []const u8 = &.{ "dev", "proc", "run", "sys", "tmp" };

fn sandboxOwns(name: []const u8) bool {
    for (sandbox_owns) |owned| {
        if (std.mem.eql(u8, name, owned)) return true;
    }
    return false;
}

const testing = std.testing;

test "an image inspection yields the digest, the environment and the working directory" {
    // The exact bytes `docker image inspect --format '{{json .}}'` wrote for
    // alpine:3.20 on this machine on 2026-08-25, cut to the fields this file
    // reads plus one it must ignore.
    const text =
        \\{"Id":"sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        \\"RepoTags":["alpine:3.20"],"Comment":"buildkit.dockerfile.v0",
        \\"Config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        \\"Cmd":["/bin/sh"],"WorkingDir":""}}
    ;

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const read = try parseInspect(arena_state.allocator(), text);
    try testing.expectEqualStrings(
        "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        read.digest,
    );
    try testing.expectEqual(@as(usize, 1), read.variables.len);
    try testing.expectEqualStrings(
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        read.variables[0],
    );
    // An image that states an empty working directory means the root. A tool
    // call with an empty string as its directory would fail to start.
    try testing.expectEqualStrings("/", read.workdir);
}

test "an image that states no config gives an empty environment and the root" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const read = try parseInspect(arena_state.allocator(), "{\"Id\":\"abc\"}");
    try testing.expectEqualStrings("abc", read.digest);
    try testing.expectEqual(@as(usize, 0), read.variables.len);
    try testing.expectEqualStrings("/", read.workdir);
}

test "an inspection with no identifier is unreadable, not an image with no name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectError(error.InspectUnreadable, parseInspect(arena, "{\"Id\":\"\"}"));
    try testing.expectError(error.InspectUnreadable, parseInspect(arena, "{}"));
    try testing.expectError(error.InspectUnreadable, parseInspect(arena, "not json at all"));
}

test "the five paths the sandbox creates are never bound from an image" {
    // **`run` is here because it was measured, not because it looked risky.**
    // A real `alpine:3.20` in a Debian container bound its own empty `/run`,
    // and the git object store the workspace puts at `/run/chock/objects` was
    // then covered by it. Every tool call ended in `LandlockRuleFailed`.
    for ([_][]const u8{ "dev", "proc", "run", "sys", "tmp" }) |owned| {
        try testing.expect(sandboxOwns(owned));
    }
    for ([_][]const u8{ "usr", "bin", "lib", "etc", "var", "home", "root", "opt", "srv" }) |wanted| {
        try testing.expect(!sandboxOwns(wanted));
    }
    // A name that merely starts the same is a different directory.
    try testing.expect(!sandboxOwns("development"));
    try testing.expect(!sandboxOwns("system"));
}

test "the mount set is every top level entry of the tree except the sandbox's own" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const rootfs = buffer[0..len];

    for ([_][]const u8{ "usr", "bin", "etc", "proc", "dev", "sys", "tmp" }) |name| {
        try tmp.dir.createDir(testing.io, name, .default_dir);
    }
    // A regular file at the top of the tree. Measured in a real image on
    // 2026-08-25: Debian's own `.dockerenv`. It has to be a mount of kind
    // `file`, because Landlock refuses a directory right over one.
    {
        var file = try tmp.dir.createFile(testing.io, ".dockerenv", .{});
        defer file.close(testing.io);
    }

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const mounts = try mountsIn(arena_state.allocator(), testing.io, rootfs, null);
    try testing.expectEqual(@as(usize, 4), mounts.len);
    // Sorted by target, so the answer does not depend on the order the
    // filesystem happened to hand entries back in.
    try testing.expectEqualStrings("/.dockerenv", mounts[0].target);
    try testing.expectEqual(Mount.Kind.file, mounts[0].kind);
    try testing.expectEqualStrings("/bin", mounts[1].target);
    try testing.expectEqual(Mount.Kind.directory, mounts[1].kind);
    try testing.expectEqualStrings("/etc", mounts[2].target);
    try testing.expectEqualStrings("/usr", mounts[3].target);

    for (mounts) |mount| {
        try testing.expect(mount.read_only);
        // Every source is inside the tree, never anywhere else on the host.
        try testing.expect(isUnder(mount.source, rootfs));
    }
}

test "a top level link is mounted as the directory it names, which is what Debian needs" {
    // Measured on 2026-08-25: in `debian:stable-slim`, `/bin`, `/lib` and
    // `/sbin` are symbolic links into `/usr`. Without this a Debian image
    // gives a sandbox with no `/bin` and nothing in it starts.
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const rootfs = buffer[0..len];

    try tmp.dir.createDirPath(testing.io, "usr/bin");
    try tmp.dir.createDirPath(testing.io, "usr/lib");
    // Relative, which is what Debian really writes.
    try tmp.dir.symLink(testing.io, "usr/bin", "bin", .{});
    // Absolute, which another image may write. It means the image's own root,
    // never this machine's.
    try tmp.dir.symLink(testing.io, "/usr/lib", "lib", .{});

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const mounts = try mountsIn(arena_state.allocator(), testing.io, rootfs, null);
    try testing.expectEqual(@as(usize, 3), mounts.len);

    try testing.expectEqualStrings("/bin", mounts[0].target);
    try testing.expect(std.mem.endsWith(u8, mounts[0].source, "/usr/bin"));
    try testing.expectEqual(Mount.Kind.directory, mounts[0].kind);

    try testing.expectEqualStrings("/lib", mounts[1].target);
    // **The whole point.** An absolute link resolves inside the tree. A source
    // of plain `/usr/lib` would bind this machine's own libraries into a
    // sandbox that asked for the image's.
    try testing.expect(isUnder(mounts[1].source, rootfs));
    try testing.expect(std.mem.endsWith(u8, mounts[1].source, "/usr/lib"));

    try testing.expectEqualStrings("/usr", mounts[2].target);
}

test "a top level link that leaves the image is left out and said out loud" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const rootfs = buffer[0..len];

    try tmp.dir.createDir(testing.io, "usr", .default_dir);
    // A link that walks out of the tree. Binding what this names would put a
    // directory of the real machine inside the sandbox.
    try tmp.dir.symLink(testing.io, "../../../../etc", "etc", .{});

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(allocator);
    const mounts = try mountsIn(arena, testing.io, rootfs, diagnostic.sinkOf(allocator, &diag));
    try testing.expectEqual(@as(usize, 1), mounts.len);
    try testing.expectEqualStrings("/usr", mounts[0].target);

    // Left out is not enough. Nothing disappears without a word, or a person
    // whose program cannot find `/etc` has nothing to go on.
    try testing.expectEqualStrings("etc", diag.?.mount_skipped.entry);
    try testing.expectEqual(Diagnostic.Why.link_leaves_the_image, diag.?.mount_skipped.why);
}

test "a directory whose name merely starts with the tree's name is not inside it" {
    try testing.expect(isUnder("/cache/rootfs", "/cache/rootfs"));
    try testing.expect(isUnder("/cache/rootfs/usr", "/cache/rootfs"));
    try testing.expect(!isUnder("/cache/rootfs-old/usr", "/cache/rootfs"));
    try testing.expect(!isUnder("/cache", "/cache/rootfs"));
    try testing.expect(!isUnder("/etc/passwd", "/cache/rootfs"));
}

test "a stamp names the runtime as well as the image, so two runtimes do not share a tree" {
    var docker_buffer: [max_stamp_bytes]u8 = undefined;
    var podman_buffer: [max_stamp_bytes]u8 = undefined;

    const from_docker = try stampText(&docker_buffer, .docker, "sha256:abc");
    const from_podman = try stampText(&podman_buffer, .podman, "sha256:abc");
    try testing.expect(!std.mem.eql(u8, from_docker, from_podman));
    try testing.expect(std.mem.indexOf(u8, from_docker, "sha256:abc") != null);
    try testing.expect(std.mem.startsWith(u8, from_docker, stamp_version));
}

test "a cache with no stamp, a wrong stamp, or no tree is not current" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..len];

    const rootfs = try std.fs.path.join(testing.allocator, &.{ cache_dir, rootfs_name });
    defer testing.allocator.free(rootfs);

    try testing.expect(!try isCurrent(testing.io, cache_dir, .docker, "sha256:abc", rootfs));

    try writeStamp(testing.allocator, testing.io, cache_dir, .docker, "sha256:abc");
    try testing.expect(!try isCurrent(testing.io, cache_dir, .docker, "sha256:abc", rootfs));

    try tmp.dir.createDir(testing.io, rootfs_name, .default_dir);
    try testing.expect(try isCurrent(testing.io, cache_dir, .docker, "sha256:abc", rootfs));

    // A tag that moved to new content is a different image.
    try testing.expect(!try isCurrent(testing.io, cache_dir, .docker, "sha256:def", rootfs));
    // And the same image out of the other runtime is a different tree.
    try testing.expect(!try isCurrent(testing.io, cache_dir, .podman, "sha256:abc", rootfs));
}

test "a reference that is not an image is refused before any command is built" {
    // `load` runs no runtime at all for this, which is why the runner below is
    // one that fails the test if it is ever called.
    const allocator = testing.allocator;

    var never = NeverRunner{};
    const answer = try load(allocator, testing.io, .{
        .reference = "--privileged",
        .cache_dir = "/chock-no-such-cache",
        .kind = .docker,
        .trust = .root_daemon,
        .runner = never.runner(),
    });
    switch (answer) {
        .provided => |image| {
            var owned = image;
            owned.deinit(testing.io);
            return error.TestUnexpectedResult;
        },
        .refused => |text| {
            defer allocator.free(text);
            try testing.expect(std.mem.indexOf(u8, text, "--privileged") != null);
        },
    }
    // **Nothing was run.** A reference that could be read as an option must
    // never reach an argument vector, so the count and not only the answer is
    // what this test pins.
    try testing.expectEqual(@as(usize, 0), never.calls);
}

/// A `Runner` that counts every call and answers nothing useful. Used by the
/// one test which asserts that a refusal happens before a command is built.
const NeverRunner = struct {
    calls: usize = 0,

    fn runner(self: *NeverRunner) Runtime.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Runtime.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        _: []const []const u8,
    ) Runtime.Error!@import("proc.zig").Output {
        const self: *NeverRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return error.RunnerFailed;
    }
};

test "an image that is not on the disk is a refusal that names the pull command" {
    // **The rule the whole no-network requirement rests on.** A session must
    // never fetch, so the missing image case has to be a sentence a person can
    // act on rather than an attempt to reach a registry.
    const allocator = testing.allocator;

    var missing = MissingImageRunner{};
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const answer = try inspect(arena_state.allocator(), testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = "/chock-no-such-cache",
        .kind = .podman,
        .trust = .user_only,
        .runner = missing.runner(),
        .pull = .never,
    });
    switch (answer) {
        .read => return error.TestUnexpectedResult,
        .refused => |text| {
            try testing.expect(std.mem.indexOf(u8, text, "podman pull alpine:3.20") != null);
            try testing.expect(std.mem.indexOf(u8, text, "no network") != null);
        },
    }
    // And it asked once, never twice: a `pull` was not attempted.
    try testing.expectEqual(@as(usize, 1), missing.calls);
}

test "a caller that asked for a fetch gets one, and only then" {
    const allocator = testing.allocator;

    var missing = MissingImageRunner{ .succeed_after_pull = true };
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const answer = try inspect(arena_state.allocator(), testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = "/chock-no-such-cache",
        .kind = .docker,
        .trust = .root_daemon,
        .runner = missing.runner(),
        .pull = .if_missing,
    });
    switch (answer) {
        .read => |read| try testing.expectEqualStrings("sha256:pulled", read.digest),
        .refused => return error.TestUnexpectedResult,
    }
    // Inspect, pull, inspect. The order is what makes the fetch happen on the
    // host and before any sandbox exists.
    try testing.expectEqual(@as(usize, 3), missing.calls);
    try testing.expectEqualStrings("pull", missing.second_verb);
}

test "a cache another session holds is a refusal that names the image, never a wait with no end" {
    // **The whole point of the bound.** A session that waits for ever on a
    // cache directory looks like a hang and gives a person nothing to do.
    //
    // Mutation check: remove the `.busy` branch of `load`, or give
    // `takeCacheLock` a wait long enough to outlast the test, and this fails on
    // the refusal it never gets.
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    // The other session. A second open file description, which `flock` treats
    // as a real contender: see `lock.zig`'s own tests.
    var other = switch (lock.take(testing.io, cache_dir, .{})) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer other.release(testing.io);

    var canned = CannedRunner{};
    const answer = try load(allocator, testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = cache_dir,
        .kind = .docker,
        .trust = .root_daemon,
        .runner = canned.runner(),
        .wait_ns = 20 * std.time.ns_per_ms,
    });

    switch (answer) {
        .provided => |image| {
            var owned = image;
            owned.deinit(testing.io);
            return error.TestUnexpectedResult;
        },
        .refused => |text| {
            defer allocator.free(text);
            try testing.expect(std.mem.indexOf(u8, text, "alpine:3.20") != null);
            // And it says what to do, which is the difference between a refusal
            // and a failure.
            try testing.expect(std.mem.indexOf(u8, text, "Run this again") != null);
        },
    }

    // **Nothing was removed while the other session held the cache.** This is
    // the fault itself: the old code deleted the tree and the stamp before it
    // knew whether anybody else was reading them.
    try testing.expect(canned.created == 0);
}

test "a tree another session is using is never replaced, and the refusal says why" {
    // **The fault the use lock exists for.** The stamp names another digest, so
    // this load would extract, and extracting means removing a tree that a
    // session is binding right now. Measured against real processes in
    // `test/container/concurrent.zig`: 50 of 50 holders lost their tree before
    // this lock.
    //
    // Mutation check: give `takeUseLock` `.shared` in both branches and this
    // fails, because the extraction then goes ahead over the other session
    // instead of being refused.
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    // A cache holding some other image's tree, which is what a moved tag or the
    // other container runtime leaves behind.
    try writeStamp(allocator, testing.io, cache_dir, .docker, "sha256:something-else");
    try tmp.dir.createDir(testing.io, rootfs_name, .default_dir);

    // The session that is running. It holds the use lock shared, which is what
    // `Image.load` leaves every session holding.
    var other = switch (lock.take(testing.io, cache_dir, .{
        .name = lock.use_file_name,
        .mode = .shared,
        .wait_ns = 0,
    })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer other.release(testing.io);

    var canned = CannedRunner{};
    const answer = try load(allocator, testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = cache_dir,
        .kind = .docker,
        .trust = .root_daemon,
        .runner = canned.runner(),
    });

    switch (answer) {
        .provided => |image| {
            var owned = image;
            owned.deinit(testing.io);
            return error.TestUnexpectedResult;
        },
        .refused => |text| {
            defer allocator.free(text);
            try testing.expect(std.mem.indexOf(u8, text, "alpine:3.20") != null);
            // A refusal has to say what to do, or it is only a failure with
            // better spelling.
            try testing.expect(std.mem.indexOf(u8, text, "Run this again") != null);
        },
    }

    // **Nothing was made and nothing was removed.** This is the fault itself:
    // the tree the other session is binding is still there.
    try testing.expectEqual(@as(usize, 0), canned.created);
    _ = try tmp.dir.statFile(testing.io, rootfs_name, .{});
}

test "a second session on the same image starts at once, next to the one already running" {
    // **The cost of the use lock, pinned.** It is shared and not exclusive so
    // that the ordinary case, two terminals on one project, keeps working. A
    // lock that refused this would pass the test above and make the image cache
    // worth nothing.
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    // The tree the `CannedRunner` answers for is already on the disk.
    try writeStamp(allocator, testing.io, cache_dir, .docker, "sha256:canned");
    try tmp.dir.createDir(testing.io, rootfs_name, .default_dir);

    var other = switch (lock.take(testing.io, cache_dir, .{
        .name = lock.use_file_name,
        .mode = .shared,
        .wait_ns = 0,
    })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer other.release(testing.io);

    var canned = CannedRunner{};
    const answer = try load(allocator, testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = cache_dir,
        .kind = .docker,
        .trust = .root_daemon,
        .runner = canned.runner(),
    });

    switch (answer) {
        .refused => |text| {
            allocator.free(text);
            return error.TestUnexpectedResult;
        },
        .provided => |image| {
            var owned = image;
            defer owned.deinit(testing.io);
            // It read the cache. Nothing was extracted next to a live session.
            try testing.expect(!owned.extracted);
        },
    }
    try testing.expectEqual(@as(usize, 0), canned.created);
}

test "an image lets go of its tree when it is released, and not before" {
    // Mutation check: drop `in_use.release` from `Image.deinit` and the second
    // half fails, because the tree stays locked for the life of the process.
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    var canned = CannedRunner{ .refuse_create = true };
    // A cache that is already current, so this load takes the lock and extracts
    // nothing. `refuse_create` proves it: reaching an extraction would fail.
    try writeStamp(allocator, testing.io, cache_dir, .docker, "sha256:canned");
    try tmp.dir.createDir(testing.io, rootfs_name, .default_dir);

    var image = switch (try load(allocator, testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = cache_dir,
        .kind = .docker,
        .trust = .root_daemon,
        .runner = canned.runner(),
    })) {
        .provided => |value| value,
        .refused => |text| {
            allocator.free(text);
            return error.TestUnexpectedResult;
        },
    };

    const writing = lock.Options{
        .name = lock.use_file_name,
        .mode = .exclusive,
        .wait_ns = 0,
    };

    // While the image is held, no other session may replace its tree.
    switch (lock.take(testing.io, cache_dir, writing)) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }

    image.deinit(testing.io);

    // And the moment it is released, the next session gets the whole directory.
    var next = switch (lock.take(testing.io, cache_dir, writing)) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    next.release(testing.io);
}

test "a load that fails inside the lock still leaves it free for the next session" {
    // Mutation check: drop the `defer guard.release(io)` in `load` and this
    // fails, because the next taker finds the cache held by a session that has
    // already given up.
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    var canned = CannedRunner{ .refuse_create = true };
    try testing.expectError(error.ExtractFailed, load(allocator, testing.io, .{
        .reference = "alpine:3.20",
        .cache_dir = cache_dir,
        .kind = .docker,
        .trust = .root_daemon,
        .runner = canned.runner(),
    }));
    try testing.expectEqual(@as(usize, 1), canned.created);

    var next = switch (lock.take(testing.io, cache_dir, .{ .wait_ns = 0 })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    next.release(testing.io);

    // **Both locks, because a load that fails takes both.** A failed extraction
    // that kept the use lock would leave the image unusable by anybody until
    // this process ended, and no error message would say so.
    var using = switch (lock.take(testing.io, cache_dir, .{
        .name = lock.use_file_name,
        .mode = .exclusive,
        .wait_ns = 0,
    })) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    using.release(testing.io);
}

/// A `Runner` whose inspection always answers and whose `create` answers what
/// the test asked for. Used by the two lock tests, which must reach the locked
/// part of `load` without a container runtime on the machine.
const CannedRunner = struct {
    refuse_create: bool = false,
    created: usize = 0,

    fn runner(self: *CannedRunner) Runtime.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Runtime.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        args: []const []const u8,
    ) Runtime.Error!@import("proc.zig").Output {
        const self: *CannedRunner = @ptrCast(@alignCast(ptr));
        if (std.mem.eql(u8, args[0], "create")) {
            self.created += 1;
            if (self.refuse_create) return .{
                .term = .{ .exited = 1 },
                .stdout = try allocator.dupe(u8, ""),
                .stderr = try allocator.dupe(u8, "no such image"),
            };
        }
        return .{
            .term = .{ .exited = 0 },
            .stdout = try allocator.dupe(u8, "{\"Id\":\"sha256:canned\"}"),
            .stderr = try allocator.dupe(u8, ""),
        };
    }
};

/// A `Runner` whose image is missing until it is fetched.
const MissingImageRunner = struct {
    calls: usize = 0,
    succeed_after_pull: bool = false,
    pulled: bool = false,
    second_verb: []const u8 = "",

    fn runner(self: *MissingImageRunner) Runtime.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Runtime.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        args: []const []const u8,
    ) Runtime.Error!@import("proc.zig").Output {
        const self: *MissingImageRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        if (self.calls == 2) self.second_verb = args[0];

        if (std.mem.eql(u8, args[0], "pull")) {
            self.pulled = true;
            return .{
                .term = .{ .exited = 0 },
                .stdout = try allocator.dupe(u8, ""),
                .stderr = try allocator.dupe(u8, ""),
            };
        }

        if (self.pulled and self.succeed_after_pull) {
            return .{
                .term = .{ .exited = 0 },
                .stdout = try allocator.dupe(u8, "{\"Id\":\"sha256:pulled\"}"),
                .stderr = try allocator.dupe(u8, ""),
            };
        }

        return .{
            .term = .{ .exited = 1 },
            .stdout = try allocator.dupe(u8, ""),
            .stderr = try allocator.dupe(u8, "Error response from daemon: No such image"),
        };
    }
};
