//! What a container image states: the environment every tool call runs with,
//! and the directories the sandbox mounts for it.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const ref = @import("reference.zig");
const lock = @import("lock.zig");
const Runtime = @import("Runtime.zig");

const Image = @This();

pub const Error = Runtime.Error || error{
    InspectUnreadable,
    ExtractFailed,
    CacheUnusable,
};

pub const Mount = struct {
    source: []const u8,
    target: []const u8,
    /// Always true: the extracted tree is shared across sessions.
    read_only: bool = true,
    kind: Kind,

    pub const Kind = enum { directory, file };
};

pub const Pull = enum {
    never,
    if_missing,
};

/// Owns every string below.
arena: *std.heap.ArenaAllocator,
kind: Runtime.Kind,
trust: Runtime.Trust,
reference: []const u8,
digest: []const u8,
/// The variables the image states, as `KEY=VALUE`.
variables: []const []const u8,
/// The image's own `WorkingDir`, or `/` when it states none.
workdir: []const u8,
rootfs: []const u8,
/// Sorted by target.
mounts: []const Mount,
extracted: bool,
in_use: lock.Held,

pub fn deinit(self: *Image, io: std.Io) void {
    self.in_use.release(io);
    const gpa = self.arena.child_allocator;
    self.arena.deinit();
    gpa.destroy(self.arena);
    self.* = undefined;
}

pub const Answer = union(enum) {
    provided: Image,
    refused: []const u8,
};

pub const Options = struct {
    reference: []const u8,
    cache_dir: []const u8,
    kind: Runtime.Kind,
    trust: Runtime.Trust,
    runner: Runtime.Runner,
    pull: Pull = .never,
    /// Called once, before a slow extraction starts, and never on a cache hit.
    on_extract: ?*const fn (reference: []const u8) void = null,
    /// Called once, when another session is already extracting this image and
    /// this one is about to wait for it.
    on_wait: ?*const fn (reference: []const u8) void = null,
    wait_ns: u64 = lock.default_wait_ns,
    diag: ?diagnostic.Sink = null,
};

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
            // The refusal outlives the arena, which goes away with this branch.
            const copy = try gpa.dupe(u8, text);
            arena.deinit();
            gpa.destroy(arena);
            return .{ .refused = copy };
        },
        .read => |value| value,
    };

    const rootfs = try std.fs.path.join(allocator, &.{ options.cache_dir, rootfs_name });

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
        // Written after the tree, so a crash halfway through leaves a cache
        // that reads as missing rather than as current.
        writeStamp(allocator, io, options.cache_dir, options.kind, inspected.digest) catch |err| {
            diagnostic.noteNamed(options.diag, .cache_not_written, options.cache_dir, err) catch {};
        };
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

/// Take the lock that says this session is using the tree. Never waits: a
/// wait here would be for a whole session, so it refuses at once instead.
fn takeUseLock(io: std.Io, options: Options, current: bool) lock.Answer {
    return lock.take(io, options.cache_dir, .{
        .name = lock.use_file_name,
        .mode = if (current) .shared else .exclusive,
        .wait_ns = 0,
    });
}

/// Take the cache lock, and tell the caller before any waiting starts.
fn takeCacheLock(io: std.Io, options: Options) lock.Answer {
    const first = lock.take(io, options.cache_dir, .{ .wait_ns = 0 });
    switch (first) {
        .busy => {},
        .held, .unusable => return first,
    }

    if (options.on_wait) |report| report(options.reference);
    return lock.take(io, options.cache_dir, .{ .wait_ns = options.wait_ns });
}

/// Releases the arena on the way out. The message is built first, since its
/// arguments can point into the arena this destroys.
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

/// True when this image is already on the disk. Inspects only, and never
/// extracts or fetches.
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
        "--",
        options.reference,
    });
}

const InspectJson = struct {
    Id: []const u8,
    Config: ?ConfigJson = null,

    const ConfigJson = struct {
        Env: ?[]const []const u8 = null,
        WorkingDir: ?[]const u8 = null,
    };
};

/// `allocator` must be an arena: the parse is leaky on purpose.
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

fn tailOf(stderr: []const u8) []const u8 {
    const said = std.mem.trim(u8, stderr, " \t\r\n");
    if (said.len <= max_said_bytes) return said;
    return said[said.len - max_said_bytes ..];
}

const max_said_bytes: usize = 512;

const rootfs_name = "rootfs";
const stamp_name = "stamp";
const tar_name = "image.tar";

/// Bump this when the cache format changes, so an older stamp does not read
/// as current.
const stamp_version = "chock container image 1";

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
    defer cache.deleteFile(io, tar_name) catch {};

    const container = try create(allocator, io, options);
    try exportRootfs(allocator, io, options, container, tar_path);
    // Best effort: a leftover container costs disk, not correctness.
    remove(allocator, io, options, container) catch {};

    cache.createDirPath(io, rootfs_name) catch return error.CacheUnusable;
    var tree = cache.openDir(io, rootfs_name, .{}) catch return error.CacheUnusable;
    defer tree.close(io);

    try unpack(allocator, io, tar_path, tree, options.diag);
    _ = rootfs;
}

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
    // `--output`: a root filesystem is gigabytes, the wrong size for a pipe.
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
        .strip_components = 0,
        // The set-user-id bit never reaches the disk.
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

const read_buffer_bytes: usize = 256 * 1024;

fn firstRefusedName(err: std.tar.Diagnostics.Error) []const u8 {
    return switch (err) {
        .unable_to_create_sym_link => |value| value.file_name,
        .unable_to_create_file => |value| value.file_name,
        .unsupported_file_type => |value| value.file_name,
        .components_outside_stripped_prefix => |value| value.file_name,
    };
}

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

    // A matching stamp does not mean the tree is still there.
    _ = std.Io.Dir.cwd().statFile(io, rootfs, .{}) catch return false;
    return true;
}

/// A torn write leaves a prefix that `isCurrent` rejects.
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

/// Carries the runtime as well as the digest, so switching runtimes forces a
/// fresh extraction.
fn stampText(buffer: []u8, kind: Runtime.Kind, digest: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}\n{s}\n{s}\n", .{ stamp_version, kind.program(), digest });
}

const max_stamp_bytes: usize = 512;

/// A top level symbolic link is followed and mounted at the link's own
/// path, since a bind mount cannot be a symbolic link.
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

/// Resolved inside the tree and never against the host, so `/lib ->
/// /usr/lib` becomes `<rootfs>/usr/lib`. A link that leaves the tree, or
/// names another link, is left out and noted.
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

/// The separator check stops `/a/rootfs-other` reading as under `/a/rootfs`.
fn isUnder(path: []const u8, root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, root)) return false;
    if (path.len == root.len) return true;
    return path[root.len] == '/';
}

fn lessThanTarget(_: void, a: Mount, b: Mount) bool {
    return std.mem.lessThan(u8, a.target, b.target);
}

/// The paths the sandbox creates itself, which an image must not cover.
pub const sandbox_owns: []const []const u8 = &.{ "dev", "proc", "run", "sys", "tmp" };

fn sandboxOwns(name: []const u8) bool {
    for (sandbox_owns) |owned| {
        if (std.mem.eql(u8, name, owned)) return true;
    }
    return false;
}

const testing = std.testing;

test "an image inspection yields the digest, the environment and the working directory" {
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
    for ([_][]const u8{ "dev", "proc", "run", "sys", "tmp" }) |owned| {
        try testing.expect(sandboxOwns(owned));
    }
    for ([_][]const u8{ "usr", "bin", "lib", "etc", "var", "home", "root", "opt", "srv" }) |wanted| {
        try testing.expect(!sandboxOwns(wanted));
    }
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
    {
        var file = try tmp.dir.createFile(testing.io, ".dockerenv", .{});
        defer file.close(testing.io);
    }

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const mounts = try mountsIn(arena_state.allocator(), testing.io, rootfs, null);
    try testing.expectEqual(@as(usize, 4), mounts.len);
    try testing.expectEqualStrings("/.dockerenv", mounts[0].target);
    try testing.expectEqual(Mount.Kind.file, mounts[0].kind);
    try testing.expectEqualStrings("/bin", mounts[1].target);
    try testing.expectEqual(Mount.Kind.directory, mounts[1].kind);
    try testing.expectEqualStrings("/etc", mounts[2].target);
    try testing.expectEqualStrings("/usr", mounts[3].target);

    for (mounts) |mount| {
        try testing.expect(mount.read_only);
        try testing.expect(isUnder(mount.source, rootfs));
    }
}

test "a top level link is mounted as the directory it names, which is what Debian needs" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const rootfs = buffer[0..len];

    try tmp.dir.createDirPath(testing.io, "usr/bin");
    try tmp.dir.createDirPath(testing.io, "usr/lib");
    try tmp.dir.symLink(testing.io, "usr/bin", "bin", .{});
    try tmp.dir.symLink(testing.io, "/usr/lib", "lib", .{});

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const mounts = try mountsIn(arena_state.allocator(), testing.io, rootfs, null);
    try testing.expectEqual(@as(usize, 3), mounts.len);

    try testing.expectEqualStrings("/bin", mounts[0].target);
    try testing.expect(std.mem.endsWith(u8, mounts[0].source, "/usr/bin"));
    try testing.expectEqual(Mount.Kind.directory, mounts[0].kind);

    try testing.expectEqualStrings("/lib", mounts[1].target);
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
    try tmp.dir.symLink(testing.io, "../../../../etc", "etc", .{});

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(allocator);
    const mounts = try mountsIn(arena, testing.io, rootfs, diagnostic.sinkOf(allocator, &diag));
    try testing.expectEqual(@as(usize, 1), mounts.len);
    try testing.expectEqualStrings("/usr", mounts[0].target);

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

    try testing.expect(!try isCurrent(testing.io, cache_dir, .docker, "sha256:def", rootfs));
    try testing.expect(!try isCurrent(testing.io, cache_dir, .podman, "sha256:abc", rootfs));
}

test "a reference that is not an image is refused before any command is built" {
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
    try testing.expectEqual(@as(usize, 0), never.calls);
}

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
    try testing.expectEqual(@as(usize, 3), missing.calls);
    try testing.expectEqualStrings("pull", missing.second_verb);
}

test "a cache another session holds is a refusal that names the image, never a wait with no end" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    // A second open file description, which `flock` treats as a real
    // contender even from the same process.
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
            try testing.expect(std.mem.indexOf(u8, text, "Run this again") != null);
        },
    }

    try testing.expect(canned.created == 0);
}

test "a tree another session is using is never replaced, and the refusal says why" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    try writeStamp(allocator, testing.io, cache_dir, .docker, "sha256:something-else");
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
        .provided => |image| {
            var owned = image;
            owned.deinit(testing.io);
            return error.TestUnexpectedResult;
        },
        .refused => |text| {
            defer allocator.free(text);
            try testing.expect(std.mem.indexOf(u8, text, "alpine:3.20") != null);
            try testing.expect(std.mem.indexOf(u8, text, "Run this again") != null);
        },
    }

    try testing.expectEqual(@as(usize, 0), canned.created);
    _ = try tmp.dir.statFile(testing.io, rootfs_name, .{});
}

test "a second session on the same image starts at once, next to the one already running" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

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
            try testing.expect(!owned.extracted);
        },
    }
    try testing.expectEqual(@as(usize, 0), canned.created);
}

test "an image lets go of its tree when it is released, and not before" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try tmp.dir.realPath(testing.io, &buffer);
    const cache_dir = buffer[0..length];

    var canned = CannedRunner{ .refuse_create = true };
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

    switch (lock.take(testing.io, cache_dir, writing)) {
        .busy => {},
        .held, .unusable => return error.TestUnexpectedResult,
    }

    image.deinit(testing.io);

    var next = switch (lock.take(testing.io, cache_dir, writing)) {
        .held => |held| held,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    next.release(testing.io);
}

test "a load that fails inside the lock still leaves it free for the next session" {
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
