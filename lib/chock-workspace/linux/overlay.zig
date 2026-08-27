//! The Linux driver for `../overlay.zig`: overlayfs, for a project that is
//! not a git repository.
//!
//! **The upper layer is the diff.** A project with no git has no commit to
//! diff against, so `changedFiles` reads the upper layer instead: whatever
//! landed there is exactly what the agent changed, nothing more and nothing
//! less. This is the same review step a git project gets, built a different
//! way.
//!
//! **A deletion is a whiteout, not a removal.** overlayfs never deletes a path
//! out of the lower layer, because the lower layer is read only and the kernel
//! never writes to it. Instead, deleting a path that the lower layer has marks
//! the same path in the upper layer with a whiteout: a character device file,
//! with major and minor device number both 0, that the kernel makes for
//! exactly this purpose. `changedFiles` reads a whiteout as a deletion by
//! checking for that exact device number, in `isWhiteout` below, not by
//! assuming every character device in the upper layer is one.
//!
//! **`userxattr` is required, and its absence looked like a kernel fault.**
//! Without it, overlayfs stores its own bookkeeping, such as the marker that
//! says a directory replaced a deleted lower path, in the `trusted.overlay.*`
//! extended attribute namespace. Only `CAP_SYS_ADMIN` over the host can write
//! that namespace, and a user namespace never has it, so the kernel returned
//! `EIO` for `rm x && mkdir x`, for `rm -rf` of a project directory, and for
//! replacing a file with a directory. An earlier version of this file recorded
//! that as an unfixable kernel limitation. It was not: `userxattr` moves the
//! same bookkeeping into `user.overlay.*`, a namespace this process can
//! already write, and the mount options `../../chock-sandbox`'s own
//! `namespace.mountOverlay` carries it. Confirmed by hand on kernel 6.18.42:
//! all three operations now succeed, with all of this file's own tests still
//! passing and a whiteout still recognised as character device 0,0.
//!
//! **A directory that replaces a deleted lower path is marked opaque, not
//! whited out.** A whiteout is a character device, and a directory cannot be
//! one, so when a directory lands where the lower layer had something,
//! overlayfs instead sets `user.overlay.opaque` to `y` on the new directory.
//! An opaque directory's own lower counterpart is hidden completely, the same
//! outcome as a deletion. `changedFiles` checks every directory it finds under
//! the upper layer for this attribute, in `isOpaqueDir` below, and reports the
//! directory's own path as deleted when it finds it, on top of walking into
//! the directory for whatever the agent put there. Without this check, `rm x
//! && mkdir x` and replacing a file with a directory both lose the deletion
//! from the diff `changedFiles` reports.
//!
//! `create` only makes plain directories, so it needs no special privilege and
//! takes an ordinary `std.Io`. `changedFiles` and `nestedMounts` need no
//! namespace either: they read the upper layer and the project directly, on
//! the host, the same files a real overlay mount reads. The one call that
//! actually performs the overlay mount, `mount(2)` with `userxattr` in the
//! options, lives in `lib/chock-sandbox`'s own `namespace.mountOverlay`, and
//! is never reached from here.
//!
//! **A nested mount inside the project is invisible to the merged view.**
//! overlayfs mounts one directory tree. If the project holds its own mount
//! point somewhere inside it, such as a second disk or a bind mount the user
//! set up, the merged view shows whatever plain, usually empty, directory sits
//! at that path on the lower filesystem, never what is actually mounted there.
//! An agent shown an empty directory where the user has files can act on that
//! wrong belief with full confidence, and nothing about the mount says
//! otherwise on its own. `nestedMounts` finds every one of these under a
//! project, the way `worktree.zig`'s own `ImportReport.skipped` names a path
//! it could not carry across, so a caller can tell the user before the session
//! starts.

const std = @import("std");

const diagnostic = @import("../diagnostic.zig");
const Diagnostic = diagnostic.Diagnostic;
const linux = std.os.linux;

const iface = @import("../overlay.zig");
const Overlay = iface.Overlay;
const Error = iface.Error;
const ChangeKind = iface.ChangeKind;
const ChangedFile = iface.ChangedFile;
const Skip = iface.Skip;
const ChangeReport = iface.ChangeReport;
const NestedMount = iface.NestedMount;

/// Own copies of `path` and `reason` into `skipped`. `reason` is copied, not
/// retained, so a caller can pass a temporary buffer.
fn recordSkip(
    skipped: *std.ArrayList(Skip),
    allocator: std.mem.Allocator,
    path: []const u8,
    reason: []const u8,
) Error!void {
    const path_copy = allocator.dupe(u8, path) catch return error.OutOfMemory;
    errdefer allocator.free(path_copy);
    const reason_copy = allocator.dupe(u8, reason) catch return error.OutOfMemory;
    errdefer allocator.free(reason_copy);
    skipped.append(allocator, .{ .path = path_copy, .reason = reason_copy }) catch return error.OutOfMemory;
}

/// Create the scratch layout for an overlay of `project`: an upper directory
/// and a work directory, both fresh and empty, directly under `scratch`, plus
/// the path `Overlay.mounts` later mounts the merged view onto. `scratch` must
/// already exist: a real caller gives it a session scratch directory, and a
/// test gives it its own `std.testing.tmpDir`. Does not mount anything: see
/// `Overlay.mounts`.
///
/// If a later step fails, every scratch directory this call already made is
/// removed again before the error is returned: a caller that gets an error
/// back from `create` is never left with a half built scratch layout to clean
/// up by hand.
pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    const project_owned = allocator.dupe(u8, project) catch return error.OutOfMemory;
    errdefer allocator.free(project_owned);

    const upper = std.fs.path.join(allocator, &.{ scratch, "upper" }) catch return error.OutOfMemory;
    errdefer allocator.free(upper);
    const work = std.fs.path.join(allocator, &.{ scratch, "work" }) catch return error.OutOfMemory;
    errdefer allocator.free(work);
    const merged = std.fs.path.join(allocator, &.{ scratch, "merged" }) catch return error.OutOfMemory;
    errdefer allocator.free(merged);

    try makeScratchDir(io, upper, diag);
    errdefer removeScratchDir(io, upper);
    try makeScratchDir(io, work, diag);
    errdefer removeScratchDir(io, work);
    try makeScratchDir(io, merged, diag);

    return .{ .project = project_owned, .upper = upper, .work = work, .merged = merged };
}

fn makeScratchDir(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!void {
    std.Io.Dir.createDirAbsolute(io, absolute_path, .default_dir) catch |err| {
        diagnostic.noteErr(diag, .overlay_scratch_mkdir, err);
        return error.Unexpected;
    };
}

/// Best effort cleanup for a scratch directory `create` already made, when a
/// later step in `create` fails. `create` is already returning the error
/// that triggered this, and there is no second error channel to report a
/// removal failure on: the same reasoning `worktree.zig`'s own
/// `cleanupFailedAdd` gives for the same shape of problem.
fn removeScratchDir(io: std.Io, absolute_path: []const u8) void {
    std.Io.Dir.deleteDirAbsolute(io, absolute_path) catch {};
}

/// Read the upper layer and report every path that changed: added,
/// modified, or deleted, plus every path found but not understood. This
/// is the whole review step for a project with no git: the upper layer is the
/// diff, so nothing but the upper layer needs to be read.
///
/// Runs against `self.upper` and `self.project` directly, on the host.
/// Neither the overlay mount nor a namespace of any kind is needed: overlayfs
/// writes the very same files, and the very same whiteouts and opaque
/// directories, that this function reads.
///
/// A plain, non-opaque directory found under the upper layer is not reported
/// on its own: it only exists to hold a changed file underneath it, the same
/// way `worktree.zig`'s own import never reports an empty directory,
/// because nothing changed at the directory's own path. An opaque
/// directory is different: see this file's own top comment for why it is
/// reported as a deletion at its own path, on top of being walked into.
/// Anything that is not a regular file, a symbolic link, a directory, or
/// a whiteout, such as a fifo or a socket the agent made, is recorded in
/// the returned report's own `skipped` list rather than the `changed`
/// one: this function never assumes an entry it does not recognise is
/// safe to read further, and never drops it in silence either.
///
/// Known gaps, left as is because closing them needs comparing file
/// content, a bigger change than this function makes: a file changed and
/// then changed back to its original bytes is reported as modified, and
/// so is a file whose only change is to its metadata (its mode or its
/// timestamps), and so is a plain hard link the agent makes to a file the
/// project already has. An empty directory the agent creates is reported
/// as nothing at all, on purpose, the same choice `worktree.zig` makes
/// for the same reason: only a file is a unit of change here, not a
/// directory with nothing in it.
///
/// The caller owns the returned report and frees it with `deinit`.
pub fn changedFiles(
    self: Overlay,
    allocator: std.mem.Allocator,
    io: std.Io,
    diag: ?*?Diagnostic,
) Error!ChangeReport {
    var changed: std.ArrayList(ChangedFile) = .empty;
    errdefer {
        for (changed.items) |*item| item.deinit(allocator);
        changed.deinit(allocator);
    }
    var skipped: std.ArrayList(Skip) = .empty;
    errdefer {
        for (skipped.items) |*item| item.deinit(allocator);
        skipped.deinit(allocator);
    }

    var upper_dir = std.Io.Dir.cwd().openDir(io, self.upper, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .upper_layer_open, err);
        return error.Unexpected;
    };
    defer upper_dir.close(io);

    var walker = upper_dir.walkSelectively(allocator) catch return error.OutOfMemory;
    defer walker.deinit();

    while (true) {
        const entry = (walker.next(io) catch |err| {
            diagnostic.noteErr(diag, .upper_layer_walk, err);
            return error.Unexpected;
        }) orelse break;

        const absolute = std.fs.path.join(allocator, &.{ self.upper, entry.path }) catch return error.OutOfMemory;
        defer allocator.free(absolute);

        // entry.kind comes from the directory listing's own d_type. A
        // filesystem that never fills that in reports .unknown for every
        // entry; resolveKind falls back to a statx only in that case, so
        // an entry no filesystem tells us about outright is still
        // classified instead of silently vanishing from the diff.
        const kind = resolveKind(allocator, absolute, entry.kind, diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| {
                diagnostic.noteErr(diag, .upper_entry_kind, e);
                return error.Unexpected;
            },
        };

        switch (kind) {
            .character_device => {
                // A character device that is not overlayfs's own
                // whiteout marker is some other file the agent made. It
                // is not a deletion, and this function has nothing else
                // to say about it.
                if (try isWhiteout(allocator, absolute, diag)) {
                    const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
                    changed.append(allocator, .{ .path = path_copy, .kind = .deleted }) catch return error.OutOfMemory;
                } else {
                    try recordSkip(&skipped, allocator, entry.path, "a character device, not overlayfs's own whiteout marker");
                }
            },
            .directory => {
                if (try isOpaqueDir(allocator, absolute, diag)) {
                    const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
                    changed.append(allocator, .{ .path = path_copy, .kind = .deleted }) catch return error.OutOfMemory;
                }
                walker.enter(io, entry) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| {
                        diagnostic.noteErr(diag, .upper_directory_enter, e);
                        return error.Unexpected;
                    },
                };
            },
            .file, .sym_link => {
                const existed_in_project = existsInProject(allocator, io, self.project, entry.path) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => |e| {
                        diagnostic.noteErr(diag, .project_entry_check, e);
                        return error.Unexpected;
                    },
                };

                const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
                changed.append(allocator, .{
                    .path = path_copy,
                    .kind = if (existed_in_project) .modified else .added,
                }) catch return error.OutOfMemory;
            },
            else => |other| {
                const reason = std.fmt.allocPrint(
                    allocator,
                    "not a regular file, a link, a directory, or a whiteout (it is a {s})",
                    .{@tagName(other)},
                ) catch return error.OutOfMemory;
                defer allocator.free(reason);
                try recordSkip(&skipped, allocator, entry.path, reason);
            },
        }
    }

    return .{
        .changed = changed.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .skipped = skipped.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

/// Find every directory under `project` that is itself the mount point of a
/// separate filesystem. overlayfs mounts one directory tree. It does not, and
/// cannot, show what is mounted on top of one of its own paths, so the merged
/// view presents whatever plain, usually empty, directory sits there on the
/// lower filesystem instead. See this file's own top comment for why a
/// caller must tell the user about this rather than let the agent believe an
/// empty directory is the truth.
///
/// A directory that is found to be a nested mount point is reported but not
/// descended into: whatever filesystem is mounted there is a separate
/// question from what `project` itself holds, and this function only answers
/// the second one.
///
/// Told apart from an ordinary directory by comparing device numbers, read
/// with `statx`, never by trusting a directory listing's own `d_type`: unlike
/// `changedFiles`, this function always confirms the kind it acts on, since a
/// missed mount point here is a wrong answer shown to the user, not merely an
/// entry skipped from a diff.
pub fn nestedMounts(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    diag: ?*?Diagnostic,
) Error![]NestedMount {
    var list: std.ArrayList(NestedMount) = .empty;
    errdefer {
        for (list.items) |*item| item.deinit(allocator);
        list.deinit(allocator);
    }

    var project_dir = std.Io.Dir.cwd().openDir(io, project, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .project_open, err);
        return error.Unexpected;
    };
    defer project_dir.close(io);

    const project_stat = try statNoFollow(allocator, project, diag);
    const project_device = deviceNumber(project_stat);

    var walker = project_dir.walkSelectively(allocator) catch return error.OutOfMemory;
    defer walker.deinit();

    while (true) {
        const entry = (walker.next(io) catch |err| {
            diagnostic.noteErr(diag, .project_walk, err);
            return error.Unexpected;
        }) orelse break;

        const absolute = std.fs.path.join(allocator, &.{ project, entry.path }) catch return error.OutOfMemory;
        defer allocator.free(absolute);

        const entry_stat = try statNoFollow(allocator, absolute, diag);
        if ((entry_stat.mode & linux.S.IFMT) != linux.S.IFDIR) continue;

        if (deviceNumber(entry_stat) == project_device) {
            walker.enter(io, entry) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => |e| {
                    diagnostic.noteErr(diag, .project_directory_enter, e);
                    return error.Unexpected;
                },
            };
            continue;
        }

        // A different device: a nested mount. Reported, not entered: see
        // this function's own doc comment.
        const path_copy = allocator.dupe(u8, entry.path) catch return error.OutOfMemory;
        list.append(allocator, .{ .path = path_copy }) catch return error.OutOfMemory;
    }

    return list.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn deviceNumber(stx: linux.Statx) u64 {
    return (@as(u64, stx.dev_major) << 32) | stx.dev_minor;
}

/// `statx`, on `absolute_path` itself, never a symbolic link it names.
fn statNoFollow(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!linux.Statx {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path_z.ptr, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &stx);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| {
            diagnostic.noteErrno(diag, .upper_entry_stat, err);
            return error.Unexpected;
        },
    }
    return stx;
}

/// True if `project` has a file at `rel_path`, false if nothing is there.
/// Used by `changedFiles` to tell an added path from a modified one: added if
/// the project never had this path, modified if it did.
///
/// Resolves `rel_path` one component at a time, from `project` down, rather
/// than joining the whole path and asking the kernel to resolve it in one
/// call. `follow_symlinks = false` only ever controls the final path
/// component. The kernel always resolves every component before the last one
/// through a symbolic link, no matter that flag. A single call on the whole
/// joined path could therefore walk straight through a symbolic link the
/// project already has partway down `rel_path`, land on a completely
/// different file, and report a path the agent just added as modified
/// instead, because something unrelated happens to exist at the link's own
/// target. Checking one component at a time, and refusing to continue past
/// one that is not an ordinary directory, closes that off. Only the last
/// component may be anything, including a link: this function only asks
/// whether something is there, and never opens anything for reading, so
/// nothing about what a link points at can reach the agent through this
/// check either way.
fn existsInProject(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    rel_path: []const u8,
) (std.Io.Dir.StatFileError || error{OutOfMemory})!bool {
    var current = allocator.dupe(u8, project) catch return error.OutOfMemory;
    defer allocator.free(current);

    var components = std.mem.tokenizeScalar(u8, rel_path, '/');
    while (components.next()) |component| {
        const joined = std.fs.path.join(allocator, &.{ current, component }) catch return error.OutOfMemory;
        allocator.free(current);
        current = joined;

        const info = std.Io.Dir.cwd().statFile(io, current, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return false,
            else => |e| return e,
        };

        if (components.peek() != null and info.kind != .directory) return false;
    }
    return true;
}

/// True if `absolute_path`, already known to be a character device from a
/// directory listing's own entry kind, is overlayfs's own whiteout marker:
/// major and minor device number both 0. Any other character device, such as
/// one the agent itself made with `mknod`, reports false: this function
/// never assumes every character device in the upper layer is a deletion.
fn isWhiteout(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!bool {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, path_z.ptr, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true }, &stx);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| {
            diagnostic.noteErrno(diag, .whiteout_stat, err);
            return error.Unexpected;
        },
    }
    if ((stx.mode & linux.S.IFMT) != linux.S.IFCHR) return false;
    return stx.rdev_major == 0 and stx.rdev_minor == 0;
}

/// True if `absolute_path`, already known to be a directory from a directory
/// listing's own entry kind, is marked opaque: overlayfs's own way of saying
/// this directory replaced whatever the lower layer had at the same path, so
/// the lower layer's own entry of that name, if any, must never be merged
/// into this directory's listing. See this file's own top comment for why a
/// directory carries this instead of a whiteout.
///
/// Read as `user.overlay.opaque`, not `trusted.overlay.opaque`: `userxattr`
/// in the mount options, in `../../chock-sandbox`'s own `namespace.mountOverlay`,
/// moves it into the namespace a user namespace can actually write. The value
/// overlayfs itself ever writes here is the single byte `y`. Anything else,
/// or the attribute being absent entirely, means an ordinary directory.
fn isOpaqueDir(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!bool {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var value: [1]u8 = undefined;
    const rc = linux.lgetxattr(path_z.ptr, "user.overlay.opaque", &value, value.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        // No such attribute at all: an ordinary directory.
        .NODATA => return false,
        // The attribute holds more than one byte, so it cannot be exactly
        // "y", the only value overlayfs itself ever writes here.
        .RANGE => return false,
        // The filesystem underneath the upper layer does not support
        // extended attributes at all, confirmed against a nested build
        // sandbox where the outer directory rejects every getxattr call this
        // way. A directory cannot be marked opaque on a filesystem that
        // cannot hold the attribute in the first place, so this is the same
        // answer as NODATA, not a fault.
        .OPNOTSUPP => return false,
        else => |err| {
            diagnostic.noteErrno(diag, .opaque_directory_getxattr, err);
            return error.Unexpected;
        },
    }
    const len: usize = @intCast(rc);
    return len == 1 and value[0] == 'y';
}

/// `reported`, the kind a directory listing's own `d_type` gave for an
/// entry, unless the filesystem never filled that field in, in which case
/// every entry reports `.unknown` and this falls back to one `statx` call to
/// find the real kind. Without this fallback, an entry a filesystem never
/// identifies would silently fail to match any of `changedFiles`'s own
/// cases and disappear from the diff, rather than being classified or
/// recorded as a skip. The ordinary path, where `d_type` is filled in, costs
/// nothing extra: `resolveKind` returns immediately without touching the
/// filesystem at all.
fn resolveKind(
    allocator: std.mem.Allocator,
    absolute_path: []const u8,
    reported: std.Io.File.Kind,
    diag: ?*?Diagnostic,
) Error!std.Io.File.Kind {
    if (reported != .unknown) return reported;

    const stx = try statNoFollow(allocator, absolute_path, diag);
    return switch (stx.mode & linux.S.IFMT) {
        linux.S.IFREG => .file,
        linux.S.IFDIR => .directory,
        linux.S.IFLNK => .sym_link,
        linux.S.IFCHR => .character_device,
        linux.S.IFBLK => .block_device,
        linux.S.IFIFO => .named_pipe,
        linux.S.IFSOCK => .unix_domain_socket,
        else => .unknown,
    };
}

// Every test below builds its own project directory inside a fresh
// std.testing.tmpDir, the same convention worktree.zig's own tests use. A real
// overlay mount needs a user namespace, so every test that writes through the
// overlay starts test/workspace/overlay_helper.zig as a second process and
// reads its exit status, the same pattern test/sandbox/escape.zig uses to run
// test/sandbox/probe.zig. See build.zig for how this binary's path reaches
// this test binary. This whole file only ever compiles on Linux, selected by
// `../overlay.zig`'s own comptime driver dispatch, so its tests reach for
// `linux.*` directly wherever it is convenient, the same as
// `lib/chock-sandbox/linux/driver.zig`'s own tests do.

const overlay_helper_path = @import("overlay_helper_path").overlay_helper_path;

fn absoluteDirPath(buffer: []u8, dir_fd: linux.fd_t) ![:0]u8 {
    var link_buffer: [64]u8 = undefined;
    const link = std.fmt.bufPrintZ(&link_buffer, "/proc/self/fd/{d}", .{dir_fd}) catch unreachable;
    const rc = linux.readlink(link, buffer.ptr, buffer.len);
    if (linux.errno(rc) != .SUCCESS) return error.ReadlinkFailed;
    const len: usize = @intCast(rc);
    buffer[len] = 0;
    return buffer[0..len :0];
}

/// A fresh project directory and a fresh scratch directory, both directly
/// under the same tmpDir, kept apart the same way worktree.zig's own
/// TestProject keeps a project and a scratch directory apart: listing one
/// must never pick up the other's files.
const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    scratch_path: []u8,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(&buffer, tmp.dir.handle);

        const root_path = try std.fs.path.join(allocator, &.{ tmp_path, "project" });
        errdefer allocator.free(root_path);
        const scratch_path = try std.fs.path.join(allocator, &.{ tmp_path, "scratch" });
        errdefer allocator.free(scratch_path);

        try std.Io.Dir.createDirAbsolute(std.testing.io, root_path, .default_dir);
        try std.Io.Dir.createDirAbsolute(std.testing.io, scratch_path, .default_dir);

        return .{ .allocator = allocator, .root_path = root_path, .scratch_path = scratch_path };
    }

    fn deinit(self: *TestProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
    }

    fn writeFile(self: TestProject, name: []const u8, contents: []const u8) !void {
        const file_path = try std.fs.path.join(self.allocator, &.{ self.root_path, name });
        defer self.allocator.free(file_path);
        var file = try std.Io.Dir.createFileAbsolute(std.testing.io, file_path, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, contents);
    }
};

fn readProjectFile(allocator: std.mem.Allocator, project: TestProject, name: []const u8) ![]u8 {
    const file_path = try std.fs.path.join(allocator, &.{ project.root_path, name });
    defer allocator.free(file_path);
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, file_path, allocator, .limited(4096));
}

fn readUpperFile(allocator: std.mem.Allocator, ov: Overlay, name: []const u8) ![]u8 {
    const file_path = try std.fs.path.join(allocator, &.{ ov.upper, name });
    defer allocator.free(file_path);
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, file_path, allocator, .limited(4096));
}

/// The nested "work" directory overlayfs itself creates inside `ov.work` for
/// its own bookkeeping is left behind with mode 0000. `std.testing.tmpDir`'s
/// own cleanup cannot delete a directory it cannot even read, and swallows
/// that failure rather than reporting it, which is how a pile of
/// undeletable, permission-0000 directories built up under `.zig-cache/tmp`
/// across test runs before this existed. Put the permission back before
/// `tmpDir.cleanup` ever tries. Best effort: the directory may not exist at
/// all if the mount itself never happened, and there is no meaningful
/// recovery from a `chmod` failure here beyond leaving `tmpDir.cleanup` to
/// report whatever is left.
fn allowScratchCleanup(allocator: std.mem.Allocator, ov: Overlay) void {
    const kernel_work_dir = std.fs.path.join(allocator, &.{ ov.work, "work" }) catch return;
    defer allocator.free(kernel_work_dir);
    const path_z = allocator.dupeZ(u8, kernel_work_dir) catch return;
    defer allocator.free(path_z);
    _ = linux.chmod(path_z.ptr, 0o700);
}

/// True if this process can use extended attributes on an ordinary file
/// under `tmp` at all, confirmed with a real `setxattr`, not assumed. Some
/// sandboxed build environments disable extended attributes entirely for
/// build reproducibility: `nix flake check` builds this package inside one,
/// where even a plain `setfattr` on an ordinary file returns `EOPNOTSUPP`,
/// confirmed by hand outside this codebase entirely, nothing to do with
/// overlayfs, userxattr, or a bug in `isOpaqueDir`. A test that needs to
/// observe an opaque directory's own marker calls this first, so it can
/// print an honest, visible skip of the one assertion that needs the
/// attribute rather than fail somewhere no fix in this file could reach.
fn xattrsSupported(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = absoluteDirPath(&buffer, tmp.dir.handle) catch return false;
    const probe_path = std.fs.path.join(allocator, &.{ tmp_path, ".xattr-probe" }) catch return false;
    defer allocator.free(probe_path);

    var file = std.Io.Dir.createFileAbsolute(std.testing.io, probe_path, .{}) catch return false;
    file.close(std.testing.io);

    const path_z = allocator.dupeZ(u8, probe_path) catch return false;
    defer allocator.free(path_z);
    const rc = linux.setxattr(path_z.ptr, "user.chock_probe", "y", 1, 0);
    return linux.errno(rc) == .SUCCESS;
}

/// Start test/workspace/overlay_helper.zig against `ov`'s own paths, apply
/// every op in `ops` inside a real overlay mount, and return its exit status.
/// Each op string is documented at the top of overlay_helper.zig.
fn runOverlayHelper(allocator: std.mem.Allocator, ov: Overlay, ops: []const []const u8) !std.process.Child.Term {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, overlay_helper_path);
    try argv.append(allocator, ov.project);
    try argv.append(allocator, ov.upper);
    try argv.append(allocator, ov.work);
    try argv.append(allocator, ov.merged);
    try argv.appendSlice(allocator, ops);

    var child = try std.process.spawn(std.testing.io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const term = try child.wait(std.testing.io);
    allowScratchCleanup(allocator, ov);
    return term;
}

test "a write inside the overlay does not change the file in the project" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("tracked.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"W:tracked.txt:changed by the agent\n"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    // Read the project's own file directly, not the mount options: this is
    // the whole point of the overlay, proved by the fact and not by trust.
    const project_contents = try readProjectFile(allocator, project, "tracked.txt");
    defer allocator.free(project_contents);
    try std.testing.expectEqualStrings("original\n", project_contents);

    const upper_contents = try readUpperFile(allocator, ov, "tracked.txt");
    defer allocator.free(upper_contents);
    try std.testing.expectEqualStrings("changed by the agent\n", upper_contents);
}

test "the upper layer holds only the files that changed" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("a.txt", "a\n");
    try project.writeFile("b.txt", "b\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"W:a.txt:a, changed\n"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var upper_dir = try std.Io.Dir.cwd().openDir(std.testing.io, ov.upper, .{ .iterate = true });
    defer upper_dir.close(std.testing.io);
    var it = upper_dir.iterate();
    var entry_count: usize = 0;
    var saw_a = false;
    while (try it.next(std.testing.io)) |entry| {
        entry_count += 1;
        try std.testing.expect(!std.mem.eql(u8, entry.name, "b.txt"));
        if (std.mem.eql(u8, entry.name, "a.txt")) saw_a = true;
    }
    try std.testing.expectEqual(@as(usize, 1), entry_count);
    try std.testing.expect(saw_a);
}

test "a file deleted in the overlay is still in the project" {
    // overlayfs marks a deletion with a whiteout. Prove the original survives.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("todelete.txt", "keep me\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"D:todelete.txt"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    const project_contents = try readProjectFile(allocator, project, "todelete.txt");
    defer allocator.free(project_contents);
    try std.testing.expectEqualStrings("keep me\n", project_contents);

    const upper_path = try std.fs.path.join(allocator, &.{ ov.upper, "todelete.txt" });
    defer allocator.free(upper_path);
    try std.testing.expect(try isWhiteout(allocator, upper_path, null));
}

test "changedFiles lists a new file, a changed file, and a deleted one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("changed.txt", "before\n");
    try project.writeFile("deleted.txt", "gone soon\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{
        "W:new.txt:brand new\n",
        "W:changed.txt:after\n",
        "D:deleted.txt",
    });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), report.changed.len);

    var found_new = false;
    var found_changed = false;
    var found_deleted = false;
    for (report.changed) |change| {
        if (std.mem.eql(u8, change.path, "new.txt")) {
            try std.testing.expectEqual(ChangeKind.added, change.kind);
            found_new = true;
        } else if (std.mem.eql(u8, change.path, "changed.txt")) {
            try std.testing.expectEqual(ChangeKind.modified, change.kind);
            found_changed = true;
        } else if (std.mem.eql(u8, change.path, "deleted.txt")) {
            try std.testing.expectEqual(ChangeKind.deleted, change.kind);
            found_deleted = true;
        }
    }
    try std.testing.expect(found_new);
    try std.testing.expect(found_changed);
    try std.testing.expect(found_deleted);
}

test "a symbolic link made inside the overlay does not touch the project, and changedFiles reports it as added" {
    // Suspicious case: the worktree import treats a link as a name, never the
    // file it names, and an early review found the opposite bug there.
    // changedFiles must not try to read through a link either: it only asks
    // whether the path existed, never what a link points at.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"L:link.txt:/somewhere/outside"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    // The project must not gain a link it never had.
    var project_dir = try std.Io.Dir.cwd().openDir(std.testing.io, project.root_path, .{ .iterate = true });
    defer project_dir.close(std.testing.io);
    var project_it = project_dir.iterate();
    try std.testing.expectEqual(null, try project_it.next(std.testing.io));

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("link.txt", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.added, report.changed[0].kind);
}

test "a new directory the agent made is not reported on its own, only the file inside it" {
    // Suspicious case: changedFiles must descend into a directory the agent
    // adds and report the file inside it, never the directory's own path,
    // and it must not crash walking into it.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "M:sub", "W:sub/inside.txt:nested\n" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    // The project must not gain a directory it never had.
    var project_dir = try std.Io.Dir.cwd().openDir(std.testing.io, project.root_path, .{ .iterate = true });
    defer project_dir.close(std.testing.io);
    var project_it = project_dir.iterate();
    try std.testing.expectEqual(null, try project_it.next(std.testing.io));

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("sub/inside.txt", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.added, report.changed[0].kind);
}

test "mounts describes an overlay onto the project's own path, with project as the lower layer" {
    // Finding 3 of the original review: a reviewer swapped the mount target to
    // `merged` and set read_only to true, the opposite of what it must be, and
    // every test still passed, because nothing asserted on the returned list
    // itself. Pin the facts that matter, now that `mounts` only describes the
    // overlay instead of performing it: the target is the project's real
    // path, and `project` itself is the lower, read only layer, never the
    // upper one. `mounts` needs no namespace and no real mount to check this:
    // it is a pure description now, so this test calls it directly, with no
    // subprocess.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const list = try ov.mounts(allocator);
    defer allocator.free(list);

    try std.testing.expectEqual(@as(usize, 1), list.len);
    const entry = switch (list[0]) {
        .overlay => |o| o,
        .bind, .proc, .deny => return error.ExpectedAnOverlayEntry,
    };
    try std.testing.expectEqualStrings(project.root_path, entry.lower);
    try std.testing.expectEqualStrings(ov.upper, entry.upper);
    try std.testing.expectEqualStrings(ov.work, entry.work);
    try std.testing.expectEqualStrings(project.root_path, entry.target);
}

test "regression: a directory that replaces a deleted file is reported as a deletion, not lost" {
    // Finding 1 of the review that added userxattr to the mount options.
    // Before userxattr, mkdir over a whiteout failed outright with EIO. With
    // it, the mkdir succeeds and the kernel marks the new directory opaque
    // instead of leaving a whiteout: without isOpaqueDir, changedFiles had
    // nothing that told it "x" had been deleted at all. rm x && mkdir x is
    // exactly this shape.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("x", "a file, soon a directory\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "D:x", "M:x", "W:x/inside.txt:new content\n" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);

    // Whether "x" itself is reported deleted depends on reading the opaque
    // marker back with getxattr, which needs an environment that supports
    // extended attributes at all: see xattrsSupported's own doc comment.
    // Every other environment this runs in supports it, confirmed by hand.
    // **The skipped assertion is named here and nowhere else.** A test that
    // writes to standard error puts a `failed command:` line in the build log
    // even when it passes, and this test runs in exactly the environment
    // where that matters: a Nix build sandbox supports no extended attribute
    // at all, so the marker cannot be read there. Every other assertion below
    // still runs, and the fact this test exists to pin is one of them.
    const check_opaque_marker = xattrsSupported(allocator, tmp);

    var found_deleted_x = false;
    var found_added_inside = false;
    for (report.changed) |change| {
        if (std.mem.eql(u8, change.path, "x")) {
            if (check_opaque_marker) try std.testing.expectEqual(ChangeKind.deleted, change.kind);
            found_deleted_x = true;
        } else if (std.mem.eql(u8, change.path, "x/inside.txt")) {
            try std.testing.expectEqual(ChangeKind.added, change.kind);
            found_added_inside = true;
        }
    }
    if (check_opaque_marker) try std.testing.expect(found_deleted_x);
    try std.testing.expect(found_added_inside);
}

test "regression: a project symlink does not let existsInProject see through a replaced directory" {
    // Finding 6 of the review: existsInProject used to resolve rel_path in
    // one statFile call, and follow_symlinks only ever governs the last
    // component. The project's own read-only symlink at "x", still on disk
    // after the agent replaces "x" with a real directory in the overlay,
    // used to make a brand new file underneath that directory land on
    // whatever the old link pointed at, and get reported as modified
    // instead of added.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const other_dir_path = try std.fs.path.join(allocator, &.{ project.root_path, "other" });
    defer allocator.free(other_dir_path);
    try std.Io.Dir.createDirAbsolute(std.testing.io, other_dir_path, .default_dir);
    const other_file_path = try std.fs.path.join(allocator, &.{ other_dir_path, "existing.txt" });
    defer allocator.free(other_file_path);
    var other_file = try std.Io.Dir.createFileAbsolute(std.testing.io, other_file_path, .{});
    try other_file.writeStreamingAll(std.testing.io, "unrelated content\n");
    other_file.close(std.testing.io);

    const link_path = try std.fs.path.join(allocator, &.{ project.root_path, "x" });
    defer allocator.free(link_path);
    try std.Io.Dir.cwd().symLink(std.testing.io, "other", link_path, .{});

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "D:x", "M:x", "W:x/existing.txt:brand new\n" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);

    // The fact this test exists to pin, existsInProject not following the
    // project's own symlink, shows up in "x/existing.txt" and needs no
    // extended attribute support. Whether "x" itself is reported deleted
    // needs the opaque marker: see xattrsSupported's own doc comment.
    const check_opaque_marker = xattrsSupported(allocator, tmp);

    var found_x_deleted = false;
    var found_inside_added = false;
    for (report.changed) |change| {
        if (std.mem.eql(u8, change.path, "x")) {
            if (check_opaque_marker) try std.testing.expectEqual(ChangeKind.deleted, change.kind);
            found_x_deleted = true;
        } else if (std.mem.eql(u8, change.path, "x/existing.txt")) {
            try std.testing.expectEqual(ChangeKind.added, change.kind);
            found_inside_added = true;
        }
    }
    if (check_opaque_marker) try std.testing.expect(found_x_deleted);
    try std.testing.expect(found_inside_added);
}

test "an entire project directory removed in the overlay is reported as one deletion" {
    // Reviewer's second Finding 1 case: rm -rf of a project directory.
    // Nothing replaces "olddir", so this is an ordinary whiteout of the
    // directory itself, not the opaque-directory case the regression test
    // above pins.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const olddir_path = try std.fs.path.join(allocator, &.{ project.root_path, "olddir" });
    defer allocator.free(olddir_path);
    try std.Io.Dir.createDirAbsolute(std.testing.io, olddir_path, .default_dir);
    const inside_path = try std.fs.path.join(allocator, &.{ olddir_path, "inside.txt" });
    defer allocator.free(inside_path);
    var inside_file = try std.Io.Dir.createFileAbsolute(std.testing.io, inside_path, .{});
    try inside_file.writeStreamingAll(std.testing.io, "bye\n");
    inside_file.close(std.testing.io);

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{ "D:olddir/inside.txt", "R:olddir" });
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("olddir", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.deleted, report.changed[0].kind);
}

test "a fifo made inside the overlay is recorded as a skip, not silently dropped" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const term = try runOverlayHelper(allocator, ov, &.{"F:pipe1"});
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.changed.len);
    try std.testing.expectEqual(@as(usize, 1), report.skipped.len);
    try std.testing.expectEqualStrings("pipe1", report.skipped[0].path);
}

test "resolveKind falls back to statx when the caller reports unknown" {
    // Suspicious case: a filesystem with no d_type reports every entry as
    // unknown. Pin that resolveKind still recovers the real kind instead of
    // leaving the caller to silently drop the entry, the bug this function
    // exists to fix.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try absoluteDirPath(&buffer, tmp.dir.handle);
    const file_path = try std.fs.path.join(allocator, &.{ tmp_path, "plain.txt" });
    defer allocator.free(file_path);
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, file_path, .{});
    file.close(std.testing.io);

    const kind = try resolveKind(allocator, file_path, .unknown, null);
    try std.testing.expectEqual(std.Io.File.Kind.file, kind);
}

test "nestedMounts finds nothing under a project with no mounts of its own" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("a.txt", "a\n");
    const sub_path = try std.fs.path.join(allocator, &.{ project.root_path, "sub" });
    defer allocator.free(sub_path);
    try std.Io.Dir.createDirAbsolute(std.testing.io, sub_path, .default_dir);

    const found = try nestedMounts(allocator, std.testing.io, project.root_path, null);
    defer iface.freeNestedMounts(allocator, found);
    try std.testing.expectEqual(@as(usize, 0), found.len);
}
