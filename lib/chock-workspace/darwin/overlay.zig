//! The Darwin driver for `../overlay.zig`: the backing for a project that has
//! no git repository of its own, built on `clonefile(2)` instead of on an
//! overlayfs mount. See `../overlay.zig`'s own top comment for what the
//! backing is for, and for the driver split.
//!
//! **This is not a port of `linux/overlay.zig`.** The two drivers reach the
//! same result by different means, and only the result is shared:
//!
//! * Linux mounts an overlay. The project is the read only lower layer, and
//!   every write the agent makes lands in a separate upper directory. The
//!   kernel keeps the two apart.
//! * Darwin clones the project. `clonefile(2)` makes a second directory tree
//!   whose files share their blocks with the originals until one side is
//!   written to. The agent works in the clone, and the project is never
//!   opened for write at all.
//!
//! A clone is cheap on APFS in both time and space, because it is copy on
//! write: a measured 200 MiB tree cloned to a tree that reported zero blocks
//! of its own.
//!
//! ## Why `changedFiles` is the hard half
//!
//! **overlayfs gives the changed set away for free. A clone does not.** The
//! upper directory of an overlay mount holds exactly the paths the agent
//! wrote, so `linux/overlay.zig` only has to read one directory. A clone has
//! no upper layer. The agent writes straight into the copy, and nothing
//! anywhere records that it did.
//!
//! So this driver compares the clone against the project, entry by entry,
//! and it compares **size first and then content bytes**. It reads no
//! timestamp at all. Two measurements on a real Apple Silicon machine say
//! why:
//!
//! * `clonefile` copies each file's `mtime` from the original. A file the
//!   agent never touched has the same `mtime` in the clone as in the project.
//! * `clonefile` gives every cloned file a **fresh `ctime`**, stamped at the
//!   moment of the clone, and it gives every cloned **directory a fresh
//!   `mtime`** too.
//!
//! A rule of "changed if the timestamp is at or after the clone" therefore
//! reports the whole tree as changed, which is the failure the test "a file
//! nobody touched is reported as unchanged" exists to catch. Content is the
//! only signal that is true whatever the filesystem does to a timestamp, so
//! content is what this driver reads. Size is checked first, because two
//! files of different lengths cannot hold the same bytes, and that check
//! costs one `stat` rather than a full read.
//!
//! The cost is one walk of the clone, one walk of the project, and a read of
//! both copies of every file whose size did not change. If that walk ever
//! becomes the bottleneck for a large project, the next step is a manifest of
//! content hashes recorded by `create`, which trades a walk at report time
//! for a walk at create time. It is not needed yet, and a manifest can go
//! stale, while a direct comparison cannot.
//!
//! One deliberate difference from `linux/overlay.zig` follows from reading
//! content: a file the agent changed and then changed back to its original
//! bytes is reported here as **unchanged**, where the Linux driver reports it
//! as modified. The Linux driver names that in its own doc comment as a known
//! gap it cannot close without reading content. This driver reads content
//! already, so it does not have the gap.
//!
//! ## Two ways `clonefile` refuses
//!
//! * **The two paths must be on the same volume.** A scratch directory on
//!   another volume gives `EXDEV`, which this driver reports as
//!   `error.ScratchOnAnotherVolume`. Chock refuses rather than moving the
//!   scratch directory next to the project: a workspace exists so the agent
//!   never writes inside the user's project, and putting the scratch
//!   directory there would give up the very thing the workspace is for. The
//!   caller picks a scratch directory on the project's own volume.
//! * **The destination must not exist.** `clonefile` gives `EEXIST` for a
//!   destination that is already there, which this driver reports as
//!   `error.ScratchAlreadyExists` and names the path. A scratch directory
//!   left behind by an earlier session therefore gives a message that says
//!   what to remove, not a confusing one.
//!
//! A volume with no copy on write clone at all, such as HFS+, gives
//! `ENOTSUP`. That is the one case that keeps the old
//! `error.NoOverlayFilesystem`: this driver cannot build the backing there,
//! and Chock refuses to run before it runs without the guarantee it
//! claims.
//!
//! ## What this file may not do
//!
//! `clonefile` is a macOS call, and `std` does not carry it, so the prototype
//! is declared below. That makes this file a real platform driver, in the
//! same sense `linux/overlay.zig` is: it does not compile for another target,
//! and `../overlay.zig` only ever reaches it through its own comptime driver
//! dispatch. Every test below therefore returns early, at comptime, on any
//! host that is not macOS, the same guard `../overlay.zig`'s own "same public
//! shape" test uses in the other direction.

const std = @import("std");

const diagnostic = @import("../diagnostic.zig");
const Diagnostic = diagnostic.Diagnostic;
const builtin = @import("builtin");
const iface = @import("../overlay.zig");

const Overlay = iface.Overlay;
const Error = iface.Error;
const ChangeKind = iface.ChangeKind;
const ChangedFile = iface.ChangedFile;
const Skip = iface.Skip;
const ChangeReport = iface.ChangeReport;
const NestedMount = iface.NestedMount;

/// `clonefile(2)`, from `<sys/clonefile.h>`. Declared here because `std` does
/// not carry it. Zig links libSystem for a macOS target already, so no build
/// step has to ask for it. Given a directory, it clones the whole tree below
/// it, and it keeps a symbolic link as a symbolic link.
///
/// `flags` is 0 here. The only flag macOS defines is `CLONE_NOFOLLOW`, which
/// asks it not to follow a symbolic link at `src` itself, and `src` is always
/// a directory in this file.
extern "c" fn clonefile(src: [*:0]const u8, dst: [*:0]const u8, flags: u32) c_int;

/// `mkfifo(3)`, used by one test below to make a named pipe. There is no
/// portable way to make one, and the test that proves an entry this driver
/// cannot classify is recorded rather than dropped needs one to exist.
extern "c" fn mkfifo(path: [*:0]const u8, mode: c_uint) c_int;

/// `lstat(2)`, for the one field `nestedMounts` reads: `st_dev`. See
/// `DeviceStat`.
extern "c" fn lstat(path: [*:0]const u8, out: *DeviceStat) c_int;

/// Darwin's own `struct stat`, with only the first field named. `st_dev` sits
/// at offset zero on every macOS release that has the 64 bit inode layout,
/// which is every release this project supports, so naming that one field and
/// giving `lstat` room for the rest is enough for `nestedMounts` and leaves
/// no other field to get wrong. Darwin's own structure is 144 bytes on arm64,
/// well inside the room below.
const DeviceStat = extern struct {
    /// `st_dev`: the number of the filesystem this path lives on.
    device: i32,
    /// Room for the rest of `struct stat`. Never read.
    rest: [260]u8 align(8),
};

/// How many bytes `sameContent` compares at a time. One buffer per side, both
/// allocated once per `changedFiles` call and reused for every file.
const compare_chunk_bytes: usize = 64 * 1024;

/// Clone `project` into a fresh directory under `scratch`, and describe the
/// result in the same shape `linux/overlay.zig`'s own `create` returns.
/// `scratch` must already exist, and must be on the same volume as `project`:
/// see this file's own top comment for both failure modes and for why Chock
/// refuses rather than working around the second one.
///
/// The clone lands at `scratch/upper`, which must not exist yet.
/// `scratch/work` and `scratch/merged` are made empty, so this driver's own
/// `Overlay` carries the same four paths the Linux driver's does and no
/// caller has to know which driver built it. Neither is read on Darwin:
/// overlayfs owns `work`, and `merged` is the mount point of a mount this
/// platform never performs.
///
/// If a later step fails, everything this call already made is removed again,
/// so a caller that gets an error back is never left with a half built
/// scratch layout to clean up by hand.
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

    // The clone comes first, and nothing makes `upper` beforehand: clonefile
    // refuses a destination that already exists.
    try cloneTree(allocator, project_owned, upper, diag);
    errdefer removeScratchTree(io, upper);

    try makeScratchDir(io, work, diag);
    errdefer removeScratchDir(io, work);
    try makeScratchDir(io, merged, diag);

    return .{ .project = project_owned, .upper = upper, .work = work, .merged = merged };
}

/// One `clonefile` call, with every errno it can give mapped to an error that
/// names what went wrong. See this file's own top comment.
fn cloneTree(
    allocator: std.mem.Allocator,
    source: []const u8,
    destination: []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    const source_z = allocator.dupeZ(u8, source) catch return error.OutOfMemory;
    defer allocator.free(source_z);
    const destination_z = allocator.dupeZ(u8, destination) catch return error.OutOfMemory;
    defer allocator.free(destination_z);

    const result = clonefile(source_z.ptr, destination_z.ptr, 0);
    if (result == 0) return;

    switch (std.posix.errno(result)) {
        // These three name themselves. `overlay.Error`'s own doc comments
        // carry the whole explanation, and the two paths a message would
        // name are the project root and the scratch directory, both of
        // which the command that chose them already holds. So the error is
        // the diagnostic here, and `src/` writes the sentence.
        .XDEV => return error.ScratchOnAnotherVolume,
        .EXIST => return error.ScratchAlreadyExists,
        .OPNOTSUPP => return error.NoOverlayFilesystem,
        else => |errno| {
            diagnostic.noteErrno(diag, .project_clone, errno);
            return error.Unexpected;
        },
    }
}

fn makeScratchDir(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!void {
    std.Io.Dir.createDirAbsolute(io, absolute_path, .default_dir) catch |err| {
        diagnostic.noteErr(diag, .overlay_scratch_mkdir, err);
        return error.Unexpected;
    };
}

/// Best effort cleanup for a scratch directory `create` already made, when a
/// later step in `create` fails. `create` is already returning the error that
/// triggered this, and there is no second error channel to report a removal
/// failure on: the same reasoning `linux/overlay.zig` gives for the same
/// shape of problem.
fn removeScratchDir(io: std.Io, absolute_path: []const u8) void {
    std.Io.Dir.deleteDirAbsolute(io, absolute_path) catch {};
}

/// Best effort cleanup for the clone, which is a whole tree rather than one
/// empty directory. Same reasoning as `removeScratchDir`.
fn removeScratchTree(io: std.Io, absolute_path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, absolute_path) catch {};
}

/// One directory this walk still has to look at, named relative to the
/// project root.
const PendingDir = struct {
    /// The path relative to the project root. Empty for the root itself.
    /// Owned by this value.
    relative: []u8,
    /// False when the project has no directory at this path, so every file
    /// under it is new. A clone directory with no counterpart in the project
    /// is an entire tree the agent made.
    in_project: bool,
};

/// Compare the clone against the project and report every path that changed:
/// added, modified, or deleted, plus every path found but not understood.
/// This is the whole review step for a project with no git.
///
/// The report has exactly the shape `linux/overlay.zig`'s own `changedFiles`
/// returns, so `Workspace` needs no branch for this platform: one
/// `ChangedFile` per changed path, named relative to the project root, plus
/// one `Skip` per entry this driver could not classify.
///
/// The rules, which follow `linux/overlay.zig`'s so that a reader of a report
/// cannot tell which driver made it:
///
/// * A file or a link in the clone with no counterpart in the project is
///   `added`.
/// * A file or a link in both, whose content differs, is `modified`. A
///   symbolic link is compared by its target, not by what it points at.
/// * A path in the project with nothing at all in the clone is `deleted`.
///   A directory is reported once, at its own path, and is not walked into:
///   removing a whole directory is one deletion, not one per file.
/// * A path the agent replaced with a directory is `deleted`, and the new
///   directory is still walked into. This matches the opaque directory case
///   `linux/overlay.zig` handles.
/// * A directory is never reported on its own. It only holds the files that
///   did change, so an empty directory the agent made is reported as nothing,
///   the same choice `worktree.zig` makes.
/// * Anything that is not a regular file, a symbolic link, or a directory,
///   such as a fifo or a socket, goes in `skipped`, never dropped in silence.
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

    const left = allocator.alloc(u8, compare_chunk_bytes) catch return error.OutOfMemory;
    defer allocator.free(left);
    const right = allocator.alloc(u8, compare_chunk_bytes) catch return error.OutOfMemory;
    defer allocator.free(right);

    var pending: std.ArrayList(PendingDir) = .empty;
    defer {
        for (pending.items) |item| allocator.free(item.relative);
        pending.deinit(allocator);
    }

    const root_relative = allocator.dupe(u8, "") catch return error.OutOfMemory;
    pending.append(allocator, .{ .relative = root_relative, .in_project = true }) catch {
        allocator.free(root_relative);
        return error.OutOfMemory;
    };

    while (pending.pop()) |dir| {
        defer allocator.free(dir.relative);

        const clone_path = try joinAbsolute(allocator, self.upper, dir.relative);
        defer allocator.free(clone_path);

        var clone_dir = try openIterable(io, clone_path, diag);
        defer clone_dir.close(io);

        var project_dir: ?std.Io.Dir = null;
        defer if (project_dir) |d| d.close(io);
        if (dir.in_project) {
            const project_path = try joinAbsolute(allocator, self.project, dir.relative);
            defer allocator.free(project_path);
            project_dir = try openIterable(io, project_path, diag);
        }

        // Every name the clone holds in this directory, so the second pass
        // below can tell a path the agent deleted from one it left alone.
        // The keys are owned and freed together at the end of this
        // directory.
        var clone_names: std.StringHashMapUnmanaged(void) = .empty;
        defer {
            var it = clone_names.keyIterator();
            while (it.next()) |key| allocator.free(key.*);
            clone_names.deinit(allocator);
        }

        var clone_it = clone_dir.iterate();
        while (true) {
            const entry = (clone_it.next(io) catch |err| {
                diagnostic.noteErr(diag, .clone_read, err);
                return error.Unexpected;
            }) orelse break;

            const name = allocator.dupe(u8, entry.name) catch return error.OutOfMemory;
            clone_names.put(allocator, name, {}) catch {
                allocator.free(name);
                return error.OutOfMemory;
            };

            // The kind comes from a stat of the clone, never from the
            // directory listing's own type field: a listing may report
            // nothing at all for an entry, and an entry this driver cannot
            // classify is an entry missing from the diff.
            const clone_stat = (try statNoFollow(io, clone_dir, name, diag)) orelse continue;
            const project_stat = if (project_dir) |d| try statNoFollow(io, d, name, diag) else null;

            const relative = try joinRelative(allocator, dir.relative, name);
            var relative_owned = true;
            defer if (relative_owned) allocator.free(relative);

            switch (clone_stat.kind) {
                .directory => {
                    // A directory that replaced a file, or a link, is a
                    // deletion at that path, on top of being walked into.
                    const replaced_something = if (project_stat) |ps| ps.kind != .directory else false;
                    if (replaced_something) {
                        changed.append(allocator, .{ .path = relative, .kind = .deleted }) catch return error.OutOfMemory;
                        relative_owned = false;
                    }
                    const still_in_project = if (project_stat) |ps| ps.kind == .directory else false;
                    // The deletion above already took `relative`, so this
                    // needs a copy of its own to walk into.
                    const pushed = if (relative_owned) relative else (allocator.dupe(u8, relative) catch return error.OutOfMemory);
                    pending.append(allocator, .{ .relative = pushed, .in_project = still_in_project }) catch {
                        if (!relative_owned) allocator.free(pushed);
                        return error.OutOfMemory;
                    };
                    relative_owned = false;
                },
                .file, .sym_link => {
                    const kind = try classifyFile(
                        io,
                        clone_dir,
                        project_dir,
                        name,
                        clone_stat,
                        project_stat,
                        left,
                        right,
                        diag,
                    );
                    if (kind) |k| {
                        changed.append(allocator, .{ .path = relative, .kind = k }) catch return error.OutOfMemory;
                        relative_owned = false;
                    }
                },
                else => |other| {
                    const reason = std.fmt.allocPrint(
                        allocator,
                        "not a regular file, a link, or a directory (it is a {s})",
                        .{@tagName(other)},
                    ) catch return error.OutOfMemory;
                    defer allocator.free(reason);
                    try recordSkip(&skipped, allocator, relative, reason);
                },
            }
        }

        // The second pass: everything the project holds here that the clone
        // does not hold at all. A directory is reported once and not walked
        // into, because the whole tree below it went with it.
        if (project_dir) |d| {
            var project_it = d.iterate();
            while (true) {
                const entry = (project_it.next(io) catch |err| {
                    diagnostic.noteErr(diag, .project_read, err);
                    return error.Unexpected;
                }) orelse break;
                if (clone_names.contains(entry.name)) continue;

                const relative = try joinRelative(allocator, dir.relative, entry.name);
                changed.append(allocator, .{ .path = relative, .kind = .deleted }) catch {
                    allocator.free(relative);
                    return error.OutOfMemory;
                };
            }
        }
    }

    return .{
        .changed = changed.toOwnedSlice(allocator) catch return error.OutOfMemory,
        .skipped = skipped.toOwnedSlice(allocator) catch return error.OutOfMemory,
    };
}

/// How one file or one symbolic link in the clone differs from the project,
/// or null when it does not differ at all. See `changedFiles`'s own doc
/// comment for the rules, and this file's top comment for why this reads
/// content and never a timestamp.
fn classifyFile(
    io: std.Io,
    clone_dir: std.Io.Dir,
    project_dir: ?std.Io.Dir,
    name: []const u8,
    clone_stat: std.Io.File.Stat,
    project_stat: ?std.Io.File.Stat,
    left: []u8,
    right: []u8,
    diag: ?*?Diagnostic,
) Error!?ChangeKind {
    const project = project_stat orelse return .added;
    const other = project_dir orelse return .added;

    // A file where the project has a directory, or a link where the project
    // has a file, is a change at that path whatever the bytes say.
    if (project.kind != clone_stat.kind) return .modified;

    if (clone_stat.kind == .sym_link) {
        return if (try sameLinkTarget(io, clone_dir, other, name, diag)) null else .modified;
    }

    // Different lengths cannot hold the same bytes, and this costs no read.
    if (project.size != clone_stat.size) return .modified;

    return if (try sameContent(io, clone_dir, other, name, left, right, diag)) null else .modified;
}

/// Whether the two symbolic links of the same name point at the same target.
/// The target itself is compared, never what it resolves to: a link into the
/// clone and the same link into the project resolve to different files by
/// design.
fn sameLinkTarget(
    io: std.Io,
    left_dir: std.Io.Dir,
    right_dir: std.Io.Dir,
    name: []const u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var left_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var right_buffer: [std.fs.max_path_bytes]u8 = undefined;

    const left_len = left_dir.readLink(io, name, &left_buffer) catch |err| {
        diagnostic.noteErr(diag, .clone_link_read, err);
        return error.Unexpected;
    };
    const right_len = right_dir.readLink(io, name, &right_buffer) catch |err| {
        diagnostic.noteErr(diag, .project_link_read, err);
        return error.Unexpected;
    };
    return std.mem.eql(u8, left_buffer[0..left_len], right_buffer[0..right_len]);
}

/// Whether the two files of the same name hold the same bytes. Both are read
/// a chunk at a time, into buffers the caller owns and reuses, so a large
/// file costs no allocation of its own.
fn sameContent(
    io: std.Io,
    left_dir: std.Io.Dir,
    right_dir: std.Io.Dir,
    name: []const u8,
    left: []u8,
    right: []u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var left_file = left_dir.openFile(io, name, .{}) catch |err| {
        diagnostic.noteErr(diag, .clone_file_open, err);
        return error.Unexpected;
    };
    defer left_file.close(io);
    var right_file = right_dir.openFile(io, name, .{}) catch |err| {
        diagnostic.noteErr(diag, .project_file_open, err);
        return error.Unexpected;
    };
    defer right_file.close(io);

    while (true) {
        const left_len = try readChunk(io, left_file, left, diag);
        const right_len = try readChunk(io, right_file, right, diag);
        if (left_len != right_len) return false;
        if (left_len == 0) return true;
        if (!std.mem.eql(u8, left[0..left_len], right[0..right_len])) return false;
    }
}

/// Fill `buffer` from `file`, or return fewer bytes at the end of the file.
/// `std.Io.File.readStreaming` may give back less than the room it was
/// offered, so this asks again until the buffer is full or the file ends.
fn readChunk(io: std.Io, file: std.Io.File, buffer: []u8, diag: ?*?Diagnostic) Error!usize {
    var filled: usize = 0;
    while (filled < buffer.len) {
        const count = file.readStreaming(io, &.{buffer[filled..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => |e| {
                diagnostic.noteErr(diag, .compared_file_read, e);
                return error.Unexpected;
            },
        };
        if (count == 0) break;
        filled += count;
    }
    return filled;
}

/// Metadata for `name` inside `dir`, without following a symbolic link, or
/// null when there is nothing there. A link is described as a link, which is
/// what `changedFiles` needs: following it would describe its target instead.
fn statNoFollow(
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    diag: ?*?Diagnostic,
) Error!?std.Io.File.Stat {
    return dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => |e| {
            diagnostic.noteErr(diag, .entry_metadata_read, e);
            return error.Unexpected;
        },
    };
}

fn openIterable(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!std.Io.Dir {
    return std.Io.Dir.cwd().openDir(io, absolute_path, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .directory_open, err);
        return error.Unexpected;
    };
}

/// `root` joined with a path relative to it. An empty relative path names the
/// root itself.
fn joinAbsolute(allocator: std.mem.Allocator, root: []const u8, relative: []const u8) Error![]u8 {
    if (relative.len == 0) return allocator.dupe(u8, root) catch return error.OutOfMemory;
    return std.fs.path.join(allocator, &.{ root, relative }) catch return error.OutOfMemory;
}

/// One entry's own path relative to the project root. An empty prefix names a
/// directory's entry directly, with no leading separator.
fn joinRelative(allocator: std.mem.Allocator, prefix: []const u8, name: []const u8) Error![]u8 {
    if (prefix.len == 0) return allocator.dupe(u8, name) catch return error.OutOfMemory;
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name }) catch return error.OutOfMemory;
}

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

/// Find every directory under `project` that is itself the mount point of a
/// separate filesystem, in the same shape `linux/overlay.zig`'s own
/// `nestedMounts` reports.
///
/// This matters more for a clone than for an overlay mount, not less.
/// `clonefile` clones one filesystem. It does not descend into another one
/// mounted inside the project, so a directory that is a mount point comes out
/// of the clone empty, and the agent would read that emptiness as the truth.
/// A caller has to tell the user, the same way it does on Linux.
///
/// A directory found to be a nested mount point is reported but not descended
/// into: whatever is mounted there is a separate question from what `project`
/// itself holds, and this function only answers the second one.
///
/// Told apart from an ordinary directory by comparing filesystem numbers,
/// read with `lstat`, never by trusting a directory listing.
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

    const root_device = try deviceOf(allocator, project, diag);

    var pending: std.ArrayList([]u8) = .empty;
    defer {
        for (pending.items) |item| allocator.free(item);
        pending.deinit(allocator);
    }

    const root_relative = allocator.dupe(u8, "") catch return error.OutOfMemory;
    pending.append(allocator, root_relative) catch {
        allocator.free(root_relative);
        return error.OutOfMemory;
    };

    while (pending.pop()) |relative| {
        defer allocator.free(relative);

        const absolute = try joinAbsolute(allocator, project, relative);
        defer allocator.free(absolute);

        var dir = try openIterable(io, absolute, diag);
        defer dir.close(io);

        var it = dir.iterate();
        while (true) {
            const entry = (it.next(io) catch |err| {
                diagnostic.noteErr(diag, .project_read, err);
                return error.Unexpected;
            }) orelse break;

            const stat = (try statNoFollow(io, dir, entry.name, diag)) orelse continue;
            if (stat.kind != .directory) continue;

            const child_relative = try joinRelative(allocator, relative, entry.name);
            var owned = true;
            defer if (owned) allocator.free(child_relative);

            const child_absolute = try joinAbsolute(allocator, project, child_relative);
            defer allocator.free(child_absolute);

            if ((try deviceOf(allocator, child_absolute, diag)) != root_device) {
                list.append(allocator, .{ .path = child_relative }) catch return error.OutOfMemory;
                owned = false;
                continue;
            }

            pending.append(allocator, child_relative) catch return error.OutOfMemory;
            owned = false;
        }
    }

    return list.toOwnedSlice(allocator) catch return error.OutOfMemory;
}

/// The number of the filesystem `absolute_path` lives on. See `DeviceStat`.
fn deviceOf(allocator: std.mem.Allocator, absolute_path: []const u8, diag: ?*?Diagnostic) Error!i32 {
    const path_z = allocator.dupeZ(u8, absolute_path) catch return error.OutOfMemory;
    defer allocator.free(path_z);

    var stat: DeviceStat = undefined;
    const result = lstat(path_z.ptr, &stat);
    if (result != 0) {
        diagnostic.noteErrno(diag, .entry_device_read, std.posix.errno(result));
        return error.Unexpected;
    }
    return stat.device;
}

/// A project and a scratch directory, side by side under one `tmpDir`, so
/// both are on the same volume and `clonefile` has no reason to refuse.
/// Mirrors `linux/overlay.zig`'s own `TestProject`.
const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    scratch_path: []u8,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(std.testing.io, &buffer);
        const tmp_path = buffer[0..length];

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
        self.* = undefined;
    }

    fn writeFile(self: TestProject, relative: []const u8, contents: []const u8) !void {
        try writeUnder(self.allocator, self.root_path, relative, contents);
    }

    fn makeDir(self: TestProject, relative: []const u8) !void {
        const path = try std.fs.path.join(self.allocator, &.{ self.root_path, relative });
        defer self.allocator.free(path);
        try std.Io.Dir.createDirAbsolute(std.testing.io, path, .default_dir);
    }
};

fn writeUnder(allocator: std.mem.Allocator, root: []const u8, relative: []const u8, contents: []const u8) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, contents);
}

fn deleteUnder(allocator: std.mem.Allocator, root: []const u8, relative: []const u8) !void {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    try std.Io.Dir.deleteFileAbsolute(std.testing.io, path);
}

fn readUnder(allocator: std.mem.Allocator, root: []const u8, relative: []const u8) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    var buffer: [4096]u8 = undefined;
    const length = try readChunk(std.testing.io, file, &buffer, null);
    return allocator.dupe(u8, buffer[0..length]);
}

/// The one change reported for `path`, or null when nothing was reported for
/// it. Every test below asks this rather than trusting the order of the
/// report, which no driver promises.
fn changeFor(report: ChangeReport, path: []const u8) ?ChangeKind {
    for (report.changed) |item| {
        if (std.mem.eql(u8, item.path, path)) return item.kind;
    }
    return null;
}

test "create clones the project, and the clone carries the project's own content" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeDir("sub");
    try project.writeFile("sub/kept.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    const cloned = try readUnder(allocator, ov.upper, "sub/kept.txt");
    defer allocator.free(cloned);
    try std.testing.expectEqualStrings("original\n", cloned);
}

test "a file the agent created is reported as added" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "new.txt", "brand new\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "new.txt").?);
}

test "a file the agent changed is reported as modified" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("changed.txt", "before\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "changed.txt", "after\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.modified, changeFor(report, "changed.txt").?);

    // The project's own copy is untouched: the clone is where the write
    // landed. This is the property the whole backing exists for.
    const original = try readUnder(allocator, project.root_path, "changed.txt");
    defer allocator.free(original);
    try std.testing.expectEqualStrings("before\n", original);
}

test "a file the agent deleted is reported as deleted" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("gone.txt", "goodbye\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try deleteUnder(allocator, ov.upper, "gone.txt");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.deleted, changeFor(report, "gone.txt").?);
}

test "a file nobody touched is reported as unchanged, though clonefile copies its timestamps" {
    if (builtin.os.tag != .macos) return;
    // The case a timestamp comparison gets wrong. clonefile copies each
    // file's mtime and stamps a fresh ctime on it, and it gives every cloned
    // directory a fresh mtime too, so a rule of "changed if the timestamp is
    // at or after the clone" reports this whole tree as changed. Only the
    // content says the truth. See this file's own top comment.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("untouched.txt", "same bytes\n");
    try project.makeDir("sub");
    try project.writeFile("sub/also-untouched.txt", "same bytes too\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    // The agent writes one file and leaves the other two alone.
    try writeUnder(allocator, ov.upper, "written.txt", "the only change\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "written.txt").?);
    try std.testing.expectEqual(@as(?ChangeKind, null), changeFor(report, "untouched.txt"));
    try std.testing.expectEqual(@as(?ChangeKind, null), changeFor(report, "sub/also-untouched.txt"));
}

test "a file changed and then changed back to its own bytes is reported as unchanged" {
    if (builtin.os.tag != .macos) return;
    // The one place this driver is stricter than linux/overlay.zig, which
    // names this as a known gap it cannot close without reading content.
    // This driver reads content already, so it reports the truth.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("round-trip.txt", "original\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "round-trip.txt", "different\n");
    try writeUnder(allocator, ov.upper, "round-trip.txt", "original\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.changed.len);
}

test "a file of the same length with different bytes is still reported as modified" {
    if (builtin.os.tag != .macos) return;
    // The size check is a shortcut for files of different lengths, never the
    // whole answer. A driver that stopped at the size would call this pair
    // equal.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("same-length.txt", "aaaa\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    try writeUnder(allocator, ov.upper, "same-length.txt", "bbbb\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.modified, changeFor(report, "same-length.txt").?);
}

test "a whole project directory the agent removed is reported as one deletion" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeDir("olddir");
    try project.writeFile("olddir/inside.txt", "bye\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    const olddir = try std.fs.path.join(allocator, &.{ ov.upper, "olddir" });
    defer allocator.free(olddir);
    try std.Io.Dir.cwd().deleteTree(std.testing.io, olddir);

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqualStrings("olddir", report.changed[0].path);
    try std.testing.expectEqual(ChangeKind.deleted, report.changed[0].kind);
}

test "a new directory the agent made is not reported on its own, only the file inside it" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    const newdir = try std.fs.path.join(allocator, &.{ ov.upper, "newdir" });
    defer allocator.free(newdir);
    try std.Io.Dir.createDirAbsolute(std.testing.io, newdir, .default_dir);
    try writeUnder(allocator, ov.upper, "newdir/inside.txt", "hello\n");

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "newdir/inside.txt").?);
}

test "a symbolic link the agent made is reported as added, and the project keeps none" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("target.txt", "pointed at\n");

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    // A relative target, so the link means the same thing in the clone as it
    // would in the project. symLinkAbsolute refuses a relative target.
    var clone_dir = try std.Io.Dir.cwd().openDir(std.testing.io, ov.upper, .{});
    defer clone_dir.close(std.testing.io);
    try clone_dir.symLink(std.testing.io, "target.txt", "link", .{});

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.added, changeFor(report, "link").?);

    const project_link = try std.fs.path.join(allocator, &.{ project.root_path, "link" });
    defer allocator.free(project_link);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, project_link, .{ .follow_symlinks = false }),
    );
}

test "a symbolic link the agent repointed is modified, and one it left alone is not" {
    if (builtin.os.tag != .macos) return;
    // A link is compared by its own target, never by what the target
    // resolves to: the same relative target names a different file inside the
    // clone than it does in the project, and that is not a change.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.writeFile("first.txt", "one\n");
    try project.writeFile("second.txt", "two\n");

    var project_dir = try std.Io.Dir.cwd().openDir(std.testing.io, project.root_path, .{});
    defer project_dir.close(std.testing.io);
    try project_dir.symLink(std.testing.io, "first.txt", "moved", .{});
    try project_dir.symLink(std.testing.io, "first.txt", "kept", .{});

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);

    var clone_dir = try std.Io.Dir.cwd().openDir(std.testing.io, ov.upper, .{});
    defer clone_dir.close(std.testing.io);
    try clone_dir.deleteFile(std.testing.io, "moved");
    try clone_dir.symLink(std.testing.io, "second.txt", "moved", .{});

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.changed.len);
    try std.testing.expectEqual(ChangeKind.modified, changeFor(report, "moved").?);
    try std.testing.expectEqual(@as(?ChangeKind, null), changeFor(report, "kept"));
}

test "a fifo the agent made is recorded as a skip, not silently dropped" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var ov = try create(allocator, std.testing.io, project.root_path, project.scratch_path, null);
    defer ov.deinit(allocator);
    const fifo_path = try std.fs.path.joinZ(allocator, &.{ ov.upper, "pipe1" });
    defer allocator.free(fifo_path);
    try std.testing.expectEqual(@as(c_int, 0), mkfifo(fifo_path.ptr, 0o600));

    var report = try ov.changedFiles(allocator, std.testing.io, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.changed.len);
    try std.testing.expectEqual(@as(usize, 1), report.skipped.len);
    try std.testing.expectEqualStrings("pipe1", report.skipped[0].path);
}

test "create refuses a scratch directory that already holds a clone, and names the path" {
    if (builtin.os.tag != .macos) return;
    // clonefile refuses a destination that exists. A scratch directory left
    // behind by an earlier session must give a message that says what to
    // remove, not a confusing one.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const stale = try std.fs.path.join(allocator, &.{ project.scratch_path, "upper" });
    defer allocator.free(stale);
    try std.Io.Dir.createDirAbsolute(std.testing.io, stale, .default_dir);

    try std.testing.expectError(
        error.ScratchAlreadyExists,
        create(allocator, std.testing.io, project.root_path, project.scratch_path, null),
    );
}

test "create refuses a scratch directory on another volume, and names the volume problem" {
    if (builtin.os.tag != .macos) return;
    // clonefile cannot clone across a volume. This needs a second writable
    // volume to prove, and a machine may have none, so this test looks for
    // one and skips when it finds none rather than passing on nothing.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const project_device = try deviceOf(allocator, project.root_path, null);

    // Candidates that are separate APFS volumes on an ordinary macOS
    // install. Each is only used when it really is a different volume from
    // the project's own.
    const candidates = [_][]const u8{ "/nix", "/System/Volumes/VM", "/System/Volumes/Data" };
    var other_volume: ?[]const u8 = null;
    for (candidates) |candidate| {
        const device = deviceOf(allocator, candidate, null) catch continue;
        if (device != project_device) {
            other_volume = candidate;
            break;
        }
    }
    const scratch = other_volume orelse return error.SkipZigTest;

    try std.testing.expectError(
        error.ScratchOnAnotherVolume,
        create(allocator, std.testing.io, project.root_path, scratch, null),
    );
}

test "nestedMounts finds nothing under a project with no mounts of its own" {
    if (builtin.os.tag != .macos) return;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeDir("sub");
    try project.writeFile("sub/file.txt", "plain\n");

    const mounts = try nestedMounts(allocator, std.testing.io, project.root_path, null);
    defer iface.freeNestedMounts(allocator, mounts);
    try std.testing.expectEqual(@as(usize, 0), mounts.len);
}
