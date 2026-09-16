//! The overlay backing for a project that is not a git repository, behind one
//! driver per way of building it.
//!
//! **The two drivers share a result, not a mechanism.** Neither is a port of
//! the other, and neither could be.
//!
//! A caller that only ever sees a `Workspace` this file's own `create` helped
//! build cannot tell which driver ran. Both `create` calls return the same
//! four paths, and both `changedFiles` calls return the same `ChangeReport`,
//! so no caller needs a platform branch of its own.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why a call here failed, past what `Error` can say. One type for the whole
/// module: see `chock-workspace/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const builtin = @import("builtin");
const layout_mod = @import("layout.zig");
/// Where the sandbox sees the workspace. See `chock-workspace/layout.zig`.
pub const Layout = layout_mod.Layout;
const sandbox = @import("chock-sandbox");

/// One mount list entry, in the shape `Sandbox.spawn` reads. See
/// `worktree.zig`'s own `Mount` for why this is the type
/// `lib/chock-sandbox/namespace.zig` defines, not a copy of it.
pub const Mount = sandbox.namespace.Mount;

pub const Error = error{
    OutOfMemory,
    /// The kernel, or the filesystem, returned an errno with no specific
    /// recovery. Reported as a bug.
    Unexpected,
    /// This driver cannot build an overlay backing on this filesystem at
    /// all. Only the Darwin driver returns this, from `create`, and only for
    /// a volume with no copy on write clone, such as HFS+: see
    /// `darwin/overlay.zig`.
    NoOverlayFilesystem,
    /// The scratch directory and the project are on different volumes, and
    /// the Darwin driver's `clonefile(2)` cannot clone across one. Only the
    /// Darwin driver returns this. The caller answers it by choosing a
    /// scratch directory on the project's own volume: see
    /// `darwin/overlay.zig` for why Chock refuses rather than putting the
    /// scratch directory inside the project.
    ScratchOnAnotherVolume,
    /// The Darwin driver's clone destination already exists, usually because
    /// an earlier session left it behind. `clonefile(2)` refuses a
    /// destination that exists. Only the Darwin driver returns this.
    ScratchAlreadyExists,
    /// `adopt` found no upper layer under the scratch directory it was given,
    /// so there is no overlay there to take. **Never a fault**: it is what a
    /// person gets after `chock workspace clear`, and what a caller gets for a
    /// session that never opened an overlay at all.
    NoOverlayToAdopt,
    /// `carryOut` was given a destination that already holds something. The
    /// work is still in the upper layer, and nothing at the destination was
    /// read, written, or removed. See `carryOut`.
    WorkAlreadyCarriedOut,
};

/// How one path under the upper layer changed. `changedFiles` reports one of
/// these per path.
pub const ChangeKind = enum {
    /// The project had no file at this path. The agent made it.
    added,
    /// The project had a file at this path, and the agent wrote a new
    /// version of it.
    modified,
    /// The project had a file at this path, and the agent removed it, or
    /// replaced it with a directory. See `linux/overlay.zig`'s own top
    /// comment for how overlayfs records a plain removal as a whiteout, and
    /// a replacement with a directory as an opaque directory, and how
    /// `changedFiles` recognises each.
    deleted,
};

/// One path `changedFiles` found under the upper layer, and how it changed.
pub const ChangedFile = struct {
    /// The path relative to the project root, read off the upper layer.
    /// Owned by this value.
    path: []u8,
    kind: ChangeKind,

    pub fn deinit(self: *ChangedFile, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

/// Free every path `changedFiles` returned, and the slice itself.
pub fn freeChangedFiles(allocator: std.mem.Allocator, list: []ChangedFile) void {
    for (list) |*item| item.deinit(allocator);
    allocator.free(list);
}

/// One path `changedFiles` found under the upper layer but could not
/// classify as added, modified, or deleted: a fifo, a socket, or a device
/// node the agent made with `mknod`. Recorded rather than dropped, the same
/// reason `worktree.zig`'s own `ImportReport.skipped` exists: a skip nobody
/// can see is the same silent gap as reporting nothing at all.
pub const Skip = struct {
    /// The path relative to the project root, read off the upper layer.
    path: []u8,
    /// Why this path was skipped, in one line.
    reason: []u8,

    pub fn deinit(self: *Skip, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.reason);
        self.* = undefined;
    }
};

/// Free every skip `changedFiles` returned, and the slice itself.
pub fn freeSkips(allocator: std.mem.Allocator, list: []Skip) void {
    for (list) |*item| item.deinit(allocator);
    allocator.free(list);
}

/// What `changedFiles` found under the upper layer: every path that changed,
/// and every path it found but could not classify. The caller owns both
/// slices and frees them together with `deinit`.
pub const ChangeReport = struct {
    changed: []ChangedFile,
    skipped: []Skip,

    pub fn deinit(self: *ChangeReport, allocator: std.mem.Allocator) void {
        freeChangedFiles(allocator, self.changed);
        freeSkips(allocator, self.skipped);
        self.* = undefined;
    }
};

/// One path under `project` that is itself the mount point of a separate
/// filesystem, so `Overlay.mounts`'s own merged view cannot show what is
/// mounted there. See `linux/overlay.zig`'s own `nestedMounts`.
pub const NestedMount = struct {
    /// The path relative to `project`.
    path: []u8,

    pub fn deinit(self: *NestedMount, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

/// Free every path `nestedMounts` returned, and the slice itself.
pub fn freeNestedMounts(allocator: std.mem.Allocator, list: []NestedMount) void {
    for (list) |*item| item.deinit(allocator);
    allocator.free(list);
}

/// What `carryOut` put at the destination it was given.
///
/// **Three counts and not one**, because the three are different promises. A
/// caller says all three to the person: a count of files alone would let a
/// carried out directory that dropped every deletion read as a complete
/// answer.
pub const CarriedOut = struct {
    /// How many files and links arrived under `<destination>/files`.
    files: usize,
    /// How many paths the session deleted. Every one of them is named in
    /// `<destination>/deleted`, and **not one of them is applied to the
    /// project**: see `carryOut`.
    deleted: usize,
    /// How many paths `changedFiles` found and could not classify, plus every
    /// path that went away between the walk and the copy. Every one of them is
    /// named in `<destination>/skipped`, with the reason.
    skipped: usize,
};

/// What `carryOut` calls the directory it puts the changed files in.
pub const carried_files_name = "files";

/// What `carryOut` calls the file it writes the deleted paths into, one per
/// line.
pub const carried_deleted_name = "deleted";

/// What `carryOut` calls the file it writes the skipped paths into, one
/// `path: reason` per line.
pub const carried_skipped_name = "skipped";

/// The overlayfs layers for one project that has no git repository of its own.
/// Every field is an absolute host path, and every field is owned by this
/// value unless its own doc comment says otherwise.
pub const Overlay = struct {
    /// The project. The lower layer. Nothing in this file ever opens this for
    /// write, and the real overlay mount refuses a write to it too: the
    /// kernel keeps the lower layer of an overlay mount read only on its own.
    project: []u8,
    /// The upper layer, under the scratch directory `create` was given. Every
    /// write the agent makes, while the overlay is mounted, lands here and
    /// nowhere else. `changedFiles` reads this directory, never the project.
    upper: []u8,
    /// overlayfs's own work directory, under the same scratch directory as
    /// `upper`. The kernel uses this to prepare a change before it becomes
    /// visible in `upper`. No caller of this file ever reads it.
    work: []u8,
    /// Where `mounts` mounts the overlay: the merged view of `project` and
    /// `upper` together. Empty until `mounts` runs.
    merged: []u8,
    /// Which of the two shapes `mounts` builds. See
    /// `chock-workspace/layout.zig`. The default is the host's own, so a
    /// driver that builds an `Overlay` needs no field of its own for it, and
    /// `createWithLayout` is the one call that says otherwise.
    layout: Layout = Layout.forHost(),

    /// The absolute path at which the sandbox sees the agent's own copy of the
    /// project.
    ///
    /// **The merged view under `.remapped`, and the clone itself under
    /// `.in_place`.** macOS has no overlayfs and no bind mount, so there is no
    /// merged view to show and no way to give the clone the project's name.
    /// The tool call works in the clone, under the clone's own real path.
    pub fn sandboxRoot(self: Overlay) []const u8 {
        return switch (self.layout) {
            .remapped => self.project,
            .in_place => self.upper,
        };
    }

    /// Free every path this value owns. `self` is not valid after this call
    /// returns. Does not unmount `merged`: the real overlay mount, made by
    /// `mounts`, lives in the caller's own private mount namespace and goes
    /// away on its own once that namespace's last process exits, the same way
    /// every mount `chock-sandbox`'s own `buildRoot` makes does.
    pub fn deinit(self: *Overlay, allocator: std.mem.Allocator) void {
        allocator.free(self.project);
        allocator.free(self.upper);
        allocator.free(self.work);
        allocator.free(self.merged);
        self.* = undefined;
    }

    /// Describe the overlay mount: `project` as the read only lower layer,
    /// `upper` as the read write upper layer, `work` as overlayfs's own
    /// scratch directory, mounted at `project`'s own real path. The caller
    /// owns the returned slice and frees it with `allocator.free`.
    ///
    /// This performs no mount of its own: it only builds the one entry a
    /// caller hands to `chock-sandbox`'s own `buildRoot`, which is the only
    /// place that ever calls `mount(2)` for it, with `userxattr` in the
    /// options: see `linux/overlay.zig`'s own top comment for why that option
    /// is required, not optional, for a rootless overlay mount to behave
    /// correctly. Building this list needs no privilege and no namespace of
    /// any kind: `Workspace.sandboxConfig` calls this for the overlay kind
    /// exactly the way it calls `Worktree.mounts` for the worktree kind, from
    /// an ordinary, unprivileged caller.
    ///
    /// Unlike `create` and `changedFiles`, this needs no driver: nothing
    /// about describing a mount reads overlayfs's own on disk state, so this
    /// same body already ran on a build with no real overlayfs at all, before
    /// the driver split ever separated this file from `linux/overlay.zig`.
    pub fn mounts(self: Overlay, allocator: std.mem.Allocator) Error![]Mount {
        const list = allocator.alloc(Mount, 1) catch return error.OutOfMemory;
        list[0] = switch (self.layout) {
            .remapped => .{ .overlay = .{
                .lower = self.project,
                .upper = self.upper,
                .work = self.work,
                .target = self.project,
            } },
            // **The clone, where it is, and no lower layer at all.** macOS has
            // no overlayfs, so `darwin/overlay.zig` already made a whole copy
            // on write clone of the project at `upper`. There is nothing left
            // to merge and nothing to move, so the one entry is the clone
            // itself, read write, at its own path. `changedFiles` reads the
            // same directory afterwards, exactly as it does on the other
            // layout.
            .in_place => .{ .bind = .{
                .source = self.upper,
                .target = self.upper,
                .read_only = false,
            } },
        };
        return list;
    }

    /// Report every path that changed.
    /// Forwards to whichever driver `builtin.os.tag` selects below, and both
    /// return the same shape: `linux/overlay.zig` reads the overlay mount's
    /// own upper layer, and `darwin/overlay.zig` compares the clone against
    /// the project by content. See each driver's own `changedFiles` for the
    /// real work.
    pub fn changedFiles(
        self: Overlay,
        allocator: std.mem.Allocator,
        io: std.Io,
        diag: ?*?Diagnostic,
    ) Error!ChangeReport {
        return driver.changedFiles(self, allocator, io, diag);
    }

    /// Put the work of an overlay at `destination`, and answer what arrived.
    ///
    /// ## Why the work goes beside the project and never over it
    ///
    /// A git project gets its work back at `refs/chock/<session>`: the objects are
    /// in the repository, a name points at them, **nothing of the person's has
    /// moved**, and the person runs `git merge` when they choose. That property is
    /// what makes an apply safe to run without asking about every file.
    ///
    /// A project with no git has no object store and no ref, so the nearest thing
    /// that keeps the same property is a plain directory the person owns. This
    /// call writes the changed files into `<destination>/files`, at the paths they
    /// have in the project, and writes nothing anywhere else. A person reads it
    /// with `ls` and `diff -r` and takes what they want with `cp`. No format has to
    /// be learned, and no step of this can lose a file the person already had.
    ///
    /// The two other ways this could have gone, and why neither is this one:
    ///
    /// * **Copy the upper layer over the project.** It finishes the job and it is
    ///   the one way that can destroy work. A project with no git has no commit to
    ///   go back to, so a wrong file written over a right one is gone. The git path
    ///   never writes into the person's checked out files without an approved
    ///   `workspace.apply`, and there is no approval here, because the session that
    ///   did the work has already ended.
    /// * **Make a patch or an archive.** It is portable and it costs a format
    ///   Chock then owns. A patch carries no binary file, no symbolic link and no
    ///   file mode, and a project with no git is exactly the project with no `git
    ///   apply` either. An archive needs a second step before anybody can read what
    ///   is in it.
    ///
    /// ## A deletion is work, so it is carried as a name and never as an act
    ///
    /// The session that removed a file did work, and a carry out that quietly left
    /// the file in place would report success for an answer that is wrong. A
    /// deletion also cannot be a file in `<destination>/files`: the absence of a
    /// path says nothing, since a path the session never touched is absent too.
    ///
    /// So every deleted path is written to `<destination>/deleted`, one per line,
    /// sorted. `CarriedOut.deleted` counts them, the caller says the count out
    /// loud, and the log records it. **Not one of them is applied to the project**,
    /// for the reason above: removing a person's file is the destructive act this
    /// call refuses to take on its own.
    ///
    /// ## The destination has to be free
    ///
    /// `error.WorkAlreadyCarriedOut` when anything at all is at `destination`,
    /// checked before a single byte is read out of the upper layer. Merging into a
    /// directory that already holds a carry out would write over files a person may
    /// have already edited, and there is no way to tell those apart from the ones
    /// this call put there. The upper layer is not changed by this call, so a
    /// caller that meets the refusal names another destination and gets everything.
    pub fn carryOut(
        self: Overlay,
        allocator: std.mem.Allocator,
        io: std.Io,
        destination: []const u8,
        diag: ?*?Diagnostic,
    ) Error!CarriedOut {
        // **First, and before the upper layer is opened at all.** See the doc
        // comment: a refusal that had already written half a directory is a
        // refusal a caller cannot act on.
        const occupied = std.Io.Dir.cwd().statFile(io, destination, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => {
                diagnostic.noteErr(diag, .carried_work_check, err);
                return error.Unexpected;
            },
        };
        if (occupied != null) return error.WorkAlreadyCarriedOut;

        var report = try self.changedFiles(allocator, io, diag);
        defer report.deinit(allocator);

        const files_root = std.fs.path.join(allocator, &.{ destination, carried_files_name }) catch return error.OutOfMemory;
        defer allocator.free(files_root);
        std.Io.Dir.cwd().createDirPath(io, files_root) catch |err| {
            diagnostic.noteErr(diag, .carried_work_mkdir, err);
            return error.Unexpected;
        };

        var deleted: std.ArrayList([]const u8) = .empty;
        defer deleted.deinit(allocator);
        // One owned line per skip, `path: reason`. Owned by `allocator` and freed
        // below, whichever way this call leaves.
        var skipped: std.ArrayList([]u8) = .empty;
        defer {
            for (skipped.items) |line| allocator.free(line);
            skipped.deinit(allocator);
        }

        for (report.skipped) |one| {
            const line = std.fmt.allocPrint(allocator, "{s}: {s}", .{ one.path, one.reason }) catch return error.OutOfMemory;
            errdefer allocator.free(line);
            skipped.append(allocator, line) catch return error.OutOfMemory;
        }

        var carried: usize = 0;
        for (report.changed) |one| {
            if (one.kind == .deleted) {
                deleted.append(allocator, one.path) catch return error.OutOfMemory;
                continue;
            }
            if (try carryOne(allocator, io, self.upper, files_root, one.path, &skipped, diag)) carried += 1;
        }

        std.mem.sort([]const u8, deleted.items, {}, lessThanBytes);
        std.mem.sort([]u8, skipped.items, {}, lessThanBytesMutable);

        try writeLines(allocator, io, destination, carried_deleted_name, deleted.items, diag);
        try writeLinesMutable(allocator, io, destination, carried_skipped_name, skipped.items, diag);

        return .{ .files = carried, .deleted = deleted.items.len, .skipped = skipped.items.len };
    }
};

const driver = switch (builtin.os.tag) {
    .linux => @import("linux/overlay.zig"),
    .macos => @import("darwin/overlay.zig"),
    else => @compileError("chock-workspace: no overlay driver for target os " ++ @tagName(builtin.os.tag)),
};

/// Create the scratch layout for an overlay of `project`: see whichever
/// driver `builtin.os.tag` selects. `linux/overlay.zig`'s own `create` makes
/// the empty upper and work directories an overlay mount needs;
/// `darwin/overlay.zig`'s own `create` clones the project into the same
/// `upper` path instead. Both return the same four paths.
pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    return driver.create(allocator, io, project, scratch, diag);
}

/// `create`, with the layout named rather than read from the target. See
/// `worktree.createWithLayout` for why the two calls exist.
pub fn createWithLayout(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    layout: Layout,
    diag: ?*?Diagnostic,
) Error!Overlay {
    var made = try driver.create(allocator, io, project, scratch, diag);
    made.layout = layout;
    return made;
}

/// Take over the overlay of a session whose process has ended, instead of
/// making a new one: see whichever driver `builtin.os.tag` selects. Both
/// drivers rebuild the same four paths `create` built, from the same
/// components in the same order, and neither makes an upper layer and neither
/// copies anything.
///
/// **The overlay analogue of `worktree.adopt`, and the same rule holds: this
/// call never removes a thing it did not make.** The upper layer holds work
/// nothing else has a copy of, so a failure part way through leaves every file
/// where it was.
///
/// `error.NoOverlayToAdopt` when there is no upper layer under `scratch`.
///
/// Where the work goes afterwards is `carryOut`'s question, not this one's.
pub fn adopt(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    return driver.adopt(allocator, io, project, scratch, diag);
}

/// `adopt`, with the layout named rather than read from the target. See
/// `createWithLayout`, which this stands beside for the same reason.
pub fn adoptWithLayout(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    layout: Layout,
    diag: ?*?Diagnostic,
) Error!Overlay {
    var taken = try driver.adopt(allocator, io, project, scratch, diag);
    taken.layout = layout;
    return taken;
}

/// Whether `absolute_path` is a directory on disk now. Used by both drivers'
/// own `adopt` to tell a scratch layout that is there from one that is not.
///
/// **The link is not followed, and the kind is checked.** A symbolic link at
/// one of the three scratch paths is not a scratch layout this process made,
/// and adopting it would make every later path join follow it somewhere else.
pub fn scratchDirOnDisk(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!bool {
    const found = std.Io.Dir.cwd().statFile(io, absolute_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => {
            diagnostic.noteErr(diag, .overlay_scratch_check, err);
            return error.Unexpected;
        },
    };
    return found.kind == .directory;
}

/// Copy one changed path out of `upper` into `files_root`, at the same
/// relative path. Answers whether it arrived.
///
/// **A symbolic link is copied as a link and never as what it points at.** A
/// link the agent made can point outside the project, and following it here
/// would copy a file the session never wrote, at a size nobody asked for.
///
/// A path that went away between `changedFiles` and this copy is recorded as a
/// skip rather than dropped, and rather than failing the whole carry out: the
/// other files are still work worth having.
fn carryOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    upper: []const u8,
    files_root: []const u8,
    relative: []const u8,
    skipped: *std.ArrayList([]u8),
    diag: ?*?Diagnostic,
) Error!bool {
    const source = std.fs.path.join(allocator, &.{ upper, relative }) catch return error.OutOfMemory;
    defer allocator.free(source);
    const target = std.fs.path.join(allocator, &.{ files_root, relative }) catch return error.OutOfMemory;
    defer allocator.free(target);

    const found = std.Io.Dir.cwd().statFile(io, source, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return try noteSkip(allocator, skipped, relative, "it went away while the work was being carried out"),
        else => {
            diagnostic.noteErr(diag, .carried_entry_stat, err);
            return error.Unexpected;
        },
    };

    switch (found.kind) {
        .file => {
            // `copyFile` carries the permissions of the source with it, so a
            // script the agent made executable is still executable here. The
            // parent directories come with `make_path`.
            std.Io.Dir.copyFileAbsolute(source, target, io, .{ .make_path = true }) catch |err| {
                diagnostic.noteErr(diag, .carried_file_copy, err);
                return error.Unexpected;
            };
            return true;
        },
        .sym_link => {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const length = std.Io.Dir.readLinkAbsolute(io, source, &buffer) catch |err| {
                diagnostic.noteErr(diag, .carried_link_read, err);
                return error.Unexpected;
            };
            const parent = std.fs.path.dirname(target) orelse target;
            std.Io.Dir.cwd().createDirPath(io, parent) catch |err| {
                diagnostic.noteErr(diag, .carried_work_mkdir, err);
                return error.Unexpected;
            };
            // **`cwd().symLink` and never `symLinkAbsolute`.** The second
            // asserts that the target is absolute, and a link an agent makes
            // inside a project is usually relative, so that call panics in a
            // Debug or ReleaseSafe build on the ordinary case. Measured: this
            // is what the test below found the first time it ran.
            std.Io.Dir.cwd().symLink(io, buffer[0..length], target, .{}) catch |err| {
                diagnostic.noteErr(diag, .carried_link_write, err);
                return error.Unexpected;
            };
            return true;
        },
        // `changedFiles` reports a path as added or modified only for a file
        // or a link, so anything else here is a path that changed kind since
        // the walk. Recorded, never guessed at.
        else => |other| {
            const reason = std.fmt.allocPrint(
                allocator,
                "it is a {s} now, and only a file or a link is carried",
                .{@tagName(other)},
            ) catch return error.OutOfMemory;
            defer allocator.free(reason);
            return try noteSkip(allocator, skipped, relative, reason);
        },
    }
}

/// Add one `path: reason` line to `skipped`. Always answers false, so a caller
/// writes `return try noteSkip(...)` where the path did not arrive.
fn noteSkip(
    allocator: std.mem.Allocator,
    skipped: *std.ArrayList([]u8),
    relative: []const u8,
    reason: []const u8,
) Error!bool {
    const line = std.fmt.allocPrint(allocator, "{s}: {s}", .{ relative, reason }) catch return error.OutOfMemory;
    errdefer allocator.free(line);
    skipped.append(allocator, line) catch return error.OutOfMemory;
    return false;
}

fn lessThanBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn lessThanBytesMutable(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Write one file under `destination` holding `lines`, one per line, each with
/// a newline after it. **Written whether or not there are any lines**: a file
/// that is there and empty says that nothing was deleted, and a file that is
/// missing says only that some build did not write it.
fn writeLines(
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: []const u8,
    name: []const u8,
    lines: []const []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (lines) |line| {
        text.appendSlice(allocator, line) catch return error.OutOfMemory;
        text.append(allocator, '\n') catch return error.OutOfMemory;
    }

    const path = std.fs.path.join(allocator, &.{ destination, name }) catch return error.OutOfMemory;
    defer allocator.free(path);
    var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch |err| {
        diagnostic.noteErr(diag, .carried_list_write, err);
        return error.Unexpected;
    };
    defer file.close(io);
    file.writeStreamingAll(io, text.items) catch |err| {
        diagnostic.noteErr(diag, .carried_list_write, err);
        return error.Unexpected;
    };
}

/// `writeLines`, for a list of owned lines. Zig has no implicit conversion
/// from `[][]u8` to `[]const []const u8`, and one copy of the body is better
/// than one cast that hides which list is owned.
fn writeLinesMutable(
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: []const u8,
    name: []const u8,
    lines: []const []u8,
    diag: ?*?Diagnostic,
) Error!void {
    var view: std.ArrayList([]const u8) = .empty;
    defer view.deinit(allocator);
    for (lines) |line| view.append(allocator, line) catch return error.OutOfMemory;
    return writeLines(allocator, io, destination, name, view.items, diag);
}

/// Find every directory under `project` that is itself the mount point of a
/// separate filesystem: see whichever driver `builtin.os.tag` selects, and
/// `NestedMount`'s own doc comment.
pub fn nestedMounts(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    diag: ?*?Diagnostic,
) Error![]NestedMount {
    return driver.nestedMounts(allocator, io, project, diag);
}

test "the linux driver and the darwin driver expose the same public shape" {
    // Guarded on `builtin.os.tag`, a comptime known value, so the branch this
    // test does not take is never even imported: unconditionally importing
    // `linux/overlay.zig` while compiling for Darwin is exactly the mistake
    // this whole split exists to avoid, since that file's own Linux syscalls
    // do not type check for that target. See `driver` above for the same
    // technique used for the real dispatch, not only this test, and
    // `lib/chock-sandbox/Sandbox.zig`'s own test of the same name, which this
    // one mirrors.
    if (builtin.os.tag != .linux) return;

    const linux_driver = @import("linux/overlay.zig");
    const darwin_driver = @import("darwin/overlay.zig");

    const shape = .{ "create", "adopt", "changedFiles", "nestedMounts" };
    inline for (shape) |name| {
        if (!@hasDecl(linux_driver, name)) @compileError("linux overlay driver is missing " ++ name);
        if (!@hasDecl(darwin_driver, name)) @compileError("darwin overlay driver is missing " ++ name);
    }
}
