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

    const shape = .{ "create", "changedFiles", "nestedMounts" };
    inline for (shape) |name| {
        if (!@hasDecl(linux_driver, name)) @compileError("linux overlay driver is missing " ++ name);
        if (!@hasDecl(darwin_driver, name)) @compileError("darwin overlay driver is missing " ++ name);
    }
}
