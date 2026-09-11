//! Joins the two backings `worktree.zig` and `overlay.zig` build into one type a
//! caller can use without knowing which one a project got. `open` picks git or
//! overlay by asking `git.isRepository`. The caller never chooses. `sandboxConfig`
//! turns that choice into the `Sandbox.Config` a caller hands to `Sandbox.spawn`:
//! the mount list the backing already builds, the Landlock rules that go with
//! it, the `chock.zon` protection, when the project has one, and one covering
//! mount per file that project's own `deny_read` block names, all in one place.
//!
//! Three refusals this file exists to make provable: no write to
//! `.git/objects`, no write to `.git/hooks`, no delete of `chock.zon`. An
//! earlier sandbox could not prove them, because it had no `.git` to
//! protect. `test/workspace/escape.zig` is where that proof
//! lives now.
//!
//! **Every path in that config has two possible shapes, and one call decides
//! which.** `Layout.remapped` puts the checkout at the project's own path and
//! Chock's own paths under `Sandbox.runtime_prefix`, which needs a mount
//! namespace. `Layout.in_place` leaves every path where it really is, which is
//! the only shape macOS can express: see `chock-workspace/layout.zig` for what
//! that costs a person. `open` and `adopt` read the layout from the host's own
//! sandbox driver, and `openWithLayout` and `adoptWithLayout` take one, so a
//! test on either platform can build the mount list the other gets.
//!
//! This file imports `chock-sandbox` for `Sandbox.Config` and its own `Mount` and
//! `landlock` types, the same reason `worktree.zig` and `overlay.zig` each give in
//! their own top comments. `lib/chock-workspace.zig`, the root of this module,
//! must never import `chock-sandbox` itself. This file is the third of the three
//! that does.

const std = @import("std");
const builtin = @import("builtin");

const diagnostic = @import("diagnostic.zig");
/// Why a call here failed, past what `Error` can say. One type for the whole
/// module: see `chock-workspace/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const git = @import("git.zig");
const layout_mod = @import("layout.zig");
/// Where the sandbox sees the workspace. See `chock-workspace/layout.zig`.
pub const Layout = layout_mod.Layout;
const worktree_mod = @import("worktree.zig");
const overlay_mod = @import("overlay.zig");
const deny_mod = @import("deny.zig");
const sandbox = @import("chock-sandbox");

pub const Error = worktree_mod.Error || overlay_mod.Error || deny_mod.Error || error{
    /// `adopt` was asked for a project with no git of its own, which gets the
    /// overlay backing, and no second process can take one of those over
    /// today. **A refusal, not a fault, and not a claim that the work is
    /// lost**: `Workspace.adopt`'s own doc comment records what was read and
    /// what is missing, and the whole of what is missing is an
    /// `overlay.adopt` beside `overlay.create`, one per driver.
    OverlayCannotBeAdopted,
    /// `chock.zon` names a symbolic link instead of an ordinary file, in the
    /// checkout `findChockZon` was asked to read. Chock's own policy file
    /// must be real: an agent that can write its own checkout can otherwise
    /// replace `chock.zon` with a link to an arbitrary host path, and the
    /// bind mount that is meant to protect it would then bind that path in
    /// instead. Refused rather than followed. See `findChockZon`'s own doc
    /// comment.
    ChockZonIsSymlink,
};

/// Which backing a session got. `Workspace.open` decides. A caller never
/// chooses by hand.
///
/// The two kinds are equally free to build from an ordinary, unprivileged
/// caller, all the way through `sandboxConfig`. `Worktree.mounts` and
/// `Overlay.mounts` both only describe mounts: neither opens anything or
/// mounts anything, so neither needs a namespace to call. `chock-sandbox`'s
/// own `Mount` type carries a kind for exactly this, a bind mount or an
/// overlay mount, and `chock-sandbox`'s own `buildRoot` is the only place
/// that ever performs either one, inside the sandbox's own namespace, once
/// `Sandbox.spawn` runs. An earlier version of `Overlay.mounts` performed the
/// real overlay mount itself, here, before `Mount` could describe one, which
/// needed `CAP_SYS_ADMIN` over the caller's own mount namespace and so needed
/// a caller of the overlay kind to already be inside one, an extra step the
/// worktree kind never carried. That asymmetry is gone: a caller of either
/// kind calls `open`, then `sandboxConfig`, then hands the result to
/// `Sandbox.spawn`, and only `Sandbox.spawn` ever needs a namespace.
pub const Kind = union(enum) {
    /// The project is a git repository: a throwaway linked worktree.
    worktree: worktree_mod.Worktree,
    /// The project has no git of its own: an overlayfs mount.
    overlay: overlay_mod.Overlay,
};

pub const Workspace = struct {
    kind: Kind,
    /// Absolute host path of `chock.zon` inside the backing's own copy of the
    /// project (a worktree checkout, or an overlay's lower layer), if the
    /// project has one. `null` when it does not: not every session backs a
    /// chock project, and a caller with no policy file to protect should not
    /// be forced to invent one. Owned by this value.
    chock_zon_source: ?[]u8,
    /// Where `chock_zon_source` lands inside the sandbox: the real project
    /// path plus `chock.zon`. `null` exactly when `chock_zon_source` is
    /// `null`. Owned by this value.
    chock_zon_target: ?[]u8,
    /// Every file the project said the agent may not read, as an absolute
    /// path: `sandboxRoot` plus the entry, which is where the file sits inside
    /// the sandbox. Empty for a project that denied nothing, which is every
    /// project with no `deny_read` block. Owned by this value.
    ///
    /// **Read from the host project's own `chock.zon`, and never from the
    /// workspace.** See `deny.zig`'s own top comment: a rule that decides what
    /// the sandbox may hold must not be read out of the sandbox. This is the
    /// one field of this type that does not follow `chock_zon_source`, which
    /// deliberately prefers the checkout's own copy, so that the file bound
    /// over the agent's `chock.zon` is the one its own checkout carries.
    deny_paths: []const []u8,

    /// Pick a backing for `project_root` and build it. A git repository gets
    /// a throwaway linked worktree, detached at HEAD. Anything else gets the
    /// overlay backing, which on Linux is an overlayfs mount with the project
    /// as the read only lower layer, and on Darwin a copy on write clone of
    /// the project. The caller never chooses: `git.isRepository` decides.
    ///
    /// `scratch_dir` must already exist, and holds every scratch file the
    /// chosen backing needs: a real caller gives it a session scratch
    /// directory, and a test gives it its own `std.testing.tmpDir`.
    /// `session_id` is only used for the worktree path. An overlay backing
    /// ignores it, the same way `overlay.create` itself takes no session id.
    ///
    /// `open` needs no namespace for either kind: see `Kind`'s own doc
    /// comment for the one call later, `sandboxConfig`, where the two kinds
    /// stop being alike.
    ///
    /// Both kinds work on Darwin. `worktree.create` only runs `git`, which
    /// exists there too, and `overlay.create` clones the project with
    /// `clonefile(2)`: see `darwin/overlay.zig`'s own top comment. The one
    /// requirement Darwin adds is that `scratch_dir` sits on the project's
    /// own volume, since a clone cannot cross one; `open` reports
    /// `error.ScratchOnAnotherVolume` when it does not, rather than working
    /// in the user's real files.
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        project_root: []const u8,
        scratch_dir: []const u8,
        session_id: []const u8,
        diag: ?*?Diagnostic,
    ) Error!Workspace {
        return openWithLayout(allocator, io, env, project_root, scratch_dir, session_id, Layout.forHost(), diag);
    }

    /// `open`, with the layout named rather than read from the target. See
    /// `worktree.createWithLayout` for why the two calls exist.
    pub fn openWithLayout(
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        project_root: []const u8,
        scratch_dir: []const u8,
        session_id: []const u8,
        layout: Layout,
        diag: ?*?Diagnostic,
    ) Error!Workspace {
        // **Before either backing is built**, so a `deny_read` block this
        // cannot honour refuses the session rather than half building one. It
        // reads the host project's own `chock.zon`, which for the worktree
        // backing is not the file the checkout carries: see `deny_paths`.
        //
        // **Checked here and joined later**, because where the sandbox sees
        // the project is not known until the backing exists: under
        // `Layout.in_place` it is the agent's own copy, at its own real path.
        // See `deny.loadEntries`.
        const entries = try deny_mod.loadEntries(allocator, io, project_root, diag);
        defer deny_mod.free(allocator, entries);

        if (try git.isRepository(allocator, io, env, project_root, diag)) {
            var wt = try worktree_mod.createWithLayout(allocator, io, env, project_root, scratch_dir, session_id, layout, diag);
            // No diagnostic on the cleanup: the slot already holds the first
            // fault, which is the one that explains this removal.
            errdefer wt.remove(allocator, io, env, null) catch {};

            const denied = try deny_mod.joinOnto(allocator, entries, wt.sandboxRoot());
            errdefer deny_mod.free(allocator, denied);

            const chock_zon = try findChockZon(allocator, io, wt.path, wt.sandboxRoot(), diag);
            return .{
                .kind = .{ .worktree = wt },
                .chock_zon_source = chock_zon.source,
                .chock_zon_target = chock_zon.target,
                .deny_paths = denied,
            };
        }

        var ov = try overlay_mod.createWithLayout(allocator, io, project_root, scratch_dir, layout, diag);
        errdefer ov.deinit(allocator);

        const denied = try deny_mod.joinOnto(allocator, entries, ov.sandboxRoot());
        errdefer deny_mod.free(allocator, denied);

        // The overlay's own lower layer is already read only end to end, but
        // an agent that deletes chock.zon only makes a whiteout in the
        // writable upper layer, and the merged view would then show it gone.
        // Binding the project's own chock.zon back over that path, read
        // only, the same trick worktree.zig uses, closes that the same way.
        //
        // **Under `.in_place` the source is the clone's own copy**, because
        // nothing can be bound over anything there. The entry becomes a read
        // only rule on the clone's own `chock.zon`, which is what stops the
        // agent rewriting or deleting it.
        const zon_source_root = switch (layout) {
            .remapped => ov.project,
            .in_place => ov.upper,
        };
        const chock_zon = try findChockZon(allocator, io, zon_source_root, ov.sandboxRoot(), diag);
        return .{
            .kind = .{ .overlay = ov },
            .chock_zon_source = chock_zon.source,
            .chock_zon_target = chock_zon.target,
            .deny_paths = denied,
        };
    }

    /// Take over the workspace of a session that is handing over, instead of
    /// building a new one. The checkout is already on disk at
    /// `<scratch_dir>/<session_id>`, another process made it, and this call
    /// runs no git command at all: see `worktree.adopt`, which does the work
    /// for the git backing and explains what a worktree registration does and
    /// does not hold about the process that made it.
    ///
    /// The argument list is `open`'s, plus `base_commit`. That one field
    /// cannot be recovered from the disk: a session that committed before it
    /// handed over has a HEAD that is not its base, and reading HEAD back
    /// would make `Worktree.headMoved` answer "nothing changed" for a session
    /// that changed plenty. The caller carries the base commit across, out of
    /// the session log.
    ///
    /// **The overlay backing is refused, by name, with
    /// `error.OverlayCannotBeAdopted`.** What was read, and what it says:
    ///
    /// - The backing itself does outlive the process that made it. `upper`,
    ///   `work`, and `merged` are three plain directories under the session
    ///   scratch directory, and `Overlay.changedFiles` reads the upper layer
    ///   on the host, with no namespace and no mount. So an overlay session
    ///   whose process ends keeps every byte the agent wrote, exactly the way
    ///   a kept worktree does.
    /// - The merged view does not outlive it, and does not need to.
    ///   `Overlay.mounts` only describes the mount, and `chock-sandbox`'s own
    ///   `buildRoot` performs it again inside every `Sandbox.spawn` child's
    ///   own mount namespace, once per tool call. Nothing about it is bound
    ///   to one long lived process.
    /// - What is missing is the rebuild. `overlay.create` cannot be called a
    ///   second time on a scratch directory that already holds a layout: the
    ///   Linux driver makes all three directories with `createDirAbsolute`,
    ///   which answers `error.PathAlreadyExists`, folded into
    ///   `error.Unexpected`, and the Darwin driver's `clonefile` answers
    ///   `EEXIST`, which is `error.ScratchAlreadyExists`. Rebuilding the four
    ///   paths here by hand instead would put the scratch layout that
    ///   `overlay.zig` and its two drivers own into a second file, where it
    ///   can drift from theirs without either side noticing.
    /// - And `base_commit`, the one argument this call adds to `open`, has no
    ///   meaning for a project with no git: there is no commit, and
    ///   `headMoved` is not the test that decides what an overlay session
    ///   carries back. `Overlay.changedFiles` is.
    ///
    /// So the refusal names a gap in `overlay.zig`, not a fault in the
    /// backing. Closing it needs an `overlay.adopt` beside `overlay.create`,
    /// one per driver, which rebuilds the four paths and refuses a scratch
    /// directory that holds no layout.
    ///
    /// **`chock.zon` gets a fallback here that `open` does not need.** See
    /// `findChockZonForAdopt`.
    pub fn adopt(
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        project_root: []const u8,
        scratch_dir: []const u8,
        session_id: []const u8,
        base_commit: []const u8,
        diag: ?*?Diagnostic,
    ) Error!Workspace {
        return adoptWithLayout(allocator, io, env, project_root, scratch_dir, session_id, base_commit, Layout.forHost(), diag);
    }

    /// `adopt`, with the layout named rather than read from the target. See
    /// `worktree.createWithLayout` for why the two calls exist.
    pub fn adoptWithLayout(
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        project_root: []const u8,
        scratch_dir: []const u8,
        session_id: []const u8,
        base_commit: []const u8,
        layout: Layout,
        diag: ?*?Diagnostic,
    ) Error!Workspace {
        if (!try git.isRepository(allocator, io, env, project_root, diag)) {
            return error.OverlayCannotBeAdopted;
        }

        // **The host project's own `chock.zon`, and this is where that matters
        // most.** `adopt` takes over a checkout a whole session has already
        // worked in. Reading the deny list out of that checkout would let a
        // session hand over its way out of the list, which is the same fault
        // `findChockZonForAdopt` answers for the policy file itself.
        const entries = try deny_mod.loadEntries(allocator, io, project_root, diag);
        defer deny_mod.free(allocator, entries);

        var wt = try worktree_mod.adoptWithLayout(
            allocator,
            io,
            env,
            project_root,
            scratch_dir,
            session_id,
            base_commit,
            layout,
            diag,
        );
        // `keep`, never `remove`, unlike `open`'s own cleanup: the checkout
        // belongs to the session that is handing over, so a failure here
        // frees this value and leaves every file where it was. A `remove`
        // here would answer a failed handover by deleting the work.
        errdefer wt.keep(allocator);

        const denied = try deny_mod.joinOnto(allocator, entries, wt.sandboxRoot());
        errdefer deny_mod.free(allocator, denied);

        const chock_zon = try findChockZonForAdopt(allocator, io, wt.path, wt.sandboxRoot(), project_root, layout, diag);
        return .{
            .kind = .{ .worktree = wt },
            .chock_zon_source = chock_zon.source,
            .chock_zon_target = chock_zon.target,
            .deny_paths = denied,
        };
    }

    /// Free everything this value owns. For a git backing this also runs
    /// `git worktree remove`. For an overlay backing this only frees memory,
    /// since the real overlay mount lives in a mount namespace this process
    /// does not own, and goes away when that namespace does. `self` is not
    /// valid after this call returns, successfully or not.
    pub fn close(
        self: *Workspace,
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        diag: ?*?Diagnostic,
    ) Error!void {
        if (self.chock_zon_source) |s| allocator.free(s);
        if (self.chock_zon_target) |t| allocator.free(t);
        deny_mod.free(allocator, self.deny_paths);

        switch (self.kind) {
            .worktree => |*wt| try wt.remove(allocator, io, env, diag),
            .overlay => |*ov| ov.deinit(allocator),
        }
        self.* = undefined;
    }

    /// Free everything this value owns and **leave the workspace on disk**.
    /// For a git backing this skips `git worktree remove`, so the checkout,
    /// its registration in the project, and the scratch object store all stay.
    /// For an overlay backing this is exactly what `close` already did, since
    /// that backing never removed anything itself. `self` is not valid after
    /// this call returns.
    ///
    /// **A clean ending removes the workspace and an abnormal one keeps it.**
    /// The rule that only a commit reaches the user's repository is right and
    /// is unchanged: the loss was never the policy, it was the cleanup. A
    /// session that errored, was refused, reached its budget, or was
    /// interrupted used to have its work deleted with the worktree, and one
    /// measured on 2026-08-22 lost 105 changed files that way. See
    /// `worktree.Worktree.keep`, and `workPath`, which is what a caller prints
    /// so the kept workspace is one a person can find.
    pub fn keep(self: *Workspace, allocator: std.mem.Allocator) void {
        if (self.chock_zon_source) |s| allocator.free(s);
        if (self.chock_zon_target) |t| allocator.free(t);
        deny_mod.free(allocator, self.deny_paths);

        switch (self.kind) {
            .worktree => |*wt| wt.keep(allocator),
            .overlay => |*ov| ov.deinit(allocator),
        }
        self.* = undefined;
    }

    /// Where this workspace's own work is on the host filesystem: the checkout
    /// for a git backing, the upper layer for an overlay one.
    ///
    /// **Not the same path for the two kinds, on purpose.** A worktree is an
    /// ordinary checkout a person can open. An overlay's merged view only
    /// exists inside the sandbox's own mount namespace and is gone once the
    /// session is, so the only place its writes survive is the upper layer.
    /// A caller that names the merged path to a user would name a directory
    /// that holds nothing.
    ///
    /// Borrowed from `self`, so it is valid only until `close` or `keep`.
    pub fn workPath(self: *const Workspace) []const u8 {
        return switch (self.kind) {
            .worktree => |wt| wt.path,
            .overlay => |ov| ov.upper,
        };
    }

    /// Build the `Sandbox.Config` a caller hands to `Sandbox.spawn` to run one
    /// tool call in this workspace: the mount list the backing already
    /// builds, the Landlock rules that go with it, and the `chock.zon`
    /// protection when the project has one.
    ///
    /// `root` is the directory that becomes the root of the sandbox. The
    /// caller makes and owns it, the same as every `Sandbox.spawn` caller
    /// already does. The returned `Config`'s `cwd` is the project's own real
    /// path, so a tool call starts where the agent's files are. `env` is
    /// left empty for the overlay backing: this library knows nothing about
    /// which variables a tool call needs beyond where its files are and what
    /// may touch them. The worktree backing is the one exception:
    /// `Worktree.gitEnv` names the two variables every git call needs to
    /// work at all against a read only object store, so `env` carries those
    /// two for that backing. A caller that also needs a Nix dev shell's own
    /// environment, or a secret handle, still has to merge those in on top:
    /// this function only ever adds what it alone knows how to build.
    ///
    /// The caller owns the returned `Config`'s `mounts`, `rules`, and `env`
    /// slices and frees each with `allocator.free`. Every string inside them
    /// is a slice into `self`, and stays valid only as long as `self` does,
    /// the same convention `Worktree.mounts`, `Overlay.mounts`, and
    /// `Worktree.gitEnv` already use.
    pub fn sandboxConfig(
        self: *const Workspace,
        allocator: std.mem.Allocator,
        root: []const u8,
    ) Error!sandbox.Config {
        var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
        errdefer mounts.deinit(allocator);
        var rules: std.ArrayList(sandbox.Config.Rule) = .empty;
        errdefer rules.deinit(allocator);
        var env: []const []const u8 = &.{};
        errdefer if (env.len > 0) allocator.free(env);

        const cwd = self.sandboxRoot();

        switch (self.kind) {
            .worktree => |wt| {
                const backing_mounts = try wt.mounts(allocator);
                defer allocator.free(backing_mounts);
                try mounts.appendSlice(allocator, backing_mounts);

                // The worktree itself: ordinary read write work.
                try rules.append(allocator, .{
                    .path = wt.sandboxRoot(),
                    .access = sandbox.landlock.AccessFs.read_write,
                });
                // The whole real .git, read only: objects, refs, hooks, and
                // every worktree's own commondir, gitdir, and
                // config.worktree. The mount layer is the boundary for
                // these; this rule only needs to let git read them at all.
                try rules.append(allocator, .{
                    .path = wt.sandbox_git_root,
                    .access = sandbox.landlock.AccessFs.read_only,
                });
                // The scratch object store, read write. **It is not nested
                // under sandbox_git_root**, and it cannot be: see
                // worktree.zig's own object_store_prefix, which gives it a
                // top level path of its own because a mount point under an
                // already read only mount cannot be created. So no rule
                // above covers it, and without this rule the mount for it
                // would be present and unreachable. The mount layer is
                // still what refuses a write to the real object store: this
                // rule only lets git open the scratch one for write at all.
                try rules.append(allocator, .{
                    .path = wt.object_store_target,
                    .access = sandbox.landlock.AccessFs.read_write,
                });
                // This worktree's own metadata directory, read write: a
                // linked worktree writes its own index, HEAD, and logs
                // there. commondir, gitdir, and config.worktree sit in the
                // same directory but stay read only regardless, because the
                // mount for them, not this rule, is what actually refuses a
                // write: see Worktree.mounts.
                try rules.append(allocator, .{
                    .path = wt.worktree_meta_target,
                    .access = sandbox.landlock.AccessFs.read_write,
                });

                // GIT_OBJECT_DIRECTORY and GIT_ALTERNATE_OBJECT_DIRECTORIES,
                // so every git call the caller makes with this Config
                // writes into the scratch store and can still read every
                // object that already exists. See Worktree.gitEnv's own doc
                // comment for why this is a variable, never a file.
                env = try wt.gitEnv(allocator);
            },
            .overlay => |ov| {
                const backing_mounts = try ov.mounts(allocator);
                defer allocator.free(backing_mounts);
                try mounts.appendSlice(allocator, backing_mounts);

                try rules.append(allocator, .{
                    .path = ov.sandboxRoot(),
                    .access = sandbox.landlock.AccessFs.read_write,
                });
            },
        }

        if (self.chock_zon_source) |source| {
            try mounts.append(allocator, .{ .bind = .{
                .source = source,
                .target = self.chock_zon_target.?,
                .read_only = true,
            } });
        }

        // The other half of the `chock.zon` protection: the files the project
        // said the agent may not read. Last in the list, which reads correctly, although
        // `chock-sandbox`'s own `buildRoot` applies every denial in a pass of
        // its own after the rest whatever order they arrive in, so the
        // property does not depend on this line staying last.
        //
        // **No Landlock rule goes with these, and none could.** Landlock
        // rights accumulate on a nested path and are never narrowed by a wider
        // rule, which the comment on the scratch object store rule above says
        // as well. The project directory is read write, so a denied file under
        // it cannot be subtracted. The mount is the whole boundary here.
        for (self.deny_paths) |path| {
            try mounts.append(allocator, .{ .deny = .{ .target = path } });
        }

        return .{
            // **`.in_place` has no root of its own, so the caller's is not
            // used.** A root is the directory `Sandbox.spawn` pivots into, and
            // macOS cannot pivot: `darwin/driver.zig`'s own `expressibleOn`
            // refuses a root that is not `/` rather than promise a tree it
            // never built. The layer that keeps the tool call to the workspace
            // on that platform is the path rule set, not a root.
            .root = switch (self.sandboxLayout()) {
                .remapped => root,
                .in_place => "/",
            },
            .mounts = try mounts.toOwnedSlice(allocator),
            .rules = try rules.toOwnedSlice(allocator),
            .cwd = cwd,
            .env = env,
        };
    }

    /// Which of the two shapes this workspace's mount list has. See
    /// `chock-workspace/layout.zig`.
    pub fn sandboxLayout(self: *const Workspace) Layout {
        return switch (self.kind) {
            .worktree => |wt| wt.layout,
            .overlay => |ov| ov.layout,
        };
    }

    /// The absolute path at which the sandbox sees the agent's own copy of the
    /// project. **This is the working directory of every tool call**, and the
    /// root that `chock-core` reads every relative path against.
    pub fn sandboxRoot(self: *const Workspace) []const u8 {
        return switch (self.kind) {
            .worktree => |wt| wt.sandboxRoot(),
            .overlay => |ov| ov.sandboxRoot(),
        };
    }
};

const FoundChockZon = struct {
    source: ?[]u8,
    target: ?[]u8,
};

/// Look for `chock.zon` directly under `source_root`, the backing's own copy
/// of the project (a worktree checkout or an overlay's lower layer), and
/// report both where it lives there and where it belongs inside the sandbox,
/// under `target_root`. Neither field is set when the project has no
/// `chock.zon`: see `Workspace.chock_zon_source`'s own doc comment.
///
/// **A `chock.zon` that is a symbolic link is refused, not followed.** A
/// worktree checkout is the agent's own to write between tool calls, and
/// nothing stops it running `ln -s <host path> chock.zon` there when the
/// project has no policy file of its own to protect: the next `adopt` would
/// then read this link as if it were the project's own `chock.zon`, and
/// `chock-sandbox`'s own bind mount would land on whatever host path the
/// link names instead. `chockZonExists` answers with
/// `error.ChockZonIsSymlink` for exactly that shape, rather than the `bool`
/// `existsAsFile` gives every other caller in this file, because this is the
/// one caller for which a symbolic link is not an ordinary fact about the
/// disk but a fault this file must stop rather than hand onward.
fn findChockZon(
    allocator: std.mem.Allocator,
    io: std.Io,
    source_root: []const u8,
    target_root: []const u8,
    diag: ?*?Diagnostic,
) Error!FoundChockZon {
    const source_path = try std.fs.path.join(allocator, &.{ source_root, "chock.zon" });
    errdefer allocator.free(source_path);

    const found = chockZonExists(io, source_path) catch |err| switch (err) {
        error.ChockZonIsSymlink => return error.ChockZonIsSymlink,
        else => {
            diagnostic.noteErr(diag, .chock_zon_check, err);
            return error.Unexpected;
        },
    };
    if (!found) {
        allocator.free(source_path);
        return .{ .source = null, .target = null };
    }

    const target_path = try std.fs.path.join(allocator, &.{ target_root, "chock.zon" });
    return .{ .source = source_path, .target = target_path };
}

/// True if `absolute_path` names `chock.zon` as an ordinary file, false if
/// nothing is there, `error.ChockZonIsSymlink` if a symbolic link is. See
/// `findChockZon`'s own doc comment for why this file's policy file gets its
/// own check instead of `existsAsFile`'s.
///
/// **`follow_symlinks = false`, unlike `existsAsFile`.** `existsAsFile`
/// answers what a path resolves to, which is the right question for a file
/// this module only ever reads back through the sandbox's own mounts. This
/// answers what is at the name itself, which is the right question for a
/// name this module is about to trust as the project's own policy.
fn chockZonExists(io: std.Io, absolute_path: []const u8) (std.Io.Dir.StatFileError || error{ChockZonIsSymlink})!bool {
    const st = std.Io.Dir.cwd().statFile(io, absolute_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    if (st.kind == .sym_link) return error.ChockZonIsSymlink;
    return true;
}

/// The `chock.zon` an adopted session gets bound over it: the checkout's own
/// first, exactly as `Workspace.open` reads it, and the project's own when
/// the checkout has none.
///
/// **A session must not be able to hand over its way out of its own policy
/// file.** `findChockZon` answers for the disk it is given, and it answers
/// correctly for a checkout that has already been worked in, because a
/// checkout is an ordinary directory and nothing about having been used
/// changes what a `statFile` reads there. The difference is what the disk can
/// look like. `open` reads a checkout `git worktree add` just made, so
/// `chock.zon` is there whenever HEAD has it. `adopt` reads a checkout a
/// whole session has already used, and a `chock.zon` that is missing there
/// would give `null`, `Workspace.sandboxConfig` would add no bind, and the
/// new owner would run with no policy file over it at all: a policy nobody
/// binds is a policy nobody keeps.
///
/// The project's own file is safe to bind: `sandboxConfig` binds it read
/// only, at the same target, and nothing in this module ever opens it for
/// write. It is also the right file, because it is the user's, and the user
/// is who a policy belongs to.
///
/// The bind is what makes the delete fail in the first place: `chock.zon` is
/// a mount point inside the sandbox, and unlinking a mount point answers
/// `EBUSY`. This fallback is for the checkout that lost the file some other
/// way, before the sandbox ever covered it.
fn findChockZonForAdopt(
    allocator: std.mem.Allocator,
    io: std.Io,
    checkout_root: []const u8,
    target_root: []const u8,
    project_root: []const u8,
    layout: Layout,
    diag: ?*?Diagnostic,
) Error!FoundChockZon {
    const in_checkout = try findChockZon(allocator, io, checkout_root, target_root, diag);
    if (in_checkout.source != null) return in_checkout;
    // **No fallback under `.in_place`, because there is nowhere to put it.**
    // The fallback binds the project's own file over the checkout's path, and
    // a bind that moves a path is the one thing macOS has not got. What the
    // fallback protects is still protected: the policy a session runs under is
    // read from the host project, never from the sandbox, so a checkout with
    // no `chock.zon` changes no rule. What is lost is the covering entry, so
    // an agent on that layout can create a `chock.zon` in its own checkout.
    // That file reaches nobody until a hand back carries it, where it reads as
    // any other new file the session wrote.
    if (layout == .in_place) return in_checkout;
    return findChockZon(allocator, io, project_root, target_root, diag);
}

/// True if `absolute_path` names a file that exists on disk, false if it does
/// not exist at all or some component of it is not a directory. Any other
/// failure, such as a permission error, is passed up rather than folded into
/// `false`. The same shape `worktree.zig`'s own `existsOnDisk` uses.
fn existsAsFile(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!bool {
    _ = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    return true;
}

// This file's own tests build both kinds of `Workspace` and drive
// `sandboxConfig` for each directly, with no namespace and no second
// process: `Worktree.mounts` and `Overlay.mounts` both only describe mounts
// now, so both kinds are equally safe to call from this ordinary,
// unprivileged test process. Every test below builds its own project inside
// a fresh `std.testing.tmpDir`, the same convention `worktree.zig`'s and
// `overlay.zig`'s own tests use. A git project sets its own
// `GIT_CEILING_DIRECTORIES`, for the reason `worktree.zig`'s own tests
// explain in full: this project's own checkout is itself a git repository,
// and `tmpDir` makes every scratch directory somewhere underneath it.
//
// Proving that a real `Sandbox.spawn` actually performs the overlay mount
// `sandboxConfig` describes, and that a write through it lands in the
// workspace and not the project, needs a real user and mount namespace:
// that proof lives in `test/workspace/escape.zig`, which already carries the
// single threaded probe process a real `Sandbox.spawn` call needs, for the
// worktree kind, and now drives the overlay kind through the very same
// probe.

/// Read the absolute path of an already open directory, through
/// `std.Io.Dir.realPath`. `std.testing.tmpDir` hands back a directory reached
/// only through a relative path, but a test needs an absolute one to build a
/// project or scratch path that does not depend on the test binary's own
/// working directory.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![:0]u8 {
    const len = dir.realPath(std.testing.io, buffer) catch return error.RealPathFailed;
    buffer[len] = 0;
    return buffer[0..len :0];
}

fn testEnviron(allocator: std.mem.Allocator, scratch_path: []const u8) !std.process.Environ.Map {
    var env = try std.testing.environ.createMap(allocator);
    errdefer env.deinit();
    const ceiling = std.fs.path.dirname(scratch_path) orelse scratch_path;
    try env.put("GIT_CEILING_DIRECTORIES", ceiling);
    return env;
}

/// Whether a sandboxed program finished its work. **A program the system
/// killed answers nothing**, and must never be read as a refusal the sandbox
/// made, so a signal reads the same way a nonzero exit does here and the tests
/// that want a refusal say why in their own words.
fn ranWell(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn makeDir(path: [:0]const u8) !void {
    std.Io.Dir.createDirAbsolute(std.testing.io, path, .default_dir) catch return error.MkdirFailed;
}

/// A fresh project and scratch directory pair, both directly under the same
/// `tmpDir`, kept apart the same way `worktree.zig`'s and `overlay.zig`'s own
/// `TestProject` types do: listing one must never pick up the other's files.
/// `root_path` starts empty. A test that needs a real git repository there
/// builds one itself, with `env`, before calling `Workspace.open`.
const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: [:0]const u8,
    scratch_path: [:0]const u8,
    env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(&buffer, tmp.dir);

        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_path = try std.fmt.bufPrintZ(&root_buffer, "{s}/project", .{tmp_path});
        try makeDir(root_path);

        var scratch_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const scratch_path = try std.fmt.bufPrintZ(&scratch_buffer, "{s}/scratch", .{tmp_path});
        try makeDir(scratch_path);

        const env = try testEnviron(allocator, tmp_path);

        return .{
            .allocator = allocator,
            .root_path = try allocator.dupeZ(u8, root_path),
            .scratch_path = try allocator.dupeZ(u8, scratch_path),
            .env = env,
        };
    }

    fn deinit(self: *TestProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
        self.env.deinit();
    }

    /// Turn `root_path` into a real git repository, one commit deep. A test
    /// that wants the worktree kind calls this before `Workspace.open`. A
    /// test that wants the overlay kind leaves `root_path` exactly as
    /// `init` left it, a plain empty directory with no `.git` at all.
    fn makeGitRepository(self: TestProject) !void {
        var init_output = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{"init"}, null);
        defer init_output.deinit(self.allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, init_output.term);

        var config_email = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{ "config", "user.email", "test@example.com" }, null);
        defer config_email.deinit(self.allocator);
        var config_name = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{ "config", "user.name", "Test" }, null);
        defer config_name.deinit(self.allocator);

        var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{self.root_path});
        var tracked_file = try std.Io.Dir.createFileAbsolute(std.testing.io, tracked_path, .{});
        try tracked_file.writeStreamingAll(std.testing.io, "hello\n");
        tracked_file.close(std.testing.io);

        var add_output = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{ "add", "tracked.txt" }, null);
        defer add_output.deinit(self.allocator);
        var commit_output = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{ "commit", "-m", "first commit" }, null);
        defer commit_output.deinit(self.allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_output.term);
    }

    /// Add a `chock.zon` to the project and commit it, so a worktree checked
    /// out at HEAD carries one too. The `adopt` tests need a project that
    /// really has a policy file: a `chock.zon` left uncommitted would never
    /// reach the checkout, and the fallback those tests pin would then hold
    /// for the wrong reason.
    fn commitChockZon(self: TestProject) !void {
        return self.commitChockZonSaying(".{}\n");
    }

    /// `commitChockZon`, with the file's own bytes named. A test that needs a
    /// real `deny_read` block writes one here.
    fn commitChockZonSaying(self: TestProject, source: []const u8) !void {
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/chock.zon", .{self.root_path});
        var file = try std.Io.Dir.createFileAbsolute(std.testing.io, path, .{});
        try file.writeStreamingAll(std.testing.io, source);
        file.close(std.testing.io);

        var add_output = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{ "add", "chock.zon" }, null);
        defer add_output.deinit(self.allocator);
        var commit_output = try git.run(self.allocator, std.testing.io, &self.env, self.root_path, &.{ "commit", "-m", "add chock.zon" }, null);
        defer commit_output.deinit(self.allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_output.term);
    }
};

/// The commit `project` has at HEAD, which is what a caller of
/// `Workspace.adopt` carries across as `base_commit`. The caller owns the
/// returned string. A test reads this before it opens a workspace, the same
/// way a real caller reads it out of the session log rather than off the
/// checkout it is about to take: see `Workspace.adopt`'s own doc comment for
/// why the checkout is the one place that answer must not come from.
fn headOf(allocator: std.mem.Allocator, project: *const TestProject) ![]u8 {
    var output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "rev-parse", "HEAD" }, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return allocator.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

test "open picks the worktree kind for a project that is a git repository" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(workspace.kind == .worktree);
}

test "the in place layout builds a config the darwin driver can express, for both kinds" {
    // **The gate this whole layout exists for.** Before it, every caller built
    // a bind whose target was not its source, `darwin/driver.zig`'s own
    // `expressibleOn` refused exactly that, and so macOS ran no tool call at
    // all. The check is the driver's own function, on both backings, so a
    // change to either mount list that reintroduces a moved path fails here on
    // Linux rather than on a Mac nobody has to hand.
    //
    // Mutation check: give `Worktree.mounts` back its old entry 0, with
    // `self.project_root` as the target, and this fails with
    // `bind_moves_a_path`.
    const darwin = sandbox.darwin_driver_for_testing;
    const allocator = std.testing.allocator;

    for ([_]bool{ true, false }) |with_git| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var project = try TestProject.init(allocator, tmp);
        defer project.deinit();
        if (with_git) try project.makeGitRepository();

        var workspace = try Workspace.openWithLayout(
            allocator,
            std.testing.io,
            &project.env,
            project.root_path,
            project.scratch_path,
            "sess1",
            .in_place,
            null,
        );
        defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

        const config = try workspace.sandboxConfig(allocator, "/a/session/root/that/is/ignored");
        defer allocator.free(config.mounts);
        defer allocator.free(config.rules);
        defer if (config.env.len > 0) allocator.free(config.env);

        // One entry at a time first, so a failure names the mount that moved
        // rather than only the fact that one did.
        for (config.mounts) |mount| switch (mount) {
            .bind => |bind| try std.testing.expectEqualStrings(bind.source, bind.target),
            .deny => {},
            .overlay, .proc => return error.ExpectedABindEntry,
        };
        try std.testing.expectEqual(@as(?darwin.Inexpressible, null), darwin.expressibleOn(config));
        // The root is the real root, because macOS cannot pivot into one of
        // its own, and the working directory is the agent's own copy.
        try std.testing.expectEqualStrings("/", config.root);
        try std.testing.expectEqualStrings(workspace.sandboxRoot(), config.cwd);
        // And the working directory is not the project, which is the whole
        // difference this layout makes.
        try std.testing.expect(!std.mem.eql(u8, project.root_path, config.cwd));
    }
}

test "a real tool call runs in the workspace on macos, and the boundaries hold" {
    // **The whole point of the in place layout, and it is measured and not
    // reasoned about.** Before this, `Sandbox.spawn` refused every workspace
    // config on macOS and no tool call had ever run there. This starts real
    // programs, in a real sandbox, in a real worktree, and checks the four
    // things this file promises: the agent may write
    // in its own checkout, it may not reach the user's own project, it may not
    // write to the real object store, and it may not rewrite the one file that
    // redirects git at a path of its own choosing.
    //
    // Guarded on the target, because `sandbox.spawn` on Linux would want a
    // user namespace and a mount tree this config deliberately has not got.
    //
    // Mutation check: drop the `deny` half of a read only bind in
    // `darwin/driver.zig`'s own `optionsFor`, so a read only bind emits only an
    // allowance of read, and the `commondir` case below passes where it must
    // fail. Measured on 2026-08-25: that was the real behaviour before the
    // `deny` line was added.
    if (builtin.os.tag != .macos) return;
    // **Nix on macOS runs every builder under `sandbox-exec`, and macOS refuses
    // to nest one profile inside another.** So inside a Nix build this test asks
    // a question the environment will not answer, and a failure there would say
    // the workspace boundary broke when no boundary was ever built. Measured on
    // a real Mac on 2026-08-25: from a login shell `sandbox_init` answers 0 and
    // this test runs, and inside a Nix build the same call answers -1 with
    // `EPERM`. See `chock-sandbox/darwin/seatbelt.zig`'s own `confinedAlready`.
    if (sandbox.darwin_driver_for_testing.confinedAlready()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    var workspace = try Workspace.open(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, io, &project.env, null) catch unreachable;
    try std.testing.expectEqual(Layout.in_place, workspace.sandboxLayout());

    const config = try workspace.sandboxConfig(allocator, "/unused");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer if (config.env.len > 0) allocator.free(config.env);

    const quiet = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{ .mode = .read_write });
    defer quiet.close(io);

    var run = config;
    run.stdout_fd = quiet.handle;
    run.stderr_fd = quiet.handle;

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try std.fmt.bufPrint(&buffer, "{s}/agent-wrote-this.txt", .{workspace.sandboxRoot()});
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", written }, null, null),
    );
    // It landed in the agent's own checkout, and the user's project is
    // untouched. A tool call that wrote nowhere would pass an exit code check.
    try std.testing.expect(try existsAsFile(io, written));
    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_project = try std.fmt.bufPrint(&project_buffer, "{s}/agent-wrote-this.txt", .{project.root_path});
    try std.testing.expect(!try existsAsFile(io, in_project));

    // The user's own working tree is not reachable at all.
    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked = try std.fmt.bufPrint(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try std.testing.expect(!ranWell(try sandbox.spawn(allocator, run, &.{ "/bin/cat", tracked }, null, null)));

    const wt = workspace.kind.worktree;

    // No write to the real object store, and the same file is
    // still readable, so this is a boundary and not a broken mount list.
    var objects_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_objects = try std.fmt.bufPrint(&objects_buffer, "{s}/objects/agent-wrote-this", .{wt.sandbox_git_root});
    try std.testing.expect(!ranWell(try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", in_objects }, null, null)));

    // `commondir` redirects git at a git directory of the
    // agent's own choosing, and it sits inside the one directory under `.git`
    // the agent may write. **This is the case a read only rule alone does not
    // hold**, because a profile grants one access at a time and a later
    // allowance of read says nothing about an earlier allowance of write.
    try std.testing.expect(!ranWell(try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", wt.worktree_commondir_target }, null, null)));
    // And the directory it is in really is writable, which is what makes the
    // refusal above a narrowing rather than a wider denial nobody noticed.
    var index_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_meta = try std.fmt.bufPrint(&index_buffer, "{s}/agent-wrote-this", .{wt.worktree_meta_target});
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", in_meta }, null, null),
    );
    // Finding 4: and the directory that write reached is the session's own
    // copy, so the project's own `.git/worktrees/<id>` did not gain a file.
    // Read on the host, where the sandbox's mount namespace is gone: this is
    // the state a person finds after the session ends.
    var real_meta_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_real_meta = try std.fmt.bufPrint(&real_meta_buffer, "{s}/agent-wrote-this", .{wt.worktree_meta_source});
    try std.testing.expect(!try existsAsFile(io, in_real_meta));
}

test "the remapped layout still moves the workspace to the project's own path" {
    // The other edge. A test that only ever checked the in place shape would
    // pass just as well for a build that had lost the remapping altogether,
    // and the remapping is what every Linux session runs on.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    var workspace = try Workspace.openWithLayout(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        .remapped,
        null,
    );
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const config = try workspace.sandboxConfig(allocator, "/session/root");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer if (config.env.len > 0) allocator.free(config.env);

    // The caller's own root is passed through, and the working directory is
    // the project's own path.
    try std.testing.expectEqualStrings("/session/root", config.root);
    try std.testing.expectEqualStrings(project.root_path, config.cwd);
    // And the workspace mount really moves a path, which is the one thing
    // macOS has not got. Read off the mount rather than through
    // `expressibleOn`, which would answer for the root above first.
    try std.testing.expect(!std.mem.eql(
        u8,
        config.mounts[0].bind.source,
        config.mounts[0].bind.target,
    ));
    try std.testing.expectEqualStrings(project.root_path, config.mounts[0].bind.target);
}

test "open picks the overlay kind for a project with no git of its own" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    // No makeGitRepository call: root_path stays a plain, empty directory.

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(workspace.kind == .overlay);
}

test "keeping a workspace leaves the agent's file on disk, and closing one takes it away" {
    // **The pair, in one test, because the two can break each other.** A
    // `keep` that quietly still removed would lose the work it was added to
    // save, and a `close` that quietly stopped removing would fill the user's
    // disk with every session they ever ran. Neither is visible from the
    // return value of either call, so both are checked against the filesystem.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    // The work an agent did and never committed. This is the 105 files of the
    // session measured on 2026-08-22, in miniature.
    var kept_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const kept_file = kept: {
        var workspace = try Workspace.open(
            allocator,
            io,
            &project.env,
            project.root_path,
            project.scratch_path,
            "kept",
            null,
        );
        const written = try std.fmt.bufPrintZ(
            &kept_path_buffer,
            "{s}/agent-wrote-this.txt",
            .{workspace.workPath()},
        );
        var handle = try std.Io.Dir.createFileAbsolute(io, written, .{});
        try handle.writeStreamingAll(io, "work nobody committed\n");
        handle.close(io);

        workspace.keep(allocator);
        break :kept written;
    };

    // Still there, and still holding what the agent wrote. A path alone would
    // not be enough: an empty directory left behind is not salvaged work.
    var kept_handle = try std.Io.Dir.openFileAbsolute(io, kept_file, .{});
    defer kept_handle.close(io);
    var read_buffer: [64]u8 = undefined;
    var reader = kept_handle.readerStreaming(io, &read_buffer);
    const contents = try reader.interface.allocRemaining(allocator, .limited(1024));
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("work nobody committed\n", contents);

    // The clean ending, unchanged: the workspace goes, and so does its file.
    var removed_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const removed_file = removed: {
        var workspace = try Workspace.open(
            allocator,
            io,
            &project.env,
            project.root_path,
            project.scratch_path,
            "removed",
            null,
        );
        const written = try std.fmt.bufPrintZ(
            &removed_path_buffer,
            "{s}/agent-wrote-this.txt",
            .{workspace.workPath()},
        );
        var handle = try std.Io.Dir.createFileAbsolute(io, written, .{});
        try handle.writeStreamingAll(io, "work about to be discarded\n");
        handle.close(io);

        try workspace.close(allocator, io, &project.env, null);
        break :removed written;
    };

    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(io, removed_file, .{}),
    );
}

test "sandboxConfig for the worktree kind needs no namespace, so an ordinary caller can call it directly" {
    // The worktree kind's own half of the proof that the two kinds are now
    // symmetric: Worktree.mounts only describes bind mounts, so sandboxConfig
    // for this kind is exactly as safe to call from a plain, unprivileged
    // process as this test itself is. test/workspace/escape.zig already
    // relies on this in practice, calling sandboxConfig straight from its own
    // un-namespaced test process; this test pins it here too, next to the
    // overlay kind's own test below, so a reader can see both kinds behave
    // the same way in one file.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    var workspace = try Workspace.openWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const config = try workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);

    try std.testing.expect(config.mounts.len > 0);
    try std.testing.expect(config.rules.len > 0);
    try std.testing.expectEqualStrings(workspace.kind.worktree.project_root, config.cwd);

    // The worktree kind's env carries the two variables that
    // let git work against a read only object store. This pins that
    // sandboxConfig actually wires Worktree.gitEnv in, not just that
    // Worktree.gitEnv exists on its own.
    try std.testing.expectEqual(@as(usize, 2), config.env.len);
    var found_object_directory = false;
    var found_alternate = false;
    for (config.env) |entry| {
        if (std.mem.startsWith(u8, entry, "GIT_OBJECT_DIRECTORY=")) found_object_directory = true;
        if (std.mem.startsWith(u8, entry, "GIT_ALTERNATE_OBJECT_DIRECTORIES=")) found_alternate = true;
    }
    try std.testing.expect(found_object_directory);
    try std.testing.expect(found_alternate);
}

test "sandboxConfig for the overlay kind needs no namespace either, so an ordinary caller can call it directly" {
    // The overlay kind's own half of the proof, and the whole point of
    // giving Mount a second kind: an earlier version of Overlay.mounts
    // performed a real mount(2) call and needed CAP_SYS_ADMIN over the
    // caller's own mount namespace to do it, so this same call used to fail
    // here with error.OverlayNotSupported, because this test process has
    // never entered one. Overlay.mounts now only describes the overlay, the
    // same way Worktree.mounts only describes its bind mounts, so this
    // succeeds with no namespace at all, exactly like the worktree test
    // above, and the one call that used to need a namespace,
    // chock-sandbox's own buildRoot, is not reached until a real
    // Sandbox.spawn runs: see test/workspace/escape.zig's own proof that a
    // real sandbox spawned from this Config actually performs the overlay
    // mount and a write lands in the workspace, not the project.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    // No makeGitRepository call: root_path stays a plain, empty directory,
    // so Workspace.open picks the overlay kind.

    var workspace = try Workspace.openWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const config = try workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);

    try std.testing.expect(config.mounts.len > 0);
    try std.testing.expect(config.rules.len > 0);
    try std.testing.expectEqualStrings(workspace.kind.overlay.project, config.cwd);
    // The overlay kind has no .git of its own to protect, so it gets none
    // of the worktree kind's git environment: a project with no git has no
    // object store to work around.
    try std.testing.expectEqual(@as(usize, 0), config.env.len);

    // The first entry is the overlay descriptor itself, mounted at the
    // project's own real path, the way Worktree.mounts's own entry 0 is
    // always the worktree bound at project_root: see Worktree.mounts's own
    // doc comment for why order matters here too.
    const overlay_entry = switch (config.mounts[0]) {
        .overlay => |o| o,
        .bind, .proc, .deny => return error.ExpectedAnOverlayEntry,
    };
    try std.testing.expectEqualStrings(workspace.kind.overlay.project, overlay_entry.target);
}

test "every landlock rule sandboxConfig writes names a path its own mount list holds" {
    // **The two lists are one judgement written twice.** This function appends
    // a mount, then appends a rule, by hand, a few lines apart. Nothing
    // computes either list from the other, so a path added to one and not the
    // other compiles and runs. `sandbox.firstGap` reads both real lists, and
    // never a copy of them written into this test: a copy would be a third
    // place to drift.
    //
    // Both kinds are driven, and both layouts, because the layout is what
    // decides whether a target is moved or is its own source.
    const allocator = std.testing.allocator;

    for ([_]Layout{ .remapped, .in_place }) |layout| {
        // The worktree kind, with a `chock.zon` that also denies a file, so
        // the run covers the bind for the policy file and the denial beside
        // it.
        var git_tmp = std.testing.tmpDir(.{});
        defer git_tmp.cleanup();
        var git_project = try TestProject.init(allocator, git_tmp);
        defer git_project.deinit();
        try git_project.makeGitRepository();
        try git_project.commitChockZonSaying(".{ .deny_read = .{ \".env\" } }\n");

        var worktree_workspace = try Workspace.openWithLayout(allocator, std.testing.io, &git_project.env, git_project.root_path, git_project.scratch_path, "sess1", layout, null);
        defer worktree_workspace.close(allocator, std.testing.io, &git_project.env, null) catch unreachable;

        const worktree_config = try worktree_workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
        defer allocator.free(worktree_config.mounts);
        defer allocator.free(worktree_config.rules);
        defer allocator.free(worktree_config.env);

        try expectLayersAgree(worktree_config);

        // The overlay kind, which is a project with no git of its own.
        var plain_tmp = std.testing.tmpDir(.{});
        defer plain_tmp.cleanup();
        var plain_project = try TestProject.init(allocator, plain_tmp);
        defer plain_project.deinit();

        var overlay_workspace = try Workspace.openWithLayout(allocator, std.testing.io, &plain_project.env, plain_project.root_path, plain_project.scratch_path, "sess1", layout, null);
        defer overlay_workspace.close(allocator, std.testing.io, &plain_project.env, null) catch unreachable;

        const overlay_config = try overlay_workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
        defer allocator.free(overlay_config.mounts);
        defer allocator.free(overlay_config.rules);
        defer allocator.free(overlay_config.env);

        try expectLayersAgree(overlay_config);
    }
}

/// Fail when `config`'s mount list and its Landlock rule list disagree, and
/// name the path they disagree about. See `sandbox.LayerGap`.
///
/// **Compared against an empty string, and never printed.** `expectEqualStrings`
/// puts both sides in the failure, so a reader sees which path moved, and this
/// file keeps the rule that no line outside `main` names standard error: see
/// `test/proto/lock.zig`.
fn expectLayersAgree(config: sandbox.Config) !void {
    var buffer: [256]u8 = undefined;
    const said = if (sandbox.firstGap(config)) |gap|
        try std.fmt.bufPrint(&buffer, "{f}", .{gap})
    else
        "";
    try std.testing.expectEqualStrings("", said);
}

test "adopt takes the worktree a first process left, with the work still in it" {
    // The whole handover, through the type a caller actually holds: one
    // process opens a workspace, writes, and keeps it, and a second one
    // adopts the same session and reaches the same checkout with the same
    // bytes. `workPath` is compared because that is the path a caller prints
    // and a person opens: an adopt that named a different directory would
    // read as a success and hand back an empty tree. Make `adopt` build a new
    // worktree instead of taking the one on disk and both checks stop
    // holding.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    const base_commit = try headOf(allocator, &project);
    defer allocator.free(base_commit);

    var work_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var left_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var work_path: [:0]const u8 = undefined;
    const left_path = left: {
        var first = try Workspace.open(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", null);
        defer first.keep(allocator);

        work_path = try std.fmt.bufPrintZ(&work_buffer, "{s}/agent-wrote-this.txt", .{first.workPath()});
        var handle = try std.Io.Dir.createFileAbsolute(io, work_path, .{});
        try handle.writeStreamingAll(io, "work nobody committed\n");
        handle.close(io);

        break :left try std.fmt.bufPrint(&left_path_buffer, "{s}", .{first.workPath()});
    };

    var second = try Workspace.adopt(
        allocator,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        base_commit,
        null,
    );
    defer second.close(allocator, io, &project.env, null) catch unreachable;

    try std.testing.expect(second.kind == .worktree);
    try std.testing.expectEqualStrings(left_path, second.workPath());

    const contents = try std.Io.Dir.cwd().readFileAlloc(io, work_path, allocator, .limited(1024));
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("work nobody committed\n", contents);
}

test "adopt binds a chock.zon the checkout lost, from the project itself" {
    // **Stated as `.remapped`, because the fallback is a bind that moves a
    // path.** Under `Layout.in_place` there is nowhere to put the project's own
    // file, and `findChockZonForAdopt` says what is kept and what is lost
    // there instead.
    //
    // **A session must not be able to hand over its way out of its own policy
    // file.** The checkout the first process leaves has no `chock.zon`, and
    // `findChockZon` alone would answer null for it, so `sandboxConfig` would
    // add no bind and the new owner would run with no policy file over it.
    // The fallback in `findChockZonForAdopt` binds the project's own file
    // instead. Drop that fallback and `chock_zon_source` is null here, and
    // the mount list below loses the read only entry that keeps the policy in
    // place.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();
    try project.commitChockZon();

    const base_commit = try headOf(allocator, &project);
    defer allocator.free(base_commit);

    var deleted_buffer: [std.fs.max_path_bytes]u8 = undefined;
    {
        var first = try Workspace.openWithLayout(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer first.keep(allocator);

        // The checkout really did start with one, so the deletion below is
        // the thing being tested and not an empty gesture.
        try std.testing.expect(first.chock_zon_source != null);

        const path = try std.fmt.bufPrintZ(&deleted_buffer, "{s}/chock.zon", .{first.workPath()});
        try std.Io.Dir.deleteFileAbsolute(io, path);
    }

    var second = try Workspace.adoptWithLayout(
        allocator,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        base_commit,
        .remapped,
        null,
    );
    defer second.close(allocator, io, &project.env, null) catch unreachable;

    const project_chock_zon = try std.fs.path.join(allocator, &.{ project.root_path, "chock.zon" });
    defer allocator.free(project_chock_zon);
    try std.testing.expectEqualStrings(project_chock_zon, second.chock_zon_source.?);
    // The target is unchanged: the policy file still lands at the project's
    // own path inside the sandbox, which is the only path anything reads it
    // from.
    try std.testing.expectEqualStrings(project_chock_zon, second.chock_zon_target.?);

    // And the bind really reaches the mount list, not only the value: the
    // last entry is the read only `chock.zon`.
    const config = try second.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);
    const last = switch (config.mounts[config.mounts.len - 1]) {
        .bind => |b| b,
        .overlay, .proc, .deny => return error.ExpectedABindEntry,
    };
    try std.testing.expectEqualStrings(project_chock_zon, last.target);
    try std.testing.expectEqual(true, last.read_only);
}

test "adopt keeps the checkout's own chock.zon when the checkout still has one" {
    // The ordinary case, beside the fallback above: an adopted session that
    // never lost its policy file gets exactly what `open` gives, the copy
    // inside its own checkout. Without this the fallback could quietly become
    // the only path, and every adopted session would read the project's file
    // rather than the one it is working on.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();
    try project.commitChockZon();

    const base_commit = try headOf(allocator, &project);
    defer allocator.free(base_commit);

    {
        var first = try Workspace.open(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", null);
        first.keep(allocator);
    }

    var second = try Workspace.adopt(
        allocator,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        base_commit,
        null,
    );
    defer second.close(allocator, io, &project.env, null) catch unreachable;

    const in_checkout = try std.fs.path.join(allocator, &.{ second.workPath(), "chock.zon" });
    defer allocator.free(in_checkout);
    try std.testing.expectEqualStrings(in_checkout, second.chock_zon_source.?);
}

test "adopt refuses a chock.zon that is a symlink instead of an ordinary file" {
    // **The live path needs no committed chock.zon at all.** A project with
    // none gets no bind, and nothing stops an agent creating one of its own
    // kind in its own checkout between tool calls: `ln -s <host path>
    // chock.zon` there is exactly this shape. `findChockZonForAdopt` must not
    // read that link as though it were the project's own policy file.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();
    // No commitChockZon: the project itself has no policy file, so the
    // checkout starts with none either.

    const base_commit = try headOf(allocator, &project);
    defer allocator.free(base_commit);

    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var target_buffer: [std.fs.max_path_bytes]u8 = undefined;
    {
        var first = try Workspace.openWithLayout(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer first.keep(allocator);

        try std.testing.expect(first.chock_zon_source == null);

        const link_path = try std.fmt.bufPrintZ(&link_buffer, "{s}/chock.zon", .{first.workPath()});
        // The target does not need to exist, or even resolve, for what this
        // test is about: `chockZonExists` must refuse the link itself,
        // never follow it to find out where it leads.
        const target_path = try std.fmt.bufPrintZ(&target_buffer, "{s}/outside-the-project", .{project.scratch_path});
        try std.Io.Dir.symLinkAbsolute(io, target_path, link_path, .{});
    }

    try std.testing.expectError(error.ChockZonIsSymlink, Workspace.adoptWithLayout(
        allocator,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        base_commit,
        .remapped,
        null,
    ));
}

test "adopt refuses the overlay kind by name, because there is no overlay.adopt to call" {
    // What was found, in one check: an overlay backing survives its process
    // on disk, and no second process can rebuild the value for it, because
    // `overlay.create` refuses a scratch directory that already holds a
    // layout and nothing else builds one. See `Workspace.adopt`'s own doc
    // comment for the whole reading.
    //
    // **The refusal has to be by name.** An `error.Unexpected`, which is what
    // calling `overlay.create` a second time gives on Linux, reads as a bug
    // in Chock, and a caller would report a crash for a case that is simply
    // not built yet. Change `adopt` to fall through to `overlay.create` and
    // this test sees `error.Unexpected` instead.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    // No makeGitRepository call: root_path stays a plain directory, so this
    // project gets the overlay backing.

    var first = try Workspace.open(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    try std.testing.expect(first.kind == .overlay);
    first.keep(allocator);

    try std.testing.expectError(error.OverlayCannotBeAdopted, Workspace.adopt(
        allocator,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        "0000000000000000000000000000000000000000",
        null,
    ));
}
