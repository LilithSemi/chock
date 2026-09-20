//! Joins the two backings `worktree.zig` and `overlay.zig` build into one type
//! a caller can use without knowing which one a project got. `open` picks by
//! asking `git.isRepository`, and the caller never chooses.

const std = @import("std");
const builtin = @import("builtin");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const git = @import("git.zig");
const layout_mod = @import("layout.zig");
pub const Layout = layout_mod.Layout;
const worktree_mod = @import("worktree.zig");
const overlay_mod = @import("overlay.zig");
const deny_mod = @import("deny.zig");
const sandbox = @import("chock-sandbox");

pub const Error = worktree_mod.Error || overlay_mod.Error || deny_mod.Error || error{
    OverlayCannotBeAdopted,
    /// `chock.zon` names a symbolic link instead of an ordinary file, in the
    /// copy the sandbox would bind.
    ChockZonIsSymlink,
};

/// The name and the address every commit made inside the sandbox carries.
///
/// A commit is the only way a session's work reaches the user, and without this
/// git refuses with "Author identity unknown": the sandbox has no `HOME`, so no
/// global configuration is readable, and the whole of `.git` is read only, so
/// `git config user.name` cannot create one either. An agent once worked around
/// it by inventing an identity of its own, and a second session invented a
/// different one.
///
/// Environment variables and never a configuration file, for two reasons that
/// each stand alone: they outrank every configuration file in git's own
/// precedence, and they need nothing writable.
pub const identity_name = "Chock";
pub const identity_email = "chock@lilithsemi.com";

/// The four entries `sandboxConfig` puts in front of every other environment
/// variable, in `KEY=VALUE` form.
///
/// Author and committer both, because git takes the two from separate variables
/// and falls back to the configuration for either one it is not given.
///
/// No project may override this. An identity a project could rename is an
/// identity that says nothing, and a person who wants different authorship has
/// `git commit --amend --author` on their own branch.
///
/// `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` are deliberately absent. `git.zig`
/// forces both to `/dev/null` for a host side reason, which is that Chock parses
/// what git prints. Inside the sandbox the agent reads it, and no global or
/// system configuration is reachable anyway, so the two would neutralize nothing
/// while taking away a gitconfig a dev shell may have put in the tree on purpose.
///
/// No `GIT_AUTHOR_DATE` and no `GIT_COMMITTER_DATE`: git reads the real clock
/// when neither is set, which is what a commit's timestamp must be.
pub const identity_env = [_][]const u8{
    "GIT_AUTHOR_NAME=" ++ identity_name,
    "GIT_AUTHOR_EMAIL=" ++ identity_email,
    "GIT_COMMITTER_NAME=" ++ identity_name,
    "GIT_COMMITTER_EMAIL=" ++ identity_email,
};

/// Which backing a session got. Both kinds are equally free to build from an
/// ordinary, unprivileged caller, all the way through `sandboxConfig`. Neither
/// `mounts` call opens or mounts anything, and `chock-sandbox`'s own `buildRoot`
/// is the only place either mount is performed. An earlier `Overlay.mounts`
/// performed the real overlay mount here, which needed `CAP_SYS_ADMIN` over the
/// caller's own namespace and so needed a caller already inside one.
pub const Kind = union(enum) {
    worktree: worktree_mod.Worktree,
    overlay: overlay_mod.Overlay,
};

pub const Workspace = struct {
    kind: Kind,
    chock_zon_source: ?[]u8,
    chock_zon_target: ?[]u8,
    deny_paths: []const []u8,

    /// Pick a backing for `project_root` and build it. `git.isRepository`
    /// decides, and the caller never chooses.
    ///
    /// `scratch_dir` must already exist and holds every scratch file the chosen
    /// backing needs. `session_id` is only used for the worktree path.
    ///
    /// Darwin adds one requirement: `scratch_dir` must sit on the project's own
    /// volume, since a clone cannot cross one. `error.ScratchOnAnotherVolume`
    /// rather than working in the user's real files.
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

    pub fn openAndDenied(
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        project_root: []const u8,
        scratch_dir: []const u8,
        session_id: []const u8,
        also_denied: []const []const u8,
        diag: ?*?Diagnostic,
    ) Error!Workspace {
        return openWithLayoutAndDenied(
            allocator,
            io,
            env,
            project_root,
            scratch_dir,
            session_id,
            Layout.forHost(),
            also_denied,
            diag,
        );
    }

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
        return openWithLayoutAndDenied(
            allocator,
            io,
            env,
            project_root,
            scratch_dir,
            session_id,
            layout,
            &.{},
            diag,
        );
    }

    pub fn openWithLayoutAndDenied(
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        project_root: []const u8,
        scratch_dir: []const u8,
        session_id: []const u8,
        layout: Layout,
        also_denied: []const []const u8,
        diag: ?*?Diagnostic,
    ) Error!Workspace {
        // Before either backing is built, so a `deny_read` block this cannot
        // honour refuses the session rather than half building one. It reads
        // the host project's own `chock.zon`, which for the worktree backing is
        // not the file the checkout carries.
        //
        // Checked here and joined later, because where the sandbox sees the
        // project is not known until the backing exists.
        const own = try deny_mod.loadEntries(allocator, io, project_root, diag);
        defer deny_mod.free(allocator, own);

        const entries = try withAlsoDenied(allocator, own, also_denied);
        defer deny_mod.free(allocator, entries);

        if (try git.isRepository(allocator, io, env, project_root, diag)) {
            var wt = try worktree_mod.createWithLayout(allocator, io, env, project_root, scratch_dir, session_id, layout, diag);
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

        // The overlay's lower layer is read only end to end, but an agent that
        // deletes chock.zon only makes a whiteout in the writable upper layer,
        // and the merged view would then show it gone. Binding the project's
        // own file back over that path closes it.
        //
        // Under `.in_place` the source is the clone's own copy, because nothing
        // can be bound over anything there.
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

    fn withAlsoDenied(
        allocator: std.mem.Allocator,
        own: []const []u8,
        also: []const []const u8,
    ) Error![]const []u8 {
        for (also) |entry| try deny_mod.check(entry);
        if (own.len + also.len > deny_mod.max_paths) return error.TooManyDenyPaths;
        return copiedInto(allocator, own, also);
    }

    fn copiedInto(
        allocator: std.mem.Allocator,
        own: []const []u8,
        also: []const []const u8,
    ) Error![]const []u8 {
        const list = try allocator.alloc([]u8, own.len + also.len);
        var filled: usize = 0;
        errdefer {
            for (list[0..filled]) |one| allocator.free(one);
            allocator.free(list);
        }
        for (own) |one| {
            list[filled] = try allocator.dupe(u8, one);
            filled += 1;
        }
        for (also) |one| {
            list[filled] = try allocator.dupe(u8, one);
            filled += 1;
        }
        return list;
    }

    /// Take over the workspace of a session that is handing over. The checkout
    /// is already on disk, another process made it, and this runs no git
    /// command at all.
    ///
    /// The argument list is `open`'s plus `base_commit`, which the disk cannot
    /// give back: a session that committed before handing over has a HEAD that
    /// is not its base, so reading HEAD would make `headMoved` answer "nothing
    /// changed" for a session that changed plenty.
    ///
    /// The overlay backing is refused with `error.OverlayCannotBeAdopted`. That
    /// is about moving a running session to a second process and not about
    /// reaching the work: an ended overlay session gives its work up through
    /// `chock workspace adopt`. What is left before this call can take the
    /// overlay kind is `base_commit` no longer being an argument a caller must
    /// supply, and `src/run.zig`'s `takenOver` accepting an overlay open.
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

        // The host project's own `chock.zon`, and this is where that matters
        // most. Reading the deny list out of the checkout would let a session
        // hand over its way out of the list.
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
        // belongs to the session that is handing over, and a `remove` here
        // would answer a failed handover by deleting the work.
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

    pub fn workPath(self: *const Workspace) []const u8 {
        return switch (self.kind) {
            .worktree => |wt| wt.path,
            .overlay => |ov| ov.upper,
        };
    }

    /// Build the `Sandbox.Config` a caller hands to `Sandbox.spawn` for one
    /// tool call: the backing's mount list, the Landlock rules that go with it,
    /// and the `chock.zon` protection.
    ///
    /// `env` carries only what this library alone knows how to build. Both
    /// backings get `identity_env`, and the worktree backing gets
    /// `Worktree.gitEnv` as well. A caller that needs a dev shell's environment
    /// merges it in on top.
    ///
    /// The caller owns the returned slices. Every string inside them is a slice
    /// into `self` and stays valid only as long as `self` does.
    /// Three refusals this makes provable: no write to `.git/objects`, no write
    /// to `.git/hooks`, no delete of `chock.zon`.
    ///
    pub fn sandboxConfig(
        self: *const Workspace,
        allocator: std.mem.Allocator,
        root: []const u8,
    ) Error!sandbox.Config {
        var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
        errdefer mounts.deinit(allocator);
        var rules: std.ArrayList(sandbox.Config.Rule) = .empty;
        errdefer rules.deinit(allocator);
        // The identity comes first and for both backings, because without it
        // git refuses to make a commit at all.
        var env: std.ArrayList([]const u8) = .empty;
        errdefer env.deinit(allocator);
        try env.appendSlice(allocator, &identity_env);

        const cwd = self.sandboxRoot();

        switch (self.kind) {
            .worktree => |wt| {
                const backing_mounts = try wt.mounts(allocator);
                defer allocator.free(backing_mounts);
                try mounts.appendSlice(allocator, backing_mounts);

                try rules.append(allocator, .{
                    .path = wt.sandboxRoot(),
                    .access = sandbox.landlock.AccessFs.read_write,
                });
                try rules.append(allocator, .{
                    .path = wt.sandbox_git_root,
                    .access = sandbox.landlock.AccessFs.read_only,
                });
                // The scratch object store, read write. It is not nested
                // under sandbox_git_root and cannot be, so no rule above
                // covers it and the mount would otherwise be unreachable. The
                // mount layer still refuses a write to the real object store.
                try rules.append(allocator, .{
                    .path = wt.object_store_target,
                    .access = sandbox.landlock.AccessFs.read_write,
                });
                try rules.append(allocator, .{
                    .path = wt.worktree_meta_target,
                    .access = sandbox.landlock.AccessFs.read_write,
                });

                const backing_env = try wt.gitEnv(allocator);
                defer allocator.free(backing_env);
                try env.appendSlice(allocator, backing_env);
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

        // The files the project said the agent may not read. No Landlock rule
        // goes with these and none could: rights accumulate on a nested path
        // and are never narrowed by a wider rule, and the project directory is
        // read write, so a denied file under it cannot be subtracted. The mount
        // is the whole boundary here.
        for (self.deny_paths) |path| {
            try mounts.append(allocator, .{ .deny = .{ .target = path } });
        }

        return .{
            // `.in_place` has no root of its own. A root is what
            // `Sandbox.spawn` pivots into, and macOS cannot pivot. The layer
            // that keeps a tool call to the workspace there is the path rules.
            .root = switch (self.sandboxLayout()) {
                .remapped => root,
                .in_place => "/",
            },
            .mounts = try mounts.toOwnedSlice(allocator),
            .rules = try rules.toOwnedSlice(allocator),
            .cwd = cwd,
            .env = try env.toOwnedSlice(allocator),
        };
    }

    pub fn sandboxLayout(self: *const Workspace) Layout {
        return switch (self.kind) {
            .worktree => |wt| wt.layout,
            .overlay => |ov| ov.layout,
        };
    }

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

fn chockZonExists(io: std.Io, absolute_path: []const u8) (std.Io.Dir.StatFileError || error{ChockZonIsSymlink})!bool {
    const st = std.Io.Dir.cwd().statFile(io, absolute_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    if (st.kind == .sym_link) return error.ChockZonIsSymlink;
    return true;
}

/// The `chock.zon` an adopted session gets bound over it: the checkout's own
/// first, and the project's own when the checkout has none.
///
/// A session must not be able to hand over its way out of its own policy file.
/// `open` reads a checkout `git worktree add` just made, so the file is there
/// whenever HEAD has it. `adopt` reads a checkout a whole session has used, and
/// a missing file there would mean no bind and no policy file at all.
///
/// The bind is what makes the delete fail: `chock.zon` is a mount point inside
/// the sandbox, and unlinking a mount point answers `EBUSY`. This fallback is
/// for the checkout that lost the file some other way.
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
    // No fallback under `.in_place`, because a bind that moves a path is the
    // one thing macOS has not got. The policy a session runs under is still
    // read from the host project, so a checkout with no `chock.zon` changes no
    // rule. What is lost is the covering entry, so an agent on that layout can
    // create a `chock.zon` in its own checkout, which reaches nobody until a
    // hand back carries it.
    if (layout == .in_place) return in_checkout;
    return findChockZon(allocator, io, project_root, target_root, diag);
}

fn existsAsFile(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!bool {
    _ = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    return true;
}

// This file's own tests build both kinds of `Workspace`.

/// `std.testing.tmpDir` hands back a directory only a relative path reaches.
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

/// A program the system could not start answers differently from one that ran
/// and failed.
fn ranWell(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn makeDir(path: [:0]const u8) !void {
    std.Io.Dir.createDirAbsolute(std.testing.io, path, .default_dir) catch return error.MkdirFailed;
}

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

    fn commitChockZon(self: TestProject) !void {
        return self.commitChockZonSaying(".{}\n");
    }

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
    // Before this layout existed, every caller built the remapped shape.
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

        for (config.mounts) |mount| switch (mount) {
            .bind => |bind| try std.testing.expectEqualStrings(bind.source, bind.target),
            .deny => {},
            .overlay, .proc => return error.ExpectedABindEntry,
        };
        try std.testing.expectEqual(@as(?darwin.Inexpressible, null), darwin.expressibleOn(config));
        // The root is the real root, because macOS cannot pivot into one of ours.
        try std.testing.expectEqualStrings("/", config.root);
        try std.testing.expectEqualStrings(workspace.sandboxRoot(), config.cwd);
        try std.testing.expect(!std.mem.eql(u8, project.root_path, config.cwd));
    }
}

test "a real tool call runs in the workspace on macos, and the boundaries hold" {
    // The whole point of the in place layout: the tool call works in the
    // checkout under its own real name.
    if (builtin.os.tag != .macos) return;
    // Nix on macOS runs every builder under `sandbox-exec`, and macOS refuses
    // a nested sandbox, so the check has to run outside one.
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
    try std.testing.expect(try existsAsFile(io, written));
    var project_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_project = try std.fmt.bufPrint(&project_buffer, "{s}/agent-wrote-this.txt", .{project.root_path});
    try std.testing.expect(!try existsAsFile(io, in_project));

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked = try std.fmt.bufPrint(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try std.testing.expect(!ranWell(try sandbox.spawn(allocator, run, &.{ "/bin/cat", tracked }, null, null)));

    const wt = workspace.kind.worktree;

    var objects_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_objects = try std.fmt.bufPrint(&objects_buffer, "{s}/objects/agent-wrote-this", .{wt.sandbox_git_root});
    try std.testing.expect(!ranWell(try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", in_objects }, null, null)));

    // `commondir` redirects git at a git directory of the agent's
    // own choosing.
    try std.testing.expect(!ranWell(try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", wt.worktree_commondir_target }, null, null)));
    var index_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_meta = try std.fmt.bufPrint(&index_buffer, "{s}/agent-wrote-this", .{wt.worktree_meta_target});
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 0 },
        try sandbox.spawn(allocator, run, &.{ "/usr/bin/touch", in_meta }, null, null),
    );
    var real_meta_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const in_real_meta = try std.fmt.bufPrint(&real_meta_buffer, "{s}/agent-wrote-this", .{wt.worktree_meta_source});
    try std.testing.expect(!try existsAsFile(io, in_real_meta));
}

test "the remapped layout still moves the workspace to the project's own path" {
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

    try std.testing.expectEqualStrings("/session/root", config.root);
    try std.testing.expectEqualStrings(project.root_path, config.cwd);
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

    var workspace = try Workspace.open(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(workspace.kind == .overlay);
}

test "keeping a workspace leaves the agent's file on disk, and closing one takes it away" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    // The work an agent did and never committed. This is the 105 files of the
    // session a rate limit ended.
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

    var kept_handle = try std.Io.Dir.openFileAbsolute(io, kept_file, .{});
    defer kept_handle.close(io);
    var read_buffer: [64]u8 = undefined;
    var reader = kept_handle.readerStreaming(io, &read_buffer);
    const contents = try reader.interface.allocRemaining(allocator, .limited(1024));
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("work nobody committed\n", contents);

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

    try std.testing.expectEqual(identity_env.len + 2, config.env.len);
    var found_object_directory = false;
    var found_alternate = false;
    for (config.env) |entry| {
        if (std.mem.startsWith(u8, entry, "GIT_OBJECT_DIRECTORY=")) found_object_directory = true;
        if (std.mem.startsWith(u8, entry, "GIT_ALTERNATE_OBJECT_DIRECTORIES=")) found_alternate = true;
    }
    try std.testing.expect(found_object_directory);
    try std.testing.expect(found_alternate);
}

test "both backings carry the git identity, author and committer, and neither carries a date" {
    // The one variable set is the difference between work delivered and work
    // lost.
    const allocator = std.testing.allocator;

    const wanted = [_][]const u8{
        "GIT_AUTHOR_NAME=Chock",
        "GIT_AUTHOR_EMAIL=chock@lilithsemi.com",
        "GIT_COMMITTER_NAME=Chock",
        "GIT_COMMITTER_EMAIL=chock@lilithsemi.com",
    };

    for ([_]bool{ true, false }) |as_git_repository| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var project = try TestProject.init(allocator, tmp);
        defer project.deinit();
        if (as_git_repository) try project.makeGitRepository();

        var workspace = try Workspace.openWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

        const config = try workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
        defer allocator.free(config.mounts);
        defer allocator.free(config.rules);
        defer allocator.free(config.env);

        for (wanted) |entry| {
            const key = entry[0 .. std.mem.indexOfScalar(u8, entry, '=').? + 1];
            var found: ?[]const u8 = null;
            for (config.env) |candidate| {
                if (std.mem.startsWith(u8, candidate, key)) found = candidate;
            }
            try std.testing.expectEqualStrings(
                entry,
                found orelse return error.TheGitIdentityWasNotInTheSandboxEnvironment,
            );
        }

        // No date, ever. git reads the real clock when neither is set.
        for (config.env) |candidate| {
            try std.testing.expect(!std.mem.startsWith(u8, candidate, "GIT_AUTHOR_DATE="));
            try std.testing.expect(!std.mem.startsWith(u8, candidate, "GIT_COMMITTER_DATE="));
        }
    }
}

test "sandboxConfig for the overlay kind needs no namespace either, so an ordinary caller can call it directly" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var workspace = try Workspace.openWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    const config = try workspace.sandboxConfig(allocator, "/does-not-need-to-exist-for-this-check");
    defer allocator.free(config.mounts);
    defer allocator.free(config.rules);
    defer allocator.free(config.env);

    try std.testing.expect(config.mounts.len > 0);
    try std.testing.expect(config.rules.len > 0);
    try std.testing.expectEqualStrings(workspace.kind.overlay.project, config.cwd);
    try std.testing.expectEqual(identity_env.len, config.env.len);

    const overlay_entry = switch (config.mounts[0]) {
        .overlay => |o| o,
        .bind, .proc, .deny => return error.ExpectedAnOverlayEntry,
    };
    try std.testing.expectEqualStrings(workspace.kind.overlay.project, overlay_entry.target);
}

test "every landlock rule sandboxConfig writes names a path its own mount list holds" {
    // The two lists are one judgement written twice, so they must not drift.
    const allocator = std.testing.allocator;

    for ([_]Layout{ .remapped, .in_place }) |layout| {
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

fn expectLayersAgree(config: sandbox.Config) !void {
    var buffer: [256]u8 = undefined;
    const said = if (sandbox.firstGap(config)) |gap|
        try std.fmt.bufPrint(&buffer, "{f}", .{gap})
    else
        "";
    try std.testing.expectEqualStrings("", said);
}

test "adopt takes the worktree a first process left, with the work still in it" {
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
    // Stated as `.remapped`, because the fallback is a bind that moves a path.
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
    try std.testing.expectEqualStrings(project_chock_zon, second.chock_zon_target.?);

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
    // The live path needs no committed chock.zon at all.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();
    try project.makeGitRepository();

    const base_commit = try headOf(allocator, &project);
    defer allocator.free(base_commit);

    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var target_buffer: [std.fs.max_path_bytes]u8 = undefined;
    {
        var first = try Workspace.openWithLayout(allocator, io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer first.keep(allocator);

        try std.testing.expect(first.chock_zon_source == null);

        const link_path = try std.fmt.bufPrintZ(&link_buffer, "{s}/chock.zon", .{first.workPath()});
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
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

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

test "a layer above the project adds denied paths, and the project cannot take one off" {
    // An org policy bundle could narrow a rule and be answered by a project
    // that simply did not name the file.
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    try writeChockZon(project, ".{ .deny_read = .{ \"own.txt\" } }\n");

    var workspace = try Workspace.openAndDenied(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        &.{"from-the-org.txt"},
        null,
    );
    defer workspace.close(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expectEqual(@as(usize, 2), workspace.deny_paths.len);
    try std.testing.expect(endsWithAny(workspace.deny_paths, "own.txt"));
    try std.testing.expect(endsWithAny(workspace.deny_paths, "from-the-org.txt"));
}

test "a path the layer above names is refused by the same rules a project's own is" {
    // One copy of the rules, and it is `deny.check`.
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const refused = [_]struct { entry: []const u8, want: anyerror }{
        .{ .entry = "/etc/shadow", .want = error.DenyPathNotRelative },
        .{ .entry = "../outside.txt", .want = error.DenyPathLeavesProject },
        .{ .entry = "secret*.txt", .want = error.DenyPathIsAPattern },
        .{ .entry = "chock.zon", .want = error.DenyPathIsChockZon },
    };
    for (refused) |one| {
        try std.testing.expectError(one.want, Workspace.openAndDenied(
            allocator,
            std.testing.io,
            &project.env,
            project.root_path,
            project.scratch_path,
            "sess1",
            &.{one.entry},
            null,
        ));
    }
}

fn writeChockZon(project: TestProject, source: []const u8) !void {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buffer, "{s}/chock.zon", .{project.root_path});
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, path, .{});
    try file.writeStreamingAll(std.testing.io, source);
    file.close(std.testing.io);
}

/// The paths are absolute and joined onto a root a test does not spell.
fn endsWithAny(paths: []const []u8, leaf: []const u8) bool {
    for (paths) |one| {
        if (std.mem.endsWith(u8, one, leaf)) return true;
    }
    return false;
}
