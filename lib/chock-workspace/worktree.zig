//! Creates the throwaway git worktree the agent works in, and builds the mount
//! list that lets the sandbox mount it at the project's own path.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const git = @import("git.zig");
const layout_mod = @import("layout.zig");
pub const Layout = layout_mod.Layout;
const sandbox = @import("chock-sandbox");

pub const Error = git.Error || error{
    GitFailed,
    NotALinkedWorktree,
    /// `session_id` goes straight into a path join for the worktree's own
    /// path, the sandbox mount target, and the pointer file name.
    InvalidSessionId,
    /// A path `git status` named that was absolute or held a `..` component.
    /// Joining it onto `project_root` or onto the worktree could reach outside
    /// both, so it is refused and never followed.
    PathEscapesProject,
    /// A refusal and not a fault: `adopt` only ever takes a checkout another
    /// process already made. A caller that wants a new worktree calls `create`.
    NoWorktreeToAdopt,
    /// git prunes the registration of a checkout it cannot find, and a checkout
    /// whose registration is gone is one no git command works in. Refused here,
    /// where the reason is still readable.
    WorktreeRegistrationGone,
};

pub const Mount = sandbox.namespace.Mount;

/// The prefix, meaningful only inside the sandbox, under which `mounts` puts
/// the shared parts of `.git`. Chosen to be a path no real project uses.
const sandbox_git_root_prefix = chock_runtime_prefix ++ "/git";

/// Nothing creates `/run` or `/run/chock` on its own. `namespace.makePath`
/// creates every parent of a mount target as a directory before the mount
/// happens and tolerates one that already exists.
///
/// The kernel takes the last matching mount, not the longest prefix, so a wide
/// mount at `/run` applied after these would shadow all three at once. Nothing
/// in Chock mounts `/run`, and the tests below hold that.
const chock_runtime_prefix = sandbox.runtime_prefix;

/// Deliberately not nested under `sandbox_git_root_prefix`. `namespace.buildRoot`
/// marks a mount read only the moment it makes it, and `mkdir` for a mount
/// point that must create something new under an already read only parent gets
/// EROFS. `worktree_meta_target` escapes that only because it reuses a name
/// that already exists under the real `.git`; a scratch object store has no
/// such name, so it gets a prefix of its own.
const object_store_prefix = chock_runtime_prefix ++ "/objects";

pub const ImportReport = struct {
    modified: std.ArrayList([]u8) = .empty,
    /// A file already `git add`ed before this ran is new to HEAD, and is still
    /// counted under `modified`: telling the two apart needs the rest of git's
    /// status letters.
    added: std.ArrayList([]u8) = .empty,
    deleted: std.ArrayList([]u8) = .empty,
    skipped: std.ArrayList(Skip) = .empty,

    pub const Skip = struct {
        path: []u8,
        reason: []u8,
    };

    pub fn total(self: ImportReport) usize {
        return self.modified.items.len + self.added.items.len + self.deleted.items.len;
    }

    pub fn deinit(self: *ImportReport, allocator: std.mem.Allocator) void {
        for (self.modified.items) |path| allocator.free(path);
        self.modified.deinit(allocator);
        for (self.added.items) |path| allocator.free(path);
        self.added.deinit(allocator);
        for (self.deleted.items) |path| allocator.free(path);
        self.deleted.deinit(allocator);
        for (self.skipped.items) |skip| {
            allocator.free(skip.path);
            allocator.free(skip.reason);
        }
        self.skipped.deinit(allocator);
        self.* = undefined;
    }
};

pub const Uncommitted = struct {
    modified: usize = 0,
    untracked: usize = 0,

    pub fn total(self: Uncommitted) usize {
        return self.modified + self.untracked;
    }

    pub fn any(self: Uncommitted) bool {
        return self.total() != 0;
    }
};

/// `git worktree add` checks out the commit, not the index and not the working
/// tree, so an agent in a fresh worktree sees `HEAD` and nothing else. The
/// fault this answers is the silence: a user who is never told believes the
/// agent can see work it cannot.
pub fn countUncommitted(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error!Uncommitted {
    var status_output = try git.run(allocator, io, env, project_root, status_argv, diag);
    defer status_output.deinit(allocator);
    switch (status_output.term) {
        .exited => |code| if (code != 0) return error.GitFailed,
        else => return error.GitFailed,
    }

    var counts = Uncommitted{};
    var seen_paths: std.StringHashMapUnmanaged(void) = .empty;
    defer seen_paths.deinit(allocator);

    var entries = std.mem.splitScalar(u8, status_output.stdout, 0);
    while (entries.next()) |entry| {
        if (entry.len < 4) continue; // too short to hold "XY " plus a path
        const rel_path = entry[3..];
        if (seen_paths.contains(rel_path)) continue;
        try seen_paths.put(allocator, rel_path, {});
        if (std.mem.startsWith(u8, entry, "??")) counts.untracked += 1 else counts.modified += 1;
    }
    return counts;
}

/// The one `git status` call this file makes, spelled once. `countUncommitted`
/// reads the same output the same way, so a second spelling could drift.
const status_argv = &[_][]const u8{
    "--no-optional-locks",   "status",       "--porcelain=v1", "-z",
    "--untracked-files=all", "--no-renames",
};

pub const Worktree = struct {
    path: []u8,
    project_root: []u8,
    layout: Layout,
    /// This is the project root the agent is told about. `sandboxConfig` makes
    /// it the working directory of every tool call.
    sandbox_root: []u8,
    /// Read back right after `git worktree add` ran, and never assumed to equal
    /// the project's `HEAD`: what git did is a fact, what it was asked to do is
    /// not.
    base_commit: []u8,
    git_dir: []u8,
    /// Read back from the `.git` file git wrote, never assumed to equal the
    /// session id: git deduplicates the name when one is already registered.
    worktree_id: []u8,
    sandbox_git_root: []u8,
    /// A fresh writable directory, because the real `.git/objects` stays read
    /// only and git still needs somewhere to write a loose object.
    object_store_source: []u8,
    object_store_target: []u8,
    git_object_directory_env: []u8,
    /// A variable and never a file. An `objects/info/alternates` file would
    /// have to live inside the one directory under `.git` the sandbox can
    /// write, which makes it a path naming file the agent can rewrite, the
    /// same shape `commondir`, `gitdir` and `config.worktree` already have.
    git_alternate_object_directories_env: []u8,
    /// Null under `Layout.remapped`, where the copy is bound at the path the
    /// checkout's own `gitdir:` line already names, and set under
    /// `Layout.in_place`, which can move no path.
    git_dir_env: ?[]u8,
    /// `GIT_DIR` on its own is not enough. Against git 2.55, `GIT_DIR` with no
    /// `GIT_WORK_TREE` makes git treat the current directory as the root of the
    /// working tree, so a `git add` run from a subdirectory reports every file
    /// outside that subdirectory as deleted. The two go together or neither.
    git_work_tree_env: ?[]u8,
    worktree_meta_source: []u8,
    worktree_meta_target: []u8,
    worktree_meta_bind_source: []u8,
    /// Always true today, and kept as a field because `remove` deletes a whole
    /// directory tree on the strength of it.
    worktree_meta_is_copy: bool,
    worktree_index_source: []u8,
    worktree_index_target: []u8,
    worktree_head_source: []u8,
    worktree_head_target: []u8,
    worktree_logs_source: []u8,
    worktree_logs_target: []u8,
    worktree_commondir_source: []u8,
    worktree_commondir_target: []u8,
    worktree_gitdir_file_source: []u8,
    worktree_gitdir_file_target: []u8,
    /// Always set: the project's own file when there was one at create time,
    /// and an empty scratch file this session owns when there was not. An
    /// optional field here left a route to host code execution open.
    worktree_config_worktree_source: []u8,
    worktree_config_worktree_target: []u8,
    worktree_config_worktree_is_scratch: bool,
    /// A directory cannot be bind mounted onto a path that is currently a file,
    /// which is ENOTDIR, so the worktree's own one line `.git` is shadowed by
    /// this scratch file rather than nested under. The real one is untouched.
    pointer_path: []u8,

    pub fn sandboxRoot(self: Worktree) []const u8 {
        return self.sandbox_root;
    }

    /// The mount list, in the shape `Mount` above. Every `source` and `target`
    /// is a slice into `self`, and the caller frees only the returned array.
    ///
    /// Order matters and must not change, because the kernel applies mounts in
    /// order and the last one that covers a path wins. Entry 0's target is a
    /// prefix of the last entry's, entry 3 nests under entry 1, and entries 4
    /// to 6 nest one level deeper again. Under `Layout.in_place` no mount is
    /// performed, and the Darwin driver reads the list as path rules with the
    /// same last one wins meaning.
    ///
    /// Entry 3's source is a copy, because the root of the metadata directory
    /// cannot be made read only. `git add` and `git commit` create
    /// `index.lock` and its siblings there and rename each over the file it
    /// locks. `open` with `O_CREAT|O_EXCL` under a read only mount answers
    /// EROFS, so pre-creating each name does not help, and a lock file bound in
    /// from elsewhere cannot be renamed over its target, because `rename`
    /// refuses to cross a mount point.
    ///
    /// Entry 3 binds the directory as a whole and does not name `index`, `HEAD`
    /// and `logs` one at a time: `open` for write on an existing file under a
    /// mount already marked read only fails with EROFS. `mkdir` tolerates an
    /// existing directory with EEXIST, because the kernel can answer that
    /// without asking for write access, which is what makes entry 3 possible.
    ///
    /// Entries 4 to 6 claw `commondir`, `gitdir` and `config.worktree` back to
    /// read only. Their parent is still read write when they run, so the write
    /// succeeds and the mark narrows that one file. Each redirects git at a
    /// path the agent chooses, so a writable one is code execution on the next
    /// host side git command. Entry 6 is unconditional, because git writes
    /// `config.worktree` from inside the sandbox the first time something sets
    /// a value with `--worktree`. Every other name under this directory is
    /// git's own bookkeeping and names no path outside it.
    fn metaFileSource(self: Worktree, project_file: []const u8, target: []const u8) []const u8 {
        return switch (self.layout) {
            .remapped => project_file,
            .in_place => target,
        };
    }

    pub fn mounts(self: Worktree, allocator: std.mem.Allocator) Error![]Mount {
        var list: std.ArrayList(Mount) = .empty;
        errdefer list.deinit(allocator);

        // 0: the worktree itself. Read write: the agent works here.
        try list.append(allocator, .{ .bind = .{ .source = self.path, .target = self.sandbox_root, .read_only = false } });

        // 1: the whole real .git, read only, at the synthetic path the sandbox
        // owns. Nothing narrower below overrides the object store, the refs,
        // the hooks, or any other worktree's metadata.
        try list.append(allocator, .{ .bind = .{ .source = self.git_dir, .target = self.sandbox_git_root, .read_only = true } });

        // 2: this session's own scratch object store, read write.
        try list.append(allocator, .{ .bind = .{
            .source = self.object_store_source,
            .target = self.object_store_target,
            .read_only = false,
        } });

        // 3: this worktree's metadata directory, read write, as a copy.
        try list.append(allocator, .{ .bind = .{
            .source = self.worktree_meta_bind_source,
            .target = self.worktree_meta_target,
            .read_only = false,
        } });

        // 4, 5: commondir and gitdir. git writes both for every worktree.
        try list.append(allocator, .{ .bind = .{
            .source = self.metaFileSource(self.worktree_commondir_source, self.worktree_commondir_target),
            .target = self.worktree_commondir_target,
            .read_only = true,
        } });
        try list.append(allocator, .{ .bind = .{
            .source = self.metaFileSource(self.worktree_gitdir_file_source, self.worktree_gitdir_file_target),
            .target = self.worktree_gitdir_file_target,
            .read_only = true,
        } });

        // 6: config.worktree, unconditional.
        try list.append(allocator, .{ .bind = .{
            .source = self.metaFileSource(self.worktree_config_worktree_source, self.worktree_config_worktree_target),
            .target = self.worktree_config_worktree_target,
            .read_only = true,
        } });

        // last: the replacement .git file. `.in_place` needs no such entry,
        // because nothing was moved and the pointer git wrote already names a
        // path the sandbox can resolve.
        if (self.layout == .remapped) {
            try list.append(allocator, .{ .bind = .{ .source = self.pointer_path, .target = self.git_dir, .read_only = true } });
        }

        return list.toOwnedSlice(allocator);
    }

    /// The environment a caller must add to `Sandbox.Config.env` for every tool
    /// call, so `git add` and `git commit` succeed while the real object store
    /// stays read only.
    ///
    /// `GIT_DIR` and `GIT_WORK_TREE` come under `Layout.in_place` alone. A
    /// `GIT_DIR` under `.remapped` would reach every git command a tool call
    /// makes, a repository the agent cloned for itself included.
    ///
    /// An agent can override any of these for a subprocess of its own, and
    /// gains nothing: git never writes to an alternate.
    pub fn gitEnv(self: Worktree, allocator: std.mem.Allocator) Error![]const []const u8 {
        if (self.git_dir_env) |dir_env| {
            return allocator.dupe([]const u8, &.{
                self.git_object_directory_env,
                self.git_alternate_object_directories_env,
                dir_env,
                self.git_work_tree_env.?,
            });
        }
        return allocator.dupe([]const u8, &.{
            self.git_object_directory_env,
            self.git_alternate_object_directories_env,
        });
    }

    /// Copy the project's own uncommitted work into this worktree, so a session
    /// that starts on a dirty tree sees the codebase the user sees.
    ///
    /// `git status` is asked with three flags chosen on purpose.
    /// `--untracked-files=all`, so a file the user made but never `git add`ed
    /// is named, which is what a plain `git diff` misses. `--no-renames`, so a
    /// rename is two entries this function already handles and not one entry
    /// naming two paths. `--no-optional-locks`, so this never writes a
    /// refreshed index back to the project.
    ///
    /// The action taken is decided by what is on disk and never by the status
    /// letters. A path git status names twice, which `git rm --cached` does, is
    /// imported once, and a single bad path does not abort the run.
    ///
    /// git never lists an empty directory, because it tracks paths to files and
    /// links and not directories, so one is never carried across.
    pub fn importUncommitted(
        self: Worktree,
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        diag: ?*?Diagnostic,
    ) Error!ImportReport {
        var status_output = try git.run(allocator, io, env, self.project_root, status_argv, diag);
        defer status_output.deinit(allocator);
        switch (status_output.term) {
            .exited => |code| if (code != 0) return error.GitFailed,
            else => return error.GitFailed,
        }

        var report = ImportReport{};
        errdefer report.deinit(allocator);

        var seen_paths: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_paths.deinit(allocator);

        // `-z` separates entries with NUL and turns off git's own quoting of
        // unusual characters, so slicing off the leading "XY " gives back the
        // exact bytes on disk.
        var entries = std.mem.splitScalar(u8, status_output.stdout, 0);
        while (entries.next()) |entry| {
            if (entry.len < 4) continue; // too short to hold "XY " plus a path
            const rel_path = entry[3..];
            if (seen_paths.contains(rel_path)) continue;
            try seen_paths.put(allocator, rel_path, {});
            try self.importPath(allocator, io, entry, &report);
        }

        return report;
    }

    fn importPath(
        self: Worktree,
        allocator: std.mem.Allocator,
        io: std.Io,
        entry: []const u8,
        report: *ImportReport,
    ) Error!void {
        const rel_path = entry[3..];
        try validateRelativePath(rel_path);

        const source_path = try std.fs.path.join(allocator, &.{ self.project_root, rel_path });
        defer allocator.free(source_path);
        const target_path = try std.fs.path.join(allocator, &.{ self.path, rel_path });
        defer allocator.free(target_path);

        const kind = classify(io, source_path) catch |err| {
            const reason = try std.fmt.allocPrint(allocator, "checking the project failed: {s}", .{@errorName(err)});
            return recordSkip(report, allocator, rel_path, reason);
        };

        const found_kind = kind orelse return removeFromWorktree(allocator, io, rel_path, target_path, report);

        // "??" is the code --untracked-files=all gives a path git never tracked.
        const is_new = std.mem.startsWith(u8, entry, "??");

        switch (found_kind) {
            .file => return copyRegularFile(allocator, io, rel_path, source_path, target_path, is_new, report),
            .sym_link => return recreateSymlink(allocator, io, rel_path, source_path, target_path, is_new, report),
            .directory => {
                const reason = try allocator.dupe(
                    u8,
                    "a directory, not carried across: chock does not import a submodule, a vendored " ++
                        "clone, or any other nested repository",
                );
                return recordSkip(report, allocator, rel_path, reason);
            },
            else => |other_kind| {
                const reason = try std.fmt.allocPrint(
                    allocator,
                    "not a regular file or a link, and not carried across (it is a {s})",
                    .{@tagName(other_kind)},
                );
                return recordSkip(report, allocator, rel_path, reason);
            },
        }
    }

    /// Tolerates the worktree not having the path either: a file staged as an
    /// add and then deleted by hand leaves nothing to remove.
    fn removeFromWorktree(
        allocator: std.mem.Allocator,
        io: std.Io,
        rel_path: []const u8,
        target_path: []const u8,
        report: *ImportReport,
    ) Error!void {
        std.Io.Dir.deleteFileAbsolute(io, target_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => |e| {
                const reason = try std.fmt.allocPrint(allocator, "removing from the worktree failed: {s}", .{@errorName(e)});
                return recordSkip(report, allocator, rel_path, reason);
            },
        };
        try report.deleted.append(allocator, try allocator.dupe(u8, rel_path));
    }

    pub fn copyRegularFile(
        allocator: std.mem.Allocator,
        io: std.Io,
        rel_path: []const u8,
        source_path: []const u8,
        target_path: []const u8,
        is_new: bool,
        report: *ImportReport,
    ) Error!void {
        // make_path: a brand new untracked file can sit in a directory the
        // worktree, checked out at HEAD, has never had.
        std.Io.Dir.copyFileAbsolute(source_path, target_path, io, .{ .make_path = true }) catch |err| {
            const reason = try std.fmt.allocPrint(allocator, "copying into the worktree failed: {s}", .{@errorName(err)});
            return recordSkip(report, allocator, rel_path, reason);
        };
        const list: *std.ArrayList([]u8) = if (is_new) &report.added else &report.modified;
        try list.append(allocator, try allocator.dupe(u8, rel_path));
    }

    /// This never opens `source_path` and never resolves the link.
    /// `readLinkAbsolute` reads the target string stored in the directory
    /// entry, so a link pointing outside the project is copied as that string
    /// and the worktree never gets the target's content.
    pub fn recreateSymlink(
        allocator: std.mem.Allocator,
        io: std.Io,
        rel_path: []const u8,
        source_path: []const u8,
        target_path: []const u8,
        is_new: bool,
        report: *ImportReport,
    ) Error!void {
        var link_target_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const link_target_len = std.Io.Dir.readLinkAbsolute(io, source_path, &link_target_buffer) catch |err| {
            const reason = try std.fmt.allocPrint(allocator, "reading the link failed: {s}", .{@errorName(err)});
            return recordSkip(report, allocator, rel_path, reason);
        };
        const link_target_text = link_target_buffer[0..link_target_len];

        if (std.fs.path.dirname(target_path)) |parent_path| {
            std.Io.Dir.cwd().createDirPath(io, parent_path) catch |err| {
                const reason = try std.fmt.allocPrint(
                    allocator,
                    "making room for the link in the worktree failed: {s}",
                    .{@errorName(err)},
                );
                return recordSkip(report, allocator, rel_path, reason);
            };
        }

        // Dir.symLink refuses to overwrite an existing entry, and the worktree
        // may already hold a plain file or an older link here.
        std.Io.Dir.deleteFileAbsolute(io, target_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => |e| {
                const reason = try std.fmt.allocPrint(
                    allocator,
                    "clearing the worktree for the link failed: {s}",
                    .{@errorName(e)},
                );
                return recordSkip(report, allocator, rel_path, reason);
            },
        };

        // Not symLinkAbsolute: it asserts its target text is itself absolute,
        // and an ordinary link target is very often relative.
        std.Io.Dir.cwd().symLink(io, link_target_text, target_path, .{}) catch |err| {
            const reason = try std.fmt.allocPrint(allocator, "recreating the link in the worktree failed: {s}", .{@errorName(err)});
            return recordSkip(report, allocator, rel_path, reason);
        };

        const list: *std.ArrayList([]u8) = if (is_new) &report.added else &report.modified;
        try list.append(allocator, try allocator.dupe(u8, rel_path));
    }

    pub fn recordSkip(
        report: *ImportReport,
        allocator: std.mem.Allocator,
        rel_path: []const u8,
        reason: []u8,
    ) Error!void {
        errdefer allocator.free(reason);
        const path_copy = try allocator.dupe(u8, rel_path);
        errdefer allocator.free(path_copy);
        try report.skipped.append(allocator, .{ .path = path_copy, .reason = reason });
    }

    /// The commit a session made is only in the scratch object store, so this
    /// names that store as an alternate for the one read. A read of an
    /// alternate can never write to it.
    pub fn headAfterSession(
        self: Worktree,
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        diag: ?*?Diagnostic,
    ) Error![]u8 {
        var reading_env = try env.clone(allocator);
        defer reading_env.deinit();
        try reading_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", self.object_store_source);
        // The session's own HEAD is in the copy. The checkout's `.git` names a
        // directory that still reads as `git worktree add` left it, so `GIT_DIR`
        // points this one read at the copy instead.
        if (self.worktree_meta_is_copy) {
            try reading_env.put("GIT_DIR", self.worktree_meta_bind_source);
        }
        return readHeadWith(allocator, io, &reading_env, self.path, diag);
    }

    /// An idle session answers false, so a session that changed nothing cannot
    /// make the project dirty.
    pub fn headMoved(
        self: Worktree,
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        diag: ?*?Diagnostic,
    ) Error!?[]u8 {
        const head = try self.headAfterSession(allocator, io, env, diag);
        if (std.mem.eql(u8, head, self.base_commit)) {
            allocator.free(head);
            return null;
        }
        return head;
    }

    /// Every deletion and every free happens whether or not `git worktree
    /// remove` succeeded. Every path it touches belongs to the session and not
    /// to one process, so the process that removes need not be the one that
    /// made: the registration names two paths and no process.
    pub fn remove(
        self: *Worktree,
        allocator: std.mem.Allocator,
        io: std.Io,
        env: *const std.process.Environ.Map,
        diag: ?*?Diagnostic,
    ) Error!void {
        var output = try git.run(allocator, io, env, self.project_root, &.{
            "worktree", "remove", "--force", self.path,
        }, diag);
        defer output.deinit(allocator);
        const failed = switch (output.term) {
            .exited => |code| code != 0,
            else => true,
        };

        deleteFileAbsolute(io, self.pointer_path, diag) catch {};
        // The project's own real config.worktree, when create found one
        // instead, is never touched here.
        if (self.worktree_config_worktree_is_scratch) {
            deleteFileAbsolute(io, self.worktree_config_worktree_source, diag) catch {};
        }
        // Only ever the copy: under `.in_place` there is none, and the path
        // this field holds is then the project's own.
        if (self.worktree_meta_is_copy) {
            std.Io.Dir.cwd().deleteTree(io, self.worktree_meta_bind_source) catch {};
        }
        std.Io.Dir.cwd().deleteTree(io, self.object_store_source) catch {};

        self.freeFields(allocator);

        if (failed) return error.GitFailed;
    }

    /// Free every field and leave the worktree where it is on disk. `remove`
    /// runs on every ending, so a session that errored, was refused, reached
    /// its budget or was interrupted used to destroy whatever it had produced:
    /// a rate limit once took 105 changed files with the worktree.
    pub fn keep(self: *Worktree, allocator: std.mem.Allocator) void {
        self.freeFields(allocator);
    }

    fn freeFields(self: *Worktree, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.project_root);
        allocator.free(self.base_commit);
        allocator.free(self.git_dir);
        allocator.free(self.worktree_id);
        allocator.free(self.sandbox_root);
        allocator.free(self.sandbox_git_root);
        allocator.free(self.object_store_source);
        allocator.free(self.object_store_target);
        allocator.free(self.git_object_directory_env);
        allocator.free(self.git_alternate_object_directories_env);
        if (self.git_dir_env) |value| allocator.free(value);
        if (self.git_work_tree_env) |value| allocator.free(value);
        allocator.free(self.worktree_meta_source);
        allocator.free(self.worktree_meta_target);
        allocator.free(self.worktree_meta_bind_source);
        allocator.free(self.worktree_index_source);
        allocator.free(self.worktree_index_target);
        allocator.free(self.worktree_head_source);
        allocator.free(self.worktree_head_target);
        allocator.free(self.worktree_logs_source);
        allocator.free(self.worktree_logs_target);
        allocator.free(self.worktree_commondir_source);
        allocator.free(self.worktree_commondir_target);
        allocator.free(self.worktree_gitdir_file_source);
        allocator.free(self.worktree_gitdir_file_target);
        allocator.free(self.worktree_config_worktree_source);
        allocator.free(self.worktree_config_worktree_target);
        allocator.free(self.pointer_path);
        self.* = undefined;
    }
};

fn targetPath(
    allocator: std.mem.Allocator,
    layout: Layout,
    source: []const u8,
    parts: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    return switch (layout) {
        .remapped => std.fs.path.join(allocator, parts),
        .in_place => allocator.dupe(u8, source),
    };
}

/// `targetPath` with the session's own copy in place of the project's own
/// directory. Under `.in_place` nothing moves, so the only path the sandbox
/// can reach the copy by is the copy's own. The caller owns the result.
fn metaTarget(
    allocator: std.mem.Allocator,
    layout: Layout,
    bind_source: []const u8,
    parts: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    return switch (layout) {
        .remapped => std.fs.path.join(allocator, parts),
        .in_place => allocator.dupe(u8, bind_source),
    };
}

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    scratch_dir: []const u8,
    session_id: []const u8,
    diag: ?*?Diagnostic,
) Error!Worktree {
    return createWithLayout(allocator, io, env, project_root, scratch_dir, session_id, Layout.forHost(), diag);
}

/// This exists so a Linux test can build the mount list macOS gets. A boundary
/// that only one platform's continuous integration compiles is one nobody
/// checks.
pub fn createWithLayout(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    scratch_dir: []const u8,
    session_id: []const u8,
    layout: Layout,
    diag: ?*?Diagnostic,
) Error!Worktree {
    try validateSessionId(session_id);

    const worktree_path = try std.fs.path.join(allocator, &.{ scratch_dir, session_id });
    errdefer allocator.free(worktree_path);

    var add_output = try git.run(allocator, io, env, project_root, &.{
        "worktree", "add", "--detach", worktree_path, "HEAD",
    }, diag);
    defer add_output.deinit(allocator);
    switch (add_output.term) {
        .exited => |code| if (code != 0) return error.GitFailed,
        else => return error.GitFailed,
    }
    // From here on `git worktree add` has registered a linked worktree. Any
    // failure below must undo that, or the session leaves a live worktree
    // behind that nothing cleans up.
    errdefer cleanupFailedAdd(allocator, io, env, project_root, worktree_path);

    const dotgit_path = try std.fs.path.join(allocator, &.{ worktree_path, ".git" });
    defer allocator.free(dotgit_path);
    const worktree_id = try readWorktreeId(allocator, io, dotgit_path, diag);
    errdefer allocator.free(worktree_id);

    const base_commit = try readHeadWith(allocator, io, env, worktree_path, diag);
    errdefer allocator.free(base_commit);

    const project_root_owned = try allocator.dupe(u8, project_root);
    errdefer allocator.free(project_root_owned);

    const git_dir = try std.fs.path.join(allocator, &.{ project_root_owned, ".git" });
    errdefer allocator.free(git_dir);

    const sandbox_root = try targetPath(allocator, layout, worktree_path, &.{project_root_owned});
    errdefer allocator.free(sandbox_root);

    const sandbox_git_root = try targetPath(allocator, layout, git_dir, &.{ sandbox_git_root_prefix, session_id });
    errdefer allocator.free(sandbox_git_root);

    const object_store_name = try std.fmt.allocPrint(allocator, "{s}.objects", .{session_id});
    defer allocator.free(object_store_name);
    const object_store_source = try std.fs.path.join(allocator, &.{ scratch_dir, object_store_name });
    errdefer allocator.free(object_store_source);
    std.Io.Dir.cwd().createDirPath(io, object_store_source) catch |err| {
        diagnostic.noteErr(diag, .scratch_object_store_create, err);
        return error.Unexpected;
    };
    errdefer std.Io.Dir.cwd().deleteTree(io, object_store_source) catch {};

    const object_store_target = try targetPath(allocator, layout, object_store_source, &.{ object_store_prefix, session_id });
    errdefer allocator.free(object_store_target);

    const git_object_directory_env = try std.fmt.allocPrint(
        allocator,
        "GIT_OBJECT_DIRECTORY={s}",
        .{object_store_target},
    );
    errdefer allocator.free(git_object_directory_env);

    const real_objects_target = try std.fs.path.join(allocator, &.{ sandbox_git_root, "objects" });
    defer allocator.free(real_objects_target);
    const git_alternate_object_directories_env = try std.fmt.allocPrint(
        allocator,
        "GIT_ALTERNATE_OBJECT_DIRECTORIES={s}",
        .{real_objects_target},
    );
    errdefer allocator.free(git_alternate_object_directories_env);

    const worktree_meta_source = try std.fs.path.join(allocator, &.{ git_dir, "worktrees", worktree_id });
    errdefer allocator.free(worktree_meta_source);

    const worktree_meta_bind_source = try metaBindSource(allocator, scratch_dir, session_id);
    errdefer allocator.free(worktree_meta_bind_source);
    const worktree_meta_is_copy = true;
    try copyMetaDirectory(allocator, io, worktree_meta_source, worktree_meta_bind_source, git_dir, diag);
    errdefer std.Io.Dir.cwd().deleteTree(io, worktree_meta_bind_source) catch {};

    const worktree_meta_target = try metaTarget(allocator, layout, worktree_meta_bind_source, &.{ sandbox_git_root, "worktrees", worktree_id });
    errdefer allocator.free(worktree_meta_target);

    const git_dir_env: ?[]u8 = switch (layout) {
        .remapped => null,
        .in_place => try std.fmt.allocPrint(allocator, "GIT_DIR={s}", .{worktree_meta_target}),
    };
    errdefer if (git_dir_env) |value| allocator.free(value);

    const git_work_tree_env: ?[]u8 = switch (layout) {
        .remapped => null,
        .in_place => try std.fmt.allocPrint(allocator, "GIT_WORK_TREE={s}", .{sandbox_root}),
    };
    errdefer if (git_work_tree_env) |value| allocator.free(value);

    // Every target below is a name under `worktree_meta_target` on both
    // layouts. The matching `_source` strings stay the project's own paths,
    // which is how a caller reads the untouched original after the session.
    const worktree_index_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "index" });
    errdefer allocator.free(worktree_index_source);
    const worktree_index_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "index" });
    errdefer allocator.free(worktree_index_target);

    const worktree_head_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "HEAD" });
    errdefer allocator.free(worktree_head_source);
    const worktree_head_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "HEAD" });
    errdefer allocator.free(worktree_head_target);

    const worktree_logs_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "logs" });
    errdefer allocator.free(worktree_logs_source);
    const worktree_logs_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "logs" });
    errdefer allocator.free(worktree_logs_target);

    const worktree_commondir_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "commondir" });
    errdefer allocator.free(worktree_commondir_source);
    const worktree_commondir_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "commondir" });
    errdefer allocator.free(worktree_commondir_target);

    const worktree_gitdir_file_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "gitdir" });
    errdefer allocator.free(worktree_gitdir_file_source);
    const worktree_gitdir_file_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "gitdir" });
    errdefer allocator.free(worktree_gitdir_file_target);

    // config.worktree exists on disk only once the project turned on
    // extensions.worktreeConfig and something set a value with --worktree.
    // This read decides which source `mounts` binds, never whether it binds
    // one at all.
    const config_worktree_source_candidate = try std.fs.path.join(allocator, &.{ worktree_meta_source, "config.worktree" });
    const has_config_worktree = existsOnDisk(io, config_worktree_source_candidate) catch |err| {
        allocator.free(config_worktree_source_candidate);
        diagnostic.noteErr(diag, .config_worktree_check, err);
        return error.Unexpected;
    };

    const worktree_config_worktree_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "config.worktree" });
    errdefer allocator.free(worktree_config_worktree_target);

    var worktree_config_worktree_source: []u8 = undefined;
    var worktree_config_worktree_is_scratch: bool = undefined;
    // `.in_place` needs no stand-in and must not write one. Nothing is
    // mounted there: the entry becomes a rule on the path itself, which the
    // kernel checks when git creates the file.
    if (has_config_worktree or layout == .in_place) {
        worktree_config_worktree_source = config_worktree_source_candidate;
        worktree_config_worktree_is_scratch = false;
    } else {
        allocator.free(config_worktree_source_candidate);
        const scratch_name = try std.fmt.allocPrint(allocator, "{s}.config-worktree", .{session_id});
        defer allocator.free(scratch_name);
        const scratch_path = try std.fs.path.join(allocator, &.{ scratch_dir, scratch_name });
        errdefer allocator.free(scratch_path);
        try writeEmptyScratchFile(io, scratch_path, diag);
        worktree_config_worktree_source = scratch_path;
        worktree_config_worktree_is_scratch = true;
    }
    errdefer if (worktree_config_worktree_is_scratch) {
        deleteFileAbsolute(io, worktree_config_worktree_source, diag) catch {};
        allocator.free(worktree_config_worktree_source);
    } else {
        allocator.free(worktree_config_worktree_source);
    };

    const pointer_name = try std.fmt.allocPrint(allocator, "{s}.gitdir", .{session_id});
    defer allocator.free(pointer_name);
    const pointer_path = try std.fs.path.join(allocator, &.{ scratch_dir, pointer_name });
    errdefer allocator.free(pointer_path);

    try writePointerFile(allocator, io, pointer_path, worktree_meta_target, diag);

    return .{
        .path = worktree_path,
        .project_root = project_root_owned,
        .base_commit = base_commit,
        .git_dir = git_dir,
        .worktree_id = worktree_id,
        .layout = layout,
        .sandbox_root = sandbox_root,
        .sandbox_git_root = sandbox_git_root,
        .object_store_source = object_store_source,
        .object_store_target = object_store_target,
        .git_object_directory_env = git_object_directory_env,
        .git_alternate_object_directories_env = git_alternate_object_directories_env,
        .git_dir_env = git_dir_env,
        .git_work_tree_env = git_work_tree_env,
        .worktree_meta_source = worktree_meta_source,
        .worktree_meta_target = worktree_meta_target,
        .worktree_meta_bind_source = worktree_meta_bind_source,
        .worktree_meta_is_copy = worktree_meta_is_copy,
        .worktree_index_source = worktree_index_source,
        .worktree_index_target = worktree_index_target,
        .worktree_head_source = worktree_head_source,
        .worktree_head_target = worktree_head_target,
        .worktree_logs_source = worktree_logs_source,
        .worktree_logs_target = worktree_logs_target,
        .worktree_commondir_source = worktree_commondir_source,
        .worktree_commondir_target = worktree_commondir_target,
        .worktree_gitdir_file_source = worktree_gitdir_file_source,
        .worktree_gitdir_file_target = worktree_gitdir_file_target,
        .worktree_config_worktree_source = worktree_config_worktree_source,
        .worktree_config_worktree_target = worktree_config_worktree_target,
        .worktree_config_worktree_is_scratch = worktree_config_worktree_is_scratch,
        .pointer_path = pointer_path,
    };
}

/// Rebuild the `Worktree` value for a checkout already on disk at
/// `<scratch_dir>/<session_id>`, so a second process can take over. It runs no
/// git command at all.
///
/// A worktree registration names two paths and no process. `<worktree>/.git` is
/// the one line `gitdir:` file, and that directory's own `gitdir` points back
/// at it. There is no pid, no lock file and no held descriptor.
///
/// So there is no `cleanupFailedAdd`: the checkout is not this call's to
/// unmake, and the scratch object store can already hold the objects of every
/// commit that session made. And `base_commit` comes from the caller, never
/// read back from HEAD: a session that already committed has a HEAD that is not
/// its base, so reading it would make `headMoved` answer false and the commit
/// would never reach the user.
pub fn adopt(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    scratch_dir: []const u8,
    session_id: []const u8,
    base_commit: []const u8,
    diag: ?*?Diagnostic,
) Error!Worktree {
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
) Error!Worktree {
    _ = env;

    try validateSessionId(session_id);

    const worktree_path = try std.fs.path.join(allocator, &.{ scratch_dir, session_id });
    errdefer allocator.free(worktree_path);

    const checkout_found = directoryOnDisk(io, worktree_path) catch |err| {
        diagnostic.noteErr(diag, .directory_open, err);
        return error.Unexpected;
    };
    if (!checkout_found) return error.NoWorktreeToAdopt;

    const dotgit_path = try std.fs.path.join(allocator, &.{ worktree_path, ".git" });
    defer allocator.free(dotgit_path);
    const dotgit_kind = classify(io, dotgit_path) catch |err| {
        diagnostic.noteErr(diag, .worktree_git_file_read, err);
        return error.Unexpected;
    };
    const found_dotgit_kind = dotgit_kind orelse return error.NoWorktreeToAdopt;
    if (found_dotgit_kind != .file) return error.NotALinkedWorktree;

    const worktree_id = try readWorktreeId(allocator, io, dotgit_path, diag);
    errdefer allocator.free(worktree_id);

    // The caller's own string, copied. Nothing here reads HEAD.
    const base_commit_owned = try allocator.dupe(u8, base_commit);
    errdefer allocator.free(base_commit_owned);

    const project_root_owned = try allocator.dupe(u8, project_root);
    errdefer allocator.free(project_root_owned);

    const git_dir = try std.fs.path.join(allocator, &.{ project_root_owned, ".git" });
    errdefer allocator.free(git_dir);

    const worktree_meta_source = try std.fs.path.join(allocator, &.{ git_dir, "worktrees", worktree_id });
    errdefer allocator.free(worktree_meta_source);

    const registration_found = directoryOnDisk(io, worktree_meta_source) catch |err| {
        diagnostic.noteErr(diag, .project_entry_check, err);
        return error.Unexpected;
    };
    if (!registration_found) return error.WorktreeRegistrationGone;

    const sandbox_root = try targetPath(allocator, layout, worktree_path, &.{project_root_owned});
    errdefer allocator.free(sandbox_root);

    const sandbox_git_root = try targetPath(allocator, layout, git_dir, &.{ sandbox_git_root_prefix, session_id });
    errdefer allocator.free(sandbox_git_root);

    const object_store_name = try std.fmt.allocPrint(allocator, "{s}.objects", .{session_id});
    defer allocator.free(object_store_name);
    const object_store_source = try std.fs.path.join(allocator, &.{ scratch_dir, object_store_name });
    errdefer allocator.free(object_store_source);
    std.Io.Dir.cwd().createDirPath(io, object_store_source) catch |err| {
        diagnostic.noteErr(diag, .scratch_object_store_create, err);
        return error.Unexpected;
    };

    const object_store_target = try targetPath(allocator, layout, object_store_source, &.{ object_store_prefix, session_id });
    errdefer allocator.free(object_store_target);

    const git_object_directory_env = try std.fmt.allocPrint(
        allocator,
        "GIT_OBJECT_DIRECTORY={s}",
        .{object_store_target},
    );
    errdefer allocator.free(git_object_directory_env);

    const real_objects_target = try std.fs.path.join(allocator, &.{ sandbox_git_root, "objects" });
    defer allocator.free(real_objects_target);
    const git_alternate_object_directories_env = try std.fmt.allocPrint(
        allocator,
        "GIT_ALTERNATE_OBJECT_DIRECTORIES={s}",
        .{real_objects_target},
    );
    errdefer allocator.free(git_alternate_object_directories_env);

    const worktree_meta_bind_source = try metaBindSource(allocator, scratch_dir, session_id);
    errdefer allocator.free(worktree_meta_bind_source);
    const worktree_meta_is_copy = true;
    const copy_found = directoryOnDisk(io, worktree_meta_bind_source) catch |err| {
        diagnostic.noteErr(diag, .worktree_meta_copy, err);
        return error.Unexpected;
    };
    if (!copy_found) {
        try copyMetaDirectory(allocator, io, worktree_meta_source, worktree_meta_bind_source, git_dir, diag);
    }

    const worktree_meta_target = try metaTarget(allocator, layout, worktree_meta_bind_source, &.{ sandbox_git_root, "worktrees", worktree_id });
    errdefer allocator.free(worktree_meta_target);

    const git_dir_env: ?[]u8 = switch (layout) {
        .remapped => null,
        .in_place => try std.fmt.allocPrint(allocator, "GIT_DIR={s}", .{worktree_meta_target}),
    };
    errdefer if (git_dir_env) |value| allocator.free(value);

    const git_work_tree_env: ?[]u8 = switch (layout) {
        .remapped => null,
        .in_place => try std.fmt.allocPrint(allocator, "GIT_WORK_TREE={s}", .{sandbox_root}),
    };
    errdefer if (git_work_tree_env) |value| allocator.free(value);

    const worktree_index_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "index" });
    errdefer allocator.free(worktree_index_source);
    const worktree_index_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "index" });
    errdefer allocator.free(worktree_index_target);

    const worktree_head_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "HEAD" });
    errdefer allocator.free(worktree_head_source);
    const worktree_head_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "HEAD" });
    errdefer allocator.free(worktree_head_target);

    const worktree_logs_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "logs" });
    errdefer allocator.free(worktree_logs_source);
    const worktree_logs_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "logs" });
    errdefer allocator.free(worktree_logs_target);

    const worktree_commondir_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "commondir" });
    errdefer allocator.free(worktree_commondir_source);
    const worktree_commondir_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "commondir" });
    errdefer allocator.free(worktree_commondir_target);

    const worktree_gitdir_file_source = try std.fs.path.join(allocator, &.{ worktree_meta_source, "gitdir" });
    errdefer allocator.free(worktree_gitdir_file_source);
    const worktree_gitdir_file_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "gitdir" });
    errdefer allocator.free(worktree_gitdir_file_target);

    const config_worktree_source_candidate = try std.fs.path.join(allocator, &.{ worktree_meta_source, "config.worktree" });
    const has_config_worktree = existsOnDisk(io, config_worktree_source_candidate) catch |err| {
        allocator.free(config_worktree_source_candidate);
        diagnostic.noteErr(diag, .config_worktree_check, err);
        return error.Unexpected;
    };

    const worktree_config_worktree_target = try std.fs.path.join(allocator, &.{ worktree_meta_target, "config.worktree" });
    errdefer allocator.free(worktree_config_worktree_target);

    var worktree_config_worktree_source: []u8 = undefined;
    var worktree_config_worktree_is_scratch: bool = undefined;
    // `.in_place` needs no stand-in and must not write one. See the same
    // decision in `create`.
    if (has_config_worktree or layout == .in_place) {
        worktree_config_worktree_source = config_worktree_source_candidate;
        worktree_config_worktree_is_scratch = false;
    } else {
        allocator.free(config_worktree_source_candidate);
        const scratch_name = try std.fmt.allocPrint(allocator, "{s}.config-worktree", .{session_id});
        defer allocator.free(scratch_name);
        const scratch_path = try std.fs.path.join(allocator, &.{ scratch_dir, scratch_name });
        errdefer allocator.free(scratch_path);
        try writeEmptyScratchFile(io, scratch_path, diag);
        worktree_config_worktree_source = scratch_path;
        worktree_config_worktree_is_scratch = true;
    }
    errdefer allocator.free(worktree_config_worktree_source);

    const pointer_name = try std.fmt.allocPrint(allocator, "{s}.gitdir", .{session_id});
    defer allocator.free(pointer_name);
    const pointer_path = try std.fs.path.join(allocator, &.{ scratch_dir, pointer_name });
    errdefer allocator.free(pointer_path);

    try writePointerFile(allocator, io, pointer_path, worktree_meta_target, diag);

    return .{
        .path = worktree_path,
        .project_root = project_root_owned,
        .base_commit = base_commit_owned,
        .git_dir = git_dir,
        .worktree_id = worktree_id,
        .layout = layout,
        .sandbox_root = sandbox_root,
        .sandbox_git_root = sandbox_git_root,
        .object_store_source = object_store_source,
        .object_store_target = object_store_target,
        .git_object_directory_env = git_object_directory_env,
        .git_alternate_object_directories_env = git_alternate_object_directories_env,
        .git_dir_env = git_dir_env,
        .git_work_tree_env = git_work_tree_env,
        .worktree_meta_source = worktree_meta_source,
        .worktree_meta_target = worktree_meta_target,
        .worktree_meta_bind_source = worktree_meta_bind_source,
        .worktree_meta_is_copy = worktree_meta_is_copy,
        .worktree_index_source = worktree_index_source,
        .worktree_index_target = worktree_index_target,
        .worktree_head_source = worktree_head_source,
        .worktree_head_target = worktree_head_target,
        .worktree_logs_source = worktree_logs_source,
        .worktree_logs_target = worktree_logs_target,
        .worktree_commondir_source = worktree_commondir_source,
        .worktree_commondir_target = worktree_commondir_target,
        .worktree_gitdir_file_source = worktree_gitdir_file_source,
        .worktree_gitdir_file_target = worktree_gitdir_file_target,
        .worktree_config_worktree_source = worktree_config_worktree_source,
        .worktree_config_worktree_target = worktree_config_worktree_target,
        .worktree_config_worktree_is_scratch = worktree_config_worktree_is_scratch,
        .pointer_path = pointer_path,
    };
}

fn readHeadWith(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    worktree_path: []const u8,
    diag: ?*?Diagnostic,
) Error![]u8 {
    var output = try git.run(allocator, io, env, worktree_path, &.{ "rev-parse", "HEAD" }, diag);
    defer output.deinit(allocator);
    switch (output.term) {
        .exited => |code| if (code != 0) return error.GitFailed,
        else => return error.GitFailed,
    }
    return allocator.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

fn validateSessionId(session_id: []const u8) Error!void {
    if (session_id.len == 0) return error.InvalidSessionId;
    if (std.mem.eql(u8, session_id, ".")) return error.InvalidSessionId;
    if (std.mem.eql(u8, session_id, "..")) return error.InvalidSessionId;
    if (std.mem.indexOfScalar(u8, session_id, '/') != null) return error.InvalidSessionId;
}

fn cleanupFailedAdd(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    worktree_path: []const u8,
) void {
    var output = git.run(allocator, io, env, project_root, &.{
        "worktree", "remove", "--force", worktree_path,
    }, null) catch return;
    output.deinit(allocator);
}

fn readWorktreeId(
    allocator: std.mem.Allocator,
    io: std.Io,
    dotgit_path: []const u8,
    diag: ?*?Diagnostic,
) Error![]u8 {
    const contents = std.Io.Dir.cwd().readFileAlloc(io, dotgit_path, allocator, .limited(4096)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => |e| {
            diagnostic.noteErr(diag, .worktree_git_file_read, e);
            return error.Unexpected;
        },
    };
    defer allocator.free(contents);

    const prefix = "gitdir: ";
    if (!std.mem.startsWith(u8, contents, prefix)) return error.NotALinkedWorktree;
    const gitdir_value = std.mem.trimEnd(u8, contents[prefix.len..], "\n");
    if (gitdir_value.len == 0) return error.NotALinkedWorktree;

    return allocator.dupe(u8, std.fs.path.basename(gitdir_value));
}

fn writePointerFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    pointer_path: []const u8,
    worktree_meta_target: []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    const contents = try std.fmt.allocPrint(allocator, "gitdir: {s}\n", .{worktree_meta_target});
    defer allocator.free(contents);

    var file = std.Io.Dir.createFileAbsolute(io, pointer_path, .{}) catch |err| {
        diagnostic.noteErr(diag, .git_pointer_file_create, err);
        return error.Unexpected;
    };
    defer file.close(io);

    file.writeStreamingAll(io, contents) catch |err| {
        diagnostic.noteErr(diag, .git_pointer_file_write, err);
        return error.Unexpected;
    };
}

fn metaBindSource(
    allocator: std.mem.Allocator,
    scratch_dir: []const u8,
    session_id: []const u8,
) std.mem.Allocator.Error![]u8 {
    const name = try std.fmt.allocPrint(allocator, "{s}.meta", .{session_id});
    defer allocator.free(name);
    return std.fs.path.join(allocator, &.{ scratch_dir, name });
}

/// Copy `source` to `destination`, then rewrite `destination`'s own
/// `commondir`. The original holds `../..`, which is correct only against the
/// path the copy is mounted at, so the copy gets the absolute path of the
/// project's `.git` and reads correctly from wherever it sits.
fn copyMetaDirectory(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    destination: []const u8,
    git_dir: []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    copyTree(allocator, io, source, destination) catch |err| {
        diagnostic.noteErr(diag, .worktree_meta_copy, err);
        return error.Unexpected;
    };

    const commondir_path = try std.fs.path.join(allocator, &.{ destination, "commondir" });
    defer allocator.free(commondir_path);
    const contents = try std.fmt.allocPrint(allocator, "{s}\n", .{git_dir});
    defer allocator.free(contents);

    var file = std.Io.Dir.createFileAbsolute(io, commondir_path, .{}) catch |err| {
        diagnostic.noteErr(diag, .worktree_meta_commondir_write, err);
        return error.Unexpected;
    };
    defer file.close(io);
    file.writeStreamingAll(io, contents) catch |err| {
        diagnostic.noteErr(diag, .worktree_meta_commondir_write, err);
        return error.Unexpected;
    };
}

fn copyTree(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
    destination: []const u8,
) !void {
    try std.Io.Dir.cwd().createDirPath(io, destination);

    var source_dir = try std.Io.Dir.openDirAbsolute(io, source, .{ .iterate = true });
    defer source_dir.close(io);
    var destination_dir = try std.Io.Dir.openDirAbsolute(io, destination, .{});
    defer destination_dir.close(io);

    var walker = try source_dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        switch (entry.kind) {
            .directory => try destination_dir.createDirPath(io, entry.path),
            .file => try entry.dir.copyFile(entry.basename, destination_dir, entry.path, io, .{
                .make_path = true,
            }),
            else => {},
        }
    }
}

fn writeEmptyScratchFile(io: std.Io, path: []const u8, diag: ?*?Diagnostic) Error!void {
    var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch |err| {
        diagnostic.noteErr(diag, .empty_scratch_file_create, err);
        return error.Unexpected;
    };
    file.close(io);
}

fn deleteFileAbsolute(io: std.Io, path: []const u8, diag: ?*?Diagnostic) Error!void {
    std.Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
        error.Canceled => return error.Unexpected,
        else => {
            diagnostic.noteErr(diag, .scratch_file_delete, err);
            return error.Unexpected;
        },
    };
}

fn existsOnDisk(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!bool {
    _ = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    return true;
}

fn directoryOnDisk(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!bool {
    const entry_stat = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    return entry_stat.kind == .directory;
}

/// What `importPath` found at `absolute_path`, without following a link to
/// whatever it names.
fn classify(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!?std.Io.File.Kind {
    const entry_stat = std.Io.Dir.cwd().statFile(io, absolute_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return null,
        else => |e| return e,
    };
    return entry_stat.kind;
}

/// Reject a `rel_path` that is absolute or holds a `..` component, because it
/// is joined onto both `project_root` and the worktree's own path.
fn validateRelativePath(rel_path: []const u8) Error!void {
    if (rel_path.len == 0) return error.PathEscapesProject;
    if (std.fs.path.isAbsolute(rel_path)) return error.PathEscapesProject;

    var components = std.mem.tokenizeScalar(u8, rel_path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return error.PathEscapesProject;
    }
}

// Every test below builds its own project inside a fresh std.testing.tmpDir.

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

fn makeDir(path: [:0]const u8) !void {
    std.Io.Dir.createDirAbsolute(std.testing.io, path, .default_dir) catch return error.MkdirFailed;
}

const TestProject = struct {
    allocator: std.mem.Allocator,
    root_path: [:0]const u8,
    scratch_path: [:0]const u8,
    env: std.process.Environ.Map,
    head_sha: []u8,

    fn init(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) !TestProject {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_path = try absoluteDirPath(&buffer, tmp.dir);

        var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const root_path = try std.fmt.bufPrintZ(&root_buffer, "{s}/project", .{tmp_path});
        try makeDir(root_path);

        var scratch_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const scratch_path = try std.fmt.bufPrintZ(&scratch_buffer, "{s}/scratch", .{tmp_path});
        try makeDir(scratch_path);

        var env = try testEnviron(allocator, tmp_path);
        errdefer env.deinit();

        var init_output = try git.run(allocator, std.testing.io, &env, root_path, &.{"init"}, null);
        defer init_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, init_output.term);

        var config_name = try git.run(allocator, std.testing.io, &env, root_path, &.{ "config", "user.email", "test@example.com" }, null);
        defer config_name.deinit(allocator);
        var config_email = try git.run(allocator, std.testing.io, &env, root_path, &.{ "config", "user.name", "Test" }, null);
        defer config_email.deinit(allocator);

        var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{root_path});
        var tracked_file = try std.Io.Dir.createFileAbsolute(std.testing.io, tracked_path, .{});
        try tracked_file.writeStreamingAll(std.testing.io, "hello\n");
        tracked_file.close(std.testing.io);

        var add_output = try git.run(allocator, std.testing.io, &env, root_path, &.{ "add", "tracked.txt" }, null);
        defer add_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, add_output.term);

        var commit_output = try git.run(allocator, std.testing.io, &env, root_path, &.{ "commit", "-m", "first commit" }, null);
        defer commit_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_output.term);

        var head_output = try git.run(allocator, std.testing.io, &env, root_path, &.{ "rev-parse", "HEAD" }, null);
        defer head_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, head_output.term);
        const head_sha = try allocator.dupe(u8, std.mem.trimEnd(u8, head_output.stdout, "\n"));

        return .{
            .allocator = allocator,
            .root_path = try allocator.dupeZ(u8, root_path),
            .scratch_path = try allocator.dupeZ(u8, scratch_path),
            .env = env,
            .head_sha = head_sha,
        };
    }

    fn deinit(self: *TestProject) void {
        self.allocator.free(self.root_path);
        self.allocator.free(self.scratch_path);
        self.allocator.free(self.head_sha);
        self.env.deinit();
    }
};

/// Find the entry in `list` that actually governs `path` once every entry has
/// been applied in order, which is the last one whose target covers it.
fn mostSpecificMount(list: []const Mount, path: []const u8) ?*const Mount.Bind {
    var found: ?*const Mount.Bind = null;
    for (list) |*mount| {
        switch (mount.*) {
            .bind => |*b| if (isMountTargetPrefix(b.target, path)) {
                found = b;
            },
            .overlay, .proc, .deny => {},
        }
    }
    return found;
}

fn isMountTargetPrefix(target: []const u8, path: []const u8) bool {
    if (target.len > path.len) return false;
    if (!std.mem.eql(u8, target, path[0..target.len])) return false;
    return target.len == path.len or path[target.len] == '/';
}

test "a worktree starts at the head of the project" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var head_output = try git.run(allocator, std.testing.io, &project.env, worktree.path, &.{ "rev-parse", "HEAD" }, null);
    defer head_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, head_output.term);
    try std.testing.expectEqualStrings(project.head_sha, std.mem.trimEnd(u8, head_output.stdout, "\n"));
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "the mount list gives the worktree read write and the object store read only" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const worktree_mount = mostSpecificMount(list, worktree.project_root) orelse return error.NoMountCoversTheWorktree;
    try std.testing.expectEqual(false, worktree_mount.read_only);
    try std.testing.expectEqualStrings(worktree.path, worktree_mount.source);

    const objects_path = try std.fs.path.join(allocator, &.{ worktree.sandbox_git_root, "objects" });
    defer allocator.free(objects_path);
    const objects_mount = mostSpecificMount(list, objects_path) orelse return error.NoMountCoversTheObjectStore;
    try std.testing.expectEqual(true, objects_mount.read_only);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "the mount list never gives .git/hooks write access" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const hooks_path = try std.fs.path.join(allocator, &.{ worktree.sandbox_git_root, "hooks" });
    defer allocator.free(hooks_path);
    const hooks_mount = mostSpecificMount(list, hooks_path) orelse return error.NoMountCoversHooks;
    try std.testing.expectEqual(true, hooks_mount.read_only);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "the index of the worktree is writable, so git status works inside the sandbox" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const index_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "index" });
    defer allocator.free(index_path);
    const index_mount = mostSpecificMount(list, index_path) orelse return error.NoMountCoversTheIndex;
    try std.testing.expectEqual(false, index_mount.read_only);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "HEAD and the logs of the worktree are writable, matching the index" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const head_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "HEAD" });
    defer allocator.free(head_path);
    const head_mount = mostSpecificMount(list, head_path) orelse return error.NoMountCoversHead;
    try std.testing.expectEqual(false, head_mount.read_only);

    const logs_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "logs" });
    defer allocator.free(logs_path);
    const logs_mount = mostSpecificMount(list, logs_path) orelse return error.NoMountCoversLogs;
    try std.testing.expectEqual(false, logs_mount.read_only);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "finding 4: the metadata directory the sandbox writes is the session's own copy" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expect(worktree.worktree_meta_is_copy);
    try std.testing.expect(!std.mem.eql(u8, worktree.worktree_meta_bind_source, worktree.worktree_meta_source));
    try std.testing.expect(std.mem.startsWith(u8, worktree.worktree_meta_bind_source, project.scratch_path));

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    for ([_][]const u8{ "index", "HEAD", "logs", "logs/HEAD", "refs", "probe-from-session" }) |name| {
        const path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, name });
        defer allocator.free(path);
        const mount = mostSpecificMount(list, path) orelse return error.NoMountCoversTheFile;
        try std.testing.expectEqual(false, mount.read_only);
        try std.testing.expect(std.mem.startsWith(u8, mount.source, worktree.worktree_meta_bind_source));
    }
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "finding 4: the copy holds what git worktree add wrote, and a commondir a host git can follow" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    for ([_][]const u8{ "HEAD", "index", "gitdir", "logs/HEAD" }) |name| {
        const in_copy = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_bind_source, name });
        defer allocator.free(in_copy);
        try std.testing.expect(try existsOnDisk(std.testing.io, in_copy));
    }

    const commondir_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_bind_source, "commondir" });
    defer allocator.free(commondir_path);
    const commondir = try readFile(allocator, commondir_path);
    defer allocator.free(commondir);
    try std.testing.expectEqualStrings(worktree.git_dir, std.mem.trimEnd(u8, commondir, "\n"));

    const project_commondir = try readFile(allocator, worktree.worktree_commondir_source);
    defer allocator.free(project_commondir);
    try std.testing.expectEqualStrings("../..", std.mem.trimEnd(u8, project_commondir, "\n"));
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "finding 4: removing a worktree deletes the copy, and keeping one leaves it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    {
        var kept = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        const copy_path = try allocator.dupe(u8, kept.worktree_meta_bind_source);
        defer allocator.free(copy_path);
        kept.keep(allocator);
        try std.testing.expect(try directoryOnDisk(std.testing.io, copy_path));
    }

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess2", .remapped, null);
    const copy_path = try allocator.dupe(u8, worktree.worktree_meta_bind_source);
    defer allocator.free(copy_path);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
    try std.testing.expect(!try directoryOnDisk(std.testing.io, copy_path));
}

test "finding 4: the in place layout gets the copy too, and reaches it by its own path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .in_place, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expect(worktree.worktree_meta_is_copy);
    try std.testing.expect(!std.mem.eql(u8, worktree.worktree_meta_source, worktree.worktree_meta_bind_source));
    try std.testing.expectEqualStrings(worktree.worktree_meta_bind_source, worktree.worktree_meta_target);
    try std.testing.expect(std.mem.startsWith(u8, worktree.worktree_meta_target, project.scratch_path));

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    for (list) |entry| {
        try std.testing.expectEqualStrings(entry.bind.source, entry.bind.target);
    }

    for (list) |entry| {
        if (entry.bind.read_only) continue;
        try std.testing.expect(!std.mem.startsWith(u8, entry.bind.target, worktree.git_dir));
    }

    const env = try worktree.gitEnv(allocator);
    defer allocator.free(env);
    var git_dir_seen = false;
    var work_tree_seen = false;
    for (env) |entry| {
        if (std.mem.startsWith(u8, entry, "GIT_DIR=")) {
            try std.testing.expectEqualStrings(worktree.worktree_meta_bind_source, entry["GIT_DIR=".len..]);
            git_dir_seen = true;
        }
        if (std.mem.startsWith(u8, entry, "GIT_WORK_TREE=")) {
            try std.testing.expectEqualStrings(worktree.sandbox_root, entry["GIT_WORK_TREE=".len..]);
            work_tree_seen = true;
        }
    }
    try std.testing.expect(git_dir_seen);
    try std.testing.expect(work_tree_seen);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "the remapped layout names no GIT_DIR, because the checkout's own .git file already does" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expectEqual(@as(?[]u8, null), worktree.git_dir_env);
    try std.testing.expectEqual(@as(?[]u8, null), worktree.git_work_tree_env);

    const env = try worktree.gitEnv(allocator);
    defer allocator.free(env);
    try std.testing.expectEqual(@as(usize, 2), env.len);
    for (env) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry, "GIT_DIR="));
        try std.testing.expect(!std.mem.startsWith(u8, entry, "GIT_WORK_TREE="));
    }
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "the mount list keeps commondir and gitdir of the worktree's own metadata read only" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    for ([_][]const u8{ "commondir", "gitdir" }) |name| {
        const path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, name });
        defer allocator.free(path);
        const mount = mostSpecificMount(list, path) orelse return error.NoMountCoversTheFile;
        try std.testing.expectEqual(true, mount.read_only);
    }
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "config.worktree stays read only when a project has one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "extensions.worktreeConfig", "true",
    }, null);
    defer config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, config_output.term);

    var worktree_config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "--worktree", "chock.probe", "1",
    }, null);
    defer worktree_config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, worktree_config_output.term);

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expect(!worktree.worktree_config_worktree_is_scratch);

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "config.worktree" });
    defer allocator.free(path);
    const mount = mostSpecificMount(list, path) orelse return error.NoMountCoversTheFile;
    try std.testing.expectEqual(true, mount.read_only);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "config.worktree is absent, so create writes an empty scratch file and mounts it read only" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expect(worktree.worktree_config_worktree_is_scratch);
    try std.testing.expect(!std.mem.eql(u8, worktree.worktree_config_worktree_source, worktree.worktree_meta_source));

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const config_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "config.worktree" });
    defer allocator.free(config_path);
    const config_mount = mostSpecificMount(list, config_path) orelse return error.NoMountCoversTheFile;
    try std.testing.expectEqual(true, config_mount.read_only);
    try std.testing.expectEqualStrings(worktree.worktree_config_worktree_source, config_mount.source);

    const contents = try readFile(allocator, worktree.worktree_config_worktree_source);
    defer allocator.free(contents);
    try std.testing.expectEqual(@as(usize, 0), contents.len);

    const shared_config_path = try std.fs.path.join(allocator, &.{ worktree.sandbox_git_root, "config" });
    defer allocator.free(shared_config_path);
    const shared_config_mount = mostSpecificMount(list, shared_config_path) orelse return error.NoMountCoversTheSharedConfig;
    try std.testing.expectEqual(true, shared_config_mount.read_only);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "removing a worktree that never had a real config.worktree deletes the empty scratch file it wrote" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    try std.testing.expect(worktree.worktree_config_worktree_is_scratch);
    const scratch_path = try allocator.dupe(u8, worktree.worktree_config_worktree_source);
    defer allocator.free(scratch_path);

    try worktree.remove(allocator, std.testing.io, &project.env, null);

    const stat_result = std.Io.Dir.cwd().statFile(std.testing.io, scratch_path, .{});
    try std.testing.expectError(error.FileNotFound, stat_result);
}

test "mostSpecificMount takes the last matching entry, not the longest" {
    const list = [_]Mount{
        .{ .bind = .{ .source = "a", .target = sandbox_git_root_prefix ++ "/sess1", .read_only = true } },
        .{ .bind = .{ .source = "b", .target = sandbox_git_root_prefix, .read_only = false } },
    };
    const found = mostSpecificMount(&list, sandbox_git_root_prefix ++ "/sess1/hooks") orelse
        return error.NoMountCoversHooks;
    try std.testing.expectEqual(false, found.read_only);
}

test "a wide mount at /run, placed last, shadows every path Chock puts under it" {
    // The trap this project has already paid for once: a wide entry applied
    // after a narrow one shadows it, whatever the two prefixes are.
    const list = [_]Mount{
        .{ .bind = .{ .source = "the-real-git-dir", .target = sandbox_git_root_prefix ++ "/sess1", .read_only = true } },
        .{ .bind = .{ .source = "the-object-store", .target = object_store_prefix ++ "/sess1", .read_only = false } },
        .{ .bind = .{ .source = "somebody-elses-run", .target = "/run", .read_only = false } },
    };

    for ([_][]const u8{
        sandbox_git_root_prefix ++ "/sess1/hooks",
        object_store_prefix ++ "/sess1",
        chock_runtime_prefix ++ "/tool-bin/cat",
    }) |path| {
        const found = mostSpecificMount(&list, path) orelse return error.NoMountCoversThePath;
        try std.testing.expectEqualStrings("somebody-elses-run", found.source);
    }

    const safe_order = [_]Mount{
        .{ .bind = .{ .source = "somebody-elses-run", .target = "/run", .read_only = false } },
        .{ .bind = .{ .source = "the-real-git-dir", .target = sandbox_git_root_prefix ++ "/sess1", .read_only = true } },
    };
    const governs = mostSpecificMount(&safe_order, sandbox_git_root_prefix ++ "/sess1/hooks") orelse
        return error.NoMountCoversHooks;
    try std.testing.expectEqualStrings("the-real-git-dir", governs.source);
}

test "no mount Chock builds is wide enough to shadow its own runtime prefix" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const too_wide = [_][]const u8{ "/", "/run", chock_runtime_prefix };
    for (list) |mount| {
        const target = switch (mount) {
            .bind => |b| b.target,
            .overlay => |o| o.target,
            .proc => |p| p.target,
            .deny => |d| d.target,
        };
        for (too_wide) |wide| {
            try std.testing.expect(!std.mem.eql(u8, target, wide));
        }
    }

    try std.testing.expect(std.mem.startsWith(u8, worktree.sandbox_git_root, chock_runtime_prefix ++ "/"));
    try std.testing.expect(std.mem.startsWith(u8, worktree.object_store_target, chock_runtime_prefix ++ "/"));
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "mostSpecificMount compares whole path components, not raw bytes" {
    // /run/chock/git/sess1 must not match /run/chock/git/sess10: a different
    // session is a different path and not a prefix of this one.
    const list = [_]Mount{
        .{ .bind = .{ .source = "a", .target = sandbox_git_root_prefix ++ "/sess1", .read_only = false } },
    };
    try std.testing.expectEqual(
        @as(?*const Mount.Bind, null),
        mostSpecificMount(&list, sandbox_git_root_prefix ++ "/sess10/hooks"),
    );
}

test "create rejects a session id that would escape the scratch directory" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    try std.testing.expectError(
        error.InvalidSessionId,
        create(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "../escaped", null),
    );
    try std.testing.expectError(
        error.InvalidSessionId,
        create(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "", null),
    );
    try std.testing.expectError(
        error.InvalidSessionId,
        create(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "..", null),
    );
}

test "create undoes git worktree add when a later step fails" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var pointer_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const blocked_pointer_path = try std.fmt.bufPrintZ(&pointer_buffer, "{s}/sess1.gitdir", .{project.scratch_path});
    try makeDir(blocked_pointer_path);

    try std.testing.expectError(
        error.Unexpected,
        create(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", null),
    );

    var list_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "worktree", "list", "--porcelain" }, null);
    defer list_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, list_output.term);
    try std.testing.expect(std.mem.indexOf(u8, list_output.stdout, "sess1") == null);
}

test "remove frees its memory and deletes the pointer file even when git worktree remove fails" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);

    var commondir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const commondir_path = try std.fmt.bufPrintZ(&commondir_buffer, "{s}/commondir", .{worktree.worktree_meta_source});
    var commondir_file = try std.Io.Dir.createFileAbsolute(std.testing.io, commondir_path, .{});
    try commondir_file.writeStreamingAll(std.testing.io, "/nonexistent\n");
    commondir_file.close(std.testing.io);

    const pointer_path = try allocator.dupe(u8, worktree.pointer_path);
    defer allocator.free(pointer_path);

    try std.testing.expectError(error.GitFailed, worktree.remove(allocator, std.testing.io, &project.env, null));

    const stat_result = std.Io.Dir.cwd().statFile(std.testing.io, pointer_path, .{});
    try std.testing.expectError(error.FileNotFound, stat_result);

    var project_scratch_dir = try std.Io.Dir.openDirAbsolute(std.testing.io, project.scratch_path, .{});
    defer project_scratch_dir.close(std.testing.io);
    project_scratch_dir.deleteTree(std.testing.io, "sess1") catch {};
}

test "remove takes the worktree away and leaves the project alone" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    const worktree_path = try allocator.dupe(u8, worktree.path);
    defer allocator.free(worktree_path);

    try worktree.remove(allocator, std.testing.io, &project.env, null);

    const stat_result = std.Io.Dir.cwd().statFile(std.testing.io, worktree_path, .{});
    try std.testing.expectError(error.FileNotFound, stat_result);

    var head_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "rev-parse", "HEAD" }, null);
    defer head_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, head_output.term);
    try std.testing.expectEqualStrings(project.head_sha, std.mem.trimEnd(u8, head_output.stdout, "\n"));
}

fn writeFile(path: [:0]const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, contents);
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(4096));
}

test "a modified file in the project appears in the worktree with the same contents" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try writeFile(tracked_path, "hello, modified\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.modified.items.len);
    try std.testing.expectEqualStrings("tracked.txt", report.modified.items[0]);
    try std.testing.expectEqual(@as(usize, 0), report.added.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.deleted.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.skipped.items.len);

    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked_path = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    const worktree_contents = try readFile(allocator, worktree_tracked_path);
    defer allocator.free(worktree_contents);
    try std.testing.expectEqualStrings("hello, modified\n", worktree_contents);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a file the user has not committed yet appears in the worktree" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/new_work.txt", .{project.root_path});
    try writeFile(new_file_path, "brand new, never committed\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.added.items.len);
    try std.testing.expectEqualStrings("new_work.txt", report.added.items[0]);
    try std.testing.expectEqual(@as(usize, 0), report.modified.items.len);

    var worktree_new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_new_file_path = try std.fmt.bufPrintZ(&worktree_new_file_buffer, "{s}/new_work.txt", .{worktree.path});
    const worktree_contents = try readFile(allocator, worktree_new_file_path);
    defer allocator.free(worktree_contents);
    try std.testing.expectEqualStrings("brand new, never committed\n", worktree_contents);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a deleted file is deleted in the worktree too" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked_path = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    try std.testing.expect(try existsOnDisk(std.testing.io, worktree_tracked_path));

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try std.Io.Dir.deleteFileAbsolute(std.testing.io, tracked_path);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.deleted.items.len);
    try std.testing.expectEqualStrings("tracked.txt", report.deleted.items[0]);
    try std.testing.expectEqual(@as(usize, 0), report.modified.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.added.items.len);

    const stat_result = std.Io.Dir.cwd().statFile(std.testing.io, worktree_tracked_path, .{});
    try std.testing.expectError(error.FileNotFound, stat_result);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "the report names how many files came across, so Chock can tell the user" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var second_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const second_path = try std.fmt.bufPrintZ(&second_buffer, "{s}/second.txt", .{project.root_path});
    try writeFile(second_path, "second\n");
    var second_add = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "add", "second.txt" }, null);
    defer second_add.deinit(allocator);
    var second_commit = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "commit", "-m", "second commit" }, null);
    defer second_commit.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, second_commit.term);

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try writeFile(tracked_path, "modified again\n");

    try std.Io.Dir.deleteFileAbsolute(std.testing.io, second_path);

    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/new_work.txt", .{project.root_path});
    try writeFile(new_file_path, "new work\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.modified.items.len); // tracked.txt
    try std.testing.expectEqual(@as(usize, 1), report.added.items.len); // new_work.txt
    try std.testing.expectEqual(@as(usize, 1), report.deleted.items.len); // second.txt
    try std.testing.expectEqual(@as(usize, 3), report.total());
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "importing nothing from a clean project is not an error" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.modified.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.added.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.deleted.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.total());
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "validateRelativePath rejects a path that escapes the project root" {
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath("../escaped.txt"));
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath("nested/../../escaped.txt"));
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath("/etc/passwd"));
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath(""));
    try validateRelativePath("ordinary/path.txt");
}

fn makeSymlink(target_text: []const u8, link_path: [:0]const u8) !void {
    try std.Io.Dir.cwd().symLink(std.testing.io, target_text, link_path, .{});
}

fn readSymlinkTarget(allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const n = try std.Io.Dir.readLinkAbsolute(std.testing.io, path, &buffer);
    return allocator.dupe(u8, buffer[0..n]);
}

fn treeContainsBytes(allocator: std.mem.Allocator, root_path: []const u8, needle: []const u8) !bool {
    var root_dir = try std.Io.Dir.openDirAbsolute(std.testing.io, root_path, .{ .iterate = true });
    defer root_dir.close(std.testing.io);

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(std.testing.io)) |entry| {
        if (entry.kind != .file) continue; // never read through a link
        const content = root_dir.readFileAlloc(std.testing.io, entry.path, allocator, .limited(1 << 20)) catch continue;
        defer allocator.free(content);
        if (std.mem.indexOf(u8, content, needle) != null) return true;
    }
    return false;
}

test "a symbolic link inside the project is recreated in the worktree, not followed" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var link_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrintZ(&link_path_buffer, "{s}/link_to_tracked", .{project.root_path});
    try makeSymlink("tracked.txt", link_path);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.added.items.len);
    try std.testing.expectEqualStrings("link_to_tracked", report.added.items[0]);
    try std.testing.expectEqual(@as(usize, 0), report.skipped.items.len);

    var worktree_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_link_path = try std.fmt.bufPrintZ(&worktree_link_buffer, "{s}/link_to_tracked", .{worktree.path});
    const kind = try classify(std.testing.io, worktree_link_path);
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, kind.?);

    const target_text = try readSymlinkTarget(allocator, worktree_link_path);
    defer allocator.free(target_text);
    try std.testing.expectEqualStrings("tracked.txt", target_text);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a symbolic link pointing outside the project never lands its target's content in the worktree" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var tmp_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try absoluteDirPath(&tmp_path_buffer, tmp.dir);
    var outside_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outside_path = try std.fmt.bufPrintZ(&outside_buffer, "{s}/outside_secret.txt", .{tmp_path});
    try writeFile(outside_path, "OUTSIDE SECRET");

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var link_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrintZ(&link_path_buffer, "{s}/key", .{project.root_path});
    try makeSymlink(outside_path, link_path);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), report.added.items.len);
    try std.testing.expectEqualStrings("key", report.added.items[0]);

    var worktree_key_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_key_path = try std.fmt.bufPrintZ(&worktree_key_buffer, "{s}/key", .{worktree.path});
    const kind = try classify(std.testing.io, worktree_key_path);
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, kind.?);

    const target_text = try readSymlinkTarget(allocator, worktree_key_path);
    defer allocator.free(target_text);
    try std.testing.expectEqualStrings(outside_path, target_text);

    try std.testing.expect(!try treeContainsBytes(allocator, worktree.path, "OUTSIDE SECRET"));
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a broken symbolic link is recreated, not treated as a deletion" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var link_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrintZ(&link_path_buffer, "{s}/dangling", .{project.root_path});
    try makeSymlink("this/path/does/not/exist.txt", link_path);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.deleted.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.skipped.items.len);
    try std.testing.expectEqual(@as(usize, 1), report.added.items.len);
    try std.testing.expectEqualStrings("dangling", report.added.items[0]);

    var worktree_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_link_path = try std.fmt.bufPrintZ(&worktree_link_buffer, "{s}/dangling", .{worktree.path});
    const kind = try classify(std.testing.io, worktree_link_path);
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, kind.?);

    const target_text = try readSymlinkTarget(allocator, worktree_link_path);
    defer allocator.free(target_text);
    try std.testing.expectEqualStrings("this/path/does/not/exist.txt", target_text);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a symbolic link to a directory is recreated as a link, not followed into the directory" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var dir_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try std.fmt.bufPrintZ(&dir_path_buffer, "{s}/a_directory", .{project.root_path});
    try makeDir(dir_path);
    var inner_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const inner_file_path = try std.fmt.bufPrintZ(&inner_file_buffer, "{s}/inside.txt", .{dir_path});
    try writeFile(inner_file_path, "inside a directory the link points at\n");

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var link_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrintZ(&link_path_buffer, "{s}/link_to_dir", .{project.root_path});
    try makeSymlink("a_directory", link_path);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    var saw_link = false;
    for (report.added.items) |path| {
        if (std.mem.eql(u8, path, "link_to_dir")) saw_link = true;
    }
    try std.testing.expect(saw_link);

    var worktree_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_link_path = try std.fmt.bufPrintZ(&worktree_link_buffer, "{s}/link_to_dir", .{worktree.path});
    const kind = try classify(std.testing.io, worktree_link_path);
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, kind.?);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a dirty submodule is skipped, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var tmp_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try absoluteDirPath(&tmp_path_buffer, tmp.dir);
    var submodule_source_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const submodule_source_path = try std.fmt.bufPrintZ(&submodule_source_buffer, "{s}/submodule_source", .{tmp_path});
    try makeDir(submodule_source_path);
    var sub_init = try git.run(allocator, std.testing.io, &project.env, submodule_source_path, &.{"init"}, null);
    defer sub_init.deinit(allocator);
    var sub_config_name = try git.run(allocator, std.testing.io, &project.env, submodule_source_path, &.{ "config", "user.email", "test@example.com" }, null);
    defer sub_config_name.deinit(allocator);
    var sub_config_email = try git.run(allocator, std.testing.io, &project.env, submodule_source_path, &.{ "config", "user.name", "Test" }, null);
    defer sub_config_email.deinit(allocator);
    var sub_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const sub_file_path = try std.fmt.bufPrintZ(&sub_file_buffer, "{s}/f.txt", .{submodule_source_path});
    try writeFile(sub_file_path, "hello from the submodule\n");
    var sub_add = try git.run(allocator, std.testing.io, &project.env, submodule_source_path, &.{ "add", "f.txt" }, null);
    defer sub_add.deinit(allocator);
    var sub_commit = try git.run(allocator, std.testing.io, &project.env, submodule_source_path, &.{ "commit", "-m", "submodule init" }, null);
    defer sub_commit.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, sub_commit.term);

    // -c protocol.file.allow=always: a local plain path submodule source is
    // refused by default since the 2022 security release.
    var submodule_add = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "-c", "protocol.file.allow=always", "submodule", "add", submodule_source_path, "sub",
    }, null);
    defer submodule_add.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, submodule_add.term);
    var submodule_commit = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "commit", "-m", "add submodule" }, null);
    defer submodule_commit.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, submodule_commit.term);

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var sub_project_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const sub_project_file_path = try std.fmt.bufPrintZ(&sub_project_file_buffer, "{s}/sub/f.txt", .{project.root_path});
    try writeFile(sub_project_file_path, "hello from the submodule, dirtied\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    var saw_sub_skip = false;
    for (report.skipped.items) |skip| {
        if (std.mem.eql(u8, skip.path, "sub")) {
            saw_sub_skip = true;
            try std.testing.expect(std.mem.indexOf(u8, skip.reason, "directory") != null);
        }
    }
    try std.testing.expect(saw_sub_skip);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "an untracked nested repository is skipped, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var nested_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const nested_path = try std.fmt.bufPrintZ(&nested_path_buffer, "{s}/nested", .{project.root_path});
    try makeDir(nested_path);
    var nested_init = try git.run(allocator, std.testing.io, &project.env, nested_path, &.{"init"}, null);
    defer nested_init.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, nested_init.term);
    var nested_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const nested_file_path = try std.fmt.bufPrintZ(&nested_file_buffer, "{s}/f.txt", .{nested_path});
    try writeFile(nested_file_path, "vendored\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    var saw_nested_skip = false;
    for (report.skipped.items) |skip| {
        if (std.mem.startsWith(u8, skip.path, "nested")) saw_nested_skip = true;
    }
    try std.testing.expect(saw_nested_skip);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a plain file replaced by a directory is skipped, not a crash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try std.Io.Dir.deleteFileAbsolute(std.testing.io, tracked_path);
    try makeDir(tracked_path);
    var inner_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const inner_path = try std.fmt.bufPrintZ(&inner_buffer, "{s}/inner.txt", .{tracked_path});
    try writeFile(inner_path, "a file where a directory now is\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    var saw_tracked_skip = false;
    for (report.skipped.items) |skip| {
        if (std.mem.eql(u8, skip.path, "tracked.txt")) saw_tracked_skip = true;
    }
    try std.testing.expect(saw_tracked_skip);

    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked_path = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    const worktree_contents = try readFile(allocator, worktree_tracked_path);
    defer allocator.free(worktree_contents);
    try std.testing.expectEqualStrings("hello\n", worktree_contents);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a file that cannot be read is skipped, and the rest of the import still completes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var unreadable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const unreadable_path = try std.fmt.bufPrintZ(&unreadable_buffer, "{s}/unreadable.txt", .{project.root_path});
    try writeFile(unreadable_path, "you cannot read this\n");
    // fchmodat by path, not open-then-fchmod: opening this file for read is
    // what the test is taking away.
    try std.Io.Dir.cwd().setFilePermissions(std.testing.io, unreadable_path, .fromMode(0o000), .{});
    defer std.Io.Dir.cwd().setFilePermissions(std.testing.io, unreadable_path, .fromMode(0o644), .{}) catch {};

    var readable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const readable_path = try std.fmt.bufPrintZ(&readable_buffer, "{s}/readable.txt", .{project.root_path});
    try writeFile(readable_path, "you can read this\n");

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    var saw_unreadable_skip = false;
    for (report.skipped.items) |skip| {
        if (std.mem.eql(u8, skip.path, "unreadable.txt")) saw_unreadable_skip = true;
    }
    try std.testing.expect(saw_unreadable_skip);

    var saw_readable_added = false;
    for (report.added.items) |path| {
        if (std.mem.eql(u8, path, "readable.txt")) saw_readable_added = true;
    }
    try std.testing.expect(saw_readable_added);

    var worktree_readable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_readable_path = try std.fmt.bufPrintZ(&worktree_readable_buffer, "{s}/readable.txt", .{worktree.path});
    const worktree_contents = try readFile(allocator, worktree_readable_path);
    defer allocator.free(worktree_contents);
    try std.testing.expectEqualStrings("you can read this\n", worktree_contents);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a path git rm --cached names twice is imported once, not double counted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var second_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const second_path = try std.fmt.bufPrintZ(&second_buffer, "{s}/second.txt", .{project.root_path});
    try writeFile(second_path, "second\n");
    var second_add = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "add", "second.txt" }, null);
    defer second_add.deinit(allocator);
    var second_commit = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "commit", "-m", "second commit" }, null);
    defer second_commit.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, second_commit.term);

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    // git rm --cached leaves the file on disk, untracked, and also leaves a
    // staged deletion, so git status names the one path twice.
    var rm_cached = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "rm", "--cached", "second.txt" }, null);
    defer rm_cached.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, rm_cached.term);

    var status_check = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "status", "--porcelain=v1", "--untracked-files=all",
    }, null);
    defer status_check.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, status_check.stdout, "second.txt"));

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    var occurrences: usize = 0;
    for (report.modified.items) |path| {
        if (std.mem.eql(u8, path, "second.txt")) occurrences += 1;
    }
    for (report.added.items) |path| {
        if (std.mem.eql(u8, path, "second.txt")) occurrences += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), occurrences);

    var worktree_second_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_second_path = try std.fmt.bufPrintZ(&worktree_second_buffer, "{s}/second.txt", .{worktree.path});
    const worktree_contents = try readFile(allocator, worktree_second_path);
    defer allocator.free(worktree_contents);
    try std.testing.expectEqualStrings("second\n", worktree_contents);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

const ProjectSnapshot = struct {
    tree: []u8,
    index_bytes: []u8,
    head: []u8,
    refs: []u8,
    stash: []u8,

    fn take(allocator: std.mem.Allocator, env: *const std.process.Environ.Map, root_path: [:0]const u8) !ProjectSnapshot {
        const tree = try snapshotTree(allocator, root_path);
        errdefer allocator.free(tree);

        var index_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const index_path = try std.fmt.bufPrintZ(&index_path_buffer, "{s}/.git/index", .{root_path});
        const index_bytes = try readFile(allocator, index_path);
        errdefer allocator.free(index_bytes);

        const head = try gitPlainOutput(allocator, env, root_path, &.{ "rev-parse", "HEAD" });
        errdefer allocator.free(head);
        const refs = try gitPlainOutput(allocator, env, root_path, &.{"for-each-ref"});
        errdefer allocator.free(refs);
        const stash = try gitPlainOutput(allocator, env, root_path, &.{ "stash", "list" });
        errdefer allocator.free(stash);

        return .{ .tree = tree, .index_bytes = index_bytes, .head = head, .refs = refs, .stash = stash };
    }

    fn deinit(self: *ProjectSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.tree);
        allocator.free(self.index_bytes);
        allocator.free(self.head);
        allocator.free(self.refs);
        allocator.free(self.stash);
        self.* = undefined;
    }
};

fn gitPlainOutput(
    allocator: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    root_path: []const u8,
    argv: []const []const u8,
) ![]u8 {
    var output = try git.run(allocator, std.testing.io, env, root_path, argv, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    return allocator.dupe(u8, output.stdout);
}

fn snapshotTree(allocator: std.mem.Allocator, root_path: [:0]const u8) ![]u8 {
    var root_dir = try std.Io.Dir.openDirAbsolute(std.testing.io, root_path, .{ .iterate = true });
    defer root_dir.close(std.testing.io);

    const Line = struct { path: []const u8, text: []const u8 };
    var lines: std.ArrayList(Line) = .empty;
    defer {
        for (lines.items) |line| {
            allocator.free(line.path);
            allocator.free(line.text);
        }
        lines.deinit(allocator);
    }

    var walker = try root_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next(std.testing.io)) |entry| {
        if (std.mem.eql(u8, entry.path, ".git") or std.mem.startsWith(u8, entry.path, ".git/")) continue;
        switch (entry.kind) {
            .file => {
                const content = try root_dir.readFileAlloc(std.testing.io, entry.path, allocator, .limited(1 << 20));
                defer allocator.free(content);
                const text = try std.fmt.allocPrint(allocator, "file {s} {d}:{s}\n", .{ entry.path, content.len, content });
                try lines.append(allocator, .{ .path = try allocator.dupe(u8, entry.path), .text = text });
            },
            .sym_link => {
                var buffer: [std.fs.max_path_bytes]u8 = undefined;
                const n = try root_dir.readLink(std.testing.io, entry.path, &buffer);
                const text = try std.fmt.allocPrint(allocator, "link {s} -> {s}\n", .{ entry.path, buffer[0..n] });
                try lines.append(allocator, .{ .path = try allocator.dupe(u8, entry.path), .text = text });
            },
            else => {}, // directories carry no content of their own to snapshot
        }
    }

    std.mem.sort(Line, lines.items, {}, struct {
        fn lessThan(_: void, a: Line, b: Line) bool {
            return std.mem.lessThan(u8, a.path, b.path);
        }
    }.lessThan);

    var blob: std.ArrayList(u8) = .empty;
    errdefer blob.deinit(allocator);
    for (lines.items) |line| try blob.appendSlice(allocator, line.text);
    return blob.toOwnedSlice(allocator);
}

test "the project's own tree, index, HEAD, refs, and stash are untouched by an import" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var tmp_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try absoluteDirPath(&tmp_path_buffer, tmp.dir);
    var outside_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outside_path = try std.fmt.bufPrintZ(&outside_buffer, "{s}/outside_secret.txt", .{tmp_path});
    try writeFile(outside_path, "OUTSIDE SECRET");

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try writeFile(tracked_path, "modified before the snapshot\n");

    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/new_work.txt", .{project.root_path});
    try writeFile(new_file_path, "new work\n");

    var inside_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const inside_link_path = try std.fmt.bufPrintZ(&inside_link_buffer, "{s}/link_inside", .{project.root_path});
    try makeSymlink("tracked.txt", inside_link_path);

    var outside_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const outside_link_path = try std.fmt.bufPrintZ(&outside_link_buffer, "{s}/key", .{project.root_path});
    try makeSymlink(outside_path, outside_link_path);

    var broken_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const broken_link_path = try std.fmt.bufPrintZ(&broken_link_buffer, "{s}/dangling", .{project.root_path});
    try makeSymlink("nowhere.txt", broken_link_path);

    var nested_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const nested_path = try std.fmt.bufPrintZ(&nested_path_buffer, "{s}/nested", .{project.root_path});
    try makeDir(nested_path);
    var nested_init = try git.run(allocator, std.testing.io, &project.env, nested_path, &.{"init"}, null);
    defer nested_init.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, nested_init.term);
    var nested_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const nested_file_path = try std.fmt.bufPrintZ(&nested_file_buffer, "{s}/f.txt", .{nested_path});
    try writeFile(nested_file_path, "vendored\n");

    var before = try ProjectSnapshot.take(allocator, &project.env, project.root_path);
    defer before.deinit(allocator);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expect(report.total() > 0);
    try std.testing.expect(report.skipped.items.len > 0);

    var after = try ProjectSnapshot.take(allocator, &project.env, project.root_path);
    defer after.deinit(allocator);

    try std.testing.expectEqualStrings(before.tree, after.tree);
    try std.testing.expectEqualStrings(before.index_bytes, after.index_bytes);
    try std.testing.expectEqualStrings(before.head, after.head);
    try std.testing.expectEqualStrings(before.refs, after.refs);
    try std.testing.expectEqualStrings(before.stash, after.stash);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "a fresh worktree holds the committed state, and neither a modification nor an untracked file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try writeFile(tracked_path, "hello, modified\n");

    var new_file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const new_file_path = try std.fmt.bufPrintZ(&new_file_buffer, "{s}/new_work.txt", .{project.root_path});
    try writeFile(new_file_path, "brand new, never committed\n");

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    const contents = try readFile(allocator, worktree_tracked);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("hello\n", contents);

    var worktree_new_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_new = try std.fmt.bufPrintZ(&worktree_new_buffer, "{s}/new_work.txt", .{worktree.path});
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, worktree_new, .{}),
    );
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "countUncommitted names the split, and a clean project counts zero" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    const clean = try countUncommitted(allocator, std.testing.io, &project.env, project.root_path, null);
    try std.testing.expectEqual(@as(usize, 0), clean.modified);
    try std.testing.expectEqual(@as(usize, 0), clean.untracked);
    try std.testing.expect(!clean.any());

    var tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tracked_path = try std.fmt.bufPrintZ(&tracked_buffer, "{s}/tracked.txt", .{project.root_path});
    try writeFile(tracked_path, "hello, modified\n");

    var names_buffer: [std.fs.max_path_bytes]u8 = undefined;
    for ([_][]const u8{ "one.txt", "two.txt", "three.txt" }) |name| {
        const path = try std.fmt.bufPrintZ(&names_buffer, "{s}/{s}", .{ project.root_path, name });
        try writeFile(path, "new\n");
    }

    const dirty = try countUncommitted(allocator, std.testing.io, &project.env, project.root_path, null);
    try std.testing.expectEqual(@as(usize, 1), dirty.modified);
    try std.testing.expectEqual(@as(usize, 3), dirty.untracked);
    try std.testing.expectEqual(@as(usize, 4), dirty.total());
    try std.testing.expect(dirty.any());
}

test "countUncommitted counts a staged addition as modified, the same way the import reports it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var staged_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const staged_path = try std.fmt.bufPrintZ(&staged_buffer, "{s}/staged.txt", .{project.root_path});
    try writeFile(staged_path, "staged, not committed\n");

    var add_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "add", "staged.txt" }, null);
    defer add_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, add_output.term);

    const counted = try countUncommitted(allocator, std.testing.io, &project.env, project.root_path, null);
    try std.testing.expectEqual(@as(usize, 1), counted.modified);
    try std.testing.expectEqual(@as(usize, 0), counted.untracked);

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};
    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(counted.modified, report.modified.items.len);
    try std.testing.expectEqual(counted.untracked, report.added.items.len);
    try std.testing.expectEqual(counted.total(), report.total());
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

test "an idle session moves no head, and a session that commits names its own commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer worktree.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expectEqualStrings(project.head_sha, worktree.base_commit);
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try worktree.headMoved(allocator, std.testing.io, &project.env, null),
    );

    var session_env = try project.env.clone(allocator);
    defer session_env.deinit();
    try session_env.put("GIT_OBJECT_DIRECTORY", worktree.object_store_source);
    try session_env.put("GIT_DIR", worktree.worktree_meta_bind_source);
    const project_objects = try std.fs.path.join(allocator, &.{ worktree.git_dir, "objects" });
    defer allocator.free(project_objects);
    try session_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", project_objects);

    var edited_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const edited_path = try std.fmt.bufPrintZ(&edited_buffer, "{s}/tracked.txt", .{worktree.path});
    try writeFile(edited_path, "the agent changed this\n");

    var add_output = try git.run(allocator, std.testing.io, &session_env, worktree.path, &.{ "add", "tracked.txt" }, null);
    defer add_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, add_output.term);
    var commit_output = try git.run(allocator, std.testing.io, &session_env, worktree.path, &.{ "commit", "-m", "the agent's work" }, null);
    defer commit_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_output.term);

    const moved = (try worktree.headMoved(allocator, std.testing.io, &project.env, null)).?;
    defer allocator.free(moved);
    try std.testing.expect(!std.mem.eql(u8, moved, worktree.base_commit));
    try std.testing.expectEqual(@as(usize, 40), moved.len);

    var project_read = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "cat-file", "-e", moved,
    }, null);
    defer project_read.deinit(allocator);
    try std.testing.expect(project_read.term.exited != 0);
    try worktree.remove(allocator, std.testing.io, &project.env, null);
}

fn expectSameWorktreeFields(expected: Worktree, actual: Worktree) !void {
    try std.testing.expectEqualStrings(expected.path, actual.path);
    try std.testing.expectEqualStrings(expected.project_root, actual.project_root);
    try std.testing.expectEqualStrings(expected.base_commit, actual.base_commit);
    try std.testing.expectEqualStrings(expected.git_dir, actual.git_dir);
    try std.testing.expectEqualStrings(expected.worktree_id, actual.worktree_id);
    try std.testing.expectEqualStrings(expected.sandbox_git_root, actual.sandbox_git_root);
    try std.testing.expectEqualStrings(expected.object_store_source, actual.object_store_source);
    try std.testing.expectEqualStrings(expected.object_store_target, actual.object_store_target);
    try std.testing.expectEqualStrings(expected.git_object_directory_env, actual.git_object_directory_env);
    try std.testing.expectEqualStrings(
        expected.git_alternate_object_directories_env,
        actual.git_alternate_object_directories_env,
    );
    try std.testing.expectEqualStrings(expected.worktree_meta_source, actual.worktree_meta_source);
    try std.testing.expectEqualStrings(expected.worktree_meta_bind_source, actual.worktree_meta_bind_source);
    try std.testing.expectEqual(expected.worktree_meta_is_copy, actual.worktree_meta_is_copy);
    try std.testing.expectEqualStrings(expected.worktree_meta_target, actual.worktree_meta_target);
    try std.testing.expectEqualStrings(expected.worktree_index_source, actual.worktree_index_source);
    try std.testing.expectEqualStrings(expected.worktree_index_target, actual.worktree_index_target);
    try std.testing.expectEqualStrings(expected.worktree_head_source, actual.worktree_head_source);
    try std.testing.expectEqualStrings(expected.worktree_head_target, actual.worktree_head_target);
    try std.testing.expectEqualStrings(expected.worktree_logs_source, actual.worktree_logs_source);
    try std.testing.expectEqualStrings(expected.worktree_logs_target, actual.worktree_logs_target);
    try std.testing.expectEqualStrings(expected.worktree_commondir_source, actual.worktree_commondir_source);
    try std.testing.expectEqualStrings(expected.worktree_commondir_target, actual.worktree_commondir_target);
    try std.testing.expectEqualStrings(expected.worktree_gitdir_file_source, actual.worktree_gitdir_file_source);
    try std.testing.expectEqualStrings(expected.worktree_gitdir_file_target, actual.worktree_gitdir_file_target);
    try std.testing.expectEqualStrings(
        expected.worktree_config_worktree_source,
        actual.worktree_config_worktree_source,
    );
    try std.testing.expectEqualStrings(
        expected.worktree_config_worktree_target,
        actual.worktree_config_worktree_target,
    );
    try std.testing.expectEqual(
        expected.worktree_config_worktree_is_scratch,
        actual.worktree_config_worktree_is_scratch,
    );
    try std.testing.expectEqualStrings(expected.pointer_path, actual.pointer_path);
}

fn countRegisteredWorktrees(
    allocator: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) !usize {
    var output = try git.run(allocator, std.testing.io, env, project_root, &.{
        "worktree", "list", "--porcelain",
    }, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);

    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, output.stdout, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "worktree ")) count += 1;
    }
    return count;
}

test "adopt rebuilds every field create built, and registers no second worktree" {
    // The fact the whole handover rests on: a second process reaches the
    // checkout through the registration alone.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer made.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expectEqual(
        @as(usize, 2),
        try countRegisteredWorktrees(allocator, &project.env, project.root_path),
    );

    var taken = try adoptWithLayout(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        project.head_sha,
        .remapped,
        null,
    );
    defer taken.keep(allocator);

    try expectSameWorktreeFields(made, taken);
    try std.testing.expectEqual(
        @as(usize, 2),
        try countRegisteredWorktrees(allocator, &project.env, project.root_path),
    );
    try made.remove(allocator, std.testing.io, &project.env, null);
}

test "adopt keeps the work the checkout already holds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const work_path = work: {
        var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer made.keep(allocator);

        const written = try std.fmt.bufPrintZ(&path_buffer, "{s}/agent-wrote-this.txt", .{made.path});
        try writeFile(written, "work nobody committed\n");
        break :work written;
    };

    var taken = try adoptWithLayout(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        project.head_sha,
        .remapped,
        null,
    );
    errdefer taken.remove(allocator, std.testing.io, &project.env, null) catch {};

    const contents = try readFile(allocator, work_path);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("work nobody committed\n", contents);

    const tracked_path = try std.fs.path.join(allocator, &.{ taken.path, "tracked.txt" });
    defer allocator.free(tracked_path);
    const tracked = try readFile(allocator, tracked_path);
    defer allocator.free(tracked);
    try std.testing.expectEqualStrings("hello\n", tracked);
    try taken.remove(allocator, std.testing.io, &project.env, null);
}

test "adopt carries the caller's base commit, and never the head the session left behind" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var session_head_buffer: [64]u8 = undefined;
    const session_head = head: {
        var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer made.keep(allocator);

        var session_env = try project.env.clone(allocator);
        defer session_env.deinit();
        try session_env.put("GIT_OBJECT_DIRECTORY", made.object_store_source);
        try session_env.put("GIT_DIR", made.worktree_meta_bind_source);
        const project_objects = try std.fs.path.join(allocator, &.{ made.git_dir, "objects" });
        defer allocator.free(project_objects);
        try session_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", project_objects);

        var edited_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const edited_path = try std.fmt.bufPrintZ(&edited_buffer, "{s}/tracked.txt", .{made.path});
        try writeFile(edited_path, "the agent changed this\n");

        var add_output = try git.run(allocator, std.testing.io, &session_env, made.path, &.{ "add", "tracked.txt" }, null);
        defer add_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, add_output.term);
        var commit_output = try git.run(allocator, std.testing.io, &session_env, made.path, &.{ "commit", "-m", "the agent's work" }, null);
        defer commit_output.deinit(allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_output.term);

        const moved = (try made.headMoved(allocator, std.testing.io, &project.env, null)).?;
        defer allocator.free(moved);
        break :head try std.fmt.bufPrint(&session_head_buffer, "{s}", .{moved});
    };
    try std.testing.expect(!std.mem.eql(u8, session_head, project.head_sha));

    var taken = try adoptWithLayout(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        project.head_sha,
        .remapped,
        null,
    );
    errdefer taken.remove(allocator, std.testing.io, &project.env, null) catch {};

    try std.testing.expectEqualStrings(project.head_sha, taken.base_commit);

    const moved = (try taken.headMoved(allocator, std.testing.io, &project.env, null)) orelse
        return error.TheSessionsOwnCommitWouldNeverBeCarriedBack;
    defer allocator.free(moved);
    try std.testing.expectEqualStrings(session_head, moved);
    try taken.remove(allocator, std.testing.io, &project.env, null);
}

test "a path with no checkout, and a checkout with no .git at all, are both refused as nothing to adopt" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    try std.testing.expectError(error.NoWorktreeToAdopt, adopt(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "never-made",
        project.head_sha,
        null,
    ));

    var empty_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const empty_path = try std.fmt.bufPrintZ(&empty_buffer, "{s}/empty", .{project.scratch_path});
    try makeDir(empty_path);

    try std.testing.expectError(error.NoWorktreeToAdopt, adopt(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "empty",
        project.head_sha,
        null,
    ));
}

test "a checkout whose .git is not a gitdir pointer is refused as not a linked worktree" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var checkout_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const checkout_path = try std.fmt.bufPrintZ(&checkout_buffer, "{s}/not-linked", .{project.scratch_path});
    try makeDir(checkout_path);

    var dotgit_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dotgit_path = try std.fmt.bufPrintZ(&dotgit_buffer, "{s}/.git", .{checkout_path});
    try writeFile(dotgit_path, "ref: refs/heads/main\n");

    try std.testing.expectError(error.NotALinkedWorktree, adopt(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "not-linked",
        project.head_sha,
        null,
    ));

    try std.Io.Dir.deleteFileAbsolute(std.testing.io, dotgit_path);
    try makeDir(dotgit_path);

    try std.testing.expectError(error.NotALinkedWorktree, adopt(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "not-linked",
        project.head_sha,
        null,
    ));
}

test "a checkout whose registration the project no longer has is refused, not adopted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    made.keep(allocator);

    var registration_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const registration_path = try std.fmt.bufPrintZ(
        &registration_buffer,
        "{s}/.git/worktrees/sess1",
        .{project.root_path},
    );
    try std.Io.Dir.cwd().deleteTree(std.testing.io, registration_path);

    try std.testing.expectError(error.WorktreeRegistrationGone, adopt(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        project.head_sha,
        null,
    ));
}

test "adopt writes over the scratch files of the session and leaves the same bytes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer made.remove(allocator, std.testing.io, &project.env, null) catch {};

    const pointer_before = try readFile(allocator, made.pointer_path);
    defer allocator.free(pointer_before);
    try std.testing.expect(made.worktree_config_worktree_is_scratch);

    var taken = try adoptWithLayout(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        project.head_sha,
        .remapped,
        null,
    );
    defer taken.keep(allocator);

    const pointer_after = try readFile(allocator, taken.pointer_path);
    defer allocator.free(pointer_after);
    try std.testing.expectEqualStrings(pointer_before, pointer_after);

    try std.testing.expect(taken.worktree_config_worktree_is_scratch);
    const stand_in = try readFile(allocator, taken.worktree_config_worktree_source);
    defer allocator.free(stand_in);
    try std.testing.expectEqual(@as(usize, 0), stand_in.len);
    try made.remove(allocator, std.testing.io, &project.env, null);
}

test "adopt binds the project's own config.worktree when the project has one" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "extensions.worktreeConfig", "true",
    }, null);
    defer config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, config_output.term);

    var worktree_config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "--worktree", "chock.probe", "1",
    }, null);
    defer worktree_config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, worktree_config_output.term);

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    errdefer made.remove(allocator, std.testing.io, &project.env, null) catch {};
    try std.testing.expect(!made.worktree_config_worktree_is_scratch);

    var taken = try adoptWithLayout(
        allocator,
        std.testing.io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        project.head_sha,
        .remapped,
        null,
    );
    defer taken.keep(allocator);

    try std.testing.expect(!taken.worktree_config_worktree_is_scratch);
    try std.testing.expectEqualStrings(
        made.worktree_config_worktree_source,
        taken.worktree_config_worktree_source,
    );
    try made.remove(allocator, std.testing.io, &project.env, null);
}
