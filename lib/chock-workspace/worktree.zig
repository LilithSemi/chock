//! Creates the throwaway git worktree the agent works in, and builds the mount list
//! that lets the sandbox mount it at the project's own path. The agent is never
//! in the user's real tree, so it cannot damage the real files, because it
//! cannot reach them.
//!
//! **Everything below describes `Layout.remapped`, and every target has a
//! second shape.** Under `Layout.in_place` no path is moved at all: the
//! checkout is reached by the scratch path git made it at, `.git` by the
//! project's own real `.git`, and the scratch object store by its own real
//! path. macOS has no bind mount, so that is the only shape it can express.
//! Every reason given below for a synthetic path is a reason that only applies
//! when a path is moved, and each one says so where it matters. See
//! `chock-workspace/layout.zig` and `targetPath`.
//!
//! The mount list splits `.git`: the worktree itself is read write, and the rest
//! of `.git`, objects and refs and hooks included, is read only, so no commit
//! lands without the broker. Inside the worktree's own metadata under
//! `.git/worktrees/<id>`, the directory as a whole is read write, since that
//! is where a linked worktree keeps its own `index`, `HEAD`, and `logs`, the
//! three files an ordinary tool call actually writes to. `commondir`,
//! `gitdir`, and `config.worktree` are the exception, and stay read only:
//! each one redirects git at a path of the agent's own choosing. `commondir`
//! and `gitdir` point at another git directory entirely, and
//! `config.worktree` points at arbitrary git config, such as
//! `core.hooksPath` or `core.fsmonitor`. A writable one is code execution on
//! the next git command the user, not the agent, runs against this worktree
//! on the host.
//!
//! **The read write directory is a copy, and the project's own is never
//! written.** A directory git may create and rename lock files in cannot be
//! made read only without breaking `git add` and `git commit`, which is
//! finding 4 and is measured in `Worktree.mounts`. So `create` copies
//! `.git/worktrees/<id>` into the session's own scratch directory and the
//! sandbox writes the copy. `.git/worktrees/<id>` itself reads byte for byte
//! as `git worktree add` left it when the session ends, whatever the agent
//! did. The three read only claw-backs below stay, over the copy's own
//! `commondir`, `gitdir` and `config.worktree`.
//!
//! **Both layouts get the copy, and only the way git is pointed at it
//! differs.** `Layout.remapped` binds the copy at the path the checkout's own
//! `.git` file already names. `Layout.in_place` cannot move a path, so it
//! names the copy in the environment instead, with `GIT_DIR` and
//! `GIT_WORK_TREE`: see `Worktree.gitEnv`. An earlier version of this file
//! gave `.in_place` no copy at all, on the reasoning that a copy is useless
//! where no path can be moved. That left the project's own
//! `.git/worktrees/<id>` read write on macOS, which is finding 4 exactly as
//! the red team found it, measured again on a real Mac on 2026-08-26.
//!
//! **Guard the path, not the file.** This has given an attacker host code
//! execution twice before, and both times the fault was the same shape: code
//! that protected a file only when the file already existed, rather than
//! owning the path outright. The third time was `config.worktree` itself: it
//! is mounted read only only when `create` finds one already on disk, and
//! `git worktree add` does not write one on a project that has
//! `extensions.worktreeConfig` on but whose main checkout has no
//! `config.worktree` of its own yet. On that project the file was simply
//! absent, nothing mounted over the path, and the agent created it from
//! inside the sandbox, the same as writing to any other file under this
//! directory. The next host side `git status` then read whatever the agent
//! had written. The fix is `Worktree.mounts`'s entry 5, unconditional: when
//! `create` finds no `config.worktree` on disk, it writes an empty scratch
//! file of its own and mounts that read only instead, the same trick
//! `pointer_path` already uses below. Presence on disk decides which file
//! `mounts` binds, real or scratch, never whether it binds one at all.
//!
//! **A linked worktree's own `.git` is a file, not a directory.** `git worktree add`
//! writes a one line file, `gitdir: <path>`, and `<path>` is always the absolute host
//! path of `.git/worktrees/<id>` under the *main* repository, the one the worktree
//! was created from. When that main repository is the real project, and the sandbox
//! mounts the worktree at the project's own real path, `<path>` and the
//! sandbox's mount target for the worktree share the same prefix: both start with the
//! project's real absolute path. A directory cannot be bind mounted onto a path that
//! is currently a file, confirmed by hand with a real `unshare -Urm` mount and a real
//! ENOTDIR, so `.git/worktrees/<id>` can never be reached by nesting a mount under the
//! worktree's own `.git` file. The mount list here works around this the same way
//! `chock.zon` is protected: a small scratch file, built once here,
//! shadows the worktree's own `.git` inside the sandbox only, and names a path the
//! sandbox mount list also covers, under a prefix (`sandbox_git_root_prefix`) no real
//! project uses. The worktree's own `.git`, on the host, is left exactly as git wrote
//! it, so a host side git command against the worktree keeps working after `create`
//! returns.
//!
//! This file imports `Mount` from `lib/chock-sandbox/namespace.zig` rather than
//! keeping its own copy. `chock-sandbox` may not import a library above it. That
//! rule says nothing against the reverse, and a
//! copy that drifts from the shape `Sandbox.spawn` actually applies is how a
//! mount list can silently stop matching what the sandbox does with it.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why a call here failed, past what `Error` can say. One type for the whole
/// module: see `chock-workspace/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const git = @import("git.zig");
const layout_mod = @import("layout.zig");
/// Where the sandbox sees the workspace. See `chock-workspace/layout.zig`.
pub const Layout = layout_mod.Layout;
const sandbox = @import("chock-sandbox");

pub const Error = git.Error || error{
    /// `git worktree add` or `git worktree remove` ran and exited with a nonzero
    /// status. The detail git printed on stderr is not kept: a caller that needs
    /// it should call `git.run` directly instead of going through `create` or
    /// `remove`.
    GitFailed,
    /// `git worktree add` left behind a `.git` that was not the one line
    /// `gitdir: <path>` file every linked worktree has. This is a bug in this
    /// file's own assumption about git's layout, not a fault a caller can
    /// recover from by retrying.
    NotALinkedWorktree,
    /// `session_id` was empty, was `.` or `..`, or held a `/`. It goes straight
    /// into a path join for the worktree's own path, the sandbox mount target,
    /// and the pointer file name, so an unchecked value could point any of the
    /// three outside the scratch directory this session owns.
    InvalidSessionId,
    /// `git status` named a path that was absolute, or held a `..` component.
    /// Joining it onto `project_root` to read it, or onto the worktree's own
    /// path to write it, could then reach outside both. Refused instead of
    /// followed: see `importUncommitted`'s own doc comment.
    PathEscapesProject,
    /// `adopt` found no checkout to take at `<scratch_dir>/<session_id>`:
    /// nothing is there at all, something that is not a directory is there,
    /// or the directory holds no `.git` of any kind. **A refusal, not a
    /// fault**: `adopt` only ever takes a checkout another process already
    /// made, and it makes none of its own, so an empty path is an answer and
    /// not a failure. A caller that wants a new worktree calls `create`.
    NoWorktreeToAdopt,
    /// `adopt` found a checkout whose `.git` names a registration that is no
    /// longer under `<project_root>/.git/worktrees/`. git prunes the
    /// registration of a checkout it cannot find, and a checkout whose
    /// registration is gone is one no git command works in, so adopting it
    /// would hand the new owner a workspace that fails on its first commit.
    /// Refused here, where the reason is still readable, rather than inside
    /// the first tool call that runs git.
    WorktreeRegistrationGone,
};

/// One bind mount, in the shape `Sandbox.spawn` reads. See
/// `lib/chock-sandbox/namespace.zig`'s own `Mount` for the field meanings. This is
/// that same type, not a copy of it.
pub const Mount = sandbox.namespace.Mount;

/// The absolute path prefix, meaningful only inside the sandbox's own mount tree,
/// under which `mounts` puts the shared parts of `.git`: the object store, the
/// refs, the hooks directory, and every other worktree's own metadata besides
/// this session's. See this file's own top doc comment for why it cannot be
/// `project_root/.git` itself. Chosen to be a path no real project uses.
const sandbox_git_root_prefix = chock_runtime_prefix ++ "/git";

/// Where every path Chock puts inside the sandbox that is Chock's own, and
/// not the project's, lives. Two of the three entries under it are this
/// file's, `sandbox_git_root_prefix` and `object_store_prefix`, and the
/// third is `lib/chock-core/tools.zig`'s own `tool_bin_dir`.
///
/// Spelled once, in `chock-sandbox`, which is the library that owns what a
/// sandbox root looks like and the one library both this file and
/// `chock-core` import: see `Sandbox.runtime_prefix` for why the root
/// belongs to the project and this does not.
///
/// Nothing creates `/run` or `/run/chock` on its own. **`namespace.makePath`
/// creates every parent of a mount target as a directory, `mkdir -p`
/// fashion, before the mount happens**, and tolerates one that already
/// exists, so the first mount under this prefix makes both and every later
/// one reuses them. See `lib/chock-sandbox/linux/namespace.zig`.
///
/// **The kernel takes the last matching mount, not the longest prefix.** So
/// nesting deeper puts more weight on that ordering: a wide mount at `/run`
/// applied after these would shadow all three at once. Nothing in Chock
/// mounts `/run`, and the tests below hold that.
const chock_runtime_prefix = sandbox.runtime_prefix;

/// The absolute path prefix under which `mounts` puts this session's own
/// scratch git object store. Deliberately
/// not nested under `sandbox_git_root_prefix`: `namespace.buildRoot` marks a
/// mount read only the moment it makes it, so a target nested under
/// `sandbox_git_root`'s own read only mount can only ever be a directory
/// that already exists somewhere inside the real `.git` this worktree came
/// from, the same reason `worktree_meta_target` works and a brand new name
/// under that same tree does not: `mkdir` for a mount point that has to
/// create something new, rather than merely confirm one that is already
/// there, still has to ask the filesystem for write access, and gets EROFS
/// once its parent is already read only. The scratch object store never
/// existed under the real `.git` before this session; there is no name a
/// mount here could reuse the way `worktree_meta_target` reuses
/// `worktrees/<worktree_id>`. Giving it a prefix of its own instead
/// sidesteps the question: nothing marks this prefix read only before
/// `mounts`'s own entry for it runs, so its own `mkdir` is ordinary,
/// unprivileged directory creation, confirmed by hand against a real mount
/// namespace. It shares a parent with `sandbox_git_root_prefix`, which is
/// only a directory `makePath` creates and never a mount, so nothing about
/// that parent is read only either.
const object_store_prefix = chock_runtime_prefix ++ "/objects";

/// What `Worktree.importUncommitted` moved from the project's own working tree
/// into the worktree. Chock must tell the user it did this: a caller turns
/// these lists into a sentence such as "12 files brought across from your
/// working tree", and can name them individually since the paths, not just the
/// counts, are kept.
pub const ImportReport = struct {
    /// Paths of tracked files the project has modified, copied into the
    /// worktree with their new contents.
    modified: std.ArrayList([]u8) = .empty,
    /// Paths of files the project has not committed yet, copied into the
    /// worktree. A path is put here when git status gave it the `??` code,
    /// meaning untracked. A file already `git add`ed before this ran is also
    /// new to HEAD, but is counted under `modified` instead: telling that
    /// case apart needs reading the rest of git's own status letters, the
    /// wider surface `importUncommitted`'s own doc comment already explains
    /// staying away from.
    added: std.ArrayList([]u8) = .empty,
    /// Paths removed from the worktree because the project no longer has
    /// them on disk, whether the deletion itself was staged or not.
    deleted: std.ArrayList([]u8) = .empty,
    /// A path git status named that was not carried across, and why: a
    /// directory (a submodule, a vendored clone, or a plain file replaced by
    /// a directory), a device node, a fifo, a socket, or a file that could
    /// not be read or written. A skip the user cannot see would be the same
    /// silent gap as the crash and the wrongful deletion this report exists
    /// to replace, so every one is recorded, never dropped.
    skipped: std.ArrayList(Skip) = .empty,

    pub const Skip = struct {
        path: []u8,
        reason: []u8,
    };

    /// How many files actually changed what the worktree holds: `modified`
    /// plus `added` plus `deleted`. `skipped` is left out, since nothing
    /// skipped changed the worktree. A caller that wants to mention it reads
    /// `skipped` on its own.
    pub fn total(self: ImportReport) usize {
        return self.modified.items.len + self.added.items.len + self.deleted.items.len;
    }

    /// Free every path and reason this report owns. `self` is not valid
    /// after this call returns.
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

/// How much of the project's own working tree is not in `HEAD`, which is
/// exactly what a fresh worktree does not carry. See `countUncommitted`.
pub const Uncommitted = struct {
    /// Paths git already tracks whose working tree copy differs from the
    /// index or from `HEAD`, plus staged additions and deletions.
    modified: usize = 0,
    /// Paths git has never tracked. The `??` code, the same one
    /// `ImportReport.added` is filled from, so the two agree on where a path
    /// belongs.
    untracked: usize = 0,

    pub fn total(self: Uncommitted) usize {
        return self.modified + self.untracked;
    }

    /// True when the project has work `git worktree add` would leave behind.
    pub fn any(self: Uncommitted) bool {
        return self.total() != 0;
    }
};

/// Count what `git worktree add` leaves behind: **it checks out the commit,
/// not the index and not the working tree**, so an agent working in a fresh
/// worktree sees `HEAD` and nothing else.
///
/// The behaviour is right, because a known commit is reproducible and easier
/// to reason about. The fault this answers is the silence: a user who is
/// never told believes the agent can see work it cannot. Chock's own
/// repository is the case that exposed it, with three files in `HEAD` and 83
/// uncommitted, so an agent run against it saw three files and none of the
/// source.
///
/// The same `git status` call `Worktree.importUncommitted` makes, read the
/// same way, including the same rule for a path git names twice. So the
/// number a warning shows and the number an import reports come from one
/// reading of one command, and cannot disagree.
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

/// The one `git status` call this file makes, spelled once. See
/// `Worktree.importUncommitted`'s own doc comment for what each option is
/// for. `countUncommitted` reads the same output the same way, so a second
/// spelling here is a second thing that could drift from it.
const status_argv = &[_][]const u8{
    "--no-optional-locks",   "status",       "--porcelain=v1", "-z",
    "--untracked-files=all", "--no-renames",
};

/// A throwaway git worktree, detached at the project's own HEAD, and everything
/// `mounts` needs to place it and its `.git` metadata correctly inside a sandbox.
/// Every field is owned by this value and is freed by `remove`.
pub const Worktree = struct {
    /// Absolute host path of the worktree's own checkout. `mounts` binds this at
    /// `sandbox_root`, read write: the agent works here.
    path: []u8,
    /// Absolute host path of the project this worktree was created from.
    ///
    /// **The host's own path, and never the path the agent works at.** Every
    /// git command this file runs against the project uses it, and
    /// `importUncommitted` reads the user's real files through it. Under
    /// `Layout.in_place` the sandbox never sees this directory at all: see
    /// `sandbox_root`.
    project_root: []u8,
    /// Which of the two shapes `mounts` builds. Chosen by the host's own
    /// sandbox driver: see `chock-workspace/layout.zig`.
    layout: Layout,
    /// Absolute path at which the sandbox sees `path`. `project_root` under
    /// `Layout.remapped`, and `path` itself under `Layout.in_place`.
    ///
    /// **This is the project root the agent is told about.** `sandboxConfig`
    /// makes it the working directory of every tool call, and `chock-core`
    /// reads every relative path the model spells against it.
    sandbox_root: []u8,
    /// The commit `git worktree add --detach` put this worktree at, read back
    /// right after it ran. **What the agent's own work is measured against**:
    /// see `headMoved`. Read back rather than assumed to equal the project's
    /// `HEAD` today, for the same reason `worktree_id` is read back rather
    /// than assumed to equal the session id: what git actually did is a fact,
    /// and what it was asked to do is not.
    base_commit: []u8,
    /// Absolute host path of `project_root`'s own `.git`.
    git_dir: []u8,
    /// The id git assigned this worktree under `.git/worktrees/`. Read back from
    /// the `.git` file git itself wrote, never assumed to equal the session id
    /// this worktree was created with: git deduplicates the worktree's name if an
    /// entry with that name is already registered.
    worktree_id: []u8,
    /// Absolute path, meaningful only inside the sandbox, that stands in for
    /// `git_dir` there. See this file's own top doc comment.
    sandbox_git_root: []u8,
    /// Absolute host path of this session's own scratch git object store: a
    /// fresh, writable directory `create` makes under `scratch_dir`, named
    /// after `session_id`. Git needs somewhere to write a loose object, and
    /// the real `.git/objects`, under
    /// `git_dir`, stays read only. `gitEnv` points `GIT_OBJECT_DIRECTORY` at
    /// `object_store_target` below, so every object `git add` and `git
    /// commit` create inside the sandbox lands here alone, never in the
    /// project's own object store. `remove` deletes this directory,
    /// recursively, along with everything a session's own git calls ever
    /// wrote into it: a refused session leaves nothing behind to clean up.
    object_store_source: []u8,
    /// Where `object_store_source` lands inside the sandbox, under
    /// `sandbox_git_root`. `mounts`'s own entry for this binds it read
    /// write, overriding entry 1 (the whole real `.git`, read only) for this
    /// one subtree.
    object_store_target: []u8,
    /// The literal string `"GIT_OBJECT_DIRECTORY=" ++ object_store_target`,
    /// built once here so `gitEnv` only ever hands back a slice into `self`,
    /// never builds a new string on every call.
    git_object_directory_env: []u8,
    /// The literal string `"GIT_ALTERNATE_OBJECT_DIRECTORIES=" ++` the real
    /// object store's own path inside the sandbox (`sandbox_git_root` plus
    /// `"objects"`). This is a variable, never a file. A variable is the
    /// choice here, over `objects/info/alternates`: an alternates *file* would
    /// have to live inside `object_store_target`, the one directory under
    /// `.git` this worktree gives the sandbox write access to, and that exact
    /// shape is already named once, for `commondir`, `gitdir`,
    /// and `config.worktree`: a file that names a path, sitting somewhere
    /// the agent can overwrite it, is a capability the agent was never meant
    /// to have. An environment variable, set fresh by the caller on every
    /// `Sandbox.spawn` call, has no such file behind it: nothing under the
    /// sandbox's own mount tree holds it, so there is nothing there for a
    /// tool call to rewrite and nothing that outlives the one call it was
    /// built for. See `gitEnv`'s own doc comment for what an agent gains by
    /// naming a different alternate on a subprocess of its own anyway:
    /// nothing that reaches the object store's write side, and nothing that
    /// reaches the project's real repository. See
    /// `test/workspace/escape.zig`'s own proof.
    git_alternate_object_directories_env: []u8,
    /// The literal string `"GIT_DIR=" ++ worktree_meta_target`, or null.
    ///
    /// **Null under `Layout.remapped`, and set under `Layout.in_place`.** A
    /// linked worktree finds its own metadata through the one line `gitdir:
    /// <path>` file `git worktree add` wrote in the checkout, and that line
    /// names the project's own `.git/worktrees/<id>`. `.remapped` binds the
    /// session's own copy at exactly that path, so git needs telling nothing.
    /// `.in_place` cannot move a path, so the same line names the project's
    /// own directory, which `mounts` now leaves read only. Naming the copy in
    /// the environment is what points git at it instead. See `gitEnv`.
    git_dir_env: ?[]u8,
    /// The literal string `"GIT_WORK_TREE=" ++ sandbox_root`, or null under
    /// `Layout.remapped`. **`GIT_DIR` on its own is not enough**: measured
    /// against git 2.55, `GIT_DIR` with no `GIT_WORK_TREE` makes git treat
    /// the current directory as the root of the working tree, so a `git add`
    /// run from a subdirectory of the checkout reports every file outside
    /// that subdirectory as deleted. The two go together or neither goes.
    git_work_tree_env: ?[]u8,
    /// Absolute host path of `git_dir`'s own `worktrees/<worktree_id>`: this
    /// worktree's own metadata directory, holding `index`, `HEAD`, `logs`, and
    /// also `commondir`, `gitdir`, and (if the project turned the extension on)
    /// `config.worktree`. **A tool call never reaches this directory on
    /// either layout**: what the sandbox writes is
    /// `worktree_meta_bind_source`, the session's own copy of it. See
    /// `mounts`'s own doc comment for why.
    worktree_meta_source: []u8,
    /// Where the copy is reached inside the sandbox: under
    /// `sandbox_git_root` on `Layout.remapped`, and the copy's own host path
    /// on `Layout.in_place`, which moves nothing. See `metaTarget`.
    worktree_meta_target: []u8,
    /// Absolute host path of the directory the sandbox writes at
    /// `worktree_meta_target`: **always the session's own copy of
    /// `worktree_meta_source`, on both layouts.** See `mounts`'s own doc
    /// comment for why a copy, and `copyMetaDirectory` for what it holds.
    worktree_meta_bind_source: []u8,
    /// True when `worktree_meta_bind_source` names the session's own copy,
    /// which `remove` deletes and `keep` leaves.
    ///
    /// **Always true today**, and kept as a field rather than folded away
    /// because `remove` deletes a whole directory tree on the strength of it.
    /// A caller that ever hands this value a directory it does not own must
    /// have somewhere to say so.
    worktree_meta_is_copy: bool,
    /// Absolute host path of `worktree_meta_source`'s own `index`. Kept for
    /// its own sake. `mounts` no longer mounts this file on its own, see
    /// `mounts`'s own doc comment for why.
    worktree_index_source: []u8,
    /// Where `worktree_index_source` lands inside the sandbox.
    worktree_index_target: []u8,
    /// Absolute host path of `worktree_meta_source`'s own `HEAD`. Kept for
    /// its own sake. See `worktree_index_source`'s own doc comment.
    worktree_head_source: []u8,
    /// Where `worktree_head_source` lands inside the sandbox.
    worktree_head_target: []u8,
    /// Absolute host path of `worktree_meta_source`'s own `logs`, the HEAD
    /// reflog directory. Kept for its own sake. See
    /// `worktree_index_source`'s own doc comment.
    worktree_logs_source: []u8,
    /// Where `worktree_logs_source` lands inside the sandbox.
    worktree_logs_target: []u8,
    /// Absolute host path of `worktree_meta_source`'s own `commondir`. A
    /// linked worktree always writes this file: unlike `config.worktree`,
    /// `mounts` never has to ask whether it exists.
    worktree_commondir_source: []u8,
    /// Where `worktree_commondir_source` lands inside the sandbox.
    worktree_commondir_target: []u8,
    /// Absolute host path of `worktree_meta_source`'s own `gitdir`. Always
    /// present, the same as `worktree_commondir_source`.
    worktree_gitdir_file_source: []u8,
    /// Where `worktree_gitdir_file_source` lands inside the sandbox.
    worktree_gitdir_file_target: []u8,
    /// Absolute host path mounted read only at
    /// `worktree_config_worktree_target`: the project's own `config.worktree`,
    /// when the project already had one at create time, or an empty scratch
    /// file this session owns, when it did not. Always set, unlike an
    /// earlier version of this field. See this file's own top doc comment
    /// for the exploit an optional field left open.
    worktree_config_worktree_source: []u8,
    /// Where `worktree_config_worktree_source` lands inside the sandbox.
    worktree_config_worktree_target: []u8,
    /// True when `worktree_config_worktree_source` names the empty scratch
    /// file `create` wrote, because the project had no `config.worktree` of
    /// its own at create time. False when it names the project's own real
    /// file instead. `remove` deletes the scratch file when this is true,
    /// and leaves the real file on the host untouched when it is false.
    worktree_config_worktree_is_scratch: bool,
    /// Absolute host path of the scratch file that shadows the worktree's own
    /// `.git` inside the sandbox. The real one, at `path` plus `.git`, is left
    /// untouched on the host.
    pointer_path: []u8,

    /// The absolute path at which the sandbox sees the checkout. Named as a
    /// call, and not read off `sandbox_root` at every use site, so that this
    /// type and `Overlay` answer the same question the same way.
    pub fn sandboxRoot(self: Worktree) []const u8 {
        return self.sandbox_root;
    }

    /// The mount list, in the shape `Mount` above, that a caller passes straight
    /// to `Sandbox.spawn`. Every `source` and `target` in it is a slice into
    /// `self`'s own fields. Only the returned array itself is a fresh
    /// allocation, and the caller frees it with `allocator.free`.
    ///
    /// Order matters and must not change, because the kernel applies mounts in
    /// order and the last one that covers a path wins. Entry 0's target,
    /// `sandbox_root`, is a prefix of the last entry's, so entry 0 must come
    /// first. Entry 3 must come after entry 1, since it nests under entry 1's
    /// target, and entries 4 and 5 (and 6, when present) must come after
    /// entry 3 for the same reason, one level deeper.
    ///
    /// **Under `Layout.in_place` every entry's target is its own source, and
    /// the order still means the same thing.** No mount is performed on that
    /// layout: the Darwin driver reads the list as a set of path rules and
    /// keeps the same last-one-wins rule, so a read only entry nested inside a
    /// read write one narrows exactly the subtree it names. Measured on macOS
    /// 15.7.9 on 2026-08-25, both ways round: a later read write rule gives
    /// back write inside an earlier read only subtree, and a later read only
    /// rule takes write away inside an earlier read write subtree. The one
    /// entry that changes is the last: see the comment on it.
    ///
    /// Entry 2 is the scratch object store. Its own target,
    /// `object_store_target`, lives under `object_store_prefix`, a wholly
    /// separate top level path from `sandbox_git_root`: see
    /// `object_store_prefix`'s own doc comment for why it cannot nest under
    /// entry 1's target the way entry 3 does. Nothing else in this list
    /// touches that prefix, so entry 2's own position relative to every other
    /// entry is free; it is placed here only to read next to the other git
    /// specific entries.
    ///
    /// **Entry 3's source is a copy, and that is finding 4.** The first
    /// complete red team run drove a tool call to write
    /// `.git/worktrees/<id>/logs/probe-from-session` into the user's own
    /// repository, and the file was still there when the session ended.
    /// Nothing was wrong with the read only claw-backs: the whole metadata
    /// directory is read write on purpose, and the agent simply used it.
    ///
    /// **The root of that directory cannot be made read only.** `git add` and
    /// `git commit` create `index.lock`, `HEAD.lock`, `AUTO_MERGE.lock`, and
    /// `COMMIT_EDITMSG` in it, and then rename each lock file over the file
    /// it locks. `open` with `O_CREAT|O_EXCL` under a read only mount answers
    /// `EROFS`, so pre-creating each name does not help, and a lock file
    /// bound in from elsewhere cannot be renamed over its target, because
    /// `rename` refuses to cross a mount point. Measured against git 2.55 in
    /// a real mount namespace: a read only root gives
    /// `fatal: Unable to create '<meta>/index.lock': Read-only file system`
    /// on the first `git add`.
    ///
    /// So the directory the sandbox writes is not the project's. `create`
    /// copies `worktree_meta_source` to `worktree_meta_bind_source`, under
    /// the session's own scratch directory, and entry 3 binds the copy. Every
    /// write a tool call makes there, git's own and the agent's alike, lands
    /// in the copy, and `.git/worktrees/<id>` reads byte for byte as
    /// `git worktree add` left it after the session ends. `headAfterSession`
    /// reads the copy, which is where the session's own `HEAD` is, and
    /// `remove` deletes it.
    ///
    /// **`Layout.in_place` gets the same copy and reaches it by its own real
    /// path.** There is no bind mount on macOS, so a copy at another path
    /// cannot appear at the project's own `.git/worktrees/<id>`. It does not
    /// have to: entry 3's target is then the copy itself, nothing overrides
    /// entry 1 for the project's own `.git`, and the whole of that directory
    /// stays read only. git is pointed at the copy with `GIT_DIR` and
    /// `GIT_WORK_TREE` instead of by path: see `gitEnv`. Measured on macOS
    /// 15.7.9 on 2026-08-26, both before and after: before, a tool call wrote
    /// `logs/probe-from-session` and `refs/pwn-test` into the project's own
    /// repository and the files were still there afterwards; after, the same
    /// two writes land in the copy and a write named straight at the
    /// project's own directory is refused. See
    /// `test/workspace/darwin_escape.zig`.
    ///
    /// Entry 3 binds that metadata directory as a whole,
    /// read write, rather than naming `index`, `HEAD`, and `logs`
    /// individually the way an earlier version of this function did. The
    /// kernel marks a mount read only the moment it is made, in
    /// `Sandbox.spawn`'s own build of the mount tree, before the next entry in
    /// this list is ever reached. `open` for write on a file that already
    /// exists under a mount already marked read only fails with EROFS, on
    /// purpose, confirmed by hand against a real mount namespace: the file
    /// existing already does not help, because `open` still has to ask the
    /// filesystem for write access. `index` and `HEAD` are files, so naming
    /// them one at a time, nested under entry 1's now read only `.git`, hit
    /// exactly that fault, and no tool call that touched git could ever start.
    /// `mkdir` behaves differently: it tolerates an existing directory under a
    /// read only mount, `EEXIST`, confirmed the same way, because the kernel
    /// can answer "this already exists" without ever asking for write access.
    /// That is what makes entry 3 itself possible: its own target,
    /// `worktree_meta_target`, already exists as part of entry 1's tree by the
    /// time entry 3 runs.
    ///
    /// Binding the whole metadata directory read write would also give away
    /// `commondir`, `gitdir`, and `config.worktree`, so entries 4 through 6
    /// claw each of those back to read only, one file at a time, the same
    /// shape entries 3 through 5 had before. This works for the opposite
    /// reason entry 3 does: at the point entries 4 through 6 run, their
    /// parent, entry 3's own target, is still read write, not yet marked
    /// read only, so `open` for write on an existing file there still
    /// succeeds, and the read only mark that follows only narrows that one
    /// file, never a sibling. Each of `commondir`, `gitdir`, and
    /// `config.worktree` redirects git at a path the agent chooses. A
    /// writable one is a route out of the sandbox, not a convenience: see
    /// this file's own top doc comment.
    ///
    /// Entry 6 is unconditional, always covering `config.worktree`'s target,
    /// even on a project that had no `config.worktree` at create time. An
    /// earlier version of this function added entry 6 only when
    /// `worktree_config_worktree_source` was not `null`, so a project with
    /// `extensions.worktreeConfig` on but no `config.worktree` of its own
    /// yet left that path under entry 3's own read write reach. git writes
    /// `config.worktree` itself the first time something sets a value with
    /// `--worktree`, and that write happens from inside the sandbox, on the
    /// agent's own say so. A file that does not exist yet is not a file that
    /// is safe to leave unprotected: `create` now always builds a source for
    /// this entry, the project's own real file when there is one, or an
    /// empty scratch file it wrote itself when there is not, the same trick
    /// `pointer_path` already uses for the worktree's own `.git`. Every other
    /// name that can appear under this directory, `HEAD`, `ORIG_HEAD`,
    /// `index`, `logs/`, `refs/`, `sparse-checkout`, `MERGE_HEAD`,
    /// `rebase-merge/`, `info/`, and any name git or the agent has not
    /// invented yet, is git's own bookkeeping data for this one worktree,
    /// never a redirect to a path outside it. Only `commondir`, `gitdir`,
    /// and `config.worktree` name another path git then reads as
    /// instructions, so only those three need an unconditional mount of
    /// their own. Every other name is left read write on purpose, and the
    /// copy is what makes that safe: a name nobody here has thought of is
    /// still a name in the session's own scratch directory, and it reaches
    /// the project's own repository never.
    /// The host path entries 4 through 6 of `mounts` put at `target`.
    ///
    /// **Under `Layout.remapped` it is the project's own file**, bound read
    /// only over the copy's, so the sandbox reads the bytes `git worktree add`
    /// wrote and no byte the session changed. `commondir` there holds `../..`,
    /// which is correct against the mount target and wrong against the copy's
    /// own path: see `copyMetaDirectory`.
    ///
    /// **Under `Layout.in_place` it is the target itself**, which is the
    /// copy's own file. Nothing is moved on that layout, so a source that
    /// differed from its target would be a mount `darwin/driver.zig`'s own
    /// `expressibleOn` refuses outright, and the rule the driver builds names
    /// the target in any case. The copy's own `commondir` holds the absolute
    /// path of the project's `.git`, which is the correct one to read when no
    /// path is moved.
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
        // owns instead of project_root/.git. This one mount is what keeps the
        // object store, the refs, and the hooks directory read only, and every
        // other worktree's own metadata besides this session's: none of them
        // are overridden by anything narrower below.
        try list.append(allocator, .{ .bind = .{ .source = self.git_dir, .target = self.sandbox_git_root, .read_only = true } });

        // 2: this session's own scratch git object store, read write, at its
        // own top level path, entirely separate from sandbox_git_root: see
        // object_store_prefix's own doc comment for why. gitEnv points
        // GIT_OBJECT_DIRECTORY here, so every object the agent writes lands
        // in scratch, never in the project's own object store.
        try list.append(allocator, .{ .bind = .{
            .source = self.object_store_source,
            .target = self.object_store_target,
            .read_only = false,
        } });

        // 3: this worktree's own metadata directory, read write as a whole,
        // overriding entry 1 for this one subtree. A linked worktree writes
        // its own index, HEAD, and logs here. If this stayed read only, git
        // would fail on the lock file and every tool call that touches git
        // would break. The source is the session's own copy, never the
        // project's own directory: see this function's own doc comment for
        // finding 4 and for why the copy is the only answer that keeps
        // `git commit` working.
        try list.append(allocator, .{ .bind = .{
            .source = self.worktree_meta_bind_source,
            .target = self.worktree_meta_target,
            .read_only = false,
        } });

        // 4, 5: commondir and gitdir, read only, overriding entry 3 for these
        // two files alone. Always present: git writes both for every linked
        // worktree.
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

        // 6: config.worktree, read only, same reasoning, unconditional. See
        // this function's own doc comment for why an entry that only fires
        // when the file already exists is exactly the shape that left a
        // route to host code execution open.
        try list.append(allocator, .{ .bind = .{
            .source = self.metaFileSource(self.worktree_config_worktree_source, self.worktree_config_worktree_target),
            .target = self.worktree_config_worktree_target,
            .read_only = true,
        } });

        // last: the replacement .git file, read only, shadowing the worktree's
        // own pointer (still on disk, untouched, at self.path plus .git) with
        // one that names a path the sandbox can actually resolve. See this
        // file's top doc comment for why the original cannot be used as is.
        //
        // **`.in_place` needs no such entry, because nothing was moved.** The
        // pointer git itself wrote already names the real metadata directory,
        // and under this layout that directory is at its own real path inside
        // the sandbox too. `create` still writes the scratch file, so `remove`
        // and `adopt` behave the same way on both layouts.
        if (self.layout == .remapped) {
            try list.append(allocator, .{ .bind = .{ .source = self.pointer_path, .target = self.git_dir, .read_only = true } });
        }

        return list.toOwnedSlice(allocator);
    }

    /// The environment variables a caller must add to `Sandbox.Config.env`
    /// for every tool call in this worktree, so `git add`, `git commit`, and
    /// `git stash` succeed inside the sandbox even though the real object
    /// store stays read only.
    ///
    /// `GIT_OBJECT_DIRECTORY` points every write at `object_store_target`,
    /// the scratch store `mounts`'s own entry 2 gives the sandbox write
    /// access to: every object the agent creates lands there, never in the
    /// project's own `.git/objects`. `GIT_ALTERNATE_OBJECT_DIRECTORIES`
    /// gives git read access to every object that already exists, by naming
    /// the real object store's own path inside the sandbox
    /// (`sandbox_git_root` plus `"objects"`, still the read only mount
    /// `mounts`'s own entry 1 makes). See `git_alternate_object_directories_env`'s
    /// own doc comment for why this is a variable and not the
    /// `objects/info/alternates` file git also supports: a file would have
    /// to live inside the one directory under `.git` this worktree gives
    /// the sandbox write access to, which makes it exactly the shape section
    /// 6.1.1 already named once, for `commondir`, `gitdir`, and
    /// `config.worktree`.
    ///
    /// **`GIT_DIR` and `GIT_WORK_TREE` come as well, under `Layout.in_place`
    /// and never under `Layout.remapped`.** A linked worktree finds its own
    /// metadata through the `gitdir: <path>` line `git worktree add` wrote in
    /// the checkout, and that line names the project's own
    /// `.git/worktrees/<id>`. `.remapped` binds the session's own copy at
    /// exactly that path, so git needs telling nothing and must be told
    /// nothing: a `GIT_DIR` there would reach every git command a tool call
    /// makes, a repository the agent cloned for itself included. `.in_place`
    /// can move no path, so the copy sits at its own real path and the
    /// environment is the only way to name it. `remove` still works either
    /// way, because the checkout's own `.git` file on the host is left as git
    /// wrote it and `git worktree remove` refuses a checkout that does not
    /// point back at its registration: measured against git 2.55 on
    /// 2026-08-26, which is why the pointer is named here and not rewritten.
    ///
    /// An agent that runs a git command of its own, inside the sandbox, can
    /// still override any of these for that one subprocess, the same as
    /// any other environment variable a shell command can set. That changes
    /// nothing this design depends on: git never writes to an alternate, so
    /// no value of `GIT_ALTERNATE_OBJECT_DIRECTORIES` ever grants a write
    /// the mount layer would otherwise refuse, and `GIT_OBJECT_DIRECTORY`
    /// pointed at the real, read only object store only makes that one git
    /// call fail with the same `EROFS` a plain `open` for write already
    /// gets there. The worst an agent reaches by naming a different
    /// alternate is a git command of its own that can no longer read the
    /// project's history; it reaches nothing that lands a change in the
    /// project's own repository. `test/workspace/escape.zig` proves this
    /// with a real sandbox, not with this paragraph alone.
    ///
    /// The same holds for `GIT_DIR`. An agent that clears it, or points it
    /// back at the project's own `.git/worktrees/<id>`, gets a git command
    /// that cannot write: `mounts`'s own entry 1 makes the whole of the real
    /// `.git` read only and nothing under it is given back. What it loses is
    /// its own git command. What it reaches is nothing.
    /// `test/workspace/darwin_escape.zig` proves the refusal on a real Mac.
    ///
    /// The returned slice is freshly allocated and owned by the caller, who
    /// frees it with `allocator.free`. Each string inside it is a slice into
    /// `self`, and stays valid only as long as `self` does, the same
    /// convention `mounts` uses for its own return value.
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

    /// Copy the project's own uncommitted work into this worktree, so a
    /// session that starts on a dirty tree still sees the codebase the user
    /// sees. A worktree starts at HEAD, so
    /// without this an agent works from a codebase the user has already
    /// moved past, and then reports on code that is not what the user has.
    ///
    /// `git status` is asked for the paths, with three flags chosen on
    /// purpose:
    ///
    /// - `--untracked-files=all` so a file the user has created but not
    ///   `git add`ed yet is named too. A plain `git diff` only shows tracked
    ///   files, so it would miss exactly the file that is often the new
    ///   work, the reason this function does not build on `git diff`.
    /// - `--no-renames` so a rename is reported as a delete of the old path
    ///   and an add of the new one, two entries this function already
    ///   handles correctly, rather than one entry naming two paths in a
    ///   format this function would otherwise have to parse separately.
    ///   The worktree ends up with the same two facts either way: the old
    ///   path gone, the new path present with the right content.
    /// - `--no-optional-locks` so this never writes a refreshed index back
    ///   to the project. Without it, `git status` can update the index's own
    ///   cached file stat info as a side effect, and this function must
    ///   never write to the project or its index, not even that.
    ///
    /// For each path git status names, this function reads the leading `??`
    /// only to sort a copy into `added` versus `modified`. The action taken
    /// is decided by what is actually on disk, never by the status letters.
    /// `importPath` classifies the path itself, without following a link:
    /// a regular file is copied, a link is recreated by its target text, a
    /// missing path is removed from the worktree, and a directory or
    /// anything else is skipped and recorded rather than acted on. See
    /// `classify` and `importPath` for why, and `ImportReport` for the
    /// shape of what comes back.
    ///
    /// A path git status names twice, which `git rm --cached` does (one
    /// entry for the index losing it, one for the working tree still having
    /// it, untracked), is only imported once: see `seen_paths` below.
    ///
    /// A single bad path, one that cannot be read, written, or classified,
    /// does not abort this function. It is recorded in `report.skipped` and
    /// the rest of the paths are still processed, so a caller always gets a
    /// report back rather than a session that fails to start over one file.
    /// The two failures that do abort, `error.PathEscapesProject` and
    /// `error.OutOfMemory`, are a security invariant and a resource
    /// exhaustion respectively, not an ordinary per-file fault: see
    /// `validateRelativePath`'s own doc comment for the first.
    ///
    /// Every read in this function is against `self.project_root`, on disk,
    /// and every write is against `self.path`, the worktree, on disk.
    /// Nothing here runs `git add`, `git commit`, or any other command that
    /// changes a git repository's own state, in the project or the
    /// worktree, so the project's tree, its index, and its HEAD are exactly
    /// as they were before this call, whether it succeeds or fails partway
    /// through.
    ///
    /// git never lists an empty directory in its own status output: git
    /// does not track directories, only paths to files and links. Since
    /// this function does nothing but walk that status output, an empty
    /// directory is never carried across into the worktree, on purpose, not
    /// as an oversight.
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

        // Keyed on the path slice inside status_output.stdout, which stays
        // alive for the whole call, so nothing here needs its own copy of
        // the key. See this function's own doc comment for why a path can
        // appear more than once.
        var seen_paths: std.StringHashMapUnmanaged(void) = .empty;
        defer seen_paths.deinit(allocator);

        // `-z` separates entries with NUL and turns off git's own quoting of
        // unusual characters in a path, so splitting on NUL and slicing off
        // the leading "XY " gives back the exact bytes on disk.
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

    /// Carry one path named by `git status` into `self`, and record it in
    /// `report`. `entry` is the whole "XY path" record `importUncommitted`
    /// split out. Only its first two bytes, the status letters, are read
    /// here, to tell an untracked path from a tracked one for `report`'s own
    /// `added` versus `modified` split. Everything else about what to do is
    /// decided by `classify`, never by the letters: see `importUncommitted`'s
    /// own doc comment.
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

        // "??" is exactly the code --untracked-files=all gives a path git
        // has never tracked. See ImportReport.added's own doc comment for
        // why this is the one status letter this file reads.
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

    /// Delete `rel_path` from the worktree at `target_path`, because the
    /// project no longer has it on disk. Tolerates the worktree not having
    /// had it either: a file staged as an add and then deleted by hand
    /// before this ran leaves the worktree, checked out at HEAD, with
    /// nothing to remove. Any other failure is recorded in `report.skipped`
    /// rather than aborting the caller. See `importUncommitted`'s own doc
    /// comment for why.
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

    /// Copy the bytes of the regular file at `source_path` to `target_path`,
    /// and record `rel_path` under `report.added` or `report.modified`
    /// depending on `is_new`. A failure to copy is recorded in
    /// `report.skipped` rather than aborting the caller.
    fn copyRegularFile(
        allocator: std.mem.Allocator,
        io: std.Io,
        rel_path: []const u8,
        source_path: []const u8,
        target_path: []const u8,
        is_new: bool,
        report: *ImportReport,
    ) Error!void {
        // make_path: true, since a brand new untracked file can sit in a
        // directory the worktree, checked out at HEAD, has never had.
        std.Io.Dir.copyFileAbsolute(source_path, target_path, io, .{ .make_path = true }) catch |err| {
            const reason = try std.fmt.allocPrint(allocator, "copying into the worktree failed: {s}", .{@errorName(err)});
            return recordSkip(report, allocator, rel_path, reason);
        };
        const list: *std.ArrayList([]u8) = if (is_new) &report.added else &report.modified;
        try list.append(allocator, try allocator.dupe(u8, rel_path));
    }

    /// Recreate, at `target_path`, the symbolic link found at `source_path`,
    /// naming the exact same target text, and record `rel_path` under
    /// `report.added` or `report.modified` depending on `is_new`.
    ///
    /// This never opens `source_path` for reading and never resolves the
    /// link: `std.Io.Dir.readLinkAbsolute` reads the link's own target
    /// string, the bytes stored in the directory entry itself, not the file
    /// the link names. A link inside the project pointing outside it, at
    /// `/home/user/.ssh/id_rsa` or anywhere else, is copied as that string
    /// and nothing more: the worktree gets a link with the same name that
    /// happens to point nowhere the sandbox mounts, never the target's own
    /// content. See this file's own top doc comment and Finding 1 of the
    /// review that added this function.
    fn recreateSymlink(
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

        // The worktree may already hold a plain file or an older link here,
        // checked out at HEAD: clear it first, since Dir.symLink refuses to
        // overwrite an existing entry.
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

        // Not symLinkAbsolute: that function asserts its target text is
        // itself an absolute path, and an ordinary symbolic link's target is
        // very often relative (`../outside/secret.txt`, `../../lib`). The
        // whole point of this function is to recreate whatever target text
        // the original link held, unchanged, so the call below is the plain
        // symLink on an absolute sym_link_path, `.cwd()` ignoring its own
        // directory handle the same way every other *Absolute call in this
        // file already relies on.
        std.Io.Dir.cwd().symLink(io, link_target_text, target_path, .{}) catch |err| {
            const reason = try std.fmt.allocPrint(allocator, "recreating the link in the worktree failed: {s}", .{@errorName(err)});
            return recordSkip(report, allocator, rel_path, reason);
        };

        const list: *std.ArrayList([]u8) = if (is_new) &report.added else &report.modified;
        try list.append(allocator, try allocator.dupe(u8, rel_path));
    }

    /// Own `rel_path` and `reason` (already allocated by the caller) into
    /// `report.skipped`. If appending fails, both are freed rather than
    /// leaked: neither has any other owner at the point this is called.
    fn recordSkip(
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

    /// The commit this worktree is at now, which is `base_commit` unless the
    /// session committed something. The caller owns the returned string.
    ///
    /// **The commit a session made is only in the scratch object store**, so
    /// this names that store as an alternate for the one read. A read of an
    /// alternate can never write to it: see
    /// `git_alternate_object_directories_env`'s own doc comment.
    ///
    /// The worktree is detached, so nothing here can move a branch of the
    /// user, and nothing here changes the project at all: this is a read.
    /// What the caller does with the answer is `chock-broker`'s
    /// `workspace.apply`, outside the sandbox, after an approval.
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
        // **The session's own HEAD is in the copy, not in the project's own
        // metadata directory.** A tool call writes the copy and never the
        // project, which is what closes finding 4, so the checkout's own
        // `.git` names a directory that still reads as `git worktree add`
        // left it. `GIT_DIR` points this one read at the copy instead. The
        // copy's own `commondir` holds the absolute path of the project's
        // `.git`, written by `copyMetaDirectory` for exactly this call, so
        // git finds the object store and the refs from there.
        if (self.worktree_meta_is_copy) {
            try reading_env.put("GIT_DIR", self.worktree_meta_bind_source);
        }
        return readHeadWith(allocator, io, &reading_env, self.path, diag);
    }

    /// True when the session left this worktree at a different commit than
    /// `git worktree add` put it at, which is the one thing that says the
    /// agent produced work worth carrying back. **An idle session answers
    /// false**, and then nothing is asked for and nothing is moved, so a
    /// session that changed nothing cannot make the project dirty.
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

    /// Detach this worktree from the project with `git worktree remove`,
    /// delete the scratch pointer file and, when `create` had to write one,
    /// the empty `config.worktree` scratch file too, and free every field.
    /// Every deletion and every free happens whether or not the `git
    /// worktree remove` call itself succeeded: this value's own bookkeeping
    /// is not left behind for a caller to leak just because the host side
    /// git operation failed. `self` is not valid after this call returns,
    /// successfully or not.
    ///
    /// **This is already correct for a worktree `adopt` rebuilt, and needs no
    /// change.** Every path it touches, the checkout, the scratch object
    /// store, the pointer file, and the `config.worktree` stand-in, belongs
    /// to the session and never to one process, and `adopt` rebuilds all four
    /// as the same strings `create` built. So the process that removes does
    /// not have to be the process that made: `git worktree remove` reads the
    /// registration, which names two paths and no process, and the three
    /// deletions name three paths under the session's own scratch directory.
    /// Nothing here deletes anything the session did not own, whichever
    /// process is holding it at the end. `keep` is correct for the same
    /// reason and more simply: it deletes nothing at all.
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

        // Best effort: on a failure this is the only cleanup a caller gets, and a
        // missing pointer file is not itself a fault worth reporting up.
        deleteFileAbsolute(io, self.pointer_path, diag) catch {};
        // Same reasoning, for the empty config.worktree scratch file, when
        // create had to write one. The project's own real config.worktree,
        // when create found one instead, is never touched here.
        if (self.worktree_config_worktree_is_scratch) {
            deleteFileAbsolute(io, self.worktree_config_worktree_source, diag) catch {};
        }
        // The session's own copy of the worktree metadata directory, which is
        // where every git write and every tool call write of this session
        // went. Best effort, the same as the two deletes above. Only ever the
        // copy: under `.in_place` there is none, and the path this field
        // holds is then the project's own, which this call must not delete.
        if (self.worktree_meta_is_copy) {
            std.Io.Dir.cwd().deleteTree(io, self.worktree_meta_bind_source) catch {};
        }
        // The scratch object store, recursively: a session that is refused
        // leaves nothing behind to clean up. Best effort, the same as the two
        // deletes above: this is the
        // only cleanup a caller gets on a failure, and a store that never
        // got made (create failed before this ran) is not itself a fault
        // worth reporting up.
        std.Io.Dir.cwd().deleteTree(io, self.object_store_source) catch {};

        self.freeFields(allocator);

        if (failed) return error.GitFailed;
    }

    /// Free every field and **leave the worktree where it is on disk**. The
    /// project keeps its `git worktree` registration for it, the checkout
    /// keeps every file the agent wrote, and the scratch object store keeps
    /// every object it made. `self` is not valid after this call returns.
    ///
    /// **This exists because a session that ends badly used to delete the work
    /// it had done.** Only a commit reaches the user's repository, which is
    /// the rule the split of `.git` exists for and is not in question here. What was
    /// wrong was the cleanup: `remove` runs on every ending, so a session that
    /// errored, was refused, reached its budget, or was interrupted destroyed
    /// whatever it had produced. Measured on 2026-08-22: a rate limit ended a
    /// session and 105 changed files went with the worktree.
    ///
    /// The caller is the one that decides which ending is which, and the
    /// caller is also the one that has to say where the kept worktree is: a
    /// directory nobody names is a directory nobody finds and nobody removes.
    /// See `src/run.zig` and `chock workspace`.
    pub fn keep(self: *Worktree, allocator: std.mem.Allocator) void {
        self.freeFields(allocator);
    }

    /// Free every string this value owns. Shared by `remove` and `keep`, so
    /// the two can never disagree about what is owned: a second copy of this
    /// list is how one of them quietly starts leaking.
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

/// Where the sandbox sees `source`.
///
/// **One function, so the two layouts cannot drift apart.** Under
/// `.remapped` the answer is the synthetic path `parts` spells, which is what
/// the mount tree builds. Under `.in_place` there is no mount tree, so the
/// answer is the host path itself and every mount built from it moves nothing.
/// The caller owns the result.
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

/// Where the sandbox sees the session's own copy of the worktree metadata
/// directory.
///
/// **This is `targetPath` with the copy in place of the project's own
/// directory, and the difference is the whole of finding 4 on macOS.** Under
/// `.remapped` a bind mount puts the copy at the path the checkout's own
/// `.git` file already names, so the answer is that synthetic path. Under
/// `.in_place` nothing moves, so the only path the sandbox can reach the copy
/// by is the copy's own, and the project's own `.git/worktrees/<id>` is then
/// covered by nothing but the read only rule over the whole of `.git`. See
/// `Worktree.gitEnv` for how git is pointed at the copy there.
///
/// The caller owns the result.
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

/// Create a throwaway worktree of `project_root`, detached at HEAD, so a session
/// can never move a branch of the user. The worktree is named after `session_id`
/// and made directly under `scratch_dir`, which must already exist: a real caller
/// gives it a session scratch directory, and a test gives it its own
/// `std.testing.tmpDir`.
///
/// The layout is the host's own: see `createWithLayout` for the call that
/// names one, and `chock-workspace/layout.zig` for what the two mean.
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

/// `create`, with the layout named rather than read from the target.
///
/// **This exists so a Linux test can build the mount list macOS gets.** The
/// layout is a comptime fact of a real build, and a boundary that only one
/// platform's continuous integration ever compiles is a boundary nobody
/// checks. See `worktree.zig`'s own tests for the in place shapes.
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
    // From here on, `git worktree add` has already registered a linked worktree
    // against project_root. Any failure below must undo that, or the session
    // leaves a live worktree behind that nothing ever cleans up.
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

    // The scratch object store. The host side directory is made now, under
    // scratch_dir, named after session_id the same way the pointer file and
    // the config.worktree scratch file below are: create is the only place any
    // of the three scratch paths this function owns come into being.
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

    // The real object store's own path inside the sandbox: sandbox_git_root
    // plus "objects", the subdirectory of entry 1's own read only bind of
    // the whole real .git. GIT_ALTERNATE_OBJECT_DIRECTORIES names it so git
    // can read every object that already exists, without ever being able to
    // write there: see gitEnv's own doc comment.
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

    // Finding 4: the sandbox writes a copy of this directory and never the
    // project's own. See `Worktree.mounts` for the measurement that rules out
    // a read only mount here, and `copyMetaDirectory` for what the copy
    // holds.
    const worktree_meta_bind_source = try metaBindSource(allocator, scratch_dir, session_id);
    errdefer allocator.free(worktree_meta_bind_source);
    const worktree_meta_is_copy = true;
    try copyMetaDirectory(allocator, io, worktree_meta_source, worktree_meta_bind_source, git_dir, diag);
    errdefer std.Io.Dir.cwd().deleteTree(io, worktree_meta_bind_source) catch {};

    const worktree_meta_target = try metaTarget(allocator, layout, worktree_meta_bind_source, &.{ sandbox_git_root, "worktrees", worktree_id });
    errdefer allocator.free(worktree_meta_target);

    // **`GIT_DIR` and `GIT_WORK_TREE`, under `.in_place` alone.** See the
    // fields of the same names for why the checkout's own `.git` file cannot
    // carry this on macOS, and why the two variables go together.
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

    // **Every target below is a name under `worktree_meta_target`, on both
    // layouts.** That directory is the copy on `.in_place` and the copy's own
    // mount target on `.remapped`, so a file named against it is the file the
    // sandbox really reaches either way. The matching `_source` strings stay
    // the project's own paths, which is what makes them worth keeping: they
    // are how a caller reads the untouched original after the session.
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

    // config.worktree only exists on disk when the project turned on
    // extensions.worktreeConfig and something has already set a value with
    // --worktree. This read of the disk decides which source `mounts` binds
    // over the target below, never whether it binds one at all: Finding 1 of
    // a later review was exactly a version of this function that treated
    // "not there yet" as "safe to leave for entry 2's read write reach", and
    // git then wrote a real one from inside the sandbox before the first
    // host side git command read it back. See this file's own top doc
    // comment.
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
    // **`.in_place` needs no stand-in, and must not write one.** The stand-in
    // exists so that a read only mount can cover a path with no file under it
    // yet. Under this layout nothing is mounted: the entry becomes a rule on
    // the path itself, and the kernel checks that rule when git creates the
    // file, so a path with nothing under it is guarded exactly as a path with
    // a file under it is. What `mounts` names there is the copy's own
    // `config.worktree`, not this string: see `Worktree.metaFileSource`.
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

/// Rebuild the `Worktree` value for a checkout that is **already on disk** at
/// `<scratch_dir>/<session_id>`, so a second process can take over the
/// workspace of a session that hands over. The value this returns is the one
/// `create` returns for the same arguments, field for field and byte for
/// byte, and this runs no git command at all.
///
/// **A worktree registration names two paths and no process.** Measured by
/// hand against real git: `<worktree>/.git` is the one line file
/// `gitdir: <project>/.git/worktrees/<name>`, and that directory's own
/// `gitdir` file points back at `<worktree>/.git`. Nothing under
/// `.git/worktrees/<name>` names a process. There is no pid, no lock file,
/// because Chock never runs `git worktree lock`, and no held file descriptor:
/// the files are `HEAD`, `ORIG_HEAD`, `index`, `commondir`, `gitdir`, and
/// `logs/`. A genuinely different process wrote a file in such a checkout,
/// staged it, and committed it, with no handover step of any kind. So a
/// second owner needs to run no git command to take a worktree. What it needs
/// is this: the value in memory, rebuilt without `git worktree add`, which
/// would fail here anyway, because the path is already registered.
///
/// Every way this differs from `create`, and the reason for each:
///
/// 1. **No `git worktree add`, and no `cleanupFailedAdd`.** The checkout is
///    not this call's to make, so it is not this call's to unmake either. A
///    failure anywhere below leaves the directory exactly as this call found
///    it, because the work in it belongs to the session that is handing over,
///    and a cleanup that removed it would destroy that work. The scratch
///    object store follows the same rule: `create` deletes it again when a
///    later step fails, and this must not, because it can already hold the
///    objects of every commit that session made.
///
/// 2. **The checkout has to be there already, and it has to be a linked
///    worktree.** Each refusal has a name of its own. `error.NoWorktreeToAdopt`
///    when the path is not a directory, is not there at all, or holds no
///    `.git`. `error.NotALinkedWorktree` when `.git` is there but is not the
///    one line `gitdir:` pointer, which covers a `.git` directory, the shape
///    a main checkout has and a linked worktree never does.
///    `error.WorktreeRegistrationGone` when the registration the `.git` file
///    names is not under `<project_root>/.git/worktrees/`. That last one is
///    checked on disk, never with a git command: a `.git` file that names a
///    registration git has pruned is a checkout no git command works in, and
///    adopting it would give the new owner a workspace that fails on its
///    first commit.
///
/// 3. **`base_commit` comes from the caller, and is never read back from
///    HEAD.** This is the one field the disk cannot give back, and getting it
///    wrong is silent. `headMoved` compares `git rev-parse HEAD` against
///    `base_commit` to decide whether the session made work worth carrying
///    back. A session that already committed before it handed over has a HEAD
///    that is not its base, so an `adopt` that read HEAD would set
///    `base_commit` to the session's own commit, `headMoved` would answer
///    false, and the commit would never reach the user's repository. The
///    caller's string is copied into the returned value, and nothing here
///    reads HEAD at all.
///
/// 4. **The scratch object store, the `config.worktree` stand-in, and the
///    pointer file are made when they are missing and reused when they are
///    there.** All three sit under `scratch_dir`, and all three belong to the
///    session and not to one process, so the second owner of the session owns
///    all three. `createDirPath` already tolerates a directory that exists.
///    `writeEmptyScratchFile` and `writePointerFile` both open with the
///    defaults of `std.Io.Dir.CreateFileOptions`, `truncate = true` and
///    `exclusive = false`, so each one rewrites a file that is already there
///    and leaves the same bytes: an empty file stays empty, and the pointer
///    file gets the same `gitdir:` line, because `worktree_meta_target` is a
///    join of the same components.
///
///    **Which `config.worktree` gets bound is a fact about the disk, never
///    about the caller.** `create` binds the project's own
///    `<meta>/config.worktree` when one is there, and an empty scratch stand
///    in when there is not. This asks the same question, at the same path,
///    with the same call, so the same disk state gives the same answer:
///    nothing here turns a real file into a stand-in, or a stand-in into a
///    real file. Carrying the flag over from the first process instead would
///    be exactly the mistake: `create` can have written a stand-in for a
///    project that has since gained a real `config.worktree`, and `mounts`
///    would then bind an empty file over a file git has to read.
///
/// 5. Every other field is a path join, and every join below is the join
///    `create` makes, from the same components in the same order, so the two
///    calls produce the same bytes. `worktree_id` is read back from the
///    `.git` file with `readWorktreeId`, exactly as `create` reads it,
///    because git deduplicates a worktree name and the id is not always the
///    session id.
///
/// `remove` and `keep` are already correct for the value this returns: see
/// `Worktree.remove`'s own doc comment.
///
/// `env` is in the argument list and unused, on purpose. `adopt` stands
/// beside `create` and a caller swaps one for the other, and every later call
/// on the returned value, `remove`, `headMoved`, and `importUncommitted`,
/// still needs the same map. A caller that holds one environment for the
/// session hands it to both.
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

/// `adopt`, with the layout named rather than read from the target. See
/// `createWithLayout`, which this stands beside for the same reason.
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

    // The checkout itself, first, so a caller that names the wrong session
    // gets a refusal before anything at all is written.
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
    // Nothing there is nothing to adopt. Something there that is not an
    // ordinary file cannot be the one line pointer every linked worktree has:
    // a `.git` directory is the shape of a main checkout, so it is refused as
    // "not a linked worktree" and not as "nothing to adopt".
    const found_dotgit_kind = dotgit_kind orelse return error.NoWorktreeToAdopt;
    if (found_dotgit_kind != .file) return error.NotALinkedWorktree;

    const worktree_id = try readWorktreeId(allocator, io, dotgit_path, diag);
    errdefer allocator.free(worktree_id);

    // Point 3 above: the caller's own string, copied. Nothing here reads HEAD.
    const base_commit_owned = try allocator.dupe(u8, base_commit);
    errdefer allocator.free(base_commit_owned);

    const project_root_owned = try allocator.dupe(u8, project_root);
    errdefer allocator.free(project_root_owned);

    const git_dir = try std.fs.path.join(allocator, &.{ project_root_owned, ".git" });
    errdefer allocator.free(git_dir);

    const worktree_meta_source = try std.fs.path.join(allocator, &.{ git_dir, "worktrees", worktree_id });
    errdefer allocator.free(worktree_meta_source);

    // The registration the `.git` file names, read straight off the disk. A
    // `git worktree list` would answer the same question, but this call runs
    // no git at all, and the directory being there is the whole fact: see
    // point 2 above.
    const registration_found = directoryOnDisk(io, worktree_meta_source) catch |err| {
        diagnostic.noteErr(diag, .project_entry_check, err);
        return error.Unexpected;
    };
    if (!registration_found) return error.WorktreeRegistrationGone;

    const sandbox_root = try targetPath(allocator, layout, worktree_path, &.{project_root_owned});
    errdefer allocator.free(sandbox_root);

    const sandbox_git_root = try targetPath(allocator, layout, git_dir, &.{ sandbox_git_root_prefix, session_id });
    errdefer allocator.free(sandbox_git_root);

    // The scratch object store. Made when
    // the first process never got this far, and reused when it did:
    // `createDirPath` tolerates a directory that already exists, and the
    // objects of every commit that session made are in it. There is no
    // `errdefer` that deletes this, unlike `create`'s own: see point 1 above.
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

    // The session's own copy of the worktree metadata directory. Made when
    // the first process never got this far, and reused when it did, the same
    // rule the scratch object store above follows and for the same reason:
    // the copy holds every commit that session made, and a second copy over
    // the top would put the workspace back at the commit it started from.
    // There is no `errdefer` that deletes this, unlike `create`'s own.
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

    // **`GIT_DIR` and `GIT_WORK_TREE`, under `.in_place` alone.** See the
    // fields of the same names for why the checkout's own `.git` file cannot
    // carry this on macOS, and why the two variables go together.
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

    // **Every target below is a name under `worktree_meta_target`, on both
    // layouts.** That directory is the copy on `.in_place` and the copy's own
    // mount target on `.remapped`, so a file named against it is the file the
    // sandbox really reaches either way. The matching `_source` strings stay
    // the project's own paths, which is what makes them worth keeping: they
    // are how a caller reads the untouched original after the session.
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

    // The same read of the same path `create` makes, for the reason point 4
    // above gives: the disk decides which file `mounts` binds, and the answer
    // must not depend on which process asked.
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
    // **`.in_place` needs no stand-in, and must not write one.** The stand-in
    // exists so that a read only mount can cover a path with no file under it
    // yet. Under this layout nothing is mounted: the entry becomes a rule on
    // the path itself, and the kernel checks that rule when git creates the
    // file, so a path with nothing under it is guarded exactly as a path with
    // a file under it is. What `mounts` names there is the copy's own
    // `config.worktree`, not this string: see `Worktree.metaFileSource`.
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
    // Only the string is freed on a later failure, never the file. `create`
    // deletes the stand-in it wrote, because it wrote it; this call cannot
    // tell its own write from one the first process already made, and
    // deleting a file of the session is the one thing point 1 forbids.
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

/// The commit the worktree at `worktree_path` has checked out, as a
/// hexadecimal object id with no trailing newline. The caller owns it.
///
/// `GIT_ALTERNATE_OBJECT_DIRECTORIES` is set to the session's own scratch
/// object store by `Worktree.headAfterSession`, its one caller that reads a
/// commit the session itself made: that commit is only in the scratch store,
/// and `rev-parse` verifies the object it names. `create`'s own call needs no
/// such alternate, because the commit it reads is one the project already
/// has.
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

/// Reject a `session_id` that is empty, is `.` or `..`, or holds a `/`. Every
/// caller of `create` below joins `session_id` straight onto `scratch_dir` to
/// build the worktree's own path, the pointer file's name, and the sandbox mount
/// target, so an unchecked `../x` would place any of those three outside the
/// scratch directory this session owns.
fn validateSessionId(session_id: []const u8) Error!void {
    if (session_id.len == 0) return error.InvalidSessionId;
    if (std.mem.eql(u8, session_id, ".")) return error.InvalidSessionId;
    if (std.mem.eql(u8, session_id, "..")) return error.InvalidSessionId;
    if (std.mem.indexOfScalar(u8, session_id, '/') != null) return error.InvalidSessionId;
}

/// Undo a `git worktree add` that succeeded when a later step in `create` fails,
/// so the failure does not leave a registered worktree behind that nothing ever
/// removes. Best effort: `create` is already returning the error that triggered
/// this, and there is no second error channel to report a cleanup failure on.
fn cleanupFailedAdd(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    worktree_path: []const u8,
) void {
    // No diagnostic: this is the best effort cleanup of a failure that is
    // already on its way to the caller, and the slot holds that first fault.
    var output = git.run(allocator, io, env, project_root, &.{
        "worktree", "remove", "--force", worktree_path,
    }, null) catch return;
    output.deinit(allocator);
}

/// Read the `.git` file `git worktree add` wrote at `dotgit_path`, and return the
/// last path component of the `gitdir:` value it names: the id git assigned this
/// worktree under `.git/worktrees/`. The caller owns the returned slice.
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

/// Write the scratch replacement `.git` file at `pointer_path`, naming
/// `worktree_meta_target` as its `gitdir:` value.
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

/// Where the session's own copy of the worktree metadata directory lives.
/// **One function, called by both `create` and `adopt`**, because `adopt` has
/// to rebuild the very string `create` built or the second owner reads a
/// different directory from the one the first owner's session wrote. The
/// caller owns the result.
///
/// **Both layouts get a copy, and the layout only decides how git is pointed
/// at it.** `Layout.remapped` binds the copy at the path the checkout's own
/// `.git` already names. `Layout.in_place` cannot move a path, so it names the
/// copy by configuration instead: see `Worktree.gitEnv`.
fn metaBindSource(
    allocator: std.mem.Allocator,
    scratch_dir: []const u8,
    session_id: []const u8,
) std.mem.Allocator.Error![]u8 {
    const name = try std.fmt.allocPrint(allocator, "{s}.meta", .{session_id});
    defer allocator.free(name);
    return std.fs.path.join(allocator, &.{ scratch_dir, name });
}

/// Copy the whole of `source` to `destination`, then write `destination`'s
/// own `commondir` so a host side git can read the copy directly. `create`
/// uses this to build `Worktree.worktree_meta_bind_source`: see
/// `Worktree.mounts`'s own doc comment for the finding this closes.
///
/// **The copy is what the sandbox writes, so the project's own metadata
/// directory is never written by a tool call.** It holds what
/// `git worktree add` wrote, which is `HEAD`, `ORIG_HEAD`, `index`,
/// `commondir`, `gitdir`, `logs/HEAD`, an empty `refs/`, and
/// `config.worktree` on a project that turned the extension on. All of it is
/// small: the index is the one file that grows with the project, and it is
/// the same file `git status` reads on every call anyway.
///
/// **`commondir` is rewritten, and it is the one byte level difference.** git
/// writes `../..` there, which is correct for the copy's own mount target
/// inside the sandbox, because that target keeps the shape
/// `<git dir>/worktrees/<id>`. It is wrong for the copy's real path under the
/// scratch directory, where `../..` names the scratch directory's own parent.
/// The copy on disk gets the absolute path of the project's own `.git`
/// instead, which is correct on the host, and `Worktree.mounts`'s own entry 4
/// binds the project's own `commondir` read only over this one inside the
/// sandbox, so the sandbox still reads `../..`. Two readers, one file each,
/// and each one correct where it looks.
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

/// Copy every directory and every regular file under `source` to
/// `destination`, which is made if it is not there. Nothing else is copied: a
/// linked worktree's own metadata directory holds directories and regular
/// files and nothing more, and a name of another kind appearing there is a
/// shape this function has no answer for, so it is skipped rather than
/// guessed at.
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

/// Write a zero byte scratch file at `path`. `create` uses this to stand in
/// for a `config.worktree` the project does not have yet, so `mounts` always
/// has a real file to bind read only over the target, never a conditional
/// mount that a project without one today can outgrow tomorrow.
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

/// True if `absolute_path` names a file that exists on disk, false if it
/// does not exist at all or some component of it is not a directory. Any
/// other failure, such as a permission error, is passed up rather than
/// folded into `false`. Used by `create` to decide whether a worktree has a
/// `config.worktree`, and by tests. `importPath` itself uses `classify`
/// below, which does not follow a link the way this function's own default
/// `statFile` call does.
fn existsOnDisk(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!bool {
    _ = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    return true;
}

/// True if `absolute_path` names a directory that exists on disk, false if
/// nothing is there at all or something that is not a directory is. Any other
/// failure, such as a permission error, is passed up rather than folded into
/// `false`, the same shape `existsOnDisk` above uses.
///
/// `adopt` asks this twice, and the two questions it answers are the two
/// halves of "is there a worktree here to take": the checkout at
/// `<scratch_dir>/<session_id>`, and the registration under
/// `<project_root>/.git/worktrees/<worktree_id>`. `existsOnDisk` cannot
/// answer either one, because it says yes to a plain file, and a file where
/// the checkout belongs is not a checkout.
fn directoryOnDisk(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!bool {
    const entry_stat = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => |e| return e,
    };
    return entry_stat.kind == .directory;
}

/// What `importPath` found at `absolute_path`, without following a link to
/// get there. `null` means nothing is there at all: no file, no link, no
/// directory, the path git named is simply gone. Anything else is the kind
/// `statFile` itself reports for the entry, unresolved.
///
/// `follow_symlinks = false` is the one thing that makes this function
/// different from `existsOnDisk`, and it is not a small difference: with the
/// default `true`, a symbolic link inside the project pointing outside it,
/// at `key -> /home/user/.ssh/id_rsa`, would be reported as an ordinary
/// file, because `statFile` resolves the link before answering. `importPath`
/// would then copy the bytes of `/home/user/.ssh/id_rsa`, a file the sandbox
/// was never given, into the worktree under an innocent name. A link is a
/// name, not the file it names, and this function reports it as exactly
/// that: `Kind.sym_link`, never resolved. A broken link, one whose target
/// does not exist, is reported the same way, `Kind.sym_link`, not folded
/// into `null`: `statFile` with `follow_symlinks = false` only ever fails to
/// find the directory entry itself, never the target it names.
fn classify(io: std.Io, absolute_path: []const u8) std.Io.Dir.StatFileError!?std.Io.File.Kind {
    const entry_stat = std.Io.Dir.cwd().statFile(io, absolute_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return null,
        else => |e| return e,
    };
    return entry_stat.kind;
}

/// Reject a `rel_path` that is absolute, or holds a `..` component. Every
/// caller joins this straight onto `project_root` to read a file, and onto
/// the worktree's own path to write one. An unchecked value could then reach
/// outside either. `git status` itself never emits such a path in ordinary
/// use, but `importPath` is the one place in this file that turns a string
/// git printed into a filesystem path, so it is the one place that checks.
///
/// This guard covers only `rel_path` itself, the name git gave a changed
/// entry. It does not, and cannot, cover a symbolic link's own target text:
/// a link named `key` with a target of `/home/user/.ssh/id_rsa` passes this
/// check cleanly, because `key` is an ordinary relative path with no `..` in
/// it. That escape route is closed a different way, not by this guard: see
/// `classify` and `recreateSymlink`, which read a link's target text only to
/// recreate it, and never open it to read the file it names.
fn validateRelativePath(rel_path: []const u8) Error!void {
    if (rel_path.len == 0) return error.PathEscapesProject;
    if (std.fs.path.isAbsolute(rel_path)) return error.PathEscapesProject;

    var components = std.mem.tokenizeScalar(u8, rel_path, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return error.PathEscapesProject;
    }
}

// Every test below builds its own project inside a fresh std.testing.tmpDir, per
// this project's own rule: no test depends on the repository Chock itself lives
// in. Each test sets its own GIT_CEILING_DIRECTORIES, the same pattern git.zig's
// own tests use and explain in full: this project's own checkout is itself a git
// repository, and tmpDir makes every scratch directory somewhere underneath it,
// so git's own upward search for a .git directory would otherwise walk past a
// fresh scratch repository and find this project's real one instead.

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

fn makeDir(path: [:0]const u8) !void {
    std.Io.Dir.createDirAbsolute(std.testing.io, path, .default_dir) catch return error.MkdirFailed;
}

/// A fresh repository at `root_path`, one commit deep, with `tracked.txt`
/// committed. `root_path` and `scratch_path` are two directories directly under
/// the same `tmpDir`: `root_path` becomes the project, `scratch_path` is where
/// `create` is told to put the worktree and its pointer file, kept apart so
/// listing one never picks up the other's files.
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
/// been applied in order, the same way a real mount namespace resolves a path
/// through a chain of bind mounts applied one after another: the kernel applies
/// mounts in order and the *last* one whose target covers the path wins, not the
/// one with the longest target. A helper that picked the longest target instead
/// would report a narrower, older mount as still governing a path that a wider
/// mount appended after it has since taken over, hiding exactly the mistake this
/// is meant to catch. Used by tests that must not trust one entry's own label,
/// only what a real mount namespace would resolve.
///
/// Every entry `Worktree.mounts` builds is a bind mount, never an overlay, so
/// this only ever matches `.bind` entries, and returns a pointer to the bind
/// payload itself: every caller keeps reading `.source` and `.read_only`
/// straight off the result, unchanged from before `Mount` grew a second kind.
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

/// True if `target` names `path` itself, or a directory that `path` is inside.
/// Compares whole path components, not raw bytes: `/chock-git/sess1` must not
/// match `/chock-git/sess10`, a different session's own path that merely starts
/// with the same characters.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // The worktree's own .git is left on disk exactly as git wrote it, so this
    // reads the worktree's HEAD directly, no sandbox needed.
    var head_output = try git.run(allocator, std.testing.io, &project.env, worktree.path, &.{ "rev-parse", "HEAD" }, null);
    defer head_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, head_output.term);
    try std.testing.expectEqualStrings(project.head_sha, std.mem.trimEnd(u8, head_output.stdout, "\n"));
}

test "the mount list gives the worktree read write and the object store read only" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const worktree_mount = mostSpecificMount(list, worktree.project_root) orelse return error.NoMountCoversTheWorktree;
    try std.testing.expectEqual(false, worktree_mount.read_only);
    try std.testing.expectEqualStrings(worktree.path, worktree_mount.source);

    const objects_path = try std.fs.path.join(allocator, &.{ worktree.sandbox_git_root, "objects" });
    defer allocator.free(objects_path);
    const objects_mount = mostSpecificMount(list, objects_path) orelse return error.NoMountCoversTheObjectStore;
    try std.testing.expectEqual(true, objects_mount.read_only);
}

test "the mount list never gives .git/hooks write access" {
    // A writable hook directory runs the agent's code on the next git command.
    // This walks the whole list through mostSpecificMount rather than looking at
    // the entry named for the metadata directory, because the fault this guards
    // against is a wider entry above it that happens to cover hooks too: a test
    // that only checked one entry would pass while that hole stayed open.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const hooks_path = try std.fs.path.join(allocator, &.{ worktree.sandbox_git_root, "hooks" });
    defer allocator.free(hooks_path);
    const hooks_mount = mostSpecificMount(list, hooks_path) orelse return error.NoMountCoversHooks;
    try std.testing.expectEqual(true, hooks_mount.read_only);
}

test "the index of the worktree is writable, so git status works inside the sandbox" {
    // A linked worktree writes .git/worktrees/<id>/index. If that mount were read
    // only, git would fail on the lock file and every tool call that touches git
    // would break.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const index_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "index" });
    defer allocator.free(index_path);
    const index_mount = mostSpecificMount(list, index_path) orelse return error.NoMountCoversTheIndex;
    try std.testing.expectEqual(false, index_mount.read_only);
}

test "HEAD and the logs of the worktree are writable, matching the index" {
    // Same reasoning as the index test above, for the other two files a linked
    // worktree writes to on an ordinary git status or commit.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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
}

test "finding 4: the metadata directory the sandbox writes is the session's own copy" {
    // The whole of `.git/worktrees/<id>` is read write, because `git add` and
    // `git commit` create and rename lock files in it and a read only mount
    // there answers EROFS. So the directory a tool call writes must not be
    // the project's own. This pins the source of the entry that governs it.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(worktree.worktree_meta_is_copy);
    try std.testing.expect(!std.mem.eql(u8, worktree.worktree_meta_bind_source, worktree.worktree_meta_source));
    // Under the session's own scratch directory, next to the scratch object
    // store and the pointer file, and never inside the project.
    try std.testing.expect(std.mem.startsWith(u8, worktree.worktree_meta_bind_source, project.scratch_path));

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    // Every writable path under the metadata directory resolves to the copy,
    // read through `mostSpecificMount` rather than off one entry's own label,
    // because a wider entry appended later is the fault this guards against.
    for ([_][]const u8{ "index", "HEAD", "logs", "logs/HEAD", "refs", "probe-from-session" }) |name| {
        const path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, name });
        defer allocator.free(path);
        const mount = mostSpecificMount(list, path) orelse return error.NoMountCoversTheFile;
        try std.testing.expectEqual(false, mount.read_only);
        try std.testing.expect(std.mem.startsWith(u8, mount.source, worktree.worktree_meta_bind_source));
    }
}

test "finding 4: the copy holds what git worktree add wrote, and a commondir a host git can follow" {
    // The copy is the sandbox's git directory, so a name git wrote and this
    // copy lost is a git command that fails on the first tool call. And
    // `headAfterSession` reads the copy on the host with `GIT_DIR`, which
    // needs a `commondir` that resolves from the copy's own real path: git
    // writes `../..` there, correct only for the mount target inside the
    // sandbox, so `copyMetaDirectory` writes the absolute path instead.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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

    // The project's own commondir is untouched and still says `../..`, which
    // is what `mounts`'s own entry 4 binds read only over the copy's, so the
    // sandbox reads the relative form and the host reads the absolute one.
    const project_commondir = try readFile(allocator, worktree.worktree_commondir_source);
    defer allocator.free(project_commondir);
    try std.testing.expectEqualStrings("../..", std.mem.trimEnd(u8, project_commondir, "\n"));
}

test "finding 4: removing a worktree deletes the copy, and keeping one leaves it" {
    // The copy holds the session's own git state, so `keep` must leave it
    // where a person can still read it, and `remove` must take it, or every
    // session leaks a whole metadata directory under the scratch directory.
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
    // **The shape of the fault this test exists for.** An earlier version of
    // this file gave `.in_place` no copy, because a copy cannot be made to
    // appear at the path git looks for where no path can be moved. That left
    // entry 3 binding the project's own `.git/worktrees/<id>` read write on
    // macOS, which is finding 4 exactly as the red team found it. The copy is
    // made on both layouts now, and `.in_place` reaches it by its own real
    // path, so nothing overrides entry 1 for the project's own `.git`.
    //
    // Mutation check: make `metaTarget` answer `parts` on both layouts and
    // the mount assertions below fail, because entry 3's target goes back
    // inside the project's own `.git`.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .in_place, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(worktree.worktree_meta_is_copy);
    try std.testing.expect(!std.mem.eql(u8, worktree.worktree_meta_source, worktree.worktree_meta_bind_source));
    // The copy is where the sandbox reaches it, because nothing is moved.
    try std.testing.expectEqualStrings(worktree.worktree_meta_bind_source, worktree.worktree_meta_target);
    try std.testing.expect(std.mem.startsWith(u8, worktree.worktree_meta_target, project.scratch_path));

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    // **Every entry moves nothing**, which is the one shape the Darwin driver
    // can express, and the whole reason the copy has to be named by its own
    // path here. See `darwin/driver.zig`'s own `expressibleOn`.
    for (list) |entry| {
        try std.testing.expectEqualStrings(entry.bind.source, entry.bind.target);
    }

    // Nothing at all under the project's own `.git` is left read write, so
    // the last word on `.git/worktrees/<id>` is entry 1's read only bind.
    for (list) |entry| {
        if (entry.bind.read_only) continue;
        try std.testing.expect(!std.mem.startsWith(u8, entry.bind.target, worktree.git_dir));
    }

    // And git is told where the copy is, since no path says so for it.
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
}

test "the remapped layout names no GIT_DIR, because the checkout's own .git file already does" {
    // The other edge, and the one that keeps the Linux answer as it was. A
    // `GIT_DIR` there would reach every git command a tool call makes,
    // including one run against a repository the agent cloned itself, and the
    // bind mount already puts the copy at the path the checkout names.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expectEqual(@as(?[]u8, null), worktree.git_dir_env);
    try std.testing.expectEqual(@as(?[]u8, null), worktree.git_work_tree_env);

    const env = try worktree.gitEnv(allocator);
    defer allocator.free(env);
    try std.testing.expectEqual(@as(usize, 2), env.len);
    for (env) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry, "GIT_DIR="));
        try std.testing.expect(!std.mem.startsWith(u8, entry, "GIT_WORK_TREE="));
    }
}

test "the mount list keeps commondir and gitdir of the worktree's own metadata read only" {
    // The attack this guards against: a writable commondir or gitdir lets the
    // agent point git at a git directory of its own choosing, and a later git
    // command run on the host, outside the sandbox, follows it and reads
    // whatever config the agent left there, including a core.hooksPath or
    // core.fsmonitor that runs on the host with no sandbox around it at all.
    // Both are named individually, and both always exist for a linked
    // worktree, unlike config.worktree: see the test below for that one.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    for ([_][]const u8{ "commondir", "gitdir" }) |name| {
        const path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, name });
        defer allocator.free(path);
        const mount = mostSpecificMount(list, path) orelse return error.NoMountCoversTheFile;
        try std.testing.expectEqual(true, mount.read_only);
    }
}

test "config.worktree stays read only when a project has one" {
    // config.worktree, on a project that turns on extensions.worktreeConfig,
    // is the same attack as a writable commondir without even needing one:
    // it is git config read straight out of this directory. Most projects
    // never write this file at all, which is what the test below covers;
    // this one covers the project that does.
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

    // Turning the extension on is not enough by itself: git only writes
    // config.worktree the first time something actually sets a value with
    // --worktree. Doing that on the main checkout, before any linked
    // worktree exists, is what makes git worktree add below hand the new
    // worktree one of its own too, confirmed by hand.
    var worktree_config_output = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "config", "--worktree", "chock.probe", "1",
    }, null);
    defer worktree_config_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, worktree_config_output.term);

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // git worktree add itself writes config.worktree once the extension is
    // on and the main checkout already has one. Confirmed here rather than
    // assumed, so this test does not pass for the wrong reason if a future
    // git version stops doing that: the source mounted below must be the
    // project's own real file, not create's own scratch stand-in.
    try std.testing.expect(!worktree.worktree_config_worktree_is_scratch);

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "config.worktree" });
    defer allocator.free(path);
    const mount = mostSpecificMount(list, path) orelse return error.NoMountCoversTheFile;
    try std.testing.expectEqual(true, mount.read_only);
}

test "config.worktree is absent, so create writes an empty scratch file and mounts it read only" {
    // Finding 1: most projects never turn extensions.worktreeConfig on, so
    // config.worktree never exists on disk at create time. An earlier
    // version of this file read that absence as "safe to leave under the
    // metadata directory's own read write entry", and a project with the
    // extension already on could gain a real config.worktree moments later,
    // written by git itself from inside the sandbox. This test pins the
    // fix: the path is covered by its own read only mount regardless, and
    // the file behind it is create's own empty scratch file, never the
    // metadata directory's real, writable source.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expect(worktree.worktree_config_worktree_is_scratch);
    try std.testing.expect(!std.mem.eql(u8, worktree.worktree_config_worktree_source, worktree.worktree_meta_source));

    const list = try worktree.mounts(allocator);
    defer allocator.free(list);

    const config_path = try std.fs.path.join(allocator, &.{ worktree.worktree_meta_target, "config.worktree" });
    defer allocator.free(config_path);
    const config_mount = mostSpecificMount(list, config_path) orelse return error.NoMountCoversTheFile;
    try std.testing.expectEqual(true, config_mount.read_only);
    try std.testing.expectEqualStrings(worktree.worktree_config_worktree_source, config_mount.source);

    // The scratch file itself is real, on disk, and empty: a bind mount
    // target must already exist, and an empty file gives git nothing to
    // read as config even if something upstream of this mount ever slipped.
    const contents = try readFile(allocator, worktree.worktree_config_worktree_source);
    defer allocator.free(contents);
    try std.testing.expectEqual(@as(usize, 0), contents.len);

    // The main .git config, which is what git actually reads to decide
    // whether extensions.worktreeConfig is on at all, stays read only
    // regardless.
    const shared_config_path = try std.fs.path.join(allocator, &.{ worktree.sandbox_git_root, "config" });
    defer allocator.free(shared_config_path);
    const shared_config_mount = mostSpecificMount(list, shared_config_path) orelse return error.NoMountCoversTheSharedConfig;
    try std.testing.expectEqual(true, shared_config_mount.read_only);
}

test "removing a worktree that never had a real config.worktree deletes the empty scratch file it wrote" {
    // remove must clean up create's own scratch file, or every session that
    // opens a project with no config.worktree yet leaks one small file
    // under the scratch directory forever.
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
    // The kernel applies mounts in order and the last one that covers a path
    // wins. A helper that instead picks the longest matching target keeps
    // reporting a narrower, earlier entry even after a wider one was appended
    // that actually shadows it. That mistake is exactly what let a wider read
    // write entry slip past the hooks test in the first review of this file.
    const list = [_]Mount{
        .{ .bind = .{ .source = "a", .target = sandbox_git_root_prefix ++ "/sess1", .read_only = true } },
        .{ .bind = .{ .source = "b", .target = sandbox_git_root_prefix, .read_only = false } },
    };
    const found = mostSpecificMount(&list, sandbox_git_root_prefix ++ "/sess1/hooks") orelse
        return error.NoMountCoversHooks;
    try std.testing.expectEqual(false, found.read_only);
}

test "a wide mount at /run, placed last, shadows every path Chock puts under it" {
    // **The trap this project has already paid for once.** Chock's own paths
    // moved a level deeper, from three top level names to `/run/chock/git`,
    // `/run/chock/objects`, and `lib/chock-core/tools.zig`'s own
    // `/run/chock/tool-bin`, which puts more weight on exactly this
    // ordering. A single entry at `/run` appended after them takes all three
    // at once.
    //
    // The wide entry goes **last**, which is the order that actually breaks:
    // put first, it is shadowed itself and nothing is wrong. A helper that
    // read the longest prefix would answer with the narrow entry here and
    // report a hole as safe.
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

    // And with the same entry first, each narrower one governs its own path
    // again, so the fact above is about the order and not about `/run`.
    const safe_order = [_]Mount{
        .{ .bind = .{ .source = "somebody-elses-run", .target = "/run", .read_only = false } },
        .{ .bind = .{ .source = "the-real-git-dir", .target = sandbox_git_root_prefix ++ "/sess1", .read_only = true } },
    };
    const governs = mostSpecificMount(&safe_order, sandbox_git_root_prefix ++ "/sess1/hooks") orelse
        return error.NoMountCoversHooks;
    try std.testing.expectEqualStrings("the-real-git-dir", governs.source);
}

test "no mount Chock builds is wide enough to shadow its own runtime prefix" {
    // The other half: the test above proves a wide entry would shadow, and
    // this one proves the real list has none. Read off `mounts` itself, so a
    // future entry at `/`, `/run`, or `/run/chock` fails here rather than
    // quietly taking over all three paths at once.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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

    // And the three paths Chock owns are all under the one prefix, so there
    // is one parent to reason about and not three siblings.
    try std.testing.expect(std.mem.startsWith(u8, worktree.sandbox_git_root, chock_runtime_prefix ++ "/"));
    try std.testing.expect(std.mem.startsWith(u8, worktree.object_store_target, chock_runtime_prefix ++ "/"));
}

test "mostSpecificMount compares whole path components, not raw bytes" {
    // /run/chock/git/sess1 must not match /run/chock/git/sess10: a different
    // session's own path that merely starts with the same characters.
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
    // Force a failure after `git worktree add` has already registered the
    // worktree: pre-create a directory at the exact path the pointer file needs
    // to go, so writePointerFile's own createFileAbsolute call fails.
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
    // Without the errdefer that undoes `git worktree add`, this worktree stays
    // registered forever: the caller got an error back and has no `Worktree`
    // value to call remove on.
    try std.testing.expect(std.mem.indexOf(u8, list_output.stdout, "sess1") == null);
}

test "remove frees its memory and deletes the pointer file even when git worktree remove fails" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);

    // Corrupt the worktree's own commondir by hand, standing in for whatever
    // left it in a state git itself refuses to remove. Before this file's own
    // Finding 1 fix, this exact file was writable from inside the sandbox and an
    // agent could do this itself; the failure this test forces here is the same
    // one that used to make Worktree.remove return GitFailed forever.
    var commondir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const commondir_path = try std.fmt.bufPrintZ(&commondir_buffer, "{s}/commondir", .{worktree.worktree_meta_source});
    var commondir_file = try std.Io.Dir.createFileAbsolute(std.testing.io, commondir_path, .{});
    try commondir_file.writeStreamingAll(std.testing.io, "/nonexistent\n");
    commondir_file.close(std.testing.io);

    const pointer_path = try allocator.dupe(u8, worktree.pointer_path);
    defer allocator.free(pointer_path);

    try std.testing.expectError(error.GitFailed, worktree.remove(allocator, std.testing.io, &project.env, null));

    // remove consumed self even on failure: the pointer file this session owned
    // is gone, not left for a caller with no way to reach it any more, and every
    // field of self was freed, not just left for the allocator's own leak check
    // to report on the next Worktree that comes along.
    const stat_result = std.Io.Dir.cwd().statFile(std.testing.io, pointer_path, .{});
    try std.testing.expectError(error.FileNotFound, stat_result);

    // The real worktree directory git refused to remove is left behind on
    // purpose: `remove`'s own contract, restated in its doc comment, is that it
    // frees Chock's own bookkeeping either way, not that it always succeeds at
    // removing a worktree git itself considers broken. Clean it up by hand so
    // tmp.cleanup does not have to walk into a directory git worktree remove
    // could not touch.
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

/// Overwrite (or create) the file at `path` with `contents`, the same way a
/// user's own editor would leave the project dirty before a session starts.
fn writeFile(path: [:0]const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, contents);
}

/// Read the whole file at `path` back, for a test to compare against the
/// contents it wrote. The caller frees the returned slice.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // Change tracked.txt on disk in the project, without staging it: the
    // ordinary shape of a file someone is in the middle of editing.
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
}

test "a file the user has not committed yet appears in the worktree" {
    // A new untracked file is the case a plain diff misses: git diff only
    // shows tracked files, so it never names this one. importUncommitted
    // instead asks git status with --untracked-files=all, which does.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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
}

test "a deleted file is deleted in the worktree too" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // tracked.txt exists in the worktree, checked out at HEAD, before this.
    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked_path = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    try std.testing.expect(try existsOnDisk(std.testing.io, worktree_tracked_path));

    // Delete it in the project, without staging the deletion.
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
}

test "the report names how many files came across, so Chock can tell the user" {
    // Chock must say that it did this. A silent import means
    // the user cannot tell why the agent sees something they do not, so the
    // report's own total has to add up across every kind of change at once,
    // not just whichever one a narrower test happened to exercise.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // One modified tracked file, one new untracked file, one deletion is not
    // possible on top of a single tracked.txt at once, so this test adds a
    // second tracked file to delete instead, keeping tracked.txt itself as
    // the modified one.
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
}

test "importing nothing from a clean project is not an error" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), report.modified.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.added.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.deleted.items.len);
    try std.testing.expectEqual(@as(usize, 0), report.total());
}

test "validateRelativePath rejects a path that escapes the project root" {
    // The defensive check named in this task's own brief: a path in a diff
    // must not be followed outside the project. git status never emits one
    // of these in ordinary use, so this drives the check directly rather
    // than trying to make a real git status print one.
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath("../escaped.txt"));
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath("nested/../../escaped.txt"));
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath("/etc/passwd"));
    try std.testing.expectError(error.PathEscapesProject, validateRelativePath(""));
    try validateRelativePath("ordinary/path.txt");
}

// A prior version of importPath followed a symbolic link and wrote a plain
// file (Finding 1), panicked on a directory (Finding 2), and treated a
// broken link as a deletion (Finding 3). Every test below builds the exact
// shape a real repository can hand importUncommitted and checks the result
// by hand, not by trusting that "no crash" alone means "correct".

/// Create a symbolic link at `link_path` naming `target_text`, exactly the
/// way `ln -s target_text link_path` would: `target_text` is written
/// verbatim, relative or absolute, resolved or not, since that is what a
/// real symbolic link on disk holds.
fn makeSymlink(target_text: []const u8, link_path: [:0]const u8) !void {
    try std.Io.Dir.cwd().symLink(std.testing.io, target_text, link_path, .{});
}

/// Read the target text of the symbolic link at `path`, for a test to
/// compare against what it created. The caller owns the returned slice.
fn readSymlinkTarget(allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const n = try std.Io.Dir.readLinkAbsolute(std.testing.io, path, &buffer);
    return allocator.dupe(u8, buffer[0..n]);
}

/// True if any regular file under `root_path`, walked recursively but never
/// through a link, holds `needle` in its bytes. Used to prove a secret that
/// lived outside the project never landed anywhere inside the worktree, not
/// just at the one path a test happens to check by name.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // A link to another file already inside the project, the ordinary case:
    // a vendored binary pinned by a symlink, a "latest" pointer, and so on.
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
}

test "a symbolic link pointing outside the project never lands its target's content in the worktree" {
    // The reviewer's own reproduction for Finding 1: a link inside the
    // project named `key`, pointing at a file outside it that holds
    // "OUTSIDE SECRET". Before the fix, importPath read through the link
    // and wrote a plain file, carrying that text into the worktree. The
    // sandbox never mounts the user's home directory at all, so this is the
    // one path that must never happen.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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

    // The money assertion: walk the whole worktree, and confirm the secret
    // text is nowhere in it, not just absent from the one file a narrower
    // test would think to check.
    try std.testing.expect(!try treeContainsBytes(allocator, worktree.path, "OUTSIDE SECRET"));
}

test "a broken symbolic link is recreated, not treated as a deletion" {
    // Finding 3: the existence check importPath used to make followed
    // links, so a link whose target is missing looked exactly like a file
    // that is gone, and got deleted from the worktree and counted as a
    // deletion. A broken link is a real thing in the user's tree and must
    // be carried across as the link it is.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    var link_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrintZ(&link_path_buffer, "{s}/link_to_dir", .{project.root_path});
    try makeSymlink("a_directory", link_path);

    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);

    // git status names the directory's own untracked contents, not the
    // directory itself, so this sees both the link and the file inside the
    // real directory it points at, two separate untracked entries.
    var saw_link = false;
    for (report.added.items) |path| {
        if (std.mem.eql(u8, path, "link_to_dir")) saw_link = true;
    }
    try std.testing.expect(saw_link);

    var worktree_link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_link_path = try std.fmt.bufPrintZ(&worktree_link_buffer, "{s}/link_to_dir", .{worktree.path});
    const kind = try classify(std.testing.io, worktree_link_path);
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, kind.?);
}

test "a dirty submodule is skipped, not a crash" {
    // Finding 2's first reproduction. A submodule's own checkout directory
    // is a real directory on disk, git-cache marker file inside it and all,
    // and the superproject's own git status names the submodule path itself
    // when it has uncommitted changes. The old code called
    // copyFileAbsolute on that path and panicked with "ISDIR".
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
    // otherwise refused by a modern git as an unapproved transport. Test
    // setup only; nothing this file ships runs `git submodule add`.
    var submodule_add = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "-c", "protocol.file.allow=always", "submodule", "add", submodule_source_path, "sub",
    }, null);
    defer submodule_add.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, submodule_add.term);
    var submodule_commit = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{ "commit", "-m", "add submodule" }, null);
    defer submodule_commit.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, submodule_commit.term);

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // Dirty the submodule's own working tree, uncommitted, so the
    // superproject's own git status names "sub" itself.
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
}

test "an untracked nested repository is skipped, not a crash" {
    // Finding 2's second reproduction: a directory with its own .git,
    // never registered as a submodule at all, just sitting untracked in
    // the project (a vendored clone, dropped in by hand). git status names
    // the whole directory as one untracked entry, with a trailing slash,
    // rather than recursing into it.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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
}

test "a plain file replaced by a directory is skipped, not a crash" {
    // Finding 2's third reproduction: the same path git tracked as a file
    // is now a directory on disk. git status reports the old path as a
    // deletion and the new directory's own contents as untracked entries,
    // never the directory path itself; classify sees the truth on disk
    // regardless of what git status's own status letters implied.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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

    // The worktree's own tracked.txt, checked out at HEAD as a plain file,
    // was left exactly as it was: never deleted, never turned into a
    // directory, never fed to a copy call that would have panicked on it.
    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked_path = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    const worktree_contents = try readFile(allocator, worktree_tracked_path);
    defer allocator.free(worktree_contents);
    try std.testing.expectEqualStrings("hello\n", worktree_contents);
}

test "a file that cannot be read is skipped, and the rest of the import still completes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    var unreadable_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const unreadable_path = try std.fmt.bufPrintZ(&unreadable_buffer, "{s}/unreadable.txt", .{project.root_path});
    try writeFile(unreadable_path, "you cannot read this\n");
    // fchmodat by path, not open-then-fchmod: opening this file for read
    // after this call would itself fail, since 0o000 also revokes the
    // owner's own read bit.
    try std.Io.Dir.cwd().setFilePermissions(std.testing.io, unreadable_path, .fromMode(0o000), .{});
    // Restore read/write on the way out so tmp.cleanup can remove it.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // git rm --cached leaves the file on disk, untracked, but also leaves a
    // staged deletion: git status now names "second.txt" twice, once for
    // each fact.
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
}

/// Everything about `root_path`, on disk and in git, that
/// `importUncommitted` must leave exactly as it found it: the working
/// tree's own files and links (never `.git` itself, walked separately
/// below), the raw bytes of `.git/index`, HEAD, every ref, and the stash.
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

/// A deterministic, sorted text rendering of every file and link under
/// `root_path`, `.git` itself excluded, path and content or link target
/// both included, so two snapshots compare equal only when the tree, byte
/// for byte, is identical. The caller owns the returned slice.
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
    // Finding 6: nothing before this checked, by assertion, the one property
    // the whole design exists to protect. This builds a project with one of
    // every shape importUncommitted now handles: a modified file, a new
    // file, a deleted file, a link inside the project, a link pointing
    // outside it, a broken link, and an untracked nested repository, then
    // proves the project itself never moved.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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
    // Every shape above was carried across or recorded, none was dropped
    // silently: worth pinning here too, not just in the smaller focused
    // tests, since this is the scenario the property itself has to survive.
    try std.testing.expect(report.total() > 0);
    try std.testing.expect(report.skipped.items.len > 0);

    var after = try ProjectSnapshot.take(allocator, &project.env, project.root_path);
    defer after.deinit(allocator);

    try std.testing.expectEqualStrings(before.tree, after.tree);
    try std.testing.expectEqualStrings(before.index_bytes, after.index_bytes);
    try std.testing.expectEqualStrings(before.head, after.head);
    try std.testing.expectEqualStrings(before.refs, after.refs);
    try std.testing.expectEqualStrings(before.stash, after.stash);
}

test "a fresh worktree holds the committed state, and neither a modification nor an untracked file" {
    // **This is the default, and it needs a test of its own.** Without one, a
    // later change could start importing the working tree silently, and
    // nothing would notice that a session stopped being reproducible from a
    // commit. See `countUncommitted`.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // The committed contents, not what is on disk in the project.
    var worktree_tracked_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_tracked = try std.fmt.bufPrintZ(&worktree_tracked_buffer, "{s}/tracked.txt", .{worktree.path});
    const contents = try readFile(allocator, worktree_tracked);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("hello\n", contents);

    // And the untracked file is not there at all.
    var worktree_new_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const worktree_new = try std.fmt.bufPrintZ(&worktree_new_buffer, "{s}/new_work.txt", .{worktree.path});
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, worktree_new, .{}),
    );
}

test "countUncommitted names the split, and a clean project counts zero" {
    // The number a warning shows. Pinned as a number and a split, not as
    // "something was found": a message that says the wrong count sends a user
    // looking for files that are not there.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    // A project straight out of a commit has nothing to warn about, and that
    // is what keeps the message worth reading.
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
    // A file already `git add`ed is new to HEAD, and `ImportReport.added` is
    // filled from the `??` code alone, so the import calls it modified. The
    // count has to agree, or a warning and the import that follows it would
    // give a user two different numbers for one project.
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
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;
    var report = try worktree.importUncommitted(allocator, std.testing.io, &project.env, null);
    defer report.deinit(allocator);
    try std.testing.expectEqual(counted.modified, report.modified.items.len);
    try std.testing.expectEqual(counted.untracked, report.added.items.len);
    try std.testing.expectEqual(counted.total(), report.total());
}

test "an idle session moves no head, and a session that commits names its own commit" {
    // The check that decides whether `chock run` asks to apply anything at
    // all. A session that changed nothing must ask for nothing, or wiring
    // the apply path would make an idle session dirty.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var worktree = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer worktree.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expectEqualStrings(project.head_sha, worktree.base_commit);
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try worktree.headMoved(allocator, std.testing.io, &project.env, null),
    );

    // Commit in the worktree the way a session does: every object into the
    // session's own scratch store, never the project's.
    var session_env = try project.env.clone(allocator);
    defer session_env.deinit();
    try session_env.put("GIT_OBJECT_DIRECTORY", worktree.object_store_source);
    // The metadata directory a tool call writes is the session's own copy,
    // which is what `Worktree.mounts`'s own entry 3 binds. `GIT_DIR` is how a
    // test with no mount namespace around it reaches the same directory: see
    // `copyMetaDirectory` for why the project's own is not written at all.
    try session_env.put("GIT_DIR", worktree.worktree_meta_bind_source);
    // The project's own objects, read only, exactly the pair `gitEnv` gives a
    // tool call inside the sandbox: a commit has to read the tree it is
    // built on, and that tree is in the project's store.
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

    // And the project's own object store never saw any of it: the commit is
    // readable only with the scratch store named as an alternate.
    var project_read = try git.run(allocator, std.testing.io, &project.env, project.root_path, &.{
        "cat-file", "-e", moved,
    }, null);
    defer project_read.deinit(allocator);
    try std.testing.expect(project_read.term.exited != 0);
}

/// Compare two `Worktree` values field by field, and fail on the first field
/// that differs. The `adopt` tests need this rather than one deep equality
/// check of the whole value: a single check names only "the two differ", and
/// the fact worth pinning is *which* join stopped matching.
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

/// How many worktrees `project_root` has registered, main checkout included,
/// counted off `git worktree list --porcelain`, which starts one record per
/// worktree with a `worktree ` line. The `adopt` tests read this to hold the
/// other half of what `adopt` promises: that it registers nothing.
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
    // **The fact the whole handover rests on.** A second process reaches the
    // same value the first one had, from the disk alone, and every field is
    // compared one at a time against the value `create` returned, never
    // against a second call of the same join helper: two calls of one helper
    // agree even when the helper is wrong. Change one join in `adopt`,
    // `"worktrees"` for `"worktree"` or the `.objects` suffix of the object
    // store, and the field that join builds stops matching here.
    //
    // The registration count is the other half of the promise, and it is the
    // half no field comparison can see: `git worktree add` refuses a path
    // that is already registered, so `adopt` runs it never. A version that
    // ran it anyway, or ran any other registering command, would leave a
    // second entry, and this counts both before and after to catch it.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer made.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    // The main checkout plus the one worktree create made.
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
    // keep, never remove: the checkout belongs to the session, and this test
    // still has the value create returned for the very same one.
    defer taken.keep(allocator);

    try expectSameWorktreeFields(made, taken);
    try std.testing.expectEqual(
        @as(usize, 2),
        try countRegisteredWorktrees(allocator, &project.env, project.root_path),
    );
}

test "adopt keeps the work the checkout already holds" {
    // **The fact the feature exists for.** A handover that lost the files the
    // first process wrote would be a handover of nothing. `adopt` writes only
    // under the scratch directory, and never into the checkout, so the bytes
    // that were there are still there. Make `adopt` delete or re-create the
    // checkout, the way `create` builds one, and this stops holding.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const work_path = work: {
        var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        // The first process ends abnormally and keeps its workspace, exactly
        // the ending `Worktree.keep`'s own doc comment describes.
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
    defer taken.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    const contents = try readFile(allocator, work_path);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings("work nobody committed\n", contents);

    // The committed file the checkout started with is still there too: this
    // is a whole checkout that carried over, not one salvaged file.
    const tracked_path = try std.fs.path.join(allocator, &.{ taken.path, "tracked.txt" });
    defer allocator.free(tracked_path);
    const tracked = try readFile(allocator, tracked_path);
    defer allocator.free(tracked);
    try std.testing.expectEqualStrings("hello\n", tracked);
}

test "adopt carries the caller's base commit, and never the head the session left behind" {
    // **The one field the disk cannot give back, and getting it wrong is
    // silent.** The session commits before it hands over, so its HEAD is no
    // longer the commit it started at. `headMoved` compares HEAD against
    // `base_commit` to decide whether there is work worth carrying back to
    // the user. Mutation check: make `adopt` read HEAD itself, the way
    // `create` does with `readHeadWith`, and `base_commit` becomes the
    // session's own commit, `headMoved` answers null, and the commit reaches
    // the user's repository never.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var session_head_buffer: [64]u8 = undefined;
    const session_head = head: {
        var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
        defer made.keep(allocator);

        // Commit the way a session does: every object into the session's own
        // scratch store, the project's own store readable and no more, the
        // pair `gitEnv` gives a tool call inside the sandbox.
        var session_env = try project.env.clone(allocator);
        defer session_env.deinit();
        try session_env.put("GIT_OBJECT_DIRECTORY", made.object_store_source);
        // The session's own copy of the metadata directory, the same reason
        // as the test above: a tool call never writes the project's own.
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
    // The session really did move: without this the check below would hold
    // for the wrong reason, on a HEAD that never left the base.
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
    defer taken.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

    try std.testing.expectEqualStrings(project.head_sha, taken.base_commit);

    const moved = (try taken.headMoved(allocator, std.testing.io, &project.env, null)) orelse
        return error.TheSessionsOwnCommitWouldNeverBeCarriedBack;
    defer allocator.free(moved);
    try std.testing.expectEqualStrings(session_head, moved);
}

test "a path with no checkout, and a checkout with no .git at all, are both refused as nothing to adopt" {
    // Two shapes of the same refusal, because both mean the same thing: there
    // is no worktree at this path to take. `adopt` makes none of its own, so
    // it has to say so rather than build a value that names a directory that
    // is not there. Delete either check and `adopt` returns a `Worktree`
    // whose every path is a guess.
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

    // A directory that is there, holding no `.git` of any kind.
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
    // A `.git` that is not the one line `gitdir:` pointer is not a linked
    // worktree, whatever else it is: an ordinary file of another shape, or
    // the directory a main checkout has. Neither can be adopted, because
    // neither names a registration under the project, so `readWorktreeId`
    // has nothing to read the id out of. Drop the check and `adopt` builds
    // `worktree_meta_source` from a basename it took off arbitrary bytes.
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

    // The same refusal for the other shape: a `.git` that is a directory,
    // which is what a main checkout has and a linked worktree never does.
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
    // **A checkout with no registration is one no git command works in**, so
    // the new owner's first commit would fail, inside a tool call, with git's
    // own words and none of Chock's. Refused here instead, where the reason
    // is still readable.
    //
    // The registration directory is removed by hand, never with `git worktree
    // prune`, so this test does not depend on git's own rules for when a
    // prune fires: measured by hand, a prune leaves the registration alone
    // while the checkout is still on disk, which is exactly the case this
    // test needs and cannot get from prune. Delete the check in `adopt` and
    // this returns a `Worktree` instead of the error.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    // keep, not remove: the registration is about to go, and `git worktree
    // remove` would fail on a worktree the project no longer knows.
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
    // Point 4 of `adopt`'s own doc comment, held against the disk rather than
    // against the source. The pointer file and the `config.worktree` stand-in
    // are already there, written by `create`, and `adopt` opens both again.
    // An `exclusive = true` on either would make `adopt` fail on every real
    // handover, and a write of different bytes would change what `mounts`
    // binds read only over the sandbox's own `.git`. Change the pointer
    // file's `gitdir:` line and this stops holding.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(allocator, tmp);
    defer project.deinit();

    var made = try createWithLayout(allocator, std.testing.io, &project.env, project.root_path, project.scratch_path, "sess1", .remapped, null);
    defer made.remove(allocator, std.testing.io, &project.env, null) catch unreachable;

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

    // The stand-in is still the empty file `mounts` binds read only, and
    // `adopt` reached the same decision `create` did for the same disk.
    try std.testing.expect(taken.worktree_config_worktree_is_scratch);
    const stand_in = try readFile(allocator, taken.worktree_config_worktree_source);
    defer allocator.free(stand_in);
    try std.testing.expectEqual(@as(usize, 0), stand_in.len);
}

test "adopt binds the project's own config.worktree when the project has one" {
    // The other half of point 4's rule: the decision is a fact about the
    // disk, so a project that really has a `config.worktree` gets that file
    // bound, never the empty stand-in. An `adopt` that carried the flag over
    // from the first process, or that always wrote a stand-in, would mount an
    // empty file over git config git has to read, and every git call in the
    // adopted session would lose it.
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
    defer made.remove(allocator, std.testing.io, &project.env, null) catch unreachable;
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
}
