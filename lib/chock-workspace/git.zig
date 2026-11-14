//! Reads facts out of a repository, and runs `git` for what ziggit cannot do
//! yet. A call to `run` goes straight to `execve`.

const std = @import("std");
const ziggit = @import("ziggit");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;

pub const Error = error{
    NotFound,
    Unexpected,
    OutOfMemory,
};

pub const Output = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *Output, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

/// Applied after `env` is copied in, so they always win even if `env` already carried one.
const forced_env = [_]struct { key: []const u8, value: []const u8 }{
    // A user's own gitconfig must not change what git tells Chock.
    .{ .key = "GIT_CONFIG_GLOBAL", .value = "/dev/null" },
    .{ .key = "GIT_CONFIG_SYSTEM", .value = "/dev/null" },
    // Nobody is here to answer a prompt; a prompt left enabled would hang the caller.
    .{ .key = "GIT_TERMINAL_PROMPT", .value = "0" },
};

/// `argv[0]` resolves against PATH from the parent environment, not `environ_map`.
pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) Error!Output {
    var child_env = try buildEnviron(allocator, env);
    defer child_env.deinit();

    const full_argv = try allocator.alloc([]const u8, argv.len + 1);
    defer allocator.free(full_argv);
    full_argv[0] = "git";
    @memcpy(full_argv[1..], argv);

    var child = std.process.spawn(io, .{
        .argv = full_argv,
        .cwd = .{ .path = cwd },
        .environ_map = &child_env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| return mapSpawnError(err, diag);

    const streams = try readPipes(allocator, io, &child);
    errdefer {
        allocator.free(streams.stdout);
        allocator.free(streams.stderr);
    }

    const term = child.wait(io) catch |err| {
        diagnostic.noteErr(diag, .git_wait, err);
        return error.Unexpected;
    };

    return .{ .term = term, .stdout = streams.stdout, .stderr = streams.stderr };
}

pub fn isRepository(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var start = try openStart(io, path, diag);
    defer start.close(io);
    var layout = openLayout(allocator, io, env, start, null, diag) catch |err| switch (err) {
        error.NotARepository => return false,
        else => |e| return e,
    };
    layout.deinit(io);
    return true;
}

pub fn topLevel(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    diag: ?*?Diagnostic,
) Error!?[]u8 {
    var output = try run(allocator, io, env, path, &.{ "rev-parse", "--show-toplevel" }, diag);
    defer output.deinit(allocator);

    const code = switch (output.term) {
        .exited => |c| c,
        else => return null,
    };
    if (code != 0) return null;

    const trimmed = std.mem.trimEnd(u8, output.stdout, "\n");
    return try allocator.dupe(u8, trimmed);
}

const LayoutError = Error || error{NotARepository};

/// A repository format or index version ziggit refuses and git reads.
const OpenError = LayoutError || error{Unsupported};

fn fail(diag: ?*?Diagnostic, err: anyerror) Error {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    diagnostic.noteErr(diag, .repository_read, err);
    return error.Unexpected;
}

fn openStart(io: std.Io, path: []const u8, diag: ?*?Diagnostic) Error!std.Io.Dir {
    return std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => error.NotFound,
        else => fail(diag, err),
    };
}

/// With `git_dir` set the walk upward is skipped, the way `GIT_DIR` skips it.
fn openLayout(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    start: std.Io.Dir,
    git_dir: ?[]const u8,
    diag: ?*?Diagnostic,
) LayoutError!ziggit.Layout {
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);
    var layout = ziggit.discover(allocator, io, start, .{ .git_dir_override = git_dir }, &fault) catch |err| switch (err) {
        error.NotARepository, error.CorruptGitFile => return error.NotARepository,
        else => |e| return fail(diag, e),
    };
    if (git_dir == null and aboveCeiling(io, env, start, layout)) {
        layout.deinit(io);
        return error.NotARepository;
    }
    return layout;
}

/// git does not enter a directory named in GIT_CEILING_DIRECTORIES while it
/// walks up, and ziggit has no such limit.
fn aboveCeiling(
    io: std.Io,
    env: *const std.process.Environ.Map,
    start: std.Io.Dir,
    layout: ziggit.Layout,
) bool {
    const list = env.get("GIT_CEILING_DIRECTORIES") orelse return false;
    var found_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var start_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const found_len = (layout.work_tree orelse layout.git_dir).realPath(io, &found_buffer) catch return false;
    const start_len = start.realPath(io, &start_buffer) catch return false;
    const found = found_buffer[0..found_len];
    const start_path = start_buffer[0..start_len];

    var entries = std.mem.splitScalar(u8, list, ':');
    while (entries.next()) |raw| {
        const ceiling = std.mem.trimEnd(u8, raw, "/");
        if (ceiling.len == 0 or std.mem.eql(u8, ceiling, start_path)) continue;
        if (pathContains(ceiling, start_path) and pathContains(found, ceiling)) return true;
    }
    return false;
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    const root = std.mem.trimEnd(u8, parent, "/");
    if (!std.mem.startsWith(u8, child, root)) return false;
    return child.len == root.len or child[root.len] == '/';
}

fn openRepository(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    start: std.Io.Dir,
    git_dir: ?[]const u8,
    diag: ?*?Diagnostic,
) OpenError!ziggit.Repository {
    var layout = try openLayout(allocator, io, env, start, git_dir, diag);
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);
    return ziggit.Repository.open(allocator, io, layout, .{}, &fault) catch |err| {
        layout.deinit(io);
        return switch (err) {
            error.NotARepository => error.NotARepository,
            error.UnsupportedRepositoryFormat, error.UnsupportedExtension => error.Unsupported,
            else => fail(diag, err),
        };
    };
}

/// A linked worktree keeps HEAD in its own directory and its branches in the
/// common one, so the common directory alone would answer with the main
/// checkout's HEAD.
fn headOid(allocator: std.mem.Allocator, repo: *ziggit.Repository, diag: ?*?Diagnostic) Error!?ziggit.Oid {
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);
    var own = ziggit.Store.init(allocator, repo.io, repo.layout.git_dir, repo.format, null);
    defer own.deinit();
    var head = own.lookup("HEAD", &fault) catch |err| switch (err) {
        error.RefNotFound => return null,
        else => return fail(diag, err),
    };
    defer head.deinit(allocator);
    switch (head.target) {
        .oid => |oid| return oid,
        .symbolic => |name| return repo.refs.resolve(name, &fault) catch |err| switch (err) {
            error.RefNotFound => null,
            else => fail(diag, err),
        },
    }
}

fn hex(allocator: std.mem.Allocator, oid: ziggit.Oid) std.mem.Allocator.Error![]u8 {
    var buffer: [ziggit.Oid.max_formatted_length]u8 = undefined;
    return allocator.dupe(u8, oid.toHex(&buffer));
}

/// The commit HEAD names, as hex. Null when HEAD names no commit yet, or
/// `path` is in no repository. `git_dir` stands in for GIT_DIR: the
/// checkout's metadata, where its own `.git` file does not point.
pub fn headCommit(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    git_dir: ?[]const u8,
    diag: ?*?Diagnostic,
) Error!?[]u8 {
    var start = try openStart(io, path, diag);
    defer start.close(io);
    var repo = openRepository(allocator, io, env, start, git_dir, diag) catch |err| switch (err) {
        error.NotARepository => return null,
        error.Unsupported => return headCommitByGit(allocator, io, env, path, git_dir, diag),
        else => |e| return e,
    };
    defer repo.deinit();
    const oid = try headOid(allocator, &repo, diag) orelse return null;
    return try hex(allocator, oid);
}

fn headCommitByGit(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    git_dir: ?[]const u8,
    diag: ?*?Diagnostic,
) Error!?[]u8 {
    var own_env = try env.clone(allocator);
    defer own_env.deinit();
    if (git_dir) |dir| try own_env.put("GIT_DIR", dir);
    return firstLine(allocator, io, &own_env, path, &.{ "rev-parse", "HEAD" }, diag);
}

/// The object the full ref `name` holds, as hex, or null when there is no such ref.
pub fn resolveRef(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    name: []const u8,
    diag: ?*?Diagnostic,
) Error!?[]u8 {
    var start = try openStart(io, path, diag);
    defer start.close(io);
    var repo = openRepository(allocator, io, env, start, null, diag) catch |err| switch (err) {
        error.NotARepository => return null,
        error.Unsupported => return firstLine(allocator, io, env, path, &.{ "rev-parse", "--verify", name }, diag),
        else => |e| return e,
    };
    defer repo.deinit();
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);
    const oid = repo.refs.resolve(name, &fault) catch |err| switch (err) {
        error.RefNotFound, error.InvalidRefName => return null,
        else => return fail(diag, err),
    };
    return try hex(allocator, oid);
}

/// `Unsupported` is a repository or revision ziggit does not read, which git may.
/// `Refused` is ziggit declining the worktree itself.
pub const WorktreeError = Error || error{ Unsupported, Refused };

/// Makes `path` and checks `revision` out into it as a detached linked worktree named `name`.
/// git picks a free name when `name` is taken, and this refuses instead.
pub fn addWorktree(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    name: []const u8,
    path: []const u8,
    revision: []const u8,
    diag: ?*?Diagnostic,
) WorktreeError!void {
    var start = try openStart(io, project_root, diag);
    defer start.close(io);
    var repo = openRepository(allocator, io, env, start, null, diag) catch |err| switch (err) {
        error.NotARepository => return error.Refused,
        else => |e| return e,
    };
    defer repo.deinit();

    if (copiesPerWorktreeState(io, &repo)) return error.Unsupported;

    const commit = try resolveCommit(allocator, &repo, revision, diag);
    if (needsFiltering(allocator, io, env, &repo, commit)) return error.Unsupported;

    const existed = if (std.Io.Dir.cwd().statFile(io, path, .{})) |_| true else |_| false;
    std.Io.Dir.cwd().createDirPath(io, path) catch |err| {
        diagnostic.noteErr(diag, .worktree_dir_create, err);
        return error.Refused;
    };
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| {
        diagnostic.noteErr(diag, .worktree_dir_create, err);
        return error.Refused;
    };
    defer dir.close(io);
    errdefer if (!existed) std.Io.Dir.cwd().deleteTree(io, path) catch {};

    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);
    ziggit.worktreeAdd(allocator, io, &repo, name, dir, commit, .{}, &fault) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            diagnostic.noteErr(diag, .repository_read, err);
            return error.Refused;
        },
    };
}

/// Deletes the linked worktree `name` and its files, whatever state they are in.
pub fn removeWorktree(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    name: []const u8,
    diag: ?*?Diagnostic,
) WorktreeError!void {
    var start = try openStart(io, project_root, diag);
    defer start.close(io);
    var repo = openRepository(allocator, io, env, start, null, diag) catch |err| switch (err) {
        error.NotARepository => return error.Refused,
        else => |e| return e,
    };
    defer repo.deinit();

    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);
    ziggit.worktreeRemove(allocator, io, &repo, name, .{ .force = .dirty }, &fault) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            diagnostic.noteErr(diag, .repository_read, err);
            return error.Refused;
        },
    };
}

/// Deletes the records of linked worktrees whose directory is gone, and answers how many.
/// Nothing is checked out, so only the repository format can make this `Unsupported`.
pub fn pruneWorktrees(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) WorktreeError!u32 {
    var start = try openStart(io, project_root, diag);
    defer start.close(io);
    var repo = openRepository(allocator, io, env, start, null, diag) catch |err| switch (err) {
        error.NotARepository => return error.Refused,
        else => |e| return e,
    };
    defer repo.deinit();

    return ziggit.worktreePrune(allocator, io, &repo) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            diagnostic.noteErr(diag, .repository_read, err);
            return error.Refused;
        },
    };
}

/// git copies `config.worktree` and the sparse checkout patterns into a new
/// worktree, and ziggit copies neither.
fn copiesPerWorktreeState(io: std.Io, repo: *ziggit.Repository) bool {
    if (repo.config.getBool("core.sparseCheckout") orelse false) return true;
    _ = repo.layout.common_dir.statFile(io, "config.worktree", .{}) catch return false;
    return true;
}

/// True when checking `commit` out through git could differ from ziggit's plain copy of
/// the blobs. Any doubt, or any read that fails, answers true, so git does the work.
fn needsFiltering(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repo: *ziggit.Repository,
    commit: ziggit.Oid,
) bool {
    if (repo.config.getString("core.autocrlf")) |value| {
        if (!std.ascii.eqlIgnoreCase(value, "false")) return true;
    }
    if (repo.config.getString("core.eol") != null) return true;
    if (repo.config.getString("core.attributesFile") != null) return true;
    if (repo.config.getBool("core.symlinks") == false) return true;

    if (hasAttributesFile(io, env)) return true;
    if (infoAttributesChange(allocator, io, repo)) return true;

    const tree = ziggit.peel(allocator, repo, commit, .tree) catch return true;
    return treeHasConvertingAttributes(allocator, repo, tree, 0);
}

/// The per user attributes file and the one in `/etc`. git also reads one under its own
/// build prefix, which this cannot find.
fn hasAttributesFile(io: std.Io, env: *const std.process.Environ.Map) bool {
    if (std.Io.Dir.cwd().statFile(io, "/etc/gitattributes", .{})) |_| return true else |_| {}
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (env.get("XDG_CONFIG_HOME")) |base| {
        if (base.len != 0) return exists(io, std.fmt.bufPrint(&buffer, "{s}/git/attributes", .{base}) catch return true);
    }
    const home = env.get("HOME") orelse return false;
    return exists(io, std.fmt.bufPrint(&buffer, "{s}/.config/git/attributes", .{home}) catch return true);
}

fn exists(io: std.Io, path: []const u8) bool {
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

fn infoAttributesChange(allocator: std.mem.Allocator, io: std.Io, repo: *ziggit.Repository) bool {
    const bytes = repo.layout.common_dir.readFileAlloc(io, "info/attributes", allocator, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return true,
    };
    defer allocator.free(bytes);
    return attributesConvert(bytes);
}

const max_tree_depth = 64;

fn treeHasConvertingAttributes(allocator: std.mem.Allocator, repo: *ziggit.Repository, tree_oid: ziggit.Oid, depth: usize) bool {
    if (depth > max_tree_depth) return true;
    const bytes = repo.odb.readAlloc(allocator, tree_oid, 1 << 28, null) catch return true;
    defer allocator.free(bytes);
    var tree = ziggit.Tree.parse(allocator, repo.format, bytes) catch return true;
    defer tree.deinit(allocator);
    for (tree.entries) |entry| {
        if (entry.mode == .tree) {
            if (treeHasConvertingAttributes(allocator, repo, entry.oid, depth + 1)) return true;
        } else if (std.mem.eql(u8, entry.name, ".gitattributes")) {
            const blob = repo.odb.readAlloc(allocator, entry.oid, 1 << 24, null) catch return true;
            defer allocator.free(blob);
            if (entry.mode != .blob and entry.mode != .blob_executable) return true;
            if (attributesConvert(blob)) return true;
        }
    }
    return false;
}

/// Names every attribute that changes the bytes of a checked out file, in any state:
/// set, unset, valued, or reached through a macro definition.
fn attributesConvert(bytes: []const u8) bool {
    const converting = [_][]const u8{ "text", "eol", "crlf", "filter", "ident", "working-tree-encoding" };
    var lines = std.mem.tokenizeAny(u8, bytes, "\r\n");
    while (lines.next()) |line| {
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const first = words.next() orelse continue;
        if (first[0] == '#') continue;
        if (std.mem.startsWith(u8, first, "[attr]")) return true;
        while (words.next()) |word| {
            var name = std.mem.trimStart(u8, word, "-!");
            if (std.mem.indexOfScalar(u8, name, '=')) |at| name = name[0..at];
            for (converting) |one| if (std.mem.eql(u8, name, one)) return true;
        }
    }
    return false;
}

fn resolveCommit(
    allocator: std.mem.Allocator,
    repo: *ziggit.Repository,
    revision: []const u8,
    diag: ?*?Diagnostic,
) WorktreeError!ziggit.Oid {
    if (std.mem.eql(u8, revision, "HEAD")) {
        return try headOid(allocator, repo, diag) orelse error.Unsupported;
    }
    const oid = ziggit.resolve(allocator, repo, revision, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Unsupported,
    };
    return ziggit.peel(allocator, repo, oid, .commit) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => error.Unsupported,
    };
}

fn firstLine(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) Error!?[]u8 {
    var output = try run(allocator, io, env, path, argv, diag);
    defer output.deinit(allocator);
    switch (output.term) {
        .exited => |code| if (code != 0) return null,
        else => return null,
    }
    return try allocator.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

/// A path that differs from HEAD or the index. `untracked` is git's `??`.
pub const Change = struct {
    path: []u8,
    untracked: bool,
};

pub fn freeChanges(allocator: std.mem.Allocator, list: []Change) void {
    for (list) |one| allocator.free(one.path);
    allocator.free(list);
}

/// What `git status --porcelain=v1 --untracked-files=all --no-renames` names,
/// each path once: tracked changes first, then untracked, each by path. Null
/// when `path` is in no repository, or in a bare one.
pub fn changes(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    diag: ?*?Diagnostic,
) Error!?[]Change {
    var start = try openStart(io, path, diag);
    defer start.close(io);
    const found = readChangesFrom(allocator, io, env, start, diag) catch |err| switch (err) {
        error.NotARepository => return null,
        error.Unsupported => return changesByGit(allocator, io, env, path, diag),
        else => |e| return e,
    };
    return found;
}

fn readChangesFrom(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    start: std.Io.Dir,
    diag: ?*?Diagnostic,
) OpenError![]Change {
    var repo = try openRepository(allocator, io, env, start, null, diag);
    defer repo.deinit();
    return readChanges(allocator, io, env, &repo, diag);
}

/// Gathers what the `Change` doc says. ziggit leaves three things to this
/// function: an unmerged entry, which git reports as one conflicted path;
/// a gitlink, which git compares with the submodule's own HEAD; and a nested
/// repository, which git names as one directory.
fn readChanges(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repo: *ziggit.Repository,
    diag: ?*?Diagnostic,
) OpenError![]Change {
    const work_tree = repo.layout.work_tree orelse return error.NotARepository;
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*one| one.deinit(allocator);

    var index = ziggit.WorktreeIndex.open(allocator, io, repo.layout.git_dir, repo.format) catch |err| switch (err) {
        error.IndexNotFound => ziggit.WorktreeIndex{ .gpa = allocator, .entries = &.{} },
        error.UnsupportedIndexVersion => return error.Unsupported,
        else => return fail(diag, err),
    };
    defer index.deinit();

    var head_tree: ?ziggit.Oid = null;
    if (try headOid(allocator, repo, diag)) |head| {
        head_tree = ziggit.peel(allocator, repo, head, .tree) catch |err| return fail(diag, err);
    }

    var ignore = ziggit.IgnoreMatcher.init(allocator);
    defer ignore.deinit();
    try addExcludes(io, env, repo, &ignore, diag);

    var found = ziggit.status(allocator, io, work_tree, &repo.odb, index, repo.format, .{
        .ignore = &ignore,
        .head_tree = head_tree,
    }, &fault) catch |err| return fail(diag, err);
    defer found.deinit(allocator);

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    var unmerged: std.StringHashMapUnmanaged(void) = .empty;
    var submodules: std.ArrayList(ziggit.IndexEntry) = .empty;
    for (index.entries) |entry| {
        if (entry.stage != .merged) {
            try unmerged.put(scratch.allocator(), entry.path, {});
        } else if (entry.mode == .gitlink) {
            try submodules.append(scratch.allocator(), entry);
        }
    }

    var out: std.ArrayList(Change) = .empty;
    errdefer {
        for (out.items) |one| allocator.free(one.path);
        out.deinit(allocator);
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    var nested_repository: std.StringHashMapUnmanaged(bool) = .empty;

    next: for (found.changes) |one| {
        if (unmerged.contains(one.path)) continue;
        for (submodules.items) |submodule| if (pathContains(submodule.path, one.path)) continue :next;
        if (one.untracked) {
            if (try nestedRepositoryRoot(scratch.allocator(), io, work_tree, &nested_repository, one.path)) |root| {
                try add(allocator, &out, &seen, root, true);
                continue;
            }
        }
        try add(allocator, &out, &seen, one.path, one.untracked);
    }

    var conflicted = unmerged.keyIterator();
    while (conflicted.next()) |name| try add(allocator, &out, &seen, name.*, false);

    for (submodules.items) |submodule| {
        if (try submoduleChanged(allocator, io, env, work_tree, submodule, diag)) {
            try add(allocator, &out, &seen, submodule.path, false);
        }
    }

    std.mem.sort(Change, out.items, {}, changeLessThan);
    return out.toOwnedSlice(allocator);
}

fn changeLessThan(_: void, a: Change, b: Change) bool {
    if (a.untracked != b.untracked) return b.untracked;
    return std.mem.order(u8, a.path, b.path) == .lt;
}

fn add(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(Change),
    seen: *std.StringHashMapUnmanaged(void),
    path: []const u8,
    untracked: bool,
) std.mem.Allocator.Error!void {
    if (seen.contains(path)) return;
    const owned = try allocator.dupe(u8, path);
    errdefer allocator.free(owned);
    try seen.put(allocator, owned, {});
    errdefer _ = seen.remove(owned);
    try out.append(allocator, .{ .path = owned, .untracked = untracked });
}

/// git lists a directory holding its own `.git` as one `dir/` entry, and ziggit lists the files in it.
fn nestedRepositoryRoot(
    scratch: std.mem.Allocator,
    io: std.Io,
    work_tree: std.Io.Dir,
    known: *std.StringHashMapUnmanaged(bool),
    path: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    var cut: usize = 0;
    while (std.mem.indexOfScalarPos(u8, path, cut, '/')) |slash| {
        cut = slash + 1;
        const directory = path[0..slash];
        const entry = try known.getOrPut(scratch, directory);
        if (!entry.found_existing) {
            entry.key_ptr.* = try scratch.dupe(u8, directory);
            const marker = try std.fmt.allocPrint(scratch, "{s}/.git", .{directory});
            entry.value_ptr.* = if (work_tree.statFile(io, marker, .{ .follow_symlinks = false })) |_| true else |_| false;
        }
        if (entry.value_ptr.*) return try std.fmt.allocPrint(scratch, "{s}/", .{directory});
    }
    return null;
}

/// git compares a gitlink with the submodule's own HEAD, and reports any change or untracked file inside it.
fn submoduleChanged(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    work_tree: std.Io.Dir,
    submodule: ziggit.IndexEntry,
    diag: ?*?Diagnostic,
) OpenError!bool {
    var directory = work_tree.openDir(io, submodule.path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return true,
        else => return fail(diag, err),
    };
    defer directory.close(io);
    // A submodule that was never initialised is an empty directory.
    _ = directory.statFile(io, ".git", .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return fail(diag, err),
    };
    var inner = openRepository(allocator, io, env, directory, null, diag) catch |err| switch (err) {
        error.NotARepository => return true,
        else => |e| return e,
    };
    defer inner.deinit();
    const head = try headOid(allocator, &inner, diag) orelse return true;
    if (!head.eql(submodule.oid)) return true;
    const inside = try readChanges(allocator, io, env, &inner, diag);
    defer freeChanges(allocator, inside);
    return inside.len != 0;
}

/// Global excludes first and `info/exclude` second, because a source added later wins.
fn addExcludes(
    io: std.Io,
    env: *const std.process.Environ.Map,
    repo: *ziggit.Repository,
    ignore: *ziggit.IgnoreMatcher,
    diag: ?*?Diagnostic,
) Error!void {
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (globalExcludesPath(env, repo, &buffer)) |global| {
        ignore.addFile(io, std.Io.Dir.cwd(), global, "") catch |err| return fail(diag, err);
    }
    ignore.addFile(io, repo.layout.common_dir, "info/exclude", "") catch |err| return fail(diag, err);
}

/// `core.excludesFile` from the repository's own config, then the default
/// path git reads when none is set. The user's and the system's config are
/// not read, the same as `forced_env` makes git not read them.
fn globalExcludesPath(
    env: *const std.process.Environ.Map,
    repo: *ziggit.Repository,
    buffer: []u8,
) ?[]const u8 {
    if (repo.config.getString("core.excludesfile")) |configured| {
        if (std.mem.startsWith(u8, configured, "/")) return configured;
        if (std.mem.startsWith(u8, configured, "~/")) {
            const home = env.get("HOME") orelse return null;
            return std.fmt.bufPrint(buffer, "{s}{s}", .{ std.mem.trimEnd(u8, home, "/"), configured[1..] }) catch null;
        }
        return null;
    }
    if (env.get("XDG_CONFIG_HOME")) |config_home| {
        if (config_home.len != 0) return std.fmt.bufPrint(buffer, "{s}/git/ignore", .{config_home}) catch null;
    }
    const home = env.get("HOME") orelse return null;
    return std.fmt.bufPrint(buffer, "{s}/.config/git/ignore", .{std.mem.trimEnd(u8, home, "/")}) catch null;
}

/// The one `git status` call this file makes, spelled once.
const status_argv = &[_][]const u8{
    "--no-optional-locks",   "status",       "--porcelain=v1", "-z",
    "--untracked-files=all", "--no-renames",
};

fn changesByGit(
    allocator: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    path: []const u8,
    diag: ?*?Diagnostic,
) Error!?[]Change {
    var output = try run(allocator, io, env, path, status_argv, diag);
    defer output.deinit(allocator);
    switch (output.term) {
        .exited => |code| if (code != 0) return null,
        else => return null,
    }

    var out: std.ArrayList(Change) = .empty;
    errdefer {
        for (out.items) |one| allocator.free(one.path);
        out.deinit(allocator);
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    // -z turns off git's own quoting, so slicing off the leading "XY " gives back the exact bytes.
    var entries = std.mem.splitScalar(u8, output.stdout, 0);
    while (entries.next()) |entry| {
        if (entry.len < 4) continue; // too short to hold "XY " plus a path
        try add(allocator, &out, &seen, entry[3..], std.mem.startsWith(u8, entry, "??"));
    }
    return try out.toOwnedSlice(allocator);
}

fn buildEnviron(allocator: std.mem.Allocator, env: *const std.process.Environ.Map) Error!std.process.Environ.Map {
    var child_env = try env.clone(allocator);
    errdefer child_env.deinit();
    for (forced_env) |entry| try child_env.put(entry.key, entry.value);
    return child_env;
}

/// Reads both output pipes to the end without deadlocking if one fills its kernel buffer first.
fn readPipes(
    allocator: std.mem.Allocator,
    io: std.Io,
    child: *std.process.Child,
) Error!struct { stdout: []u8, stderr: []u8 } {
    var stderr_future = io.concurrent(readStreamAlloc, .{ allocator, io, child.stderr.? }) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.Unexpected,
    };
    // The stderr future must be awaited or canceled even if stdout fails.
    errdefer if (stderr_future.cancel(io)) |slice| allocator.free(slice) else |_| {};

    const stdout = readStreamAlloc(allocator, io, child.stdout.?) catch |err| return mapStreamError(err);
    const stderr = stderr_future.await(io) catch |err| return mapStreamError(err);

    return .{ .stdout = stdout, .stderr = stderr };
}

const ReadStreamError = std.mem.Allocator.Error || std.Io.File.Reader.Error || error{StreamTooLong};

fn readStreamAlloc(allocator: std.mem.Allocator, io: std.Io, file: std.Io.File) ReadStreamError![]u8 {
    var file_reader: std.Io.File.Reader = .initStreaming(file, io, &.{});
    return file_reader.interface.allocRemaining(allocator, .unlimited) catch |err| switch (err) {
        error.ReadFailed => return file_reader.err.?,
        else => |e| return e,
    };
}

fn mapStreamError(err: ReadStreamError) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Unexpected,
    };
}

fn mapSpawnError(err: std.process.SpawnError, diag: ?*?Diagnostic) Error {
    return switch (err) {
        error.FileNotFound => error.NotFound,
        error.OutOfMemory => error.OutOfMemory,
        else => |e| {
            diagnostic.noteErr(diag, .git_spawn, e);
            return error.Unexpected;
        },
    };
}

const AbsoluteDirPathError = error{RealPathFailed};

/// `std.testing.tmpDir` gives a directory reached only through a relative path.
fn absoluteDirPath(io: std.Io, buffer: []u8, dir: std.Io.Dir) AbsoluteDirPathError![:0]u8 {
    const len = dir.realPath(io, buffer) catch return error.RealPathFailed;
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

fn initTestRepo(
    allocator: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    path: [:0]const u8,
) !void {
    var output = try run(allocator, std.testing.io, env, path, &.{"init"}, null);
    defer output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
}

test "isRepository is true for a repository and false for a plain directory" {
    const allocator = std.testing.allocator;

    var repo_tmp = std.testing.tmpDir(.{});
    defer repo_tmp.cleanup();
    var repo_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const repo_path = try absoluteDirPath(std.testing.io, &repo_path_buffer, repo_tmp.dir);
    var repo_env = try testEnviron(allocator, repo_path);
    defer repo_env.deinit();
    try initTestRepo(allocator, &repo_env, repo_path);
    try std.testing.expect(try isRepository(allocator, std.testing.io, &repo_env, repo_path, null));

    var plain_tmp = std.testing.tmpDir(.{});
    defer plain_tmp.cleanup();
    var plain_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const plain_path = try absoluteDirPath(std.testing.io, &plain_path_buffer, plain_tmp.dir);
    var plain_env = try testEnviron(allocator, plain_path);
    defer plain_env.deinit();
    try std.testing.expect(!try isRepository(allocator, std.testing.io, &plain_env, plain_path, null));
}

test "topLevel gives the root of a repository from a directory inside it" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);
    var env = try testEnviron(allocator, root_path);
    defer env.deinit();
    try initTestRepo(allocator, &env, root_path);

    var child_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const child_path = try std.fmt.bufPrintSentinel(&child_path_buffer, "{s}/child", .{root_path}, 0);
    std.Io.Dir.createDirAbsolute(std.testing.io, child_path, .default_dir) catch return error.MkdirFailed;

    const found = try topLevel(allocator, std.testing.io, &env, child_path, null);
    try std.testing.expect(found != null);
    defer allocator.free(found.?);
    try std.testing.expectEqualStrings(root_path, found.?);
}

test "run reports the exit status and the output of git, and does not use a shell" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const repo_path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);
    var env = try testEnviron(allocator, repo_path);
    defer env.deinit();
    try initTestRepo(allocator, &env, repo_path);

    var child_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const child_path = try std.fmt.bufPrintSentinel(&child_path_buffer, "{s}/a name with a space and a 'quote'", .{repo_path}, 0);
    std.Io.Dir.createDirAbsolute(std.testing.io, child_path, .default_dir) catch return error.MkdirFailed;
    try std.testing.expect(try isRepository(allocator, std.testing.io, &env, child_path, null));

    const value = "a value with a space and a 'quote'";
    var set_output = try run(allocator, std.testing.io, &env, repo_path, &.{ "config", "test.value", value }, null);
    defer set_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, set_output.term);

    var get_output = try run(allocator, std.testing.io, &env, repo_path, &.{ "config", "--get", "test.value" }, null);
    defer get_output.deinit(allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, get_output.term);
    try std.testing.expectEqualStrings(value, std.mem.trimEnd(u8, get_output.stdout, "\n"));
}

test "run reports a failure of git as an error and keeps what git said" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);
    var env = try testEnviron(allocator, path);
    defer env.deinit();

    var output = try run(allocator, std.testing.io, &env, path, &.{ "rev-parse", "--show-toplevel" }, null);
    defer output.deinit(allocator);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 128 }, output.term);
    try std.testing.expect(std.mem.indexOf(u8, output.stderr, "not a git repository") != null);
}

test "a git that cannot be started names the fault, and it reaches the caller" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    var file_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const not_a_dir = try std.fmt.bufPrint(&file_buffer, "{s}/plain", .{path_buffer[0..dir_len]});
    var file = try std.Io.Dir.createFileAbsolute(std.testing.io, not_a_dir, .{});
    file.close(std.testing.io);

    var env = try testEnviron(allocator, path_buffer[0..dir_len]);
    defer env.deinit();

    var diag: ?Diagnostic = null;
    const result = run(allocator, std.testing.io, &env, not_a_dir, &.{"status"}, &diag);
    if (result) |output| {
        var owned = output;
        owned.deinit(allocator);
        return error.SkipZigTest;
    } else |err| {
        try std.testing.expectEqual(@as(anyerror, error.Unexpected), err);
        try std.testing.expectEqual(Diagnostic.Call.git_spawn, diag.?.call_failed.call);

        var line_buffer: [128]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{&diag.?});
        try std.testing.expect(std.mem.startsWith(u8, line, "starting git failed: "));
    }
}

test "a caller that wants no diagnostic gets the same answer and stores nothing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try absoluteDirPath(std.testing.io, &path_buffer, tmp.dir);

    var env = try testEnviron(allocator, path);
    defer env.deinit();

    try std.testing.expect(!try isRepository(allocator, std.testing.io, &env, path, null));
    var diag: ?Diagnostic = null;
    try std.testing.expect(!try isRepository(allocator, std.testing.io, &env, path, &diag));
    try std.testing.expectEqual(@as(?Diagnostic, null), diag);
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    path: []u8,
    env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(std.testing.io, &buffer);
        const path = try allocator.dupe(u8, buffer[0..len]);
        errdefer allocator.free(path);
        var env = try testEnviron(allocator, path);
        errdefer env.deinit();
        try env.put("GIT_AUTHOR_NAME", "Test");
        try env.put("GIT_AUTHOR_EMAIL", "test@example.com");
        try env.put("GIT_COMMITTER_NAME", "Test");
        try env.put("GIT_COMMITTER_EMAIL", "test@example.com");
        var fixture: Fixture = .{ .allocator = allocator, .tmp = tmp, .path = path, .env = env };
        try fixture.git(&.{ "init", "-q" });
        return fixture;
    }

    fn deinit(self: *Fixture) void {
        self.env.deinit();
        self.allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn git(self: *Fixture, argv: []const []const u8) !void {
        try self.gitIn(self.path, argv);
    }

    fn gitIn(self: *Fixture, cwd: []const u8, argv: []const []const u8) !void {
        var output = try run(self.allocator, std.testing.io, &self.env, cwd, argv, null);
        defer output.deinit(self.allocator);
        // The fixture's own git must succeed, and its stderr is the reason when
        // it does not, so the assertion carries it.
        if (output.term != .exited or output.term.exited != 0) {
            try std.testing.expectEqualStrings("", output.stderr);
            return error.GitFixtureFailed;
        }
    }

    fn gitOutput(self: *Fixture, cwd: []const u8, argv: []const []const u8) ![]u8 {
        var output = try run(self.allocator, std.testing.io, &self.env, cwd, argv, null);
        defer output.deinit(self.allocator);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
        return self.allocator.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
    }

    fn write(self: *Fixture, name: []const u8, bytes: []const u8) !void {
        if (std.fs.path.dirname(name)) |parent| try self.tmp.dir.createDirPath(std.testing.io, parent);
        try self.tmp.dir.writeFile(std.testing.io, .{ .sub_path = name, .data = bytes });
    }

    fn commitAll(self: *Fixture, message: []const u8) !void {
        try self.git(&.{ "add", "-A" });
        try self.git(&.{ "commit", "-q", "-m", message });
    }

    /// The oracle: git's own answer, parsed the way a spawned call always was.
    fn expectChangesLikeGit(self: *Fixture, path: []const u8) !void {
        const allocator = self.allocator;
        var start = try std.Io.Dir.cwd().openDir(std.testing.io, path, .{ .iterate = true });
        defer start.close(std.testing.io);
        const mine = try readChangesFrom(allocator, std.testing.io, &self.env, start, null);
        defer freeChanges(allocator, mine);
        const theirs = (try changesByGit(allocator, std.testing.io, &self.env, path, null)).?;
        defer freeChanges(allocator, theirs);
        std.mem.sort(Change, mine, {}, byPathOnly);
        std.mem.sort(Change, theirs, {}, byPathOnly);
        // Both lists go into one comparison, so a mismatch names every path on
        // each side instead of only the first one that differs.
        var want: std.ArrayList(u8) = .empty;
        defer want.deinit(allocator);
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(allocator);
        for (theirs) |one| try want.print(allocator, "{s} untracked={}\n", .{ one.path, one.untracked });
        for (mine) |one| try got.print(allocator, "{s} untracked={}\n", .{ one.path, one.untracked });
        try std.testing.expectEqualStrings(want.items, got.items);
    }

    fn expectUnsupported(self: *Fixture) !void {
        var start = try std.Io.Dir.cwd().openDir(std.testing.io, self.path, .{ .iterate = true });
        defer start.close(std.testing.io);
        try std.testing.expectError(error.Unsupported, readChangesFrom(self.allocator, std.testing.io, &self.env, start, null));
    }

    fn byPathOnly(_: void, a: Change, b: Change) bool {
        return std.mem.order(u8, a.path, b.path) == .lt;
    }
};

test "changes agrees with git status on every state a project can be in" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.write("b.txt", "b\n");
    try fixture.write("dir/c.txt", "c\n");
    try fixture.write("run.sh", "#!/bin/sh\n");
    try fixture.write("keep.txt", "keep\n");
    try fixture.git(&.{ "update-index", "--add", "--chmod=+x", "run.sh" });
    try fixture.git(&.{ "config", "core.fileMode", "true" });
    try fixture.commitAll("first");

    try fixture.expectChangesLikeGit(fixture.path);

    try fixture.write("a.txt", "changed\n");
    try fixture.write("new.txt", "new\n");
    try fixture.git(&.{ "add", "new.txt" });
    try fixture.git(&.{ "rm", "-q", "--cached", "b.txt" });
    try fixture.tmp.dir.deleteFile(std.testing.io, "dir/c.txt");
    try fixture.write("untracked/deep/x.txt", "x\n");
    try fixture.write(".gitignore", "*.log\nbuild/\n");
    try fixture.write("noise.log", "x\n");
    try fixture.write("build/out.o", "x\n");
    try fixture.write("same.size", "12345\n");
    try fixture.write("keep.txt", "KEEP\n");
    try fixture.tmp.dir.symLink(std.testing.io, "a.txt", "link", .{});
    try fixture.write(".git/info/exclude", "excluded.txt\n");
    try fixture.write("excluded.txt", "x\n");
    var run_sh = try fixture.tmp.dir.openFile(std.testing.io, "run.sh", .{});
    defer run_sh.close(std.testing.io);
    try run_sh.setPermissions(std.testing.io, .fromMode(0o644));

    try fixture.expectChangesLikeGit(fixture.path);

    const found = (try changes(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null)).?;
    defer freeChanges(std.testing.allocator, found);
    for (found) |one| {
        try std.testing.expect(!std.mem.endsWith(u8, one.path, ".log"));
        try std.testing.expect(!std.mem.startsWith(u8, one.path, "build/"));
        try std.testing.expect(!std.mem.eql(u8, one.path, "excluded.txt"));
    }
}

test "changes reads the default global ignore file and the repository's own core.excludesFile" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.commitAll("first");

    try fixture.write("xdg/git/ignore", "*.global\n");
    const xdg = try std.fmt.allocPrint(std.testing.allocator, "{s}/xdg", .{fixture.path});
    defer std.testing.allocator.free(xdg);
    try fixture.env.put("XDG_CONFIG_HOME", xdg);
    try fixture.write("one.global", "x\n");
    try fixture.write("two.custom", "x\n");
    try fixture.expectChangesLikeGit(fixture.path);

    const custom = try std.fmt.allocPrint(std.testing.allocator, "{s}/custom-ignore", .{fixture.path});
    defer std.testing.allocator.free(custom);
    try fixture.write("custom-ignore", "*.custom\ncustom-ignore\n");
    try fixture.git(&.{ "config", "core.excludesFile", custom });
    try fixture.expectChangesLikeGit(fixture.path);

    const found = (try changes(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null)).?;
    defer freeChanges(std.testing.allocator, found);
    for (found) |one| try std.testing.expect(!std.mem.eql(u8, one.path, "two.custom"));
}

test "changes names an unmerged path once, as a change and not as untracked" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("both.txt", "base\n");
    try fixture.commitAll("base");
    try fixture.git(&.{ "checkout", "-q", "-b", "side" });
    try fixture.write("both.txt", "side\n");
    try fixture.write("added.txt", "side add\n");
    try fixture.commitAll("side");
    try fixture.git(&.{ "checkout", "-q", "-" });
    try fixture.write("both.txt", "main\n");
    try fixture.write("added.txt", "main add\n");
    try fixture.commitAll("main");

    var merge = try run(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, &.{ "merge", "side" }, null);
    defer merge.deinit(std.testing.allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, merge.term);

    try fixture.expectChangesLikeGit(fixture.path);
    const found = (try changes(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null)).?;
    defer freeChanges(std.testing.allocator, found);
    try std.testing.expectEqual(@as(usize, 2), found.len);
    for (found) |one| try std.testing.expect(!one.untracked);
}

test "changes treats a submodule and a nested repository the way git does" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var source = try Fixture.init(std.testing.allocator);
    defer source.deinit();
    try source.write("f.txt", "from the submodule\n");
    try source.commitAll("submodule");

    try fixture.write("a.txt", "a\n");
    try fixture.commitAll("first");
    try fixture.git(&.{ "-c", "protocol.file.allow=always", "submodule", "add", "-q", source.path, "sub" });
    try fixture.commitAll("add submodule");

    try fixture.expectChangesLikeGit(fixture.path);
    {
        const clean = (try changes(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null)).?;
        defer freeChanges(std.testing.allocator, clean);
        try std.testing.expectEqual(@as(usize, 0), clean.len);
    }

    try fixture.write("sub/f.txt", "dirtied\n");
    try fixture.expectChangesLikeGit(fixture.path);
    try fixture.git(&.{ "-C", "sub", "checkout", "-q", "--", "f.txt" });
    try fixture.expectChangesLikeGit(fixture.path);

    try fixture.write("sub/untracked.txt", "x\n");
    try fixture.expectChangesLikeGit(fixture.path);
    try fixture.tmp.dir.deleteFile(std.testing.io, "sub/untracked.txt");

    try fixture.write("sub/f.txt", "second\n");
    const sub = try std.fmt.allocPrint(std.testing.allocator, "{s}/sub", .{fixture.path});
    defer std.testing.allocator.free(sub);
    try fixture.gitIn(sub, &.{ "commit", "-q", "-am", "moved" });
    try fixture.expectChangesLikeGit(fixture.path);

    try fixture.write("vendored/f.txt", "x\n");
    const vendored = try std.fmt.allocPrint(std.testing.allocator, "{s}/vendored", .{fixture.path});
    defer std.testing.allocator.free(vendored);
    try fixture.gitIn(vendored, &.{ "init", "-q" });
    try fixture.expectChangesLikeGit(fixture.path);
}

test "changes falls back to git for a repository format ziggit does not read" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.write("b.txt", "b\n");
    try fixture.commitAll("first");
    try fixture.write("a.txt", "changed\n");
    try fixture.write("new.txt", "new\n");

    try fixture.git(&.{ "update-index", "--index-version", "4" });
    try fixture.expectUnsupported();
    const first = (try changes(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null)).?;
    defer freeChanges(std.testing.allocator, first);
    try std.testing.expectEqual(@as(usize, 2), first.len);

    try fixture.git(&.{ "update-index", "--index-version", "2" });
    try fixture.git(&.{ "config", "core.repositoryformatversion", "1" });
    try fixture.git(&.{ "config", "extensions.partialclone", "origin" });
    try fixture.expectUnsupported();
    const second = (try changes(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null)).?;
    defer freeChanges(std.testing.allocator, second);
    try std.testing.expectEqual(@as(usize, 2), second.len);

    const head = (try headCommit(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null, null)).?;
    defer std.testing.allocator.free(head);
    const want = try fixture.gitOutput(fixture.path, &.{ "rev-parse", "HEAD" });
    defer std.testing.allocator.free(want);
    try std.testing.expectEqualStrings(want, head);
}

test "changes counts a repository that has no commit yet" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.expectChangesLikeGit(fixture.path);
    try fixture.git(&.{ "add", "a.txt" });
    try fixture.write("b.txt", "b\n");
    try fixture.expectChangesLikeGit(fixture.path);
    try std.testing.expectEqual(@as(?[]u8, null), try headCommit(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null, null));
}

test "headCommit reads the HEAD of a linked worktree, not the one of the main checkout" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.commitAll("first");
    const linked = try std.fmt.allocPrint(std.testing.allocator, "{s}/linked", .{fixture.path});
    defer std.testing.allocator.free(linked);
    try fixture.git(&.{ "worktree", "add", "-q", "--detach", linked });
    try fixture.write("b.txt", "b\n");
    try fixture.commitAll("second");

    const main_head = try fixture.gitOutput(fixture.path, &.{ "rev-parse", "HEAD" });
    defer std.testing.allocator.free(main_head);
    const linked_head = try fixture.gitOutput(linked, &.{ "rev-parse", "HEAD" });
    defer std.testing.allocator.free(linked_head);
    try std.testing.expect(!std.mem.eql(u8, main_head, linked_head));

    const read_linked = (try headCommit(std.testing.allocator, std.testing.io, &fixture.env, linked, null, null)).?;
    defer std.testing.allocator.free(read_linked);
    try std.testing.expectEqualStrings(linked_head, read_linked);
    const read_main = (try headCommit(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null, null)).?;
    defer std.testing.allocator.free(read_main);
    try std.testing.expectEqualStrings(main_head, read_main);

    const meta = try fixture.gitOutput(linked, &.{ "rev-parse", "--absolute-git-dir" });
    defer std.testing.allocator.free(meta);
    const by_dir = (try headCommit(std.testing.allocator, std.testing.io, &fixture.env, linked, meta, null)).?;
    defer std.testing.allocator.free(by_dir);
    try std.testing.expectEqualStrings(linked_head, by_dir);
}

test "pruning forgets a worktree whose directory is gone, and git agrees" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.commitAll("first");
    const gone = try std.fmt.allocPrint(allocator, "{s}/gone", .{fixture.path});
    defer allocator.free(gone);
    const kept = try std.fmt.allocPrint(allocator, "{s}/kept", .{fixture.path});
    defer allocator.free(kept);
    try fixture.git(&.{ "worktree", "add", "-q", "--detach", gone });
    try fixture.git(&.{ "worktree", "add", "-q", "--detach", kept });
    try std.Io.Dir.cwd().deleteTree(std.testing.io, gone);

    const before = try fixture.gitOutput(fixture.path, &.{ "worktree", "list", "--porcelain" });
    defer allocator.free(before);
    try std.testing.expect(std.mem.indexOf(u8, before, gone) != null);

    const count = try pruneWorktrees(allocator, std.testing.io, &fixture.env, fixture.path, null);
    try std.testing.expectEqual(@as(u32, 1), count);

    const after = try fixture.gitOutput(fixture.path, &.{ "worktree", "list", "--porcelain" });
    defer allocator.free(after);
    try std.testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, after, gone));
    try std.testing.expect(std.mem.indexOf(u8, after, kept) != null);
    const records = try fixture.gitOutput(fixture.path, &.{ "rev-parse", "--git-path", "worktrees/gone" });
    defer allocator.free(records);
    const joined = try std.fs.path.resolve(allocator, &.{ fixture.path, records });
    defer allocator.free(joined);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(std.testing.io, joined, .{}));
    try std.testing.expectEqual(@as(u32, 0), try pruneWorktrees(allocator, std.testing.io, &fixture.env, fixture.path, null));
}

test "pruning leaves a repository ziggit does not read to git" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.commitAll("first");
    try fixture.git(&.{ "config", "core.repositoryformatversion", "1" });
    try fixture.git(&.{ "config", "extensions.partialclone", "origin" });
    try std.testing.expectError(
        error.Unsupported,
        pruneWorktrees(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null),
    );
}

test "resolveRef agrees with rev-parse for a loose ref, a packed ref, a tag, and a missing ref" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("a.txt", "a\n");
    try fixture.commitAll("first");
    try fixture.git(&.{ "update-ref", "refs/chock/selected/one", "HEAD" });
    try fixture.git(&.{ "update-ref", "refs/chock/selected/two", "HEAD" });
    try fixture.git(&.{ "tag", "-a", "-m", "note", "annotated" });
    try fixture.git(&.{ "pack-refs", "--all" });
    try fixture.git(&.{ "update-ref", "refs/chock/selected/loose", "HEAD" });

    const names = [_][]const u8{ "refs/chock/selected/one", "refs/chock/selected/loose", "refs/tags/annotated", "HEAD" };
    for (names) |name| {
        const want = try fixture.gitOutput(fixture.path, &.{ "rev-parse", "--verify", name });
        defer std.testing.allocator.free(want);
        const got = (try resolveRef(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, name, null)).?;
        defer std.testing.allocator.free(got);
        try std.testing.expectEqualStrings(want, got);
    }
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try resolveRef(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, "refs/chock/selected/none", null),
    );
}

test "isRepository stops below a ceiling directory, the way git does" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    try fixture.write("below/deeper/x.txt", "x\n");
    const below = try std.fmt.allocPrint(std.testing.allocator, "{s}/below", .{fixture.path});
    defer std.testing.allocator.free(below);
    const deeper = try std.fmt.allocPrint(std.testing.allocator, "{s}/below/deeper", .{fixture.path});
    defer std.testing.allocator.free(deeper);

    try fixture.env.put("GIT_CEILING_DIRECTORIES", fixture.path);
    try std.testing.expect(!try isRepository(std.testing.allocator, std.testing.io, &fixture.env, deeper, null));
    try std.testing.expect(!try isRepository(std.testing.allocator, std.testing.io, &fixture.env, below, null));
    try std.testing.expect(try isRepository(std.testing.allocator, std.testing.io, &fixture.env, fixture.path, null));

    var open_env = try fixture.env.clone(std.testing.allocator);
    defer open_env.deinit();
    _ = open_env.swapRemove("GIT_CEILING_DIRECTORIES");
    try std.testing.expect(try isRepository(std.testing.allocator, std.testing.io, &open_env, deeper, null));
    var shell = try run(std.testing.allocator, std.testing.io, &open_env, deeper, &.{ "rev-parse", "--is-inside-work-tree" }, null);
    defer shell.deinit(std.testing.allocator);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, shell.term);
}
