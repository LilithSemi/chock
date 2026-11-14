//! Carry the session's work onto the user's checked-out branch. No merge or
//! rebase runs there: the result is built in the scratch store, and the only write is a fast forward.

const std = @import("std");
const ziggit = @import("ziggit");
const revwalk = @import("ziggit-revwalk");
const chock_policy = @import("chock-policy");
const chock_workspace = @import("chock-workspace");
const diagnostic = @import("diagnostic.zig");
const git_write = @import("git_write.zig");

const Diagnostic = diagnostic.Diagnostic;
const git = chock_workspace.git;

pub const Landing = chock_policy.apply.Landing;

/// Looked up in the git directory, which a worktree or bare repo puts somewhere else.
const unfinished_markers = [_][]const u8{
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "rebase-merge",
    "rebase-apply",
};

pub const Reason = enum {
    policy_refused,
    nobody_answered,
    apply_refused,
    already_there,
    dirty_tree,
    detached_head,
    unfinished_operation,
    branch_has_no_commit,
    would_conflict,
    history_not_linear,
    branch_moved,
    git_refused,

    pub fn wireName(self: Reason) []const u8 {
        return switch (self) {
            .policy_refused => "policy_refused",
            .nobody_answered => "nobody_answered",
            .apply_refused => "apply_refused",
            .already_there => "already_there",
            .dirty_tree => "dirty_tree",
            .detached_head => "detached_head",
            .unfinished_operation => "unfinished_operation",
            .branch_has_no_commit => "branch_has_no_commit",
            .would_conflict => "would_conflict",
            .history_not_linear => "history_not_linear",
            .branch_moved => "branch_moved",
            .git_refused => "git_refused",
        };
    }

    pub fn sentence(self: Reason) []const u8 {
        return switch (self) {
            .policy_refused => "the policy answers deny for workspace.integrate, so no approval " ++
                "of this session moves a branch",
            .nobody_answered => "this project asks how the work should land, and nobody answered",
            .apply_refused => "the apply itself was not approved",
            .already_there => "the branch already reaches this commit",
            .dirty_tree => "the working tree holds changes that are not committed",
            .detached_head => "no branch is checked out there",
            .unfinished_operation => "a merge, a rebase, a cherry pick or a revert is unfinished " ++
                "in that repository",
            .branch_has_no_commit => "the checked out branch names no commit yet",
            .would_conflict => "this work and that branch change the same lines, so it would stop " ++
                "on a conflict",
            .history_not_linear => "this work holds a commit with more than one parent, which a " ++
                "replay of one commit at a time cannot carry across",
            .branch_moved => "the branch moved after the question was put",
            .git_refused => "git refused a step of it",
        };
    }
};

pub const Move = struct {
    landing: Landing,
    branch: []const u8,
    at: []const u8,
    to: []const u8,
    /// What the landed commits claimed, as `claimedBy` words it, for the session log.
    claimed: []const u8 = "",
};

pub const Parked = struct {
    wanted: ?Landing,
    why: Reason,
};

pub const Wanted = union(enum) {
    land: Landing,
    none: Reason,

    pub fn landing(self: Wanted) ?Landing {
        return switch (self) {
            .land => |it| it,
            .none => null,
        };
    }
};

pub const Plan = union(enum) {
    move: Move,
    park: Parked,

    pub fn parked(self: Plan) ?Parked {
        return switch (self) {
            .move => null,
            .park => |it| it,
        };
    }

    pub fn wanted(self: Plan) ?Landing {
        return switch (self) {
            .move => |m| m.landing,
            .park => |it| it.wanted,
        };
    }
};

pub const Outcome = union(enum) {
    moved: struct {
        landing: Landing,
        branch: []u8,
        from: []u8,
        to: []u8,
        claimed: []u8,
    },
    park: Parked,

    pub fn deinit(self: *Outcome, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .moved => |m| {
                gpa.free(m.branch);
                gpa.free(m.from);
                gpa.free(m.to);
                gpa.free(m.claimed);
            },
            .park => {},
        }
        self.* = undefined;
    }
};

pub const Error = git.Error || error{
    GitFailed,
};

/// Nothing here writes to the user's repository: objects go into `scratch_object_store`, strings come from `arena`.
pub fn planning(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    params: struct {
        repository: []const u8,
        scratch_object_store: []const u8,
        project_object_store: []const u8,
        wanted: Wanted,
        ref: []const u8,
        new_id: []const u8,
        claimed_identity_in_message: bool = false,
        identity: chock_policy.identity.Identity = .{},
    },
    diag: ?*?Diagnostic,
) Error!Plan {
    const landing = switch (params.wanted) {
        .land => |it| it,
        .none => |why| return .{ .park = .{ .wanted = null, .why = why } },
    };

    var writing = try env.clone(arena);
    defer writing.deinit();
    try writing.put("GIT_OBJECT_DIRECTORY", params.scratch_object_store);
    try writing.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", params.project_object_store);

    const standing = try standingOf(arena, io, params.repository, diag);
    const ready = switch (standing) {
        .park => |why| return .{ .park = .{ .wanted = landing, .why = why } },
        .ready => |it| it,
    };

    if (try isAncestor(arena, io, params.repository, params.new_id, ready.at, diag))
        return .{ .park = .{ .wanted = landing, .why = .already_there } };

    const built = switch (landing) {
        .merge, .squash => try mergeOrSquash(arena, io, &writing, .{
            .repository = params.repository,
            .scratch_object_store = params.scratch_object_store,
            .project_object_store = params.project_object_store,
            .landing = landing,
            .branch = ready.branch,
            .at = ready.at,
            .ref = params.ref,
            .new_id = params.new_id,
            .claimed_identity_in_message = params.claimed_identity_in_message,
            .identity = params.identity,
        }, diag),
        .rebase => try replay(arena, io, &writing, .{
            .repository = params.repository,
            .scratch_object_store = params.scratch_object_store,
            .project_object_store = params.project_object_store,
            .at = ready.at,
            .new_id = params.new_id,
            .claimed_identity_in_message = params.claimed_identity_in_message,
            .identity = params.identity,
        }, diag),
    };

    return switch (built) {
        .refused => |why| .{ .park = .{ .wanted = landing, .why = why } },
        .landed => |made| .{ .move = .{
            .landing = landing,
            .branch = ready.branch,
            .at = ready.at,
            .to = made.id,
            .claimed = made.claimed,
        } },
    };
}

pub fn moving(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repository: []const u8,
    move: Move,
    diag: ?*?Diagnostic,
) git.Error!Outcome {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A person can change the repository between the question and the answer.
    const standing = standingOf(arena, io, repository, diag) catch |err| switch (err) {
        error.GitFailed => return .{ .park = .{ .wanted = move.landing, .why = .git_refused } },
        else => |e| return e,
    };
    const ready = switch (standing) {
        .park => |why| return .{ .park = .{ .wanted = move.landing, .why = why } },
        .ready => |it| it,
    };
    if (!std.mem.eql(u8, ready.branch, move.branch) or !std.mem.eql(u8, ready.at, move.at)) {
        return .{ .park = .{ .wanted = move.landing, .why = .branch_moved } };
    }

    var output = try git.run(gpa, io, env, repository, &.{
        "merge", "--ff-only", "--quiet", move.to,
    }, null);
    defer output.deinit(gpa);
    if (output.term != .exited or output.term.exited != 0) {
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{ .git_refused_the_act = try gpa.dupe(u8, output.stderr) });
        }
        return .{ .park = .{ .wanted = move.landing, .why = .git_refused } };
    }

    return .{ .moved = .{
        .landing = move.landing,
        .branch = try gpa.dupe(u8, move.branch),
        .from = try gpa.dupe(u8, move.at),
        .to = try gpa.dupe(u8, move.to),
        .claimed = try gpa.dupe(u8, move.claimed),
    } };
}

const Standing = union(enum) {
    ready: struct { branch: []const u8, at: []const u8 },
    park: Reason,
};

fn standingOf(
    arena: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    diag: ?*?Diagnostic,
) Error!Standing {
    var repo = try openRepository(arena, io, repository, .{}, diag);
    defer repo.deinit();
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*it| it.deinit(arena);

    // A linked worktree keeps its own HEAD in its git directory; the refs it names are shared.
    var head_store = ziggit.Store.init(arena, io, repo.layout.git_dir, repo.format, null);
    var head = head_store.lookup("HEAD", &fault) catch |err| return refused(arena, diag, "HEAD", err, &fault);
    defer head.deinit(arena);
    const branch = switch (head.target) {
        .oid => return .{ .park = .detached_head },
        .symbolic => |name| name,
    };

    if (midOperation(io, repo.layout.git_dir)) return .{ .park = .unfinished_operation };

    const tip: ?ziggit.Oid = repo.refs.resolve(branch, &fault) catch |err| switch (err) {
        error.RefNotFound => null,
        else => return refused(arena, diag, branch, err, &fault),
    };

    // Untracked files count as dirty, but ignored files are not reported.
    if (!try cleanTree(arena, io, &repo, tip, diag)) return .{ .park = .dirty_tree };

    const at = tip orelse return .{ .park = .branch_has_no_commit };
    var hex: [ziggit.Oid.max_formatted_length]u8 = undefined;
    return .{ .ready = .{
        .branch = try arena.dupe(u8, branch),
        .at = try arena.dupe(u8, at.toHex(&hex)),
    } };
}

fn cleanTree(
    arena: std.mem.Allocator,
    io: std.Io,
    repo: *ziggit.Repository,
    tip: ?ziggit.Oid,
    diag: ?*?Diagnostic,
) Error!bool {
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*it| it.deinit(arena);
    const work_tree = repo.layout.work_tree orelse {
        _ = diagnostic.note(diag, .{ .git_refused_a_description = try arena.dupe(u8, "the repository has no working tree") });
        return error.GitFailed;
    };

    // The index belongs to the worktree, so a linked worktree has its own.
    var index = ziggit.WorktreeIndex.open(arena, io, repo.layout.git_dir, repo.format) catch |err| switch (err) {
        error.IndexNotFound => ziggit.WorktreeIndex{ .gpa = arena, .entries = &.{} },
        else => return refused(arena, diag, "the index", err, &fault),
    };
    defer index.deinit();

    // Git's own config is /dev/null for the spawned calls, so only these two sources apply.
    var ignore = ziggit.IgnoreMatcher.init(arena);
    defer ignore.deinit();
    ignore.addFile(io, repo.layout.common_dir, "info/exclude", "") catch |err| return refused(arena, diag, "info/exclude", err, &fault);

    const head_tree: ?ziggit.Oid = if (tip) |id|
        ziggit.peel(arena, repo, id, .tree) catch |err| return refused(arena, diag, "the tree of HEAD", err, &fault)
    else
        null;

    var result = ziggit.status(arena, io, work_tree, &repo.odb, index, repo.format, .{
        .ignore = &ignore,
        .head_tree = head_tree,
    }, &fault) catch |err| return refused(arena, diag, "the working tree", err, &fault);
    defer result.deinit(arena);
    return result.isClean();
}

fn midOperation(io: std.Io, git_dir: std.Io.Dir) bool {
    for (unfinished_markers) |marker| {
        // `access`, not a stat of a kind: `rebase-merge` is a directory, `MERGE_HEAD` a file.
        git_dir.access(io, marker, .{}) catch continue;
        return true;
    }
    return false;
}

/// A repository the caller owns and calls `deinit` on. `objects` names where a write
/// lands and which directories a read falls back to, the way git names both with
/// GIT_OBJECT_DIRECTORY and GIT_ALTERNATE_OBJECT_DIRECTORIES.
pub fn openRepository(
    arena: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    objects: ziggit.Odb.Options,
    diag: ?*?Diagnostic,
) Error!ziggit.Repository {
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*it| it.deinit(arena);
    var start = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch |err|
        return refused(arena, diag, path, err, &fault);
    defer start.close(io);
    var layout = ziggit.discover(arena, io, start, .{}, &fault) catch |err|
        return refused(arena, diag, path, err, &fault);
    return ziggit.Repository.open(arena, io, layout, .{ .odb = objects }, &fault) catch |err| {
        layout.deinit(io);
        return refused(arena, diag, path, err, &fault);
    };
}

/// A repository whose writes land in the scratch store, which is how a landing keeps new
/// objects out of the user's repository. A read falls back to the project's own store.
fn openWriting(
    arena: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    scratch_object_store: []const u8,
    project_object_store: []const u8,
    diag: ?*?Diagnostic,
) Error!ziggit.Repository {
    return openRepository(arena, io, repository, .{
        .object_directory = scratch_object_store,
        .alternate_directories = &.{project_object_store},
    }, diag);
}

fn oidOf(
    arena: std.mem.Allocator,
    repo: *const ziggit.Repository,
    hex: []const u8,
    diag: ?*?Diagnostic,
) Error!ziggit.Oid {
    var fault: ?ziggit.Diagnostic = null;
    return ziggit.Oid.parse(repo.format, hex) catch |err| refused(arena, diag, hex, err, &fault);
}

fn hexOf(arena: std.mem.Allocator, id: ziggit.Oid) Error![]const u8 {
    return std.fmt.allocPrint(arena, "{f}", .{id});
}

/// Reports what ziggit said, where git's stderr would have gone, and gives the one error the callers already read.
pub fn refused(
    arena: std.mem.Allocator,
    diag: ?*?Diagnostic,
    doing: []const u8,
    err: anyerror,
    fault: *?ziggit.Diagnostic,
) Error {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    if (diagnostic.wants(diag)) {
        const detail = if (fault.*) |it| it.detail orelse "" else "";
        const text = std.fmt.allocPrint(arena, "{s}: {s}{s}{s}", .{
            doing, @errorName(err), if (detail.len > 0) ": " else "", detail,
        }) catch return error.OutOfMemory;
        _ = diagnostic.note(diag, .{ .git_refused_a_description = text });
    }
    return error.GitFailed;
}

/// False also means the walk hit its bound or an id did not parse. The caller then builds the
/// merge, and `merge --ff-only` stays the last check, so a wrong false costs one extra attempt.
fn isAncestor(
    arena: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    ancestor: []const u8,
    descendant: []const u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var repo = try openRepository(arena, io, repository, .{}, diag);
    defer repo.deinit();
    const old = ziggit.Oid.parse(repo.format, ancestor) catch return false;
    const new = ziggit.Oid.parse(repo.format, descendant) catch return false;
    return revwalk.isAncestor(arena, &repo, old, new, null);
}

const Built = union(enum) {
    commit: []const u8,
    refused: Reason,
};

const Made = union(enum) {
    landed: struct { id: []const u8, claimed: []const u8 },
    refused: Reason,
};

fn mergeOrSquash(
    arena: std.mem.Allocator,
    io: std.Io,
    writing: *const std.process.Environ.Map,
    params: struct {
        repository: []const u8,
        scratch_object_store: []const u8,
        project_object_store: []const u8,
        landing: Landing,
        branch: []const u8,
        at: []const u8,
        ref: []const u8,
        new_id: []const u8,
        claimed_identity_in_message: bool,
        identity: chock_policy.identity.Identity = .{},
    },
    diag: ?*?Diagnostic,
) Error!Made {
    const tree = switch (try mergedTree(arena, io, writing, params.repository, .{
        .base = null,
        .ours = params.at,
        .theirs = params.new_id,
    }, diag)) {
        .refused => |why| return .{ .refused = why },
        .commit => |id| id,
    };

    const message = switch (params.landing) {
        .merge => try std.fmt.allocPrint(
            arena,
            "Merge {s}\n\nThe work of one chock session, carried into {s}.\n",
            .{ params.ref, params.branch },
        ),
        .squash => try squashMessage(arena, io, params.repository, params.scratch_object_store, params.ref, params.at, params.new_id, diag),
        else => unreachable,
    };

    const authorship = try landingAuthorship(arena, io, writing, params.repository, params.new_id, params.identity, diag);
    const claimed = switch (params.landing) {
        .merge => try claimedBy(arena, io, writing, params.repository, &.{params.new_id}, diag),
        .squash => try claimedBy(arena, io, writing, params.repository, try rangeIds(arena, io, writing, params.repository, params.at, params.new_id, diag), diag),
        else => unreachable,
    };
    const signed = if (params.claimed_identity_in_message) try withClaims(arena, message, claimed) else message;

    var repo = try openWriting(arena, io, params.repository, params.scratch_object_store, params.project_object_store, diag);
    defer repo.deinit();
    const at = try oidOf(arena, &repo, params.at, diag);
    const parents: []const ziggit.Oid = switch (params.landing) {
        .merge => &.{ at, try oidOf(arena, &repo, params.new_id, diag) },
        .squash => &.{at},
        else => unreachable,
    };
    const written = git_write.writeCommit(arena, &repo, .{
        .tree = try oidOf(arena, &repo, tree, diag),
        .parents = parents,
        .message = signed,
        .author = authorship.author,
        .committer = authorship.committer,
    }) catch |err| {
        var fault: ?ziggit.Diagnostic = null;
        return refused(arena, diag, "writing the landing commit", err, &fault);
    };
    return .{ .landed = .{ .id = try hexOf(arena, written), .claimed = claimed } };
}

fn rangeIds(
    arena: std.mem.Allocator,
    io: std.Io,
    reading: *const std.process.Environ.Map,
    repository: []const u8,
    at: []const u8,
    new_id: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []const u8 {
    const range = try std.fmt.allocPrint(arena, "{s}..{s}", .{ at, new_id });
    const printed = try ok(arena, io, reading, repository, &.{ "rev-list", "--reverse", range }, diag);
    var ids: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, printed, '\n');
    while (lines.next()) |line| if (line.len > 0) try ids.append(arena, line);
    return ids.items;
}

fn squashMessage(
    arena: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    scratch_object_store: []const u8,
    ref: []const u8,
    at: []const u8,
    new_id: []const u8,
    diag: ?*?Diagnostic,
) Error![]const u8 {
    var repo = try openRepository(arena, io, repository, .{ .alternate_directories = &.{scratch_object_store} }, diag);
    defer repo.deinit();
    const steps = try commitsAfter(arena, &repo, at, new_id, diag);

    var subjects: std.ArrayList(u8) = .empty;
    for (steps) |step| {
        try subjects.appendSlice(arena, "* ");
        try subjects.appendSlice(arena, try subjectOf(arena, step.message));
        try subjects.append(arena, '\n');
    }

    return std.fmt.allocPrint(
        arena,
        "Squash {s}\n\nThe work of one chock session, as one commit. It was:\n\n{s}\n",
        .{ ref, std.mem.trimEnd(u8, subjects.items, "\n") },
    );
}

/// One commit of a range, with what a landing reads off it.
const Step = struct {
    id: ziggit.Oid,
    parents: []const ziggit.Oid,
    message: []const u8,
};

/// The commits that `new_id` reaches and `at` does not, parents before children. Commit times
/// do not decide the order, so commits made in the same second still come out oldest first.
fn commitsAfter(
    arena: std.mem.Allocator,
    repo: *ziggit.Repository,
    at: []const u8,
    new_id: []const u8,
    diag: ?*?Diagnostic,
) Error![]const Step {
    var fault: ?ziggit.Diagnostic = null;
    defer if (fault) |*it| it.deinit(arena);

    const old = ziggit.Oid.parse(repo.format, at) catch |err| return refused(arena, diag, at, err, &fault);
    const new = ziggit.Oid.parse(repo.format, new_id) catch |err| return refused(arena, diag, new_id, err, &fault);
    var walk = ziggit.Walk.init(arena, repo);
    defer walk.deinit();
    walk.push(new) catch |err| return refused(arena, diag, new_id, err, &fault);
    walk.hide(old) catch |err| return refused(arena, diag, at, err, &fault);

    var steps: std.ArrayList(Step) = .empty;
    var index: std.AutoHashMapUnmanaged(ziggit.Oid, usize) = .empty;
    while (walk.next() catch |err| return refused(arena, diag, "the commits to carry", err, &fault)) |id| {
        const bytes = repo.odb.readAlloc(arena, id, max_commit_bytes, &fault) catch |err|
            return refused(arena, diag, "a commit to carry", err, &fault);
        const commit = ziggit.Commit.parse(arena, repo.format, bytes) catch |err|
            return refused(arena, diag, "a commit to carry", err, &fault);
        try index.put(arena, id, steps.items.len);
        try steps.append(arena, .{ .id = id, .parents = commit.parents, .message = commit.message });
    }

    // The walk is newest first; going from the far end and visiting parents first makes it oldest first.
    const Open = struct { at: usize, next_parent: usize };
    const done = try arena.alloc(bool, steps.items.len);
    @memset(done, false);
    var ordered: std.ArrayList(Step) = .empty;
    var open: std.ArrayList(Open) = .empty;
    var start = steps.items.len;
    while (start > 0) {
        start -= 1;
        if (done[start]) continue;
        done[start] = true;
        try open.append(arena, .{ .at = start, .next_parent = 0 });
        while (open.items.len > 0) {
            const top = &open.items[open.items.len - 1];
            const parents = steps.items[top.at].parents;
            if (top.next_parent < parents.len) {
                const parent = parents[top.next_parent];
                top.next_parent += 1;
                const found = index.get(parent) orelse continue;
                if (done[found]) continue;
                done[found] = true;
                try open.append(arena, .{ .at = found, .next_parent = 0 });
            } else {
                try ordered.append(arena, steps.items[top.at]);
                open.shrinkRetainingCapacity(open.items.len - 1);
            }
        }
    }
    return ordered.items;
}

pub const max_commit_bytes = 1 << 20;

/// Git's `%s`: the first paragraph of the message on one line.
pub fn subjectOf(arena: std.mem.Allocator, message: []const u8) std.mem.Allocator.Error![]const u8 {
    var subject: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, message, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " \t\r");
        if (line.len == 0) {
            if (subject.items.len == 0) continue;
            break;
        }
        if (subject.items.len > 0) try subject.append(arena, ' ');
        try subject.appendSlice(arena, line);
    }
    return subject.items;
}

fn replay(
    arena: std.mem.Allocator,
    io: std.Io,
    writing: *const std.process.Environ.Map,
    params: struct {
        repository: []const u8,
        scratch_object_store: []const u8,
        project_object_store: []const u8,
        at: []const u8,
        new_id: []const u8,
        claimed_identity_in_message: bool,
        identity: chock_policy.identity.Identity = .{},
    },
    diag: ?*?Diagnostic,
) Error!Made {
    var repo = try openWriting(arena, io, params.repository, params.scratch_object_store, params.project_object_store, diag);
    defer repo.deinit();
    const steps = try commitsAfter(arena, &repo, params.at, params.new_id, diag);

    var current = params.at;
    var replayed: usize = 0;
    var all_claims: std.ArrayList(u8) = .empty;
    for (steps) |step| {
        if (step.parents.len != 1) return .{ .refused = .history_not_linear };
        var parent_hex: [ziggit.Oid.max_formatted_length]u8 = undefined;
        var commit_hex: [ziggit.Oid.max_formatted_length]u8 = undefined;
        const parent = try arena.dupe(u8, step.parents[0].toHex(&parent_hex));
        const commit = try arena.dupe(u8, step.id.toHex(&commit_hex));

        const tree = switch (try mergedTree(arena, io, writing, params.repository, .{
            .base = parent,
            .ours = current,
            .theirs = commit,
        }, diag)) {
            .refused => |why| return .{ .refused = why },
            .commit => |id| id,
        };

        const message = std.mem.trimEnd(u8, step.message, "\n");
        const authorship = try landingAuthorship(arena, io, writing, params.repository, commit, params.identity, diag);
        const claimed = try claimedBy(arena, io, writing, params.repository, &.{commit}, diag);
        const body = if (message.len > 0) message else "(no message)";
        const signed = if (params.claimed_identity_in_message) try withClaims(arena, body, claimed) else body;
        try mergeClaims(arena, &all_claims, claimed);
        const written = git_write.writeCommit(arena, &repo, .{
            .tree = try oidOf(arena, &repo, tree, diag),
            .parents = &.{try oidOf(arena, &repo, current, diag)},
            .message = signed,
            .author = authorship.author,
            .committer = authorship.committer,
        }) catch |err| {
            var fault: ?ziggit.Diagnostic = null;
            return refused(arena, diag, "writing a replayed commit", err, &fault);
        };
        current = try hexOf(arena, written);
        replayed += 1;
    }

    if (replayed == 0) return .{ .refused = .already_there };
    return .{ .landed = .{ .id = current, .claimed = all_claims.items } };
}

/// `--merge-base` names the base explicitly: that's what turns a merge into a cherry pick.
fn mergedTree(
    arena: std.mem.Allocator,
    io: std.Io,
    writing: *const std.process.Environ.Map,
    repository: []const u8,
    params: struct {
        base: ?[]const u8,
        ours: []const u8,
        theirs: []const u8,
    },
    diag: ?*?Diagnostic,
) Error!Built {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(arena);
    try argv.appendSlice(arena, &.{ "merge-tree", "--write-tree" });
    if (params.base) |base| {
        try argv.append(arena, try std.fmt.allocPrint(arena, "--merge-base={s}", .{base}));
    }
    try argv.appendSlice(arena, &.{ params.ours, params.theirs });

    var output = try git.run(arena, io, writing, repository, argv.items, null);
    defer output.deinit(arena);
    if (output.term != .exited) return error.GitFailed;
    switch (output.term.exited) {
        0 => {},
        // On exit 1 the tree git printed holds conflict markers.
        1 => return .{ .refused = .would_conflict },
        else => {
            if (diagnostic.wants(diag)) {
                _ = diagnostic.note(diag, .{
                    .git_refused_a_description = try arena.dupe(u8, output.stderr),
                });
            }
            return .{ .refused = .git_refused };
        },
    }

    const printed = std.mem.trimEnd(u8, output.stdout, "\n");
    const first = printed[0 .. std.mem.indexOfScalar(u8, printed, '\n') orelse printed.len];
    if (first.len == 0) return .{ .refused = .git_refused };
    return .{ .commit = try arena.dupe(u8, first) };
}

/// Chock makes these commit objects, so chock is both the author and the committer.
/// What the source commit claimed is read by `claimedBy`, never put in a header: it
/// always goes to the session log, and into the message only when the project asks.
const Authorship = struct {
    author: ziggit.Identity,
    committer: ziggit.Identity,
};

/// The author keeps the date of the commit being carried over, as git does for a
/// rebase, so a landing does not restamp the work. The committer is now, in UTC.
fn landingAuthorship(
    arena: std.mem.Allocator,
    io: std.Io,
    reading: *const std.process.Environ.Map,
    repository: []const u8,
    commit: []const u8,
    identity: chock_policy.identity.Identity,
    diag: ?*?Diagnostic,
) Error!Authorship {
    const raw = try ok(arena, io, reading, repository, &.{
        "show", "-s", "--format=%ad", "--date=raw", commit,
    }, diag);
    // `--date=raw` is the authorship line's own time format, so ziggit reads it once a
    // name and an address stand in front of it. The date is all that is kept.
    const line = try std.fmt.allocPrint(arena, "x <y> {s}", .{raw});
    const dated = ziggit.Identity.parse(line) catch {
        var fault: ?ziggit.Diagnostic = null;
        return refused(arena, diag, raw, error.MalformedIdentity, &fault);
    };
    const seconds: i64 = @intCast(@divFloor(std.Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
    return .{
        .author = .{
            .name = identity.name,
            .email = identity.email,
            .when = dated.when,
            .tz_offset_minutes = dated.tz_offset_minutes,
            .tz_negative_zero = dated.tz_negative_zero,
        },
        .committer = .{ .name = identity.name, .email = identity.email, .when = seconds, .tz_offset_minutes = 0 },
    };
}

/// Trailer lines naming who the source commits said they were. Empty when there are none.
fn claimedBy(
    arena: std.mem.Allocator,
    io: std.Io,
    reading: *const std.process.Environ.Map,
    repository: []const u8,
    commits: []const []const u8,
    diag: ?*?Diagnostic,
) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (commits) |commit| {
        const printed = try ok(arena, io, reading, repository, &.{
            "show", "-s", "--format=Claimed-Author: %an <%ae>%nClaimed-Committer: %cn <%ce>", commit,
        }, diag);
        var lines = std.mem.splitScalar(u8, printed, '\n');
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, out.items, line) != null) continue;
            if (out.items.len > 0) try out.append(arena, '\n');
            try out.appendSlice(arena, line);
        }
    }
    return out.items;
}

/// Adds each line of `more` that `into` does not hold yet.
fn mergeClaims(arena: std.mem.Allocator, into: *std.ArrayList(u8), more: []const u8) std.mem.Allocator.Error!void {
    var lines = std.mem.splitScalar(u8, more, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or std.mem.indexOf(u8, into.items, line) != null) continue;
        if (into.items.len > 0) try into.append(arena, '\n');
        try into.appendSlice(arena, line);
    }
}

fn withClaims(arena: std.mem.Allocator, message: []const u8, claims: []const u8) std.mem.Allocator.Error![]const u8 {
    if (claims.len == 0) return message;
    return std.fmt.allocPrint(arena, "{s}\n\n{s}\n", .{ std.mem.trimEnd(u8, message, "\n"), claims });
}

fn ok(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    argv: []const []const u8,
    diag: ?*?Diagnostic,
) Error![]u8 {
    var output = try git.run(arena, io, env, cwd, argv, null);
    defer output.deinit(arena);
    if (output.term != .exited or output.term.exited != 0) {
        if (diagnostic.wants(diag)) {
            _ = diagnostic.note(diag, .{
                .git_refused_a_description = try arena.dupe(u8, output.stderr),
            });
        }
        return error.GitFailed;
    }
    return arena.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

const testing = std.testing;

test "every reason says something a person can read, and none of them is silence" {
    for (std.enums.values(Reason)) |reason| {
        try testing.expect(reason.wireName().len > 0);
        try testing.expect(reason.sentence().len > 0);
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, reason.wireName(), ' '));
        try testing.expect(!std.mem.eql(u8, "not_asked_for", reason.wireName()));
    }
    try testing.expectEqualStrings("policy_refused", Reason.policy_refused.wireName());
}

test "a plan that moves nothing names why, and one that moves says nothing about why" {
    const parked: Plan = .{ .park = .{ .wanted = .merge, .why = .dirty_tree } };
    try testing.expectEqual(Reason.dirty_tree, parked.parked().?.why);
    try testing.expectEqual(@as(?Landing, .merge), parked.wanted());

    const never: Plan = .{ .park = .{ .wanted = null, .why = .policy_refused } };
    try testing.expectEqual(@as(?Landing, null), never.wanted());
    try testing.expectEqual(Reason.policy_refused, never.parked().?.why);

    const moving_plan: Plan = .{ .move = .{
        .landing = .merge,
        .branch = "refs/heads/main",
        .at = &@as([40]u8, @splat('a')),
        .to = &@as([40]u8, @splat('b')),
    } };
    try testing.expectEqual(@as(?Parked, null), moving_plan.parked());
    try testing.expectEqual(@as(?Landing, .merge), moving_plan.wanted());
}

test "no landing plans no move, and hands back the reason it was given" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var env = try std.testing.environ.createMap(testing.allocator);
    defer env.deinit();

    for ([_]Reason{ .policy_refused, .nobody_answered }) |why| {
        const plan = try planning(arena_state.allocator(), testing.io, &env, .{
            .repository = "/nowhere/at/all",
            .scratch_object_store = "/nowhere/at/all",
            .project_object_store = "/nowhere/at/all",
            .wanted = .{ .none = why },
            .ref = "refs/chock/01S",
            .new_id = &@as([40]u8, @splat('c')),
        }, null);
        try testing.expectEqual(why, plan.parked().?.why);
        try testing.expectEqual(@as(?Landing, null), plan.wanted());
    }
}

test "a wanted landing is a landing, and nothing wanted is null" {
    try testing.expectEqual(@as(?Landing, .rebase), (Wanted{ .land = .rebase }).landing());
    try testing.expectEqual(@as(?Landing, null), (Wanted{ .none = .apply_refused }).landing());
}

test "an outcome that moved holds the whole of what moved" {
    const gpa = testing.allocator;
    var outcome: Outcome = .{ .moved = .{
        .landing = .rebase,
        .branch = try gpa.dupe(u8, "refs/heads/main"),
        .from = try gpa.dupe(u8, &@as([40]u8, @splat('a'))),
        .to = try gpa.dupe(u8, &@as([40]u8, @splat('b'))),
        .claimed = try gpa.dupe(u8, ""),
    } };
    defer outcome.deinit(gpa);
    try testing.expectEqualStrings("refs/heads/main", outcome.moved.branch);
    try testing.expectEqual(Landing.rebase, outcome.moved.landing);
}

const Scene = struct {
    arena_state: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    env: std.process.Environ.Map,
    root: []const u8,
    /// The repository's own object store, and the scratch store a landing writes into.
    /// `env` names the scratch one as an alternate, so git reads back what ziggit wrote.
    objects: []const u8,
    scratch: []const u8,

    fn init(gpa: std.mem.Allocator) !Scene {
        var scene: Scene = .{
            .arena_state = std.heap.ArenaAllocator.init(gpa),
            .tmp = testing.tmpDir(.{}),
            .env = try testing.environ.createMap(gpa),
            .root = undefined,
            .objects = undefined,
            .scratch = undefined,
        };
        errdefer scene.deinit();
        const arena = scene.arena_state.allocator();
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try scene.tmp.dir.realPath(testing.io, &buffer);
        scene.root = try std.fs.path.join(arena, &.{ buffer[0..len], "project" });
        scene.objects = try std.fs.path.join(arena, &.{ scene.root, ".git", "objects" });
        scene.scratch = try std.fs.path.join(arena, &.{ buffer[0..len], "scratch" });
        try std.Io.Dir.createDirAbsolute(testing.io, scene.scratch, .default_dir);
        try scene.env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", scene.scratch);
        try scene.env.put("GIT_CEILING_DIRECTORIES", try arena.dupe(u8, buffer[0..len]));
        try std.Io.Dir.createDirAbsolute(testing.io, scene.root, .default_dir);

        _ = ok(arena, testing.io, &scene.env, scene.root, &.{ "init", "-b", "main" }, null) catch return error.SkipZigTest;
        _ = try scene.git(&.{ "config", "user.email", "test@example.com" });
        _ = try scene.git(&.{ "config", "user.name", "Test" });
        try scene.write("tracked.txt", "hello\n");
        try scene.write(".gitignore", "*.log\n");
        _ = try scene.git(&.{ "add", "." });
        _ = try scene.git(&.{ "commit", "-m", "first" });
        return scene;
    }

    fn deinit(self: *Scene) void {
        self.env.deinit();
        self.tmp.cleanup();
        self.arena_state.deinit();
    }

    fn git(self: *Scene, argv: []const []const u8) ![]u8 {
        return ok(self.arena_state.allocator(), testing.io, &self.env, self.root, argv, null);
    }

    fn write(self: *Scene, name: []const u8, contents: []const u8) !void {
        try self.tmp.dir.writeFile(testing.io, .{
            .sub_path = try std.fs.path.join(self.arena_state.allocator(), &.{ "project", name }),
            .data = contents,
        });
    }

    fn remove(self: *Scene, name: []const u8) !void {
        try std.Io.Dir.deleteFileAbsolute(testing.io, try std.fs.path.join(self.arena_state.allocator(), &.{ self.root, name }));
    }

    /// What `standingOf` says; a ready tree must also be one git's own `status --porcelain` calls clean.
    fn standing(self: *Scene) !Standing {
        const result = try standingOf(self.arena_state.allocator(), testing.io, self.root, null);
        if (result == .ready) try testing.expectEqualStrings("", try self.git(&.{ "status", "--porcelain" }));
        return result;
    }

    fn expectPark(self: *Scene, why: Reason) !void {
        const result = try self.standing();
        try testing.expectEqual(why, result.park);
    }
};

test "a clean tree is ready, and names the branch and the tip git names" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const result = try scene.standing();
    try testing.expectEqualStrings("refs/heads/main", result.ready.branch);
    try testing.expectEqualStrings(try scene.git(&.{ "rev-parse", "HEAD" }), result.ready.at);
}

test "anything git reports as a change parks the tree as dirty, and an ignored file does not" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    try scene.write("build.log", "ignored by .gitignore\n");
    try scene.write(".git/info/exclude", "scratch.*\n");
    try scene.write("scratch.txt", "ignored by info/exclude\n");
    // A rewritten file has a new stat and the same content, which is not a change.
    try scene.write("tracked.txt", "hello\n");
    _ = try scene.standing();

    try scene.write("new.txt", "untracked\n");
    try scene.expectPark(.dirty_tree);
    try scene.remove("new.txt");

    try scene.write("tracked.txt", "edited\n");
    try scene.expectPark(.dirty_tree);
    _ = try scene.git(&.{ "add", "tracked.txt" });
    try scene.expectPark(.dirty_tree);
    _ = try scene.git(&.{ "commit", "-m", "second" });
    _ = try scene.standing();

    _ = try scene.git(&.{ "rm", "--quiet", "tracked.txt" });
    try scene.expectPark(.dirty_tree);
}

test "a conflicted index with no merge marker parks the tree as dirty" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    try scene.write("tracked.txt", "stashed\n");
    _ = try scene.git(&.{ "stash", "push", "--quiet" });
    try scene.write("tracked.txt", "committed\n");
    _ = try scene.git(&.{ "commit", "--quiet", "-am", "second" });
    const popped = try git.run(arena, testing.io, &scene.env, scene.root, &.{ "stash", "pop", "--quiet" }, null);
    try testing.expect(popped.term.exited != 0);
    try testing.expect(std.mem.startsWith(u8, try scene.git(&.{ "status", "--porcelain" }), "UU "));

    try scene.expectPark(.dirty_tree);
}

test "a detached head, an unborn branch and an unfinished operation each park for their own reason" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    try scene.write(".git/MERGE_HEAD", "0000000000000000000000000000000000000000\n");
    try scene.expectPark(.unfinished_operation);
    try scene.remove(".git/MERGE_HEAD");

    _ = try scene.git(&.{ "checkout", "--quiet", "--detach", "HEAD" });
    try scene.expectPark(.detached_head);

    _ = try scene.git(&.{ "checkout", "--quiet", "--orphan", "fresh" });
    _ = try scene.git(&.{ "rm", "--quiet", "-rf", "." });
    try scene.expectPark(.branch_has_no_commit);
}

test "a linked worktree is read for its own head, index and markers" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const linked = try std.fs.path.join(arena, &.{ std.fs.path.dirname(scene.root).?, "linked" });
    _ = try scene.git(&.{ "worktree", "add", "--quiet", "-b", "other", linked });

    const there = try standingOf(arena, testing.io, linked, null);
    try testing.expectEqualStrings("refs/heads/other", there.ready.branch);
    const here = try standingOf(arena, testing.io, scene.root, null);
    try testing.expectEqualStrings("refs/heads/main", here.ready.branch);

    var dir = try std.Io.Dir.openDirAbsolute(testing.io, linked, .{});
    defer dir.close(testing.io);
    try dir.writeFile(testing.io, .{ .sub_path = "scratch.txt", .data = "untracked in the linked tree\n" });
    try testing.expectEqual(Reason.dirty_tree, (try standingOf(arena, testing.io, linked, null)).park);
    try testing.expectEqualStrings("refs/heads/main", (try standingOf(arena, testing.io, scene.root, null)).ready.branch);
}

test "an ancestor is found as git finds it, and an unrelated or malformed id is not one" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const first = try scene.git(&.{ "rev-parse", "HEAD" });
    try scene.write("second.txt", "two\n");
    _ = try scene.git(&.{ "add", "." });
    _ = try scene.git(&.{ "commit", "-m", "second" });
    const second = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try scene.git(&.{ "checkout", "--quiet", "-b", "side", first });
    try scene.write("side.txt", "side\n");
    _ = try scene.git(&.{ "add", "." });
    _ = try scene.git(&.{ "commit", "-m", "side" });
    const side = try scene.git(&.{ "rev-parse", "HEAD" });

    try testing.expect(try isAncestor(arena, testing.io, scene.root, first, second, null));
    try testing.expect(try isAncestor(arena, testing.io, scene.root, second, second, null));
    try testing.expect(!try isAncestor(arena, testing.io, scene.root, second, first, null));
    try testing.expect(!try isAncestor(arena, testing.io, scene.root, side, second, null));
    try testing.expect(!try isAncestor(arena, testing.io, scene.root, "not an id", second, null));
}

/// What `commitsAfter` finds, written as `git rev-list --reverse --parents` writes it.
fn renderSteps(arena: std.mem.Allocator, steps: []const Step) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (steps) |step| {
        var hex: [ziggit.Oid.max_formatted_length]u8 = undefined;
        try out.appendSlice(arena, step.id.toHex(&hex));
        for (step.parents) |parent| {
            try out.append(arena, ' ');
            try out.appendSlice(arena, parent.toHex(&hex));
        }
        try out.append(arena, '\n');
    }
    return std.mem.trimEnd(u8, out.items, "\n");
}

fn expectRangeAgrees(scene: *Scene, alternates: []const []const u8, at: []const u8, new_id: []const u8) !void {
    const arena = scene.arena_state.allocator();
    var repo = try openRepository(arena, testing.io, scene.root, .{ .alternate_directories = alternates }, null);
    defer repo.deinit();

    const steps = try commitsAfter(arena, &repo, at, new_id, null);
    const range = try std.fmt.allocPrint(arena, "{s}..{s}", .{ at, new_id });
    try testing.expectEqualStrings(
        try scene.git(&.{ "rev-list", "--reverse", "--parents", range }),
        try renderSteps(arena, steps),
    );

    var subjects: std.ArrayList(u8) = .empty;
    var messages: std.ArrayList(u8) = .empty;
    for (steps) |step| {
        try subjects.print(arena, "* {s}\n", .{try subjectOf(arena, step.message)});
        var hex: [ziggit.Oid.max_formatted_length]u8 = undefined;
        const raw = try scene.git(&.{ "show", "-s", "--format=%B", step.id.toHex(&hex) });
        try testing.expectEqualStrings(raw, std.mem.trimEnd(u8, step.message, "\n"));
        try messages.appendSlice(arena, raw);
    }
    try testing.expectEqualStrings(
        try scene.git(&.{ "log", "--reverse", "--format=* %s", range }),
        std.mem.trimEnd(u8, subjects.items, "\n"),
    );
}

fn commitAt(scene: *Scene, name: []const u8, message: []const u8, when: []const u8) ![]const u8 {
    const arena = scene.arena_state.allocator();
    try scene.env.put("GIT_COMMITTER_DATE", when);
    try scene.env.put("GIT_AUTHOR_DATE", when);
    try scene.write(name, message);
    _ = try scene.git(&.{ "add", "." });
    _ = try scene.git(&.{ "commit", "-m", message });
    return arena.dupe(u8, try scene.git(&.{ "rev-parse", "HEAD" }));
}

test "a linear range comes out oldest first as git lists it, though every commit has the same time" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    for ([_][]const u8{ "one", "two", "three", "four", "five" }) |name| {
        _ = try commitAt(&scene, name, name, "2020-01-01T00:00:00Z");
    }
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });
    try expectRangeAgrees(&scene, &.{}, base, tip);

    // An unrelated history leaves the root commit in the range, and it prints no parent.
    _ = try scene.git(&.{ "checkout", "--quiet", "--orphan", "unrelated" });
    const unrelated = try commitAt(&scene, "orphan", "orphan", "2020-01-01T00:00:00Z");
    try expectRangeAgrees(&scene, &.{}, unrelated, tip);
}

test "a message with a body, a wrapped subject and no trailing newline reads as git reads it" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    try scene.write("a.txt", "a\n");
    _ = try scene.git(&.{ "add", "." });
    _ = try scene.git(&.{ "commit", "-m", "a subject that\nwraps onto a second line\n\nThe body\nhas two lines.\n\n\nAnd a gap." });
    try scene.write("b.txt", "b\n");
    _ = try scene.git(&.{ "add", "." });
    _ = try scene.git(&.{ "commit", "--allow-empty-message", "-m", "" });
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });
    try expectRangeAgrees(&scene, &.{}, base, tip);
}

test "a range with a merge lists the side branch before the merge, and the merge names both parents" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try commitAt(&scene, "main1", "main one", "2020-01-01T00:00:00Z");
    _ = try scene.git(&.{ "checkout", "--quiet", "-b", "side", base });
    _ = try commitAt(&scene, "side1", "side one", "2020-01-02T00:00:00Z");
    _ = try commitAt(&scene, "side2", "side two", "2020-01-03T00:00:00Z");
    _ = try scene.git(&.{ "checkout", "--quiet", "main" });
    try scene.env.put("GIT_COMMITTER_DATE", "2020-01-04T00:00:00Z");
    _ = try scene.git(&.{ "merge", "--no-ff", "--quiet", "-m", "merge side", "side" });
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });
    try expectRangeAgrees(&scene, &.{}, base, tip);

    const arena = scene.arena_state.allocator();
    var repo = try openRepository(arena, testing.io, scene.root, .{}, null);
    defer repo.deinit();
    const steps = try commitsAfter(arena, &repo, base, tip, null);
    try testing.expectEqual(@as(usize, 4), steps.len);
    try testing.expectEqual(@as(usize, 2), steps[3].parents.len);
}

test "commits that only the scratch store holds are read through it" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    var writing = try scene.env.clone(arena);
    try writing.put("GIT_OBJECT_DIRECTORY", scene.scratch);
    try writing.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", scene.objects);

    // `commit-tree` writes the object and moves no ref.
    const tree = try ok(arena, testing.io, &writing, scene.root, &.{ "rev-parse", "HEAD^{tree}" }, null);
    const first = try ok(arena, testing.io, &writing, scene.root, &.{ "commit-tree", tree, "-p", base, "-m", "from the session" }, null);
    const second = try ok(arena, testing.io, &writing, scene.root, &.{ "commit-tree", tree, "-p", first, "-m", "and again" }, null);

    const message = try squashMessage(arena, testing.io, scene.root, scene.scratch, "refs/chock/01S", base, second, null);
    try testing.expectEqualStrings(
        "Squash refs/chock/01S\n\nThe work of one chock session, as one commit. It was:\n\n* from the session\n* and again\n",
        message,
    );
    try testing.expectError(error.GitFailed, squashMessage(arena, testing.io, scene.root, "/nowhere/at/all", "refs/chock/01S", base, second, null));
}

test "a squash message and a replayed rebase land the same commits git lists" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try commitAt(&scene, "one", "first of the work", "2020-01-01T00:00:00Z");
    _ = try commitAt(&scene, "two", "second of the work", "2020-01-01T00:00:00Z");
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try scene.git(&.{ "checkout", "--quiet", "--detach", base });
    _ = try commitAt(&scene, "other", "moved on", "2020-01-02T00:00:00Z");
    const moved = try scene.git(&.{ "rev-parse", "HEAD" });

    const squashed = try squashMessage(arena, testing.io, scene.root, scene.root, "refs/chock/01S", moved, tip, null);
    try testing.expect(std.mem.endsWith(u8, squashed, "* first of the work\n* second of the work\n"));

    const built = try replay(arena, testing.io, &scene.env, .{
        .repository = scene.root,
        .scratch_object_store = scene.scratch,
        .project_object_store = scene.objects,
        .at = moved,
        .new_id = tip,
        .claimed_identity_in_message = false,
    }, null);
    const head = built.landed.id;
    try testing.expectEqualStrings(
        "second of the work\nfirst of the work\nmoved on\nfirst",
        try scene.git(&.{ "log", "--format=%s", head }),
    );
    try testing.expectEqualStrings("second of the work", try scene.git(&.{ "log", "-1", "--format=%s", head }));
}

test "a merge landing takes the branch as its first parent and the session as its second" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try commitAt(&scene, "one", "the work", "2020-01-01T00:00:00Z");
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try scene.git(&.{ "checkout", "--quiet", "--detach", base });
    _ = try commitAt(&scene, "other", "moved on", "2020-01-02T00:00:00Z");
    const moved = try scene.git(&.{ "rev-parse", "HEAD" });

    const landed = (try mergeOrSquash(arena, testing.io, &scene.env, .{
        .repository = scene.root,
        .scratch_object_store = scene.scratch,
        .project_object_store = scene.objects,
        .landing = .merge,
        .branch = "main",
        .at = moved,
        .ref = "refs/chock/01S",
        .new_id = tip,
        .claimed_identity_in_message = false,
    }, null)).landed;

    // Git follows the first parent for the mainline, so this order is what keeps the
    // branch's own history the one a later log and merge base read.
    try testing.expectEqualStrings(moved, try scene.git(&.{
        "rev-parse", try std.fmt.allocPrint(arena, "{s}^1", .{landed.id}),
    }));
    try testing.expectEqualStrings(tip, try scene.git(&.{
        "rev-parse", try std.fmt.allocPrint(arena, "{s}^2", .{landed.id}),
    }));
}

test "a range holding a merge is not linear, and one holding nothing is already there" {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try commitAt(&scene, "main1", "main one", "2020-01-01T00:00:00Z");
    _ = try scene.git(&.{ "checkout", "--quiet", "-b", "side", base });
    _ = try commitAt(&scene, "side1", "side one", "2020-01-02T00:00:00Z");
    _ = try scene.git(&.{ "checkout", "--quiet", "main" });
    _ = try scene.git(&.{ "merge", "--no-ff", "--quiet", "-m", "merge side", "side" });
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });

    try testing.expectEqual(Reason.history_not_linear, (try replay(arena, testing.io, &scene.env, .{
        .repository = scene.root,
        .scratch_object_store = scene.scratch,
        .project_object_store = scene.objects,
        .at = base,
        .new_id = tip,
        .claimed_identity_in_message = false,
    }, null)).refused);
    try testing.expectEqual(Reason.already_there, (try replay(arena, testing.io, &scene.env, .{
        .repository = scene.root,
        .scratch_object_store = scene.scratch,
        .project_object_store = scene.objects,
        .at = tip,
        .new_id = tip,
        .claimed_identity_in_message = false,
    }, null)).refused);
}

const claimed_author = "Claimed-Author: Mallory Author <mallory@evil.example>";
const claimed_committer = "Claimed-Committer: Mallory Committer <boss@company.example>";

/// Lands one commit with a wrong author by merge, squash and replay, and checks what git reports.
fn landWrongAuthor(in_message: bool, identity: chock_policy.identity.Identity) !void {
    var scene = try Scene.init(testing.allocator);
    defer scene.deinit();

    const arena = scene.arena_state.allocator();
    const base = try scene.git(&.{ "rev-parse", "HEAD" });
    try scene.env.put("GIT_AUTHOR_NAME", "Mallory Author");
    try scene.env.put("GIT_AUTHOR_EMAIL", "mallory@evil.example");
    try scene.env.put("GIT_COMMITTER_NAME", "Mallory Committer");
    try scene.env.put("GIT_COMMITTER_EMAIL", "boss@company.example");
    _ = try commitAt(&scene, "one", "the work", "2020-01-01T00:00:00Z");
    const tip = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = try scene.git(&.{ "checkout", "--quiet", "--detach", base });
    _ = try commitAt(&scene, "other", "moved on", "2020-01-02T00:00:00Z");
    const moved = try scene.git(&.{ "rev-parse", "HEAD" });
    _ = scene.env.swapRemove("GIT_AUTHOR_NAME");
    _ = scene.env.swapRemove("GIT_AUTHOR_EMAIL");
    _ = scene.env.swapRemove("GIT_COMMITTER_NAME");
    _ = scene.env.swapRemove("GIT_COMMITTER_EMAIL");

    var made: [3]@FieldType(Made, "landed") = undefined;
    inline for (.{ Landing.merge, Landing.squash }, 0..) |landing, i| {
        made[i] = (try mergeOrSquash(arena, testing.io, &scene.env, .{
            .repository = scene.root,
            .scratch_object_store = scene.scratch,
            .project_object_store = scene.objects,
            .landing = landing,
            .branch = "main",
            .at = moved,
            .ref = "refs/chock/01S",
            .new_id = tip,
            .claimed_identity_in_message = in_message,
            .identity = identity,
        }, null)).landed;
    }
    made[2] = (try replay(arena, testing.io, &scene.env, .{
        .repository = scene.root,
        .scratch_object_store = scene.scratch,
        .project_object_store = scene.objects,
        .at = moved,
        .new_id = tip,
        .claimed_identity_in_message = in_message,
        .identity = identity,
    }, null)).landed;

    for (made) |one| {
        const wanted = try std.fmt.allocPrint(arena, "{0s} <{1s}>\n{0s} <{1s}>", .{ identity.name, identity.email });
        try testing.expectEqualStrings(
            wanted,
            try scene.git(&.{ "show", "-s", "--format=%an <%ae>%n%cn <%ce>", one.id }),
        );
        const message = try scene.git(&.{ "show", "-s", "--format=%B", one.id });
        try testing.expectEqual(in_message, std.mem.indexOf(u8, message, "Claimed-") != null);
        try testing.expectEqual(in_message, std.mem.indexOf(u8, message, "\n\n" ++ claimed_author ++ "\n") != null);
        try testing.expectEqual(in_message, std.mem.indexOf(u8, message, claimed_committer) != null);
        // The evidence goes to the log either way.
        try testing.expectEqualStrings(claimed_author ++ "\n" ++ claimed_committer, one.claimed);
    }
    try testing.expectEqualStrings("2020-01-01T00:00:00Z", try scene.git(&.{ "show", "-s", "--format=%aI", made[2].id }));
}

test "every landing is made by chock, and the claimed identity is in the message when the project asks" {
    try landWrongAuthor(true, .{});
}

test "every landing is made by chock, the message stays clean by default, and the claim is still kept" {
    try landWrongAuthor(false, .{});
}

test "the landing identity defaults to the one the policy library names, and a configured one replaces both halves" {
    try testing.expectEqualStrings("chock", (chock_policy.identity.Identity{}).name);
    try testing.expectEqualStrings("chock@localhost", (chock_policy.identity.Identity{}).email);
    try landWrongAuthor(false, .{ .name = "Acme Bot", .email = "bot@acme.com" });
}
