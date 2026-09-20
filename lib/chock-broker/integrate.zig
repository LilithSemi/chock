//! Carry the session's work onto the branch the user has checked out. No merge
//! and no rebase ever runs in the user's repository: the result is built in the
//! session's scratch object store, and the only write to the project is one
//! fast forward.

const std = @import("std");
const chock_policy = @import("chock-policy");
const chock_workspace = @import("chock-workspace");
const diagnostic = @import("diagnostic.zig");

const Diagnostic = diagnostic.Diagnostic;
const git = chock_workspace.git;

pub const Landing = chock_policy.apply.Landing;

/// Ask git where these are. Do not join them onto `.git`: a worktree and a
/// bare repository each put the git directory somewhere else.
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
    },
    park: Parked,

    pub fn deinit(self: *Outcome, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .moved => |m| {
                gpa.free(m.branch);
                gpa.free(m.from);
                gpa.free(m.to);
            },
            .park => {},
        }
        self.* = undefined;
    }
};

pub const Error = git.Error || error{
    GitFailed,
};

/// Nothing here writes to the user's repository. Every object goes into
/// `scratch_object_store`, and every string comes out of `arena`.
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
    },
    diag: ?*?Diagnostic,
) Error!Plan {
    const landing = switch (params.wanted) {
        .land => |it| it,
        .none => |why| return .{ .park = .{ .wanted = null, .why = why } },
    };

    var reading = try env.clone(arena);
    defer reading.deinit();
    try reading.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", params.scratch_object_store);

    var writing = try env.clone(arena);
    defer writing.deinit();
    try writing.put("GIT_OBJECT_DIRECTORY", params.scratch_object_store);
    try writing.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", params.project_object_store);

    const standing = try standingOf(arena, io, env, params.repository, diag);
    const ready = switch (standing) {
        .park => |why| return .{ .park = .{ .wanted = landing, .why = why } },
        .ready => |it| it,
    };

    if (try isAncestor(arena, io, &reading, params.repository, params.new_id, ready.at))
        return .{ .park = .{ .wanted = landing, .why = .already_there } };

    const built = switch (landing) {
        .merge, .squash => try mergeOrSquash(arena, io, &writing, .{
            .repository = params.repository,
            .landing = landing,
            .branch = ready.branch,
            .at = ready.at,
            .ref = params.ref,
            .new_id = params.new_id,
        }, diag),
        .rebase => try replay(arena, io, &writing, &reading, .{
            .repository = params.repository,
            .at = ready.at,
            .new_id = params.new_id,
        }, diag),
    };

    return switch (built) {
        .refused => |why| .{ .park = .{ .wanted = landing, .why = why } },
        .commit => |id| .{ .move = .{
            .landing = landing,
            .branch = ready.branch,
            .at = ready.at,
            .to = id,
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
    const standing = standingOf(arena, io, env, repository, diag) catch |err| switch (err) {
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
    } };
}

const Standing = union(enum) {
    ready: struct { branch: []const u8, at: []const u8 },
    park: Reason,
};

fn standingOf(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repository: []const u8,
    diag: ?*?Diagnostic,
) Error!Standing {
    // `--quiet` makes a detached head an exit code, not a message on stderr.
    var head = try git.run(arena, io, env, repository, &.{
        "symbolic-ref", "--quiet", "HEAD",
    }, null);
    defer head.deinit(arena);
    if (head.term != .exited) return error.GitFailed;
    if (head.term.exited != 0) return .{ .park = .detached_head };
    const branch = try arena.dupe(u8, std.mem.trimEnd(u8, head.stdout, "\n"));
    if (branch.len == 0) return .{ .park = .detached_head };

    if (try midOperation(arena, io, env, repository, diag)) return .{ .park = .unfinished_operation };

    // Untracked files count as dirty, but ignored files are not reported.
    const status = try ok(arena, io, env, repository, &.{ "status", "--porcelain" }, diag);
    if (status.len != 0) return .{ .park = .dirty_tree };

    var tip = try git.run(arena, io, env, repository, &.{
        "rev-parse", "--verify", "--quiet", branch,
    }, null);
    defer tip.deinit(arena);
    if (tip.term != .exited) return error.GitFailed;
    if (tip.term.exited != 0) return .{ .park = .branch_has_no_commit };

    return .{ .ready = .{
        .branch = branch,
        .at = try arena.dupe(u8, std.mem.trimEnd(u8, tip.stdout, "\n")),
    } };
}

fn midOperation(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repository: []const u8,
    diag: ?*?Diagnostic,
) Error!bool {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(arena);
    try argv.appendSlice(arena, &.{ "rev-parse", "--path-format=absolute" });
    for (unfinished_markers) |marker| {
        try argv.appendSlice(arena, &.{ "--git-path", marker });
    }

    const printed = try ok(arena, io, env, repository, argv.items, diag);
    var lines = std.mem.tokenizeScalar(u8, printed, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        // `access` and not a stat of a kind: `rebase-merge` is a directory and
        // `MERGE_HEAD` is a file.
        std.Io.Dir.accessAbsolute(io, line, .{}) catch continue;
        return true;
    }
    return false;
}

fn isAncestor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repository: []const u8,
    ancestor: []const u8,
    descendant: []const u8,
) Error!bool {
    var output = try git.run(arena, io, env, repository, &.{
        "merge-base", "--is-ancestor", ancestor, descendant,
    }, null);
    defer output.deinit(arena);
    // Exit 0 is yes, exit 1 is no, and anything else is git saying it could
    // not tell. Read "could not tell" as no.
    return output.term == .exited and output.term.exited == 0;
}

const Built = union(enum) {
    commit: []const u8,
    refused: Reason,
};

fn mergeOrSquash(
    arena: std.mem.Allocator,
    io: std.Io,
    writing: *const std.process.Environ.Map,
    params: struct {
        repository: []const u8,
        landing: Landing,
        branch: []const u8,
        at: []const u8,
        ref: []const u8,
        new_id: []const u8,
    },
    diag: ?*?Diagnostic,
) Error!Built {
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
        .squash => try squashMessage(arena, io, writing, params.repository, params.ref, params.at, params.new_id, diag),
        else => unreachable,
    };

    const identity = try identityOf(arena, io, writing, params.repository, params.new_id, diag);
    const argv: []const []const u8 = switch (params.landing) {
        .merge => &.{ "commit-tree", tree, "-p", params.at, "-p", params.new_id, "-m", message },
        .squash => &.{ "commit-tree", tree, "-p", params.at, "-m", message },
        else => unreachable,
    };
    return .{ .commit = try ok(arena, io, &identity, params.repository, argv, diag) };
}

fn squashMessage(
    arena: std.mem.Allocator,
    io: std.Io,
    writing: *const std.process.Environ.Map,
    repository: []const u8,
    ref: []const u8,
    at: []const u8,
    new_id: []const u8,
    diag: ?*?Diagnostic,
) Error![]const u8 {
    const range = try std.fmt.allocPrint(arena, "{s}..{s}", .{ at, new_id });
    const subjects = try ok(arena, io, writing, repository, &.{
        "log", "--reverse", "--format=* %s", range,
    }, diag);

    return std.fmt.allocPrint(
        arena,
        "Squash {s}\n\nThe work of one chock session, as one commit. It was:\n\n{s}\n",
        .{ ref, subjects },
    );
}

fn replay(
    arena: std.mem.Allocator,
    io: std.Io,
    writing: *const std.process.Environ.Map,
    reading: *const std.process.Environ.Map,
    params: struct {
        repository: []const u8,
        at: []const u8,
        new_id: []const u8,
    },
    diag: ?*?Diagnostic,
) Error!Built {
    const range = try std.fmt.allocPrint(arena, "{s}..{s}", .{ params.at, params.new_id });
    // `--parents` prints the commit and then every parent of it on one line.
    const listed = try ok(arena, io, reading, params.repository, &.{
        "rev-list", "--reverse", "--parents", range,
    }, diag);

    var current = params.at;
    var replayed: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, listed, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const commit = fields.next() orelse continue;
        const parent = fields.next() orelse return .{ .refused = .history_not_linear };
        if (fields.next() != null) return .{ .refused = .history_not_linear };

        const tree = switch (try mergedTree(arena, io, writing, params.repository, .{
            .base = parent,
            .ours = current,
            .theirs = commit,
        }, diag)) {
            .refused => |why| return .{ .refused = why },
            .commit => |id| id,
        };

        const message = try ok(arena, io, writing, params.repository, &.{
            "show", "-s", "--format=%B", commit,
        }, diag);
        const identity = try identityOf(arena, io, writing, params.repository, commit, diag);
        current = try ok(arena, io, &identity, params.repository, &.{
            "commit-tree", tree, "-p", current, "-m", if (message.len > 0) message else "(no message)",
        }, diag);
        replayed += 1;
    }

    if (replayed == 0) return .{ .refused = .already_there };
    return .{ .commit = current };
}

/// `--merge-base` names the base explicitly, which is what turns a merge into
/// a cherry pick.
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

/// `lib/chock-workspace/git.zig` forces the global and system git config to
/// `/dev/null`, so a person's own `~/.gitconfig` cannot be the identity of a
/// commit this file writes. Do not reach around that.
fn identityOf(
    arena: std.mem.Allocator,
    io: std.Io,
    reading: *const std.process.Environ.Map,
    repository: []const u8,
    commit: []const u8,
    diag: ?*?Diagnostic,
) Error!std.process.Environ.Map {
    const printed = try ok(arena, io, reading, repository, &.{
        "show", "-s", "--format=%an%n%ae%n%aI%n%cn%n%ce", commit,
    }, diag);

    var lines = std.mem.splitScalar(u8, printed, '\n');
    const author_name = lines.next() orelse "";
    const author_email = lines.next() orelse "";
    const author_date = lines.next() orelse "";
    const committer_name = lines.next() orelse "";
    const committer_email = lines.next() orelse "";

    var out = try reading.clone(arena);
    errdefer out.deinit();
    try out.put("GIT_AUTHOR_NAME", author_name);
    try out.put("GIT_AUTHOR_EMAIL", author_email);
    try out.put("GIT_AUTHOR_DATE", author_date);
    try out.put("GIT_COMMITTER_NAME", committer_name);
    try out.put("GIT_COMMITTER_EMAIL", committer_email);
    // Committer date now, author date the work's own, as git does for a rebase.
    return out;
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
        .at = "a" ** 40,
        .to = "b" ** 40,
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
            .new_id = "c" ** 40,
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
        .from = try gpa.dupe(u8, "a" ** 40),
        .to = try gpa.dupe(u8, "b" ** 40),
    } };
    defer outcome.deinit(gpa);
    try testing.expectEqualStrings("refs/heads/main", outcome.moved.branch);
    try testing.expectEqual(Landing.rebase, outcome.moved.landing);
}
