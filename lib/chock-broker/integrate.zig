//! **Carrying the session's work onto the branch the user has checked out**,
//! for the three modes of `chock_policy.apply` that ask for it.
//!
//! `lib/chock-broker/actions.zig` owns `workspace.apply`: the objects move into
//! the project and `refs/chock/<session>` moves to the session's commit. That
//! much happens in every mode and it moves no branch of the user's. This file
//! is the part after it, and only for `merge`, `rebase` and `squash`.
//!
//! ## The one rule: the project is never left in the middle of anything
//!
//! A merge or a rebase that stops on a conflict leaves a repository with an
//! unfinished operation in it, index entries a person has to resolve, and a
//! working tree that is neither where it was nor where it was going. **Chock
//! must never hand that back.** So no merge and no rebase is ever run in the
//! user's repository. Instead:
//!
//! 1. `planning` builds the whole result **in the session's own scratch object
//!    store**, with `git merge-tree` and `git commit-tree`, which touch no
//!    index and no working tree at all. A conflict is an exit code here, not a
//!    state on disk, and the user's repository has not been written to.
//! 2. The commit that comes out has the branch tip as an ancestor, by
//!    construction, in all three modes.
//! 3. `moving` therefore has exactly one thing to do to the user's repository:
//!    **a fast forward.** A fast forward onto a clean working tree cannot
//!    conflict, and git refuses one it cannot do before it changes anything.
//!
//! That is the whole design, and it is what makes "the repository is left
//! exactly as it was" a property of the shape rather than a promise about
//! cleanup code.
//!
//! ## The result is described before it is approved
//!
//! `planning` runs while the approval request is being built, so a conflict, a
//! dirty working tree, a detached head and an unfinished rebase are all known
//! **before a person is asked**. `Plan.park` carries the reason,
//! `actions.Action.detail` prints it, and the prompt then says the work will
//! wait at the ref. A person is never asked to approve a merge that was
//! already known to be impossible.
//!
//! ## And checked again before it is done
//!
//! A person can dirty their working tree, switch branch or start a rebase
//! between reading the question and answering it. `moving` reads the same facts
//! again and parks the work when any of them has changed. **Parking is narrower
//! than what was approved and never wider**: the work still lands at the ref,
//! which is what the mode `ref` does and what every session did before these
//! modes existed, and no branch moves. The log records which of the two
//! happened, so the narrowing is never silent.
//!
//! ## Who the commit says it is
//!
//! `lib/chock-workspace/git.zig` forces `GIT_CONFIG_GLOBAL` and
//! `GIT_CONFIG_SYSTEM` to `/dev/null` on every call, so a person's own
//! `~/.gitconfig` is not readable from here and cannot be the identity of a
//! commit this file writes. Reaching around that would undo the reason it is
//! there.
//!
//! So the identity comes from **the session's own commit**, the commit being
//! carried. That is honest in both directions: a merge or a squash was made by
//! the same actor that made the work, and a rebase keeps each replayed commit's
//! own author exactly as `git rebase` does. It also needs no configuration to
//! be present, so a project whose repository names no `user.name` still
//! integrates.

const std = @import("std");
const chock_policy = @import("chock-policy");
const chock_workspace = @import("chock-workspace");
const diagnostic = @import("diagnostic.zig");

const Diagnostic = diagnostic.Diagnostic;
const git = chock_workspace.git;

/// The four shapes one apply can take, named by `chock_policy.apply`. `ref` is
/// here too, and it is the one that moves no branch.
pub const Landing = chock_policy.apply.Landing;

/// The names git gives the files it leaves in the git directory while an
/// operation is unfinished. A repository holding any one of them is mid merge,
/// mid rebase, mid cherry pick or mid revert, and Chock adds nothing to that.
///
/// **Found by asking git where they are**, never by joining them onto `.git`:
/// a worktree, a bare repository and a repository with a separate git
/// directory each put the git directory somewhere else.
const unfinished_markers = [_][]const u8{
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "rebase-merge",
    "rebase-apply",
};

/// Why no branch moved.
///
/// **An enum and not a sentence**, so a caller acts on the member and the
/// member is what the log records. `sentence` is what a person reads, and the
/// two cannot drift apart because each has one switch over the whole enum.
pub const Reason = enum {
    /// The project asked for `ref`, so no branch was ever going to move. **The
    /// one member that is the ordinary case** and not a refusal.
    not_asked_for,
    /// The branch already reaches the session's commit, so there is nothing to
    /// carry onto it.
    already_there,
    /// The working tree holds changes that are not committed, or files that are
    /// not tracked. Integrating into it could lose them.
    dirty_tree,
    /// No branch is checked out. `HEAD` names a commit and not a ref.
    detached_head,
    /// A merge, a rebase, a cherry pick or a revert is unfinished here.
    unfinished_operation,
    /// The checked out branch names no commit yet.
    branch_has_no_commit,
    /// The work and the branch change the same lines, so an integration would
    /// stop and ask a person to resolve it.
    would_conflict,
    /// A rebase was asked for and the work holds a commit with more than one
    /// parent, or with none, which a replay one commit at a time cannot carry.
    history_not_linear,
    /// The branch is not where it was when the question was put, so the act a
    /// person approved is not the act this would perform.
    branch_moved,
    /// git refused a step of the integration. What it said is in the
    /// diagnostic.
    git_refused,

    /// The word the log records.
    pub fn wireName(self: Reason) []const u8 {
        return switch (self) {
            .not_asked_for => "not_asked_for",
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

    /// The line a person reads, in the approval prompt and at the end of a
    /// run. It says what is true of their repository, and the caller says what
    /// Chock does about it.
    pub fn sentence(self: Reason) []const u8 {
        return switch (self) {
            .not_asked_for => "this project asks for the work to wait at the ref",
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

/// Which branch moves, from where, to where. Everything `moving` needs, and
/// everything the approval prompt says out loud.
pub const Move = struct {
    /// The mode that built `to`.
    landing: Landing,
    /// The full name of the branch, for example `refs/heads/main`.
    branch: []const u8,
    /// Where that branch is now. `moving` parks the work when it is somewhere
    /// else by the time it runs.
    at: []const u8,
    /// The commit the branch moves to. Already built, and already in the
    /// session's scratch object store, so `workspace.apply` carries it across
    /// with the rest of the work and a person reads it in the object list.
    to: []const u8,
};

/// No branch moves. **Both halves**: what the project asked for, and why it is
/// not happening. A reader who is told only the reason cannot tell a project
/// that wanted a merge from one that never asked for anything.
pub const Parked = struct {
    /// What the project's mode asked for. `ref` when it asked for nothing.
    wanted: Landing,
    why: Reason,
};

/// What an apply is going to do to the branch, worked out before anybody is
/// asked.
pub const Plan = union(enum) {
    /// A branch moves, and this is the whole of it.
    move: Move,
    /// No branch moves. The work still lands at the ref.
    park: Parked,

    /// Why no branch moves, or null when one does.
    pub fn parked(self: Plan) ?Parked {
        return switch (self) {
            .move => null,
            .park => |it| it,
        };
    }

    /// What the project asked for, whether or not it is happening.
    pub fn wanted(self: Plan) Landing {
        return switch (self) {
            .move => |m| m.landing,
            .park => |it| it.wanted,
        };
    }
};

/// What really happened to the branch. Every string is owned by the allocator
/// the call was given.
pub const Outcome = union(enum) {
    /// The branch moved. **The one member that means a person's own branch is
    /// somewhere new.**
    moved: struct {
        landing: Landing,
        branch: []u8,
        from: []u8,
        to: []u8,
    },
    /// No branch moved. The work is at the ref and nowhere else.
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

/// What planning an integration can fail with. A repository that says no is
/// not in here: that is a `Plan.park` carrying a `Reason`, because a refusal is
/// an answer and not a fault.
pub const Error = git.Error || error{
    /// A `git` call this file cannot go on without exited nonzero, and it is
    /// not one of the refusals `Reason` names.
    GitFailed,
};

/// Work out what an apply of `new_id` can do to the checked out branch, and
/// build the commit that branch would move to.
///
/// **Nothing here writes to the user's repository.** Every object this produces
/// is written into `scratch_object_store`, which is the session's own and which
/// `workspace.apply` moves across afterwards. The project's own store is named
/// only as an alternate, and a read of an alternate cannot write to it: see
/// `lib/chock-workspace/worktree.zig`'s own doc comment.
///
/// Every string comes out of `arena`, which the caller owns.
pub fn planning(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    params: struct {
        /// Absolute host path of the user's own project.
        repository: []const u8,
        /// Absolute host path of the session's own scratch object store.
        scratch_object_store: []const u8,
        /// Absolute host path of the project's own object store.
        project_object_store: []const u8,
        /// What the mode asked for, after the policy row bounded it.
        landing: Landing,
        /// The ref the work is parked at, which the commit message names.
        ref: []const u8,
        /// The session's commit. It lives in the scratch store.
        new_id: []const u8,
    },
    diag: ?*?Diagnostic,
) Error!Plan {
    if (!params.landing.movesABranch()) return .{ .park = .{
        .wanted = params.landing,
        .why = .not_asked_for,
    } };

    // Reading the session's commit from the project needs the scratch store as
    // an alternate. Writing the result needs the scratch store as the primary,
    // so nothing this call produces lands in the project.
    var reading = try env.clone(arena);
    defer reading.deinit();
    try reading.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", params.scratch_object_store);

    var writing = try env.clone(arena);
    defer writing.deinit();
    try writing.put("GIT_OBJECT_DIRECTORY", params.scratch_object_store);
    try writing.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", params.project_object_store);

    const standing = try standingOf(arena, io, env, params.repository, diag);
    const ready = switch (standing) {
        .park => |why| return .{ .park = .{ .wanted = params.landing, .why = why } },
        .ready => |it| it,
    };

    // Nothing to carry. Read through the alternate, because the session's
    // commit is still only in the scratch store.
    if (try isAncestor(arena, io, &reading, params.repository, params.new_id, ready.at))
        return .{ .park = .{ .wanted = params.landing, .why = .already_there } };

    const built = switch (params.landing) {
        // `movesABranch` already answered for this one.
        .ref => unreachable,
        .merge, .squash => try mergeOrSquash(arena, io, &writing, .{
            .repository = params.repository,
            .landing = params.landing,
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
        .refused => |why| .{ .park = .{ .wanted = params.landing, .why = why } },
        .commit => |id| .{ .move = .{
            .landing = params.landing,
            .branch = ready.branch,
            .at = ready.at,
            .to = id,
        } },
    };
}

/// Move the branch, after checking that the repository is still where the
/// question said it was.
///
/// **The only write this makes to the user's repository is one fast forward.**
/// See this file's own top comment. Every way the repository can say no comes
/// back as `Outcome.park`, which leaves it exactly as it was.
///
/// The strings in the answer are owned by `gpa`, and `Outcome.deinit` frees
/// them.
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

    // **The same four facts, read again.** A person can dirty their tree,
    // switch branch or start a rebase between reading the question and
    // answering it, and the act they approved was the one described then.
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

    // A fast forward and nothing else. `to` was built on `at`, `at` is where
    // the branch still is, and the tree is clean, so git either does the whole
    // of this or refuses before it changes anything.
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

/// Where the repository stands: either it can take an integration now, or here
/// is the reason it cannot.
const Standing = union(enum) {
    ready: struct { branch: []const u8, at: []const u8 },
    park: Reason,
};

/// Read the four facts that decide whether a branch can move, cheapest first.
/// Each one is about the project and none of them is about the work.
fn standingOf(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    repository: []const u8,
    diag: ?*?Diagnostic,
) Error!Standing {
    // A branch, and not a detached head. `--quiet` makes a detached head an
    // exit code instead of a message on standard error.
    var head = try git.run(arena, io, env, repository, &.{
        "symbolic-ref", "--quiet", "HEAD",
    }, null);
    defer head.deinit(arena);
    if (head.term != .exited) return error.GitFailed;
    if (head.term.exited != 0) return .{ .park = .detached_head };
    const branch = try arena.dupe(u8, std.mem.trimEnd(u8, head.stdout, "\n"));
    if (branch.len == 0) return .{ .park = .detached_head };

    if (try midOperation(arena, io, env, repository, diag)) return .{ .park = .unfinished_operation };

    // **Untracked files count.** They are work a person has not saved, and a
    // fast forward that had to write over one would be refused by git anyway.
    // Files a project ignores are not reported, so this is not every stray
    // byte in the directory.
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

/// Whether an operation is unfinished in this repository. One `git` call for
/// every marker at once, because `--git-path` takes as many as it is given and
/// prints one line each.
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
        // `MERGE_HEAD` is a file, and either one being there is the answer.
        std.Io.Dir.accessAbsolute(io, line, .{}) catch continue;
        return true;
    }
    return false;
}

/// Whether `ancestor` is reachable from `descendant`.
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
    // not tell. The safe reading of "could not tell" is no: the integration
    // then goes ahead and its own conflict check answers for it.
    return output.term == .exited and output.term.exited == 0;
}

/// What building the result came to.
const Built = union(enum) {
    commit: []const u8,
    refused: Reason,
};

/// The merge commit or the squash commit, both out of one merged tree.
///
/// The two differ in one thing: how many parents the commit gets. A merge names
/// the branch and the work, so git can see afterwards where the work came from;
/// a squash names only the branch, which is what makes it one commit on a
/// straight line.
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

/// The message a squash commit carries: one subject line, and then the subject
/// of every commit it replaces.
///
/// **A squash loses the individual commits from the history**, so the one
/// commit that is left says what they were. A person reading `git log` a month
/// later has the same list they would have had.
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

/// Replay every commit of `at..new_id` onto `at`, one at a time, and give back
/// the last commit built. This is a rebase with no index and no working tree.
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
    // `--parents` prints the commit and then every parent of it on one line,
    // so one call answers both "which commits" and "is any of them a merge".
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
        // A second parent means a merge commit, which a replay of one commit
        // at a time cannot carry across.
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

    // The caller already answered "the branch reaches this commit", so an
    // empty range here means git and that check disagree. Say so rather than
    // hand back the branch tip as if work had been carried.
    if (replayed == 0) return .{ .refused = .already_there };
    return .{ .commit = current };
}

/// The tree of merging `theirs` into `ours`, written into whichever store
/// `writing` names as the primary.
///
/// **This is where a conflict is found**, and it is found as an exit code with
/// no index, no working tree and nothing to clean up. `--merge-base` names the
/// base explicitly, which is what turns a merge into a cherry pick and is how
/// `replay` gets rebase semantics out of the same call.
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
        // Clean. The first line is the tree.
        0 => {},
        // Conflicts. git printed the tree and then the conflicted paths, and
        // the tree it printed holds conflict markers, so it is never used.
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

/// The environment a `commit-tree` runs with, so the commit it writes carries
/// the identity of `commit` rather than of nobody.
///
/// See this file's own top comment for why the identity is taken from a commit
/// and not from a person's git configuration.
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
    // **The committer date is now and the author date is the work's own.** That
    // is what git itself does for a rebase, and it keeps "when was this
    // written" apart from "when did it reach my branch".
    return out;
}

/// One `git` call that must exit zero, and what it printed on standard output,
/// trimmed. What git said on a failure travels in `diag`.
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

test "every reason says something a person can read, and only one of them is ordinary" {
    for (std.enums.values(Reason)) |reason| {
        try testing.expect(reason.wireName().len > 0);
        try testing.expect(reason.sentence().len > 0);
        // The wire name is a name and never a sentence: it goes in a log field
        // that a reader matches on.
        try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, reason.wireName(), ' '));
    }
    try testing.expectEqualStrings("not_asked_for", Reason.not_asked_for.wireName());
}

test "a plan that moves nothing names why, and one that moves says nothing about why" {
    const parked: Plan = .{ .park = .{ .wanted = .merge, .why = .dirty_tree } };
    try testing.expectEqual(Reason.dirty_tree, parked.parked().?.why);
    // **What the project asked for survives the refusal.** A reader told only
    // "dirty tree" cannot tell this from a project that wanted nothing.
    try testing.expectEqual(Landing.merge, parked.wanted());

    const moving_plan: Plan = .{ .move = .{
        .landing = .merge,
        .branch = "refs/heads/main",
        .at = "a" ** 40,
        .to = "b" ** 40,
    } };
    try testing.expectEqual(@as(?Parked, null), moving_plan.parked());
    try testing.expectEqual(Landing.merge, moving_plan.wanted());
}

test "the ref landing never plans a move at all" {
    // Read through the real entry point, with no repository behind it: `ref`
    // answers before it opens anything, which is what makes the default free.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var env = try std.testing.environ.createMap(testing.allocator);
    defer env.deinit();

    const plan = try planning(arena_state.allocator(), testing.io, &env, .{
        .repository = "/nowhere/at/all",
        .scratch_object_store = "/nowhere/at/all",
        .project_object_store = "/nowhere/at/all",
        .landing = .ref,
        .ref = "refs/chock/01S",
        .new_id = "c" ** 40,
    }, null);
    try testing.expectEqual(Reason.not_asked_for, plan.parked().?.why);
    try testing.expectEqual(Landing.ref, plan.wanted());
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
    try testing.expect(outcome.moved.landing.movesABranch());
}
