//! The git shim: a `git` first in the `PATH` inside the sandbox. It reads the
//! argument vector. A read only subcommand runs the real git. A subcommand that
//! changes state sends an approval request.
//!
//! ## The shim prevents a mistake. It does not prevent an attack
//!
//! Say it plainly, because the file is easy to mistake for a control. **The
//! capability layers are the boundary. This file is not one, and nothing in
//! Chock may be built as though it were.**
//!
//! An agent that wants to avoid this file has several ways and none of them
//! is difficult:
//!
//! - Name the real binary by its absolute path. The `PATH` is not consulted
//!   at all then, so the shim is not in the way.
//! - Write a shell script, or any program, that does the same thing.
//! - Put a value in the repository's own `.git/config` that makes an
//!   ordinary read run a program. `diff.external` and `core.fsmonitor` are
//!   two, and `git diff` is on this file's read only list, so the shim runs
//!   the real git and the real git runs the agent's program.
//!
//! Every one of those still lands inside the sandbox, with no network, with
//! the user's own repository not mounted, and with the seccomp filter and
//! the Landlock rules in front of it. That is what stops an attack.
//! `test/broker/git_shim.zig` proves the first route on a running system: it
//! runs the real git by its absolute path, with no shim anywhere, and the
//! push still fails, because there is no route out of the sandbox to fail
//! at.
//!
//! So the value of this file is that an agent which meant no harm does not
//! quietly rewrite history, or delete a branch, or garbage collect the
//! session's own object store, because it reached for the ordinary command
//! and got a question instead.
//!
//! ## What "yes" means
//!
//! One thing only: **run the real git inside the sandbox.** The shim is
//! inside the sandbox, so that is the only act it can carry out. An approval
//! here grants nothing the sandbox does not already allow, and that is the
//! rule read from the other side: the agent never gets the privilege.
//!
//! An act that has to leave the sandbox, a push to a real remote or a commit
//! into the user's own repository, cannot be done by saying yes here at all.
//! The design is that the agent calls `request_action` with an
//! `actions.Action`, and the broker does it outside the sandbox, out of a
//! payload that names the effect. **That tool is not built.** See
//! `lib/chock-policy/ratchet.zig`, which says the same: the approval wall is
//! gone and this is waiting on the tool itself. So `Ask.kind` names which act
//! it would be, and `Ask.advice` tells the agent the effect cannot be had in
//! this build, and does not name a tool it cannot call.
//!
//! **The shim cannot build that payload for the agent, and must not try.** The
//! user approves the effect and never a shell line. An `actions.Action` holds a
//! diff, an object id, a ref. An argument vector holds none of those, and a
//! shim that guessed them would put a command string in front of the user with
//! an effect attached that it invented.
//!
//! ## Two safe defaults
//!
//! A subcommand this file does not know asks. An option before the
//! subcommand that this file does not read asks, and does not go on to read
//! the subcommand at all. The second one matters more than it looks:
//! `git -c <name>=<value>` sets any configuration value for one call, several
//! of which make git run a program of the caller's choosing, so an option
//! list this file cannot account for makes everything after it unreadable
//! too.

const std = @import("std");
const chock_proto = @import("chock-proto");
const actions = @import("actions.zig");
const Broker = @import("Broker.zig");

const event = chock_proto.event;

/// Why the shim stopped a subcommand rather than running it.
pub const Reason = enum {
    /// A subcommand this file knows, and knows changes state. See
    /// `changes_state`.
    subcommand_changes_state,
    /// A subcommand on neither list. The safe default: an unknown verb is
    /// not assumed harmless.
    subcommand_not_known,
    /// An option before the subcommand that this file does not read. See
    /// this file's own top comment on why this stops the reading there.
    option_not_read,

    /// One line for a user, in the request's own summary.
    pub fn text(self: Reason) []const u8 {
        return switch (self) {
            .subcommand_changes_state => "this git subcommand changes state",
            .subcommand_not_known => "this shim does not know this git subcommand",
            .option_not_read => "this shim does not read this git option, so it cannot read the subcommand either",
        };
    }
};

/// The action name a request carries when the shim could not read the
/// subcommand at all. A policy may name it in a rule. With no rule it
/// resolves to `ask`, which is the policy table's safe default.
pub const unreadable_action = "git.unknown";

/// What the shim wants to ask about.
pub const Ask = struct {
    /// The subcommand, as a slice of the caller's own argument vector. Empty
    /// when `reason` is `option_not_read`, because the shim stopped before
    /// it reached one.
    subcommand: []const u8,
    reason: Reason,
    /// Which act carries out the effect this subcommand is reaching for, when
    /// there is one. Null for every other case. See this file's own top
    /// comment: this is what the agent is told to ask for instead, and it is
    /// never something the shim performs itself.
    kind: ?actions.Kind,

    /// The name the policy table is keyed on and the log records. Owned by
    /// the caller.
    pub fn actionName(self: Ask, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        if (self.kind) |kind| return gpa.dupe(u8, kind.wireName());
        if (self.subcommand.len == 0) return gpa.dupe(u8, unreadable_action);
        return std.fmt.allocPrint(gpa, "git.{s}", .{self.subcommand});
    }

    /// What the agent is told when the shim stops it. Owned by the caller.
    pub fn advice(self: Ask, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const kind = self.kind orelse return gpa.dupe(
            u8,
            "the answer to this question only lets the subcommand run inside the sandbox",
        );
        return std.fmt.allocPrint(
            gpa,
            "an effect outside the sandbox needs the action {s}, and this build has no tool that asks for one, so this subcommand cannot have that effect here",
            .{kind.wireName()},
        );
    }
};

/// What reading one argument vector came to.
pub const Verdict = union(enum) {
    /// A read only subcommand. Run the real git inside the sandbox, and ask
    /// nobody.
    run_the_real_git,
    /// Ask first.
    ask: Ask,
};

/// Read one `git` argument vector and decide. `argv[0]` is the name the
/// caller was invoked as and is not read: the shim is reached through the
/// `PATH` under whatever name, and what it decides must not depend on that
/// name. A vector of only that name, `git` with nothing after it, prints
/// git's own usage and changes nothing, so it runs.
pub fn classify(argv: []const []const u8) Verdict {
    var index: usize = 1;
    while (index < argv.len) {
        const arg = argv[index];
        if (arg.len == 0 or arg[0] != '-') break;

        // `--version` and `--help` answer out of git itself and touch
        // nothing. They are options and not subcommands, so they are read
        // here rather than on the list below.
        if (isOneOf(arg, &.{ "--version", "--help", "-h", "-v" })) return .run_the_real_git;

        if (isOneOf(arg, no_value_options)) {
            index += 1;
            continue;
        }
        if (valueOptionStep(arg)) |step| {
            index += step;
            continue;
        }
        // Everything else. See `Reason.option_not_read`.
        return .{ .ask = .{ .subcommand = "", .reason = .option_not_read, .kind = null } };
    }

    if (index >= argv.len) return .run_the_real_git;
    const subcommand = argv[index];
    const rest = argv[index + 1 ..];

    if (isOneOf(subcommand, read_only)) return .run_the_real_git;
    if (isOneOf(subcommand, changes_state)) {
        return .{ .ask = .{
            .subcommand = subcommand,
            .reason = .subcommand_changes_state,
            .kind = kindFor(subcommand, rest),
        } };
    }
    return .{ .ask = .{
        .subcommand = subcommand,
        .reason = .subcommand_not_known,
        .kind = null,
    } };
}

/// Which act carries out the effect a subcommand reaches for. Null when there
/// is none.
fn kindFor(subcommand: []const u8, rest: []const []const u8) ?actions.Kind {
    if (std.mem.eql(u8, subcommand, "push")) return .git_push;
    if (std.mem.eql(u8, subcommand, "commit")) return .git_commit;
    if (std.mem.eql(u8, subcommand, "branch")) {
        // `git branch` alone lists, and this file already refuses to run any
        // spelling of `branch`. Only the deleting spellings name an act, so
        // only they say so.
        for (rest) |arg| {
            if (isOneOf(arg, &.{ "-d", "-D", "--delete" })) return .git_branch_delete;
        }
        return null;
    }
    return null;
}

/// Options before the subcommand that carry no value of their own. Each one
/// changes how git prints, or which pathspec rules apply, and none of them
/// changes what the subcommand after it does.
const no_value_options: []const []const u8 = &.{
    "-p",
    "-P",
    "--paginate",
    "--no-pager",
    "--bare",
    "--no-replace-objects",
    "--no-optional-locks",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
};

/// How many arguments an option before the subcommand takes, including
/// itself, or null when this file does not read the option.
///
/// Only three are here, and every one of them says **where** git works, never
/// **what** it does. An option that could change what the subcommand does is
/// deliberately absent: see `Reason.option_not_read`.
fn valueOptionStep(arg: []const u8) ?usize {
    const with_value: []const []const u8 = &.{ "-C", "--git-dir", "--work-tree", "--namespace" };
    for (with_value) |name| {
        // `--git-dir=/x`, one argument.
        if (arg.len > name.len and std.mem.startsWith(u8, arg, name) and arg[name.len] == '=') return 1;
        // `--git-dir /x`, two.
        if (std.mem.eql(u8, arg, name)) return 2;
    }
    return null;
}

/// Subcommands that cannot change anything, whatever options follow them.
///
/// A verb is on this list only when no spelling of it writes. That is why
/// several verbs a reader might expect are missing, and each one is missing
/// for a named reason:
///
/// - `config` and `hash-object` write with an option (`--replace-all`,
///   `-w`).
/// - `branch`, `tag`, `notes`, `reflog`, `stash` and `symbolic-ref` each
///   read with one set of options and write with another.
/// - `ls-remote` and `fetch` reach a remote. `net.fetch` is the act for
///   reaching one host, and that is what covers it.
/// - `fsck`, `gc`, `repack` and `prune` rewrite the object store. The
///   session's scratch store is the agent's own work, and its loose objects
///   are what carry that work, so a collection inside a session is a way to
///   lose the work rather than a tidy up.
const read_only: []const []const u8 = &.{
    "annotate",
    "blame",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "cherry",
    "column",
    "count-objects",
    "describe",
    "diff",
    "diff-files",
    "diff-index",
    "diff-tree",
    "for-each-ref",
    "grep",
    "help",
    "log",
    "ls-files",
    "ls-tree",
    "merge-base",
    "name-rev",
    "patch-id",
    "range-diff",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-branch",
    "show-ref",
    "status",
    "stripspace",
    "var",
    "verify-commit",
    "verify-tag",
    "version",
    "whatchanged",
};

/// Subcommands this file knows change state. Being on this list rather than
/// on neither only changes what the user is told: both ask.
const changes_state: []const []const u8 = &.{
    "add",
    "am",
    "apply",
    "bisect",
    "branch",
    "checkout",
    "cherry-pick",
    "clean",
    "clone",
    "commit",
    "config",
    "fetch",
    "filter-branch",
    "fsck",
    "gc",
    "hash-object",
    "init",
    "merge",
    "mv",
    "notes",
    "prune",
    "pull",
    "push",
    "rebase",
    "reflog",
    "remote",
    "repack",
    "replace",
    "reset",
    "restore",
    "revert",
    "rm",
    "stash",
    "submodule",
    "switch",
    "symbolic-ref",
    "tag",
    "update-index",
    "update-ref",
    "worktree",
};

/// Subcommands that have to reach another host to do anything at all.
///
/// **Every one of these fails inside the sandbox whatever anybody answers**,
/// because the network namespace holds no route out and the answer to a
/// question here only ever means "run it inside the sandbox": see this file's
/// own top comment on what "yes" means. So this list is not a second opinion
/// about risk. It is the set of subcommands for which running the real git can
/// only produce a confusing failure, and for which the useful answer is a
/// sentence saying so.
///
/// **Measured, and this is what it looked like.** A session ran `git fetch`.
/// The real git forked `ssh`, `ssh` was not in the sandbox, and the model read
/// `cannot run ssh: No such file or directory`, which names a missing program
/// and not a missing network. It then spent turns looking for a proxy that was
/// never going to exist. Nothing was breached: the namespace refused, and
/// would have refused whatever `ssh` did. What was missing was the answer.
///
/// Short, and every entry is unambiguous. `remote` and `submodule` reach a
/// host in some spellings and not in others, so they are absent: a subcommand
/// that is only sometimes on this list would give a sentence that is only
/// sometimes true.
const needs_network: []const []const u8 = &.{
    "clone",
    "fetch",
    "ls-remote",
    "pull",
    "push",
};

/// Whether `subcommand` has to reach another host. See `needs_network`.
/// Takes the subcommand `classify` already read out of the argument vector,
/// so there is one reader of a git command line in this file and not two.
pub fn needsNetwork(subcommand: []const u8) bool {
    return isOneOf(subcommand, needs_network);
}

/// What the agent is told when it ran a git subcommand that has to reach
/// another host. Owned by the caller.
///
/// **Named alternatives, because that is what makes a model adapt.** The
/// refusal of a shell name in `lib/chock-core/tools.zig` was measured to do
/// this: a model told plainly that there is no shell, and told what to send
/// instead, sent the right thing on the next turn. A message that only said
/// "refused" would leave the model with the same question it started with.
pub fn networkRefusal(gpa: std.mem.Allocator, subcommand: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "git {s} was not run: the sandbox has no network, so no git subcommand can reach " ++
            "another host from here. This is not a missing program and there is no proxy to " ++
            "find. Work with what is already in the workspace: the project's own history is " ++
            "here, so git log, git show, git diff and git status all work. Commit your work " ++
            "in the workspace as usual, and the user is asked at the end of the session " ++
            "whether to carry that commit into their own repository. Nothing you run here " ++
            "reaches a remote.",
        .{subcommand},
    );
}

fn isOneOf(needle: []const u8, haystack: []const []const u8) bool {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, needle, candidate)) return true;
    }
    return false;
}

/// Everything the shim needs about the agent that ran git, which is
/// everything `Broker.Request` needs and none of it readable from an
/// argument vector.
pub const Caller = struct {
    /// The reason the agent gave for the tool call this git run came from.
    reason: []const u8,
    agent_kind: []const u8,
    model_alias: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    spawn_chain: []const event.SpawnLink = &.{},
    timeout_ms: i64 = Broker.default_timeout_ms,
};

/// What one `decide` call came to.
pub const Answer = union(enum) {
    /// A read only subcommand. Run the real git inside the sandbox. Nobody
    /// was asked and nothing was written to the log.
    read_only,
    /// The answer permitted it. Run the real git inside the sandbox, where
    /// the capability layers still bound it. See this file's own top comment
    /// on what "yes" means and on what it does not mean.
    approved: Broker.Outcome,
    /// The answer did not permit it. Nothing runs.
    refused: Broker.Outcome,
};

/// What `decide` can fail with. Asking is the only part that can fail: this
/// file runs nothing itself.
pub const Error = Broker.Error;

/// Read the argument vector, ask when it is not a read only subcommand, and
/// give back what to do.
///
/// `storage` and `locked` are what `Broker.request` needs; see its own doc
/// comment. This function performs nothing and spawns nothing. The caller
/// runs the real git, and the caller is inside the sandbox.
pub fn decide(
    broker: *const Broker,
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    locked: anytype,
    caller: Caller,
    argv: []const []const u8,
    diag: ?*?Broker.Diagnostic,
) Error!Answer {
    const ask = switch (classify(argv)) {
        .run_the_real_git => return .read_only,
        .ask => |a| a,
    };

    const action = try ask.actionName(gpa);
    defer gpa.free(action);
    const summary = try summaryOf(gpa, ask);
    defer gpa.free(summary);
    const detail = try detailOf(gpa, ask, argv);
    defer gpa.free(detail);

    const outcome = try broker.request(gpa, io, storage, locked, .{
        .action = action,
        .summary = summary,
        .detail = detail,
        .reason = caller.reason,
        .agent_kind = caller.agent_kind,
        .model_alias = caller.model_alias,
        .tool = caller.tool,
        .tool_call_id = caller.tool_call_id,
        .spawn_chain = caller.spawn_chain,
        .timeout_ms = caller.timeout_ms,
    }, diag);

    if (!outcome.permits()) return .{ .refused = outcome };
    return .{ .approved = outcome };
}

/// One line, for the list a client shows.
fn summaryOf(gpa: std.mem.Allocator, ask: Ask) std.mem.Allocator.Error![]u8 {
    if (ask.subcommand.len == 0) return gpa.dupe(u8, "the agent ran git with an option this shim does not read");
    return std.fmt.allocPrint(gpa, "the agent ran the git subcommand {s}", .{ask.subcommand});
}

/// The whole of what the user is deciding.
///
/// The argument vector is in here, and that is not a contradiction. The rule
/// forbids a shell line **in place of** the effect, so that a user is never
/// made to guess what a command does. Here the effect is stated in full on its
/// own line, and it is the same for every answer this file can give: the
/// subcommand runs inside the sandbox. The vector is below it as the fact the
/// user is being told about, which is what the agent tried to do.
fn detailOf(gpa: std.mem.Allocator, ask: Ask, argv: []const []const u8) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    try out.appendSlice(gpa,
        \\what happens if you say yes:
        \\  the subcommand runs inside the sandbox, and nothing else changes.
        \\  the sandbox has no network and does not hold your own repository.
        \\
        \\why you are being asked:
        \\
    );
    try out.appendSlice(gpa, ask.reason.text());

    const advice = try ask.advice(gpa);
    defer gpa.free(advice);
    try out.appendSlice(gpa,
        \\.
        \\
        \\what the agent should do instead:
        \\
    );
    try out.appendSlice(gpa, advice);

    try out.appendSlice(gpa,
        \\.
        \\
        \\what the agent ran:
        \\
    );
    for (argv) |arg| {
        try out.append(gpa, ' ');
        try out.appendSlice(gpa, arg);
    }
    try out.append(gpa, '\n');

    return out.toOwnedSlice(gpa);
}

const testing = std.testing;
const chock_policy = @import("chock-policy");

/// `chock_proto.storage.Locked` is not `pub`. This reaches the same type
/// through the return type of `Storage.lock`, which is. The same route
/// `Broker.zig`'s own tests take, for the same reason.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// A `Broker.Waiter` that answers the one open request with `decision` the
/// first time the broker gives control away. It never sleeps.
const TestWaiter = struct {
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *LockedHandle,
    decision: event.ApprovalDecision,
    failed: ?anyerror = null,

    fn waiter(self: *TestWaiter) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.waits == 1) {
            self.answer(io) catch |err| {
                if (self.failed == null) self.failed = err;
            };
        }
        self.now_ms += @intCast(budget_ms);
        return .slept;
    }

    fn answer(self: *TestWaiter, io: std.Io) !void {
        var replay = try self.store.replay(self.gpa, io, 0);
        defer replay.deinit();
        var request_id: ?u64 = null;
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            if (parsed.value.event != .approval_request) continue;
            request_id = parsed.value.id;
        }
        const id = request_id orelse return error.NoRequestInTheLog;
        _ = try self.locked.append(self.gpa, io, .{ .approval_response = .{
            .request_id = id,
            .decision = self.decision,
            .responder = "ross",
        } }, self.now_ms);
    }
};

const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

/// What one drive of `decide` over a real in memory log left behind.
const Run = struct {
    answer: Answer,
    requests: usize,
    responses: usize,
    /// The action name of the one `approval.request`, or empty when there
    /// was none. Owned by the caller.
    action: []u8,
    /// Its detail, or empty. Owned by the caller.
    detail: []u8,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        gpa.free(self.action);
        gpa.free(self.detail);
    }
};

/// Drive `decide` over a real `Broker` and a real log, with a test standing
/// in for the client that answers.
fn driveShim(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    decision: event.ApprovalDecision,
    argv: []const []const u8,
) !Run {
    var backing = try chock_proto.storage.Memory.init(gpa, "01SHIM");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = decision,
    };

    const policy = try chock_policy.table.Table.parse(gpa, source, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = waiter.waiter() };
    const answer = try decide(&broker, gpa, io, store, &locked, .{
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "shell",
        .tool_call_id = "call1",
    }, argv, null);
    if (waiter.failed) |err| return err;

    var out = Run{
        .answer = answer,
        .requests = 0,
        .responses = 0,
        .action = try gpa.dupe(u8, ""),
        .detail = try gpa.dupe(u8, ""),
    };
    errdefer out.deinit(gpa);

    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .approval_request => |request| {
                out.requests += 1;
                gpa.free(out.action);
                out.action = try gpa.dupe(u8, request.action);
                gpa.free(out.detail);
                out.detail = try gpa.dupe(u8, request.detail);
            },
            .approval_response => out.responses += 1,
            else => {},
        }
    }
    return out;
}

test "a read only subcommand runs the real git and never asks" {
    // Nothing is written to the log at all. A shim that asked and was
    // allowed by policy would leave an `approval.response` behind, and the
    // user would still have paid for a question they never needed, so the
    // count of both kinds is what this pins and not only the answer.
    const gpa = testing.allocator;
    const io = testing.io;

    const read_only_vectors: []const []const []const u8 = &.{
        &.{ "git", "status" },
        &.{ "git", "log", "--oneline", "-n", "5" },
        &.{ "git", "diff", "HEAD~1" },
        &.{ "git", "show", "HEAD" },
        &.{ "git", "rev-parse", "HEAD" },
        &.{ "git", "cat-file", "-e", "deadbeef" },
        &.{ "git", "for-each-ref" },
        // A bare `git` prints its own usage and changes nothing.
        &.{"git"},
        // These two answer out of git itself.
        &.{ "git", "--version" },
        &.{ "git", "--help" },
    };

    for (read_only_vectors) |argv| {
        try testing.expect(classify(argv) == .run_the_real_git);

        var run = try driveShim(gpa, io, ask_every_action, .approved_by_user, argv);
        defer run.deinit(gpa);
        try testing.expect(run.answer == .read_only);
        try testing.expectEqual(@as(usize, 0), run.requests);
        try testing.expectEqual(@as(usize, 0), run.responses);
    }
}

test "every subcommand that has to reach another host is one classify already stops" {
    // `needsNetwork` says what a caller tells the agent, never whether the
    // subcommand runs: a verb that reached a host and was on the read only
    // list would run the real git, fork ssh, and produce the confusing
    // failure this whole message exists to replace. So the two lists must not
    // disagree, and this is what says so.
    for (needs_network) |subcommand| {
        try testing.expect(needsNetwork(subcommand));
        const argv = [_][]const u8{ "git", subcommand };
        try testing.expect(classify(&argv) == .ask);
        try testing.expectEqualStrings(subcommand, classify(&argv).ask.subcommand);
    }

    // And an ordinary local subcommand is not called a network one. `commit`
    // in particular: it is how a session's work leaves the sandbox at all,
    // through the `workspace.apply` the user is asked about at the end.
    for ([_][]const u8{ "commit", "add", "status", "log", "checkout", "branch", "diff" }) |subcommand| {
        try testing.expect(!needsNetwork(subcommand));
    }
}

test "the answer for a network subcommand names what does work, and never sends the agent looking for a proxy" {
    // The measured failure: `cannot run ssh: No such file or directory` names
    // a missing program, so the model went hunting for a proxy. The
    // replacement has to say the network is the thing that is absent, and it
    // has to name what the agent can do instead, the way the shell refusal
    // does.
    const gpa = testing.allocator;

    const text = try networkRefusal(gpa, "fetch");
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "git fetch") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no network") != null);
    // The two wrong turns, said plainly so neither is taken.
    try testing.expect(std.mem.indexOf(u8, text, "no proxy") != null);
    try testing.expect(std.mem.indexOf(u8, text, "not a missing program") != null);
    // What does work instead.
    try testing.expect(std.mem.indexOf(u8, text, "git log") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Commit your work") != null);
}

test "a subcommand that changes state sends a request, and the request names the act" {
    // The request really goes in the log, and it is keyed on the action name
    // the policy table matches, which for a push is the same `git.push` that
    // `lib/chock-broker/actions.zig` performs. That shared spelling is what
    // lets one rule in `chock.zon` cover both routes to the same effect.
    const gpa = testing.allocator;
    const io = testing.io;

    const cases = [_]struct {
        argv: []const []const u8,
        action: []const u8,
        kind: ?actions.Kind,
    }{
        .{ .argv = &.{ "git", "push", "origin", "main" }, .action = "git.push", .kind = .git_push },
        .{ .argv = &.{ "git", "commit", "-m", "work" }, .action = "git.commit", .kind = .git_commit },
        .{
            .argv = &.{ "git", "branch", "-D", "spike" },
            .action = "git.branch.delete",
            .kind = .git_branch_delete,
        },
        // A `branch` that deletes nothing still asks, and no act is named
        // for it, so the action name is the subcommand's own.
        .{ .argv = &.{ "git", "branch", "spike" }, .action = "git.branch", .kind = null },
        // No act rewrites an object store.
        .{ .argv = &.{ "git", "gc", "--prune=now" }, .action = "git.gc", .kind = null },
    };

    for (cases) |case| {
        const verdict = classify(case.argv);
        try testing.expect(verdict == .ask);
        try testing.expectEqual(Reason.subcommand_changes_state, verdict.ask.reason);
        try testing.expectEqual(case.kind, verdict.ask.kind);

        var run = try driveShim(gpa, io, ask_every_action, .approved_by_user, case.argv);
        defer run.deinit(gpa);
        try testing.expectEqual(@as(usize, 1), run.requests);
        try testing.expectEqualStrings(case.action, run.action);
        try testing.expect(run.answer == .approved);

        // A refusal runs nothing, and it says which of the four refusals it
        // was rather than a bare no.
        var refused = try driveShim(gpa, io, ask_every_action, .refused_by_user, case.argv);
        defer refused.deinit(gpa);
        try testing.expect(refused.answer == .refused);
        try testing.expectEqual(Broker.Outcome.refused_by_user, refused.answer.refused);
    }
}

test "a subcommand the shim does not know sends a request rather than running" {
    // The safe default. An unknown verb is not assumed harmless, and the
    // request says so rather than claiming to know what the verb does.
    const gpa = testing.allocator;
    const io = testing.io;

    const argv: []const []const u8 = &.{ "git", "frobnicate", "--hard" };

    const verdict = classify(argv);
    try testing.expect(verdict == .ask);
    try testing.expectEqual(Reason.subcommand_not_known, verdict.ask.reason);
    try testing.expectEqual(@as(?actions.Kind, null), verdict.ask.kind);

    var run = try driveShim(gpa, io, ask_every_action, .approved_by_user, argv);
    defer run.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), run.requests);
    try testing.expectEqualStrings("git.frobnicate", run.action);
    try testing.expect(std.mem.indexOf(u8, run.detail, "does not know this git subcommand") != null);

    // And with no rule in the table at all, the answer is still `ask` and
    // never `allow`. The table's own safe default, reached through the shim.
    const empty_policy: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{},
        \\    },
        \\}
    ;
    var no_rule = try driveShim(gpa, io, empty_policy, .refused_by_user, argv);
    defer no_rule.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), no_rule.requests);
    try testing.expect(no_rule.answer == .refused);
}

test "a different spelling of the same subcommand still asks, and an option the shim cannot read stops it reading at all" {
    // The first half of the plan's last test. Every vector below reaches
    // `push`, and a shim that only compared `argv[1]` would run the real git
    // for all but the first.
    const gpa = testing.allocator;
    const io = testing.io;

    const spellings: []const []const u8 = &.{
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
    };

    for (spellings) |option| {
        // The two argument form, `--git-dir /x push`.
        const separate: []const []const u8 = &.{ "git", option, "/x", "push" };
        const separate_verdict = classify(separate);
        try testing.expect(separate_verdict == .ask);
        try testing.expectEqual(@as(?actions.Kind, .git_push), separate_verdict.ask.kind);

        // The joined form, `--git-dir=/x push`. `-C=/x` is not a real git
        // spelling, so only the long options get this half.
        if (option[1] != '-') continue;
        const joined = try std.fmt.allocPrint(gpa, "{s}=/x", .{option});
        defer gpa.free(joined);
        const joined_verdict = classify(&.{ "git", joined, "push" });
        try testing.expect(joined_verdict == .ask);
        try testing.expectEqual(@as(?actions.Kind, .git_push), joined_verdict.ask.kind);
    }

    // Several of these at once, mixed with the options that carry no value.
    const piled: []const []const u8 = &.{
        "git",          "--no-pager", "-C",     "/x",
        "--git-dir=/y", "-p",         "--bare", "push",
    };
    const piled_verdict = classify(piled);
    try testing.expect(piled_verdict == .ask);
    try testing.expectEqual(@as(?actions.Kind, .git_push), piled_verdict.ask.kind);

    // And the option the shim refuses to read. `-c` can set any
    // configuration value, several of which make git run a program of the
    // caller's choosing, so the shim stops at the option and never claims to
    // have read the `status` after it.
    const config_option: []const []const u8 = &.{ "git", "-c", "diff.external=/tmp/mine", "status" };
    const config_verdict = classify(config_option);
    try testing.expect(config_verdict == .ask);
    try testing.expectEqual(Reason.option_not_read, config_verdict.ask.reason);
    try testing.expectEqualStrings("", config_verdict.ask.subcommand);

    var run = try driveShim(gpa, io, ask_every_action, .refused_by_user, config_option);
    defer run.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), run.requests);
    try testing.expectEqualStrings(unreadable_action, run.action);
    try testing.expect(run.answer == .refused);

    // The same for `--exec-path`, which moves where git finds its own
    // subcommand programs.
    const exec_path = classify(&.{ "git", "--exec-path=/tmp/mine", "status" });
    try testing.expect(exec_path == .ask);
    try testing.expectEqual(Reason.option_not_read, exec_path.ask.reason);
}

test "the shim tells the user what saying yes does, and never offers to do the act outside the sandbox" {
    // A user approves an effect. The effect this file can give is the same in
    // every case and it is stated first, before the argument vector, so nobody
    // has to read a command line and guess. And the act that would reach
    // outside the sandbox is named as the thing to ask for instead, never as
    // something a yes here would do.
    const gpa = testing.allocator;
    const io = testing.io;

    var run = try driveShim(
        gpa,
        io,
        ask_every_action,
        .approved_by_user,
        &.{ "git", "push", "origin", "main" },
    );
    defer run.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, run.detail, "the subcommand runs inside the sandbox") != null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "the sandbox has no network") != null);
    // **Never the name of a tool that does not exist.** `request_action` is
    // designed and not built, so a message telling the agent to call it costs
    // the agent a turn and teaches it a tool that is not in its list.
    try testing.expect(std.mem.indexOf(u8, run.detail, "request_action") == null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "no tool that asks for one") != null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "git.push") != null);

    // The effect comes before the argument vector, so the first thing read
    // is what happens and not what was typed.
    const effect_at = std.mem.indexOf(u8, run.detail, "what happens if you say yes").?;
    const vector_at = std.mem.indexOf(u8, run.detail, "what the agent ran").?;
    try testing.expect(effect_at < vector_at);

    // And an approval here is only ever permission to run the real git in
    // the sandbox. There is no variant of `Answer` that performs anything.
    try testing.expect(run.answer == .approved);
    try testing.expectEqual(Broker.Outcome.approved_by_user, run.answer.approved);
}

// The shim never performs an act, and it must stay that way: performing one
// is `lib/chock-broker/actions.zig`'s job, outside the sandbox, out of a
// payload that names an effect. This fails the build if `Answer` ever gains
// a variant that carries an `actions.Result`, which is the shape performing
// one would take.
comptime {
    for (@typeInfo(Answer).@"union".fields) |field| {
        if (field.type == actions.Result) {
            @compileError("the git shim must not perform an act: " ++ field.name);
        }
    }
}
