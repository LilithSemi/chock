//! The git shim: a `git` first in the `PATH` inside the sandbox. A read only
//! subcommand runs the real git. A subcommand that changes state asks first.
//! The shim prevents a mistake. It does not prevent an attack.

const std = @import("std");
const chock_proto = @import("chock-proto");
const actions = @import("actions.zig");
const Broker = @import("Broker.zig");

const event = chock_proto.event;

pub const Reason = enum {
    subcommand_changes_state,
    subcommand_not_known,
    option_not_read,

    pub fn text(self: Reason) []const u8 {
        return switch (self) {
            .subcommand_changes_state => "this git subcommand changes state",
            .subcommand_not_known => "this shim does not know this git subcommand",
            .option_not_read => "this shim does not read this git option, so it cannot read the subcommand either",
        };
    }
};

pub const unreadable_action = "git.unknown";

pub const request_source = "git";

pub const Ask = struct {
    subcommand: []const u8,
    /// Everything after the subcommand. `git -C push push` makes a second
    /// search for `push` answer the value of `-C`, so do not search again.
    rest: []const []const u8 = &.{},
    reason: Reason,
    kind: ?actions.Kind,

    pub fn actionName(self: Ask, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        if (self.kind) |kind| return gpa.dupe(u8, kind.wireName());
        if (self.subcommand.len == 0) return gpa.dupe(u8, unreadable_action);
        return std.fmt.allocPrint(gpa, "git.{s}", .{self.subcommand});
    }

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

pub const Verdict = union(enum) {
    run_the_real_git,
    ask: Ask,
};

pub fn classify(argv: []const []const u8) Verdict {
    var index: usize = 1;
    while (index < argv.len) {
        const arg = argv[index];
        if (arg.len == 0 or arg[0] != '-') break;

        if (isOneOf(arg, &.{ "--version", "--help", "-h", "-v" })) return .run_the_real_git;

        if (isOneOf(arg, no_value_options)) {
            index += 1;
            continue;
        }
        if (valueOptionStep(arg)) |step| {
            index += step;
            continue;
        }
        return .{ .ask = .{ .subcommand = "", .reason = .option_not_read, .kind = null } };
    }

    if (index >= argv.len) return .run_the_real_git;
    const subcommand = argv[index];
    const rest = argv[index + 1 ..];

    if (isOneOf(subcommand, read_only)) return .run_the_real_git;
    if (isOneOf(subcommand, changes_state)) {
        return .{ .ask = .{
            .subcommand = subcommand,
            .rest = rest,
            .reason = .subcommand_changes_state,
            .kind = kindFor(subcommand, rest),
        } };
    }
    return .{ .ask = .{
        .subcommand = subcommand,
        .rest = rest,
        .reason = .subcommand_not_known,
        .kind = null,
    } };
}

fn kindFor(subcommand: []const u8, rest: []const []const u8) ?actions.Kind {
    if (std.mem.eql(u8, subcommand, "push")) return .git_push;
    if (std.mem.eql(u8, subcommand, "commit")) return .git_commit;
    if (std.mem.eql(u8, subcommand, "branch")) {
        for (rest) |arg| {
            if (isOneOf(arg, &.{ "-d", "-D", "--delete" })) return .git_branch_delete;
        }
        return null;
    }
    return null;
}

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

/// `git -c <name>=<value>` can make git run a program of the caller's choosing,
/// so an option this file cannot read stops it reading the subcommand too.
fn valueOptionStep(arg: []const u8) ?usize {
    const with_value: []const []const u8 = &.{ "-C", "--git-dir", "--work-tree", "--namespace" };
    for (with_value) |name| {
        if (arg.len > name.len and std.mem.startsWith(u8, arg, name) and arg[name.len] == '=') return 1;
        if (std.mem.eql(u8, arg, name)) return 2;
    }
    return null;
}

/// A verb is here only when no spelling of it writes. `config`, `hash-object`,
/// `branch`, `tag`, `notes`, `reflog`, `stash`, `symbolic-ref`, `fsck`, `gc`,
/// `repack` and `prune` all write with some option.
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

/// The real git forks `ssh` for these, and `ssh` is not in the sandbox, so the
/// failure names a missing program and not a missing network.
const needs_network: []const []const u8 = &.{
    "clone",
    "fetch",
    "ls-remote",
    "pull",
    "push",
};

pub fn needsNetwork(subcommand: []const u8) bool {
    return isOneOf(subcommand, needs_network);
}

/// Never blame the sandbox network here: the router gives a sandbox the hosts
/// `net.connect` names. What is missing is a caller that performs the act.
pub fn hostReachingRefusal(gpa: std.mem.Allocator, subcommand: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "git {s} was not run, and this is not a refusal: the part of it that reaches another " ++
            "host is not built yet. Chock performs an act that leaves the sandbox on the host " ++
            "itself, out of a payload that names the effect, and no caller builds one of those " ++
            "for a git subcommand today. This is not a missing program, and it is not the " ++
            "sandbox's network, so there is nothing here to configure and no proxy to find. " ++
            "Work with what is already in the workspace: the project's own history is here, so " ++
            "git log, git show, git diff and git status all work. Commit your work in the " ++
            "workspace as usual, and the user is asked at the end of the session whether to " ++
            "carry that commit into their own repository.",
        .{subcommand},
    );
}

fn isOneOf(needle: []const u8, haystack: []const []const u8) bool {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, needle, candidate)) return true;
    }
    return false;
}

pub const Caller = struct {
    reason: []const u8,
    agent_kind: []const u8,
    model_alias: []const u8,
    tool: []const u8,
    tool_call_id: []const u8,
    spawn_chain: []const event.SpawnLink = &.{},
    timeout_ms: i64 = Broker.default_timeout_ms,
};

pub const Answer = union(enum) {
    read_only,
    /// An approval only runs the real git inside the sandbox. It grants nothing
    /// the sandbox does not already allow.
    approved: Broker.Outcome,
    refused: Broker.Outcome,
};

pub const Error = Broker.Error;

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
        .source = request_source,
        .spawn_chain = caller.spawn_chain,
        .timeout_ms = caller.timeout_ms,
    }, diag);

    if (!outcome.permits()) return .{ .refused = outcome };
    return .{ .approved = outcome };
}

pub fn summaryOf(gpa: std.mem.Allocator, ask: Ask) std.mem.Allocator.Error![]u8 {
    if (ask.subcommand.len == 0) return gpa.dupe(u8, "the agent ran git with an option this shim does not read");
    return std.fmt.allocPrint(gpa, "the agent ran the git subcommand {s}", .{ask.subcommand});
}

pub fn detailOf(gpa: std.mem.Allocator, ask: Ask, argv: []const []const u8) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    try out.appendSlice(gpa,
        \\what happens if you say yes:
        \\  the subcommand runs inside the sandbox, and nothing else changes.
        \\  the sandbox does not hold your own repository, and it reaches only
        \\  the hosts this project's net.connect rules name.
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

/// `chock_proto.storage.Locked` is not `pub`, so this reaches it through the
/// return type of `Storage.lock`.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

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

const Run = struct {
    answer: Answer,
    requests: usize,
    responses: usize,
    action: []u8,
    detail: []u8,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        gpa.free(self.action);
        gpa.free(self.detail);
    }
};

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
        &.{"git"},
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
    for (needs_network) |subcommand| {
        try testing.expect(needsNetwork(subcommand));
        const argv = [_][]const u8{ "git", subcommand };
        try testing.expect(classify(&argv) == .ask);
        try testing.expectEqualStrings(subcommand, classify(&argv).ask.subcommand);
    }

    for ([_][]const u8{ "commit", "add", "status", "log", "checkout", "branch", "diff" }) |subcommand| {
        try testing.expect(!needsNetwork(subcommand));
    }
}

test "the answer for a host reaching subcommand blames the missing caller, and never the network" {
    const gpa = testing.allocator;

    const text = try hostReachingRefusal(gpa, "fetch");
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "git fetch") != null);
    try testing.expect(std.mem.indexOf(u8, text, "not built yet") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no caller") != null);
    try testing.expect(std.mem.indexOf(u8, text, "not a refusal") != null);
    try testing.expect(std.mem.indexOf(u8, text, "not a missing program") != null);
    try testing.expect(std.mem.indexOf(u8, text, "no proxy to find") != null);
    try testing.expect(std.mem.indexOf(u8, text, "not the sandbox's network") != null);
    try testing.expect(std.mem.indexOf(u8, text, "has no network") == null);
    try testing.expect(std.mem.indexOf(u8, text, "reaches a remote") == null);
    try testing.expect(std.mem.indexOf(u8, text, "git log") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Commit your work") != null);
}

test "a subcommand that changes state sends a request, and the request names the act" {
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
        .{ .argv = &.{ "git", "branch", "spike" }, .action = "git.branch", .kind = null },
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

        var refused = try driveShim(gpa, io, ask_every_action, .refused_by_user, case.argv);
        defer refused.deinit(gpa);
        try testing.expect(refused.answer == .refused);
        try testing.expectEqual(Broker.Outcome.refused_by_user, refused.answer.refused);
    }
}

test "the rest of a push is the arguments after the subcommand, whatever came before it" {
    switch (classify(&.{ "git", "-C", "push", "push", "origin", "main" })) {
        .ask => |ask| {
            try testing.expectEqualStrings("push", ask.subcommand);
            try testing.expectEqual(@as(usize, 2), ask.rest.len);
            try testing.expectEqualStrings("origin", ask.rest[0]);
            try testing.expectEqualStrings("main", ask.rest[1]);
        },
        .run_the_real_git => return error.ShouldHaveAsked,
    }

    switch (classify(&.{ "git", "push" })) {
        .ask => |ask| try testing.expectEqual(@as(usize, 0), ask.rest.len),
        .run_the_real_git => return error.ShouldHaveAsked,
    }

    switch (classify(&.{ "git", "--not-read", "push", "origin" })) {
        .ask => |ask| {
            try testing.expectEqualStrings("", ask.subcommand);
            try testing.expectEqual(@as(usize, 0), ask.rest.len);
        },
        .run_the_real_git => return error.ShouldHaveAsked,
    }
}

test "a subcommand the shim does not know sends a request rather than running" {
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
    const gpa = testing.allocator;
    const io = testing.io;

    const spellings: []const []const u8 = &.{
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
    };

    for (spellings) |option| {
        const separate: []const []const u8 = &.{ "git", option, "/x", "push" };
        const separate_verdict = classify(separate);
        try testing.expect(separate_verdict == .ask);
        try testing.expectEqual(@as(?actions.Kind, .git_push), separate_verdict.ask.kind);

        // `-C=/x` is not a real git spelling, so only the long options get this.
        if (option[1] != '-') continue;
        const joined = try std.fmt.allocPrint(gpa, "{s}=/x", .{option});
        defer gpa.free(joined);
        const joined_verdict = classify(&.{ "git", joined, "push" });
        try testing.expect(joined_verdict == .ask);
        try testing.expectEqual(@as(?actions.Kind, .git_push), joined_verdict.ask.kind);
    }

    const piled: []const []const u8 = &.{
        "git",          "--no-pager", "-C",     "/x",
        "--git-dir=/y", "-p",         "--bare", "push",
    };
    const piled_verdict = classify(piled);
    try testing.expect(piled_verdict == .ask);
    try testing.expectEqual(@as(?actions.Kind, .git_push), piled_verdict.ask.kind);

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

    // `--exec-path` moves where git finds its own subcommand programs.
    const exec_path = classify(&.{ "git", "--exec-path=/tmp/mine", "status" });
    try testing.expect(exec_path == .ask);
    try testing.expectEqual(Reason.option_not_read, exec_path.ask.reason);
}

test "the shim tells the user what saying yes does, and never offers to do the act outside the sandbox" {
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
    try testing.expect(std.mem.indexOf(u8, run.detail, "does not hold your own repository") != null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "net.connect rules name") != null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "has no network") == null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "request_action") == null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "no tool that asks for one") != null);
    try testing.expect(std.mem.indexOf(u8, run.detail, "git.push") != null);

    const effect_at = std.mem.indexOf(u8, run.detail, "what happens if you say yes").?;
    const vector_at = std.mem.indexOf(u8, run.detail, "what the agent ran").?;
    try testing.expect(effect_at < vector_at);

    try testing.expect(run.answer == .approved);
    try testing.expectEqual(Broker.Outcome.approved_by_user, run.answer.approved);
}

comptime {
    for (@typeInfo(Answer).@"union".fields) |field| {
        if (field.type == actions.Result) {
            @compileError("the git shim must not perform an act: " ++ field.name);
        }
    }
}
