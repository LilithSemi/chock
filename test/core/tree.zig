//! A tree of real agents, run for real. Every agent here is
//! `test/core/tree_child.zig`, a real process below a real parent, and no
//! test asserts on a clock: a handshake is bounded by a count of tries.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");
const chock_cost = @import("chock-cost");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const subagent = chock_core.subagent;

// `build.zig` embeds the helper's path as a build time constant, because the
// Zig 0.16 test runner panics on an argv it does not recognize.
const child_path = @import("tree_child_path").tree_child_path;

const testing = std.testing;

/// Twenty six Crockford characters, which is what `src/session.zig` makes and
/// what `src/run.zig`'s own walk up the tree refuses anything else for.
const root_session = "01JQ" ++ "A" ** 22;

const Tree = struct {
    tmp: std.testing.TmpDir,
    project: []u8,
    sessions: []u8,

    fn init(gpa: std.mem.Allocator) !Tree {
        var tmp = testing.tmpDir(.{});
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const root = buffer[0..len];

        try tmp.dir.createDir(testing.io, "project", .default_dir);
        try tmp.dir.createDir(testing.io, "sessions", .default_dir);

        return .{
            .tmp = tmp,
            .project = try std.fmt.allocPrint(gpa, "{s}/project", .{root}),
            .sessions = try std.fmt.allocPrint(gpa, "{s}/sessions", .{root}),
        };
    }

    fn deinit(self: *Tree, gpa: std.mem.Allocator) void {
        gpa.free(self.project);
        gpa.free(self.sessions);
        self.tmp.cleanup();
    }

    fn writeConfig(self: *Tree, source: []const u8) !void {
        var dir = try std.Io.Dir.cwd().openDir(testing.io, self.project, .{});
        defer dir.close(testing.io);
        var file = try dir.createFile(testing.io, chock_policy.subagents.file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, source);
    }

    fn run(
        self: *Tree,
        gpa: std.mem.Allocator,
        session: []const u8,
        kind: []const u8,
        task: []const u8,
        budget: ?chock_cost.budget.Budget,
    ) !void {
        const prepared = subagent.Prepared{
            .child_session = try gpa.dupe(u8, session),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/{s}.jsonl", .{ self.sessions, session }),
            .scratchpad_path = try gpa.dupe(u8, ""),
        };
        defer subagent.freePrepared(gpa, prepared);

        const argv = try subagent.commandLine(gpa, .{
            .exe_path = child_path,
            .project_root = self.project,
            .parent_session = "",
        }, .{
            .agent_kind = kind,
            .task = task,
            .reason = subagent.reasonFor(task),
            .budget = budget,
        }, prepared);
        defer subagent.freeCommandLine(gpa, argv);

        var env = try std.testing.environ.createMap(gpa);
        defer env.deinit();
        try env.put(session_dir_variable, self.sessions);

        var child = try std.process.spawn(testing.io, .{
            .argv = argv,
            .environ_map = &env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        _ = child.wait(testing.io) catch {};
    }

    fn fold(self: *Tree, gpa: std.mem.Allocator, id: []const u8) !Folded {
        const path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ self.sessions, id }, 0);
        defer gpa.free(path);

        var out = Folded{
            .session = chock_proto.state.Session.init(gpa),
            .id = try gpa.dupe(u8, id),
        };
        errdefer out.deinit(gpa);

        const log = try chock_proto.log.Log.open(testing.io, path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const storage = backing.storage();
        defer storage.close(testing.io);

        var replay = try storage.replay(gpa, testing.io, 0);
        defer replay.deinit();
        while (try replay.next(testing.io)) |parsed| {
            defer parsed.deinit();
            try out.session.apply(parsed.value);
            switch (parsed.value.event) {
                .session_start => |start| {
                    gpa.free(out.parent_session);
                    out.parent_session = try gpa.dupe(u8, start.parent_session);
                    gpa.free(out.agent_kind);
                    out.agent_kind = try gpa.dupe(u8, start.agent_kind);
                    for (out.spawn_chain.items) |kind| gpa.free(kind);
                    out.spawn_chain.clearRetainingCapacity();
                    for (start.spawn_chain) |link| {
                        try out.spawn_chain.append(gpa, try gpa.dupe(u8, link.agent_kind));
                    }
                    out.starts += 1;
                },
                .session_end => out.ends += 1,
                .agent_complete => out.completions += 1,
                .message => |said| {
                    if (said.role != .assistant) continue;
                    out.turns += 1;
                    out.answer.clearRetainingCapacity();
                    for (said.content) |part| {
                        if (part == .text) try out.answer.appendSlice(gpa, part.text);
                    }
                },
                else => {},
            }
        }
        return out;
    }
};

const Folded = struct {
    session: chock_proto.state.Session,
    id: []u8 = &.{},
    parent_session: []u8 = &.{},
    agent_kind: []u8 = &.{},
    spawn_chain: std.ArrayList([]u8) = .empty,
    answer: std.ArrayList(u8) = .empty,
    starts: usize = 0,
    ends: usize = 0,
    turns: usize = 0,
    /// An `agent.complete` is written only for a child waited for or drained.
    completions: usize = 0,

    fn deinit(self: *Folded, gpa: std.mem.Allocator) void {
        self.session.deinit();
        gpa.free(self.id);
        gpa.free(self.parent_session);
        gpa.free(self.agent_kind);
        for (self.spawn_chain.items) |kind| gpa.free(kind);
        self.spawn_chain.deinit(gpa);
        self.answer.deinit(gpa);
    }
};

/// Spelled here as well as in `test/core/tree_child.zig`, because this test
/// cannot import a program. A name that stopped matching fails every test here.
const session_dir_variable = "CHOCK_TEST_SESSION_DIR";

test "a tree three deep really runs, and every level's log names the level above it" {
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    try tree.run(gpa, root_session, "main",
        \\say I will split this in two
        \\spawn coder
        \\> say I will hand the reading to somebody else
        \\> spawn worker
        \\> > say the parser refuses an empty file
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), root.session.children.items.len);
    try testing.expectEqualStrings("", root.parent_session);

    const child_id = root.session.children.items[0].session;
    var child = try tree.fold(gpa, child_id);
    defer child.deinit(gpa);
    try testing.expectEqualStrings(root_session, child.parent_session);
    try testing.expectEqualStrings("coder", child.agent_kind);
    try testing.expectEqual(@as(usize, 1), child.session.children.items.len);

    const grandchild_id = child.session.children.items[0].session;
    var grandchild = try tree.fold(gpa, grandchild_id);
    defer grandchild.deinit(gpa);
    try testing.expectEqualStrings(child_id, grandchild.parent_session);
    try testing.expectEqualStrings("worker", grandchild.agent_kind);
    try testing.expectEqual(@as(usize, 0), grandchild.session.children.items.len);

    try testing.expectEqual(@as(usize, 0), root.spawn_chain.items.len);
    try testing.expectEqual(@as(usize, 1), child.spawn_chain.items.len);
    try testing.expectEqualStrings("main", child.spawn_chain.items[0]);
    try testing.expectEqual(@as(usize, 2), grandchild.spawn_chain.items.len);
    try testing.expectEqualStrings("main", grandchild.spawn_chain.items[0]);
    try testing.expectEqualStrings("coder", grandchild.spawn_chain.items[1]);

    for ([_]*Folded{ &root, &child, &grandchild }) |one| {
        try testing.expectEqual(@as(usize, 1), one.starts);
        try testing.expectEqual(@as(usize, 1), one.ends);
    }
    try testing.expect(!std.mem.eql(u8, root_session, child_id));
    try testing.expect(!std.mem.eql(u8, child_id, grandchild_id));

    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, root.answer.items, "the parser refuses an empty file"),
    );
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, child.answer.items, "the parser refuses an empty file"),
    );
}

test "max_depth stops a tree at the level it names, and every level below it" {
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    try tree.writeConfig(".{ .subagents = .{ .max_depth = 3, .max_width = 4 } }");

    try tree.run(gpa, root_session, "main",
        \\spawn coder
        \\> spawn worker
        \\> > spawn worker
        \\> > > say nobody should have started me
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), root.session.children.items.len);

    var second = try tree.fold(gpa, root.session.children.items[0].session);
    defer second.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), second.session.children.items.len);

    var third = try tree.fold(gpa, second.session.children.items[0].session);
    defer third.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), third.session.children.items.len);
    try testing.expectEqualStrings("refused=max_depth depth=3 width=0", third.answer.items);

    var deeper = try Tree.init(gpa);
    defer deeper.deinit(gpa);
    try deeper.writeConfig(".{ .subagents = .{ .max_depth = 5, .max_width = 4 } }");
    try deeper.run(gpa, root_session, "main",
        \\spawn coder
        \\> spawn worker
        \\> > spawn worker
        \\> > > say I am four levels down
    , null);

    var at_one = try deeper.fold(gpa, root_session);
    defer at_one.deinit(gpa);
    var at_two = try deeper.fold(gpa, at_one.session.children.items[0].session);
    defer at_two.deinit(gpa);
    var at_three = try deeper.fold(gpa, at_two.session.children.items[0].session);
    defer at_three.deinit(gpa);
    var at_four = try deeper.fold(gpa, at_three.session.children.items[0].session);
    defer at_four.deinit(gpa);
    try testing.expectEqualStrings("I am four levels down", at_four.answer.items);
}

test "a grandchild holds no permission the agent at the top of its tree lacks" {
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    try tree.writeConfig(
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "coder", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "worker", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    );

    try tree.run(gpa, root_session, "main",
        \\spawn coder
        \\> report-chain git.push
        \\> spawn worker
        \\> > report-chain git.push
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    var child = try tree.fold(gpa, root.session.children.items[0].session);
    defer child.deinit(gpa);
    var grandchild = try tree.fold(gpa, child.session.children.items[0].session);
    defer grandchild.deinit(gpa);

    try testing.expectEqualStrings("alone=allow chain=deny links=2", child.answer.items);

    try testing.expectEqualStrings("alone=allow chain=deny links=3", grandchild.answer.items);

    const table = try chock_policy.table.Table.load(gpa, testing.io, tree.project, null);
    defer chock_policy.table.Table.destroy(gpa, table);
    const key = chock_policy.table.Key{
        .agent_kind = "worker",
        .model = "test-model",
        .tool = "request_action",
        .action = "git.push",
    };
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        table.evaluateChain(&.{ "coder", "worker" }, key, null),
    );
    try testing.expectEqual(
        chock_policy.table.Decision.deny,
        table.evaluateChain(&.{ "main", "coder", "worker" }, key, null),
    );
}

test "two children of one parent really run at the same time" {
    // No clock: the handshake is a count of tries.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 4 } }");

    try tree.run(gpa, root_session, "main",
        \\background worker
        \\> rendezvous 2
        \\background worker
        \\> rendezvous 2
        \\join
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "joined=2") != null);

    for (root.session.children.items) |one| {
        var kid = try tree.fold(gpa, one.session);
        defer kid.deinit(gpa);
        try testing.expectEqualStrings("rendezvous=met", kid.answer.items);
        try testing.expectEqualStrings(root_session, kid.parent_session);
    }
}

test "four children at once, with the parent writing its own log while they finish" {
    // Four children means four threads, each one inside a process spawn while the
    // others allocate, which is the fork hazard `subagent.Table.gpa` is written for.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 4 } }");

    try tree.run(gpa, root_session, "main",
        \\background worker
        \\> rendezvous 4
        \\churn 20
        \\background worker
        \\> rendezvous 4
        \\churn 20
        \\background worker
        \\> rendezvous 4
        \\churn 20
        \\background worker
        \\> rendezvous 4
        \\churn 20
        \\join
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 4), root.session.children.items.len);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "joined=4") != null);
    try testing.expectEqual(@as(usize, 4), root.completions);

    var met: usize = 0;
    for (root.session.children.items) |one| {
        var kid = try tree.fold(gpa, one.session);
        defer kid.deinit(gpa);
        try testing.expectEqualStrings(root_session, kid.parent_session);
        try testing.expectEqual(@as(usize, 1), kid.ends);
        if (std.mem.eql(u8, kid.answer.items, "rendezvous=met")) met += 1;
    }
    try testing.expectEqual(@as(usize, 4), met);

    try testing.expect(root.turns >= 80);
}

test "the same two children run one at a time say so, which is what the handshake is worth" {
    // The bound is small here on purpose. The sibling this child waits for is
    // never started, so no number of tries would find it.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 4 } }");

    try tree.run(gpa, root_session, "main",
        \\spawn worker
        \\> rendezvous 2 64
        \\spawn worker
        \\> rendezvous 2 64
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);

    var first = try tree.fold(gpa, root.session.children.items[0].session);
    defer first.deinit(gpa);
    try testing.expectEqualStrings("rendezvous=missed", first.answer.items);

    var second = try tree.fold(gpa, root.session.children.items[1].session);
    defer second.deinit(gpa);
    try testing.expectEqualStrings("rendezvous=met", second.answer.items);
}

/// Each agent appends its own line to one file as its very last act, so this is
/// an order of process endings and not a set of timestamps.
fn endingOrder(gpa: std.mem.Allocator, tree: *Tree) ![][]const u8 {
    const path = try std.fmt.allocPrint(gpa, "{s}/order", .{tree.project});
    defer gpa.free(path);

    const text = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .limited(64 * 1024));
    defer gpa.free(text);

    var out: std.ArrayList([]const u8) = .empty;
    errdefer freeOrder(gpa, out.items);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        try out.append(gpa, try gpa.dupe(u8, line));
    }
    return out.toOwnedSlice(gpa);
}

fn freeOrder(gpa: std.mem.Allocator, order: [][]const u8) void {
    for (order) |one| gpa.free(one);
    gpa.free(order);
}

test "a tree tears down from the bottom, because every level waits for the level below it" {
    // Nothing here is a clock, and no level joins its child, so `Table.deinit`
    // is the only thing that can be waiting.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");

    try tree.run(gpa, root_session, "main",
        \\background coder
        \\> background worker
        \\> > churn 300
        \\> > say I am the last to finish
    , null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    var child = try tree.fold(gpa, root.session.children.items[0].session);
    defer child.deinit(gpa);
    var grandchild = try tree.fold(gpa, child.session.children.items[0].session);
    defer grandchild.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), grandchild.ends);
    try testing.expectEqualStrings("I am the last to finish", grandchild.answer.items);

    const order = try endingOrder(gpa, &tree);
    defer freeOrder(gpa, order);
    try testing.expectEqual(@as(usize, 3), order.len);
    try testing.expectEqualStrings(grandchild.id, order[0]);
    try testing.expectEqualStrings(child.id, order[1]);
    try testing.expectEqualStrings(root_session, order[2]);

    try testing.expectEqual(@as(usize, 1), root.session.children.items.len);
    try testing.expectEqual(@as(usize, 0), root.completions);
    try testing.expectEqual(@as(usize, 0), child.completions);
}

test "the width bound counts a reviewer, so the child after it is refused" {
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");

    // The kind is read from `chock_broker.review.default_kind`, the one place it
    // is written, so a rename cannot leave this test spelling the old name.
    const script = try std.fmt.allocPrint(gpa,
        \\spawn {s}
        \\> say the diff is the fix the task asked for
        \\spawn worker
        \\> say I read the tests
        \\spawn worker
        \\> say nobody should have started me
    , .{chock_broker.review.default_kind});
    defer gpa.free(script);

    try tree.run(gpa, root_session, "main", script, null);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);

    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);
    try testing.expectEqualStrings(
        chock_broker.review.default_kind,
        root.session.children.items[0].agent_kind,
    );
    try testing.expectEqualStrings("worker", root.session.children.items[1].agent_kind);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "refused=max_width") != null);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "width=2") != null);

    var reviewer = try tree.fold(gpa, root.session.children.items[0].session);
    defer reviewer.deinit(gpa);
    try testing.expectEqualStrings("the diff is the fix the task asked for", reviewer.answer.items);
    try testing.expectEqualStrings(root_session, reviewer.parent_session);

    const limits = chock_policy.subagents.Limits{ .max_depth = 6, .max_width = 2 };
    try testing.expectEqual(
        chock_policy.subagents.Refusal.width,
        chock_policy.subagents.check(limits, .{ .depth = 1, .width = 2 }).?,
    );
    try testing.expectEqual(
        @as(?chock_policy.subagents.Refusal, null),
        chock_policy.subagents.check(limits, .{ .depth = 1, .width = 1 }),
    );
}

/// What the whole tree below `id` spent. It walks the real logs, because a
/// child's spending never reaches its parent's log.
const Money = struct {
    spent: f64 = 0,
    agents: usize = 0,
};

fn addUp(gpa: std.mem.Allocator, tree: *Tree, id: []const u8, cap: ?f64) !Money {
    var folded = try tree.fold(gpa, id);
    defer folded.deinit(gpa);

    var out = Money{ .spent = folded.session.spend.amount, .agents = 1 };
    var promised: f64 = 0;
    for (folded.session.children.items) |one| {
        promised += one.budget_max_cost;
        // Zero is a child that was given no cap at all, and reading it as a cap
        // of nothing would make every spend it made a fault.
        const below = try addUp(
            gpa,
            tree,
            one.session,
            if (one.budget_max_cost > 0) one.budget_max_cost else null,
        );
        out.spent += below.spent;
        out.agents += below.agents;
    }

    if (cap) |limit| {
        try testing.expect(folded.session.spend.amount + promised <= limit + 0.000001);
    }
    return out;
}

test "the money a whole tree spends stays inside the cap the root was given" {
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");

    const cap = chock_cost.budget.Budget{ .max_cost = 4.0, .currency = "USD" };

    try tree.run(gpa, root_session, "main",
        \\spend 1.0 USD
        \\spawn coder
        \\> report-budget
        \\> spend 0.25 USD
        \\> spawn worker
        \\> > report-budget
        \\> > spend 0.25 USD
        \\spawn coder
        \\> report-budget
        \\> spend 0.5 USD
    , cap);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);

    try testing.expectApproxEqAbs(
        @as(f64, 1.5),
        root.session.children.items[0].budget_max_cost,
        0.000001,
    );
    try testing.expectEqualStrings("USD", root.session.children.items[0].budget_currency);

    try testing.expectApproxEqAbs(
        @as(f64, 1.5),
        root.session.children.items[1].budget_max_cost,
        0.000001,
    );

    var child = try tree.fold(gpa, root.session.children.items[0].session);
    defer child.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, child.answer.items, "budget=1.5USD") != null);

    try testing.expectApproxEqAbs(
        @as(f64, 0.625),
        child.session.children.items[0].budget_max_cost,
        0.000001,
    );

    const total = try addUp(gpa, &tree, root_session, cap.max_cost);
    try testing.expectEqual(@as(usize, 4), total.agents);
    try testing.expectApproxEqAbs(@as(f64, 2.0), total.spent, 0.000001);
    try testing.expect(total.spent <= cap.max_cost);
}

test "a parent that resumed does not hand out the money it already promised" {
    // The resume is real: a second process with the same session identifier and
    // nothing in memory from the first.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");

    const cap = chock_cost.budget.Budget{ .max_cost = 4.0, .currency = "USD" };

    try tree.run(gpa, root_session, "main",
        \\spend 1.0 USD
        \\spawn worker
        \\> report-budget
    , cap);

    {
        var after_first = try tree.fold(gpa, root_session);
        defer after_first.deinit(gpa);
        try testing.expectEqual(@as(usize, 1), after_first.session.children.items.len);
        try testing.expectApproxEqAbs(
            @as(f64, 1.5),
            after_first.session.children.items[0].budget_max_cost,
            0.000001,
        );
    }

    try tree.run(gpa, root_session, "main",
        \\spawn worker
        \\> report-budget
    , cap);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), root.starts);
    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);

    const first = root.session.children.items[0].budget_max_cost;
    const second = root.session.children.items[1].budget_max_cost;

    try testing.expectApproxEqAbs(@as(f64, 1.5), second, 0.000001);
    try testing.expect(second < 3.0);
    try testing.expectApproxEqAbs(
        @as(f64, cap.max_cost),
        root.session.spend.amount + first + second,
        0.000001,
    );

    for (root.session.children.items) |one| {
        var kid = try tree.fold(gpa, one.session);
        defer kid.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, kid.answer.items, "budget=1.5USD") != null);
    }
}

test "a parent with nothing left starts no child at all" {
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");

    try tree.run(gpa, root_session, "main",
        \\spend 2.0 USD
        \\spawn worker
        \\> say nobody should have started me
    , .{ .max_cost = 2.0, .currency = "USD" });

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), root.session.children.items.len);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "refused=budget") != null);

    var second = try Tree.init(gpa);
    defer second.deinit(gpa);
    try second.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");
    try second.run(gpa, root_session, "main",
        \\spend 0.5 USD
        \\spawn worker
        \\> say I was paid for
    , .{ .max_cost = 2.0, .currency = "USD" });

    var paid = try second.fold(gpa, root_session);
    defer paid.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), paid.session.children.items.len);
}

test "the identifier this suite gives the root is one a real session could have" {
    // `src/run.zig`'s own walk up the tree refuses an identifier that is not
    // twenty six characters of Crockford base32 before it builds a path from it.
    try testing.expectEqual(@as(usize, 26), root_session.len);
    for (root_session) |character| {
        try testing.expect(std.mem.indexOfScalar(
            u8,
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
            character,
        ) != null);
    }
}
