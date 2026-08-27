//! A tree of real agents, run for real, so the three things claimed above one
//! child stop being claims.
//!
//! `test/core/subagent.zig` proves one parent and one child. Everything above
//! that was reasoning: **the budget slice a resumed parent hands out, the width
//! bound with a reviewer in the count, and the fold that is supposed to stop a
//! grandchild holding more than its grandparent.** None of it had ever run
//! against a tree, and two of the faults below are only visible with three
//! levels or two siblings, because width is about division and simultaneity and
//! depth is about inheritance and accumulation.
//!
//! Every agent here is `test/core/tree_child.zig`, a real process that is a
//! child of the level above it and a parent of the level below it. Every
//! argument vector comes from `chock_core.subagent.commandLine`, every log is
//! written through `chock_proto.log.Log` into one real session directory, every
//! limit is read by the agent itself from a real `chock.zon`, and every slice is
//! divided by `chock_core.subagent.budgetSlice` out of the agent's own log.
//!
//! **No test here asserts on a clock.** Two agents that must run at the same
//! time prove it with a handshake bounded by a count of tries, the way
//! `test/core/subagent_child.zig`'s own `WAIT` already does, and the negative
//! control runs the same script one child at a time and shows the handshake
//! failing.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");
const chock_cost = @import("chock-cost");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const subagent = chock_core.subagent;

// Zig 0.16's test runner panics on an argv it does not recognize, so the
// helper's path cannot come in as an argument. `build.zig` embeds it as a build
// time constant, the same way it does for every other helper program here.
const child_path = @import("tree_child_path").tree_child_path;

const testing = std.testing;

/// The identifier of the agent a person started. A real one: twenty six
/// Crockford characters, which is what `src/session.zig` makes and what
/// `src/run.zig`'s own walk up the tree refuses anything else for.
const root_session = "01JQ" ++ "A" ** 22;

/// One project and one session directory, both real, in a fresh temp directory.
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

    /// Write the `chock.zon` every agent of this tree reads for itself. A real
    /// session keeps this file beyond the agent's reach, and here it is beyond
    /// the helper's too: nothing the helper does writes it.
    fn writeConfig(self: *Tree, source: []const u8) !void {
        var dir = try std.Io.Dir.cwd().openDir(testing.io, self.project, .{});
        defer dir.close(testing.io);
        var file = try dir.createFile(testing.io, chock_policy.subagents.file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, source);
    }

    /// Start the agent at the top of the tree and wait for the whole tree.
    ///
    /// **The argument vector is the real one.** `commandLine` is what
    /// `src/run.zig` builds a child's command line with, and every level below
    /// this one builds its own with the same function.
    ///
    /// Called twice with the same `session` for a resume: the agent finds the
    /// log it already wrote, appends to it, and folds it for what it already
    /// promised.
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
            // Nobody above the root, which is every session a person starts.
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

    /// Fold one session of this tree, by identifier, the way `chock run` folds
    /// a log it did not write.
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

/// One session of the tree, read back off the disk.
const Folded = struct {
    session: chock_proto.state.Session,
    /// The identifier this was folded from, kept so a test can name the agent
    /// it is holding without carrying the string beside it.
    id: []u8 = &.{},
    parent_session: []u8 = &.{},
    agent_kind: []u8 = &.{},
    /// The kinds above this agent, root first, read off its own
    /// `session.start`. It is what a reader who holds this log and no other
    /// needs to say what the policy table answered for this agent: see
    /// `event.SessionStart.spawn_chain`.
    spawn_chain: std.ArrayList([]u8) = .empty,
    /// The last thing this agent said, which is the answer its parent reads.
    answer: std.ArrayList(u8) = .empty,
    starts: usize = 0,
    ends: usize = 0,
    /// How many turns this agent took in its own voice.
    turns: usize = 0,
    /// How many children this agent was told about, which is not how many it
    /// started: an `agent.complete` is written only for a child that was
    /// waited for or drained.
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

/// Where the agents of this tree write their logs, named through the
/// environment. Spelled here as well as in `test/core/tree_child.zig`, because
/// this test cannot import a program.
///
/// **A name that stopped matching fails every test in this file at once**: an
/// agent that is told no directory writes no log, and every assertion below is
/// about a log. So this needs no test of its own.
const session_dir_variable = "CHOCK_TEST_SESSION_DIR";

test "a tree three deep really runs, and every level's log names the level above it" {
    // The link `src/run.zig`'s own walk up the tree follows. A grandchild is
    // bound by a grandparent through `session.start.parent_session` and through
    // nothing else, so a tree whose second link is missing is a tree where every
    // promise stops one level down.
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
    // **The second link, which is the one that had never run.** The grandchild
    // names the child, and the child names the root, so a walk upward reaches
    // the root from the bottom.
    try testing.expectEqualStrings(child_id, grandchild.parent_session);
    try testing.expectEqualStrings("worker", grandchild.agent_kind);
    try testing.expectEqual(@as(usize, 0), grandchild.session.children.items.len);

    // **Every level's log says which kinds are above it, and not only which
    // session is.** `parent_session` is an identifier, and the answer the
    // policy table gives is the intersection over every kind from the root
    // down, so a reader who holds one log and not its parents can re-derive a
    // decision only if the kinds are in that log. The red team oracle read a
    // child log with a parent and no chain on 2026-08-25 and correctly refused
    // to judge it. See `event.SessionStart.spawn_chain`.
    try testing.expectEqual(@as(usize, 0), root.spawn_chain.items.len);
    try testing.expectEqual(@as(usize, 1), child.spawn_chain.items.len);
    try testing.expectEqualStrings("main", child.spawn_chain.items[0]);
    try testing.expectEqual(@as(usize, 2), grandchild.spawn_chain.items.len);
    try testing.expectEqualStrings("main", grandchild.spawn_chain.items[0]);
    try testing.expectEqualStrings("coder", grandchild.spawn_chain.items[1]);

    // Three separate sessions, each begun once and ended once. A tree that
    // reused one log would show three starts in one file.
    for ([_]*Folded{ &root, &child, &grandchild }) |one| {
        try testing.expectEqual(@as(usize, 1), one.starts);
        try testing.expectEqual(@as(usize, 1), one.ends);
    }
    try testing.expect(!std.mem.eql(u8, root_session, child_id));
    try testing.expect(!std.mem.eql(u8, child_id, grandchild_id));

    // **No level's turns are in the level above it.** The two log design, at
    // two levels rather than one.
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
    // **A fault this found, and then the fix.** `chock_policy.subagents.check`
    // is given a depth, and the depth every agent computes is
    // `spawn_chain.len + 1`. That chain used to be built from a single
    // `--parent-kind`, so it held one link whatever the real depth was: every
    // agent below the first reported depth 2, at any depth, and `max_depth`
    // bounded nothing below the second level. The tree below ran five levels
    // deep under a `max_depth` of three, and nothing said a word.
    //
    // The chain now carries every agent above, so the depth an agent reports is
    // its real depth. Two levels of children, and the third is refused.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    // Three levels, and no more. An agent at depth 3 must start nothing.
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 3, .max_width = 4 } }");

    try tree.run(gpa, root_session, "main",
        \\spawn coder
        \\> spawn worker
        \\> > spawn worker
        \\> > > say nobody should have started me
    , null);

    // The two levels the limit allows, both started.
    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), root.session.children.items.len);

    var second = try tree.fold(gpa, root.session.children.items[0].session);
    defer second.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), second.session.children.items.len);

    // **The third level is where the limit answers.** It knows it is at depth
    // three, because its parent handed it a chain of two agents, and the
    // refusal names the limit and the number that reached it.
    var third = try tree.fold(gpa, second.session.children.items[0].session);
    defer third.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), third.session.children.items.len);
    try testing.expectEqualStrings("refused=max_depth depth=3 width=0", third.answer.items);

    // A `max_depth` of five lets the same script run to the bottom, so the
    // refusal above is about the limit and not about anything else that stops a
    // tree.
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
    // The other half of the same fault, and the one with teeth. A subagent
    // holds no more than every kind above it, and
    // `chock_policy.table.evaluateChain` really does fold a chain. **What used
    // not to reach it was the chain**: a parent wrote one `--parent-kind`, so a
    // grandchild folded its own kind and its parent's, and the grandparent's
    // row of `chock.zon` was not in the answer at all. The grandchild below
    // really did hold `allow` for an act the agent at the top of its own tree
    // is denied, and only a tree three deep can show that.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    // The root's kind denies the push. The two below it allow it.
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

    // The child, one level down, folds two kinds and the root's `deny` binds
    // it. That is the case `test/core/subagent.zig` already proves, and it is
    // here so the line below is about the depth and not about the table.
    try testing.expectEqualStrings("alone=allow chain=deny links=2", child.answer.items);

    // **The grandchild folds three kinds, and the root's is one of them.** Its
    // own row allows the push, its parent's row allows it, and the agent at the
    // top of the tree is what denies it. Three links: a chain that arrived one
    // link short would say two here and answer `allow`.
    try testing.expectEqualStrings("alone=allow chain=deny links=3", grandchild.answer.items);

    // And the same table answers `allow` for the two levels the fold would have
    // seen without the root, so the `deny` above is the root's row and not the
    // table refusing whatever it is asked.
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
    // **The fact that makes a tree worth more than a sequence**, and the first
    // time anything here runs at once. Neither child may end until both have
    // arrived, and neither can arrive before it starts, so a parent that ran
    // them one after the other leaves the first saying it never met the second.
    //
    // No clock: the handshake is a count of tries, the way
    // `test/core/subagent_child.zig`'s own `WAIT` already is.
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
    // Both were drained at the safe point and both were recorded by the parent,
    // because a child cannot write its parent's log.
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "joined=2") != null);

    for (root.session.children.items) |one| {
        var kid = try tree.fold(gpa, one.session);
        defer kid.deinit(gpa);
        try testing.expectEqualStrings("rendezvous=met", kid.answer.items);
        try testing.expectEqualStrings(root_session, kid.parent_session);
    }
}

test "four children at once, with the parent writing its own log while they finish" {
    // The wider case, for the three things that only have one thread's worth of
    // proof otherwise. **Four children means four threads**, each one inside a
    // process spawn while the others allocate, which is the fork hazard
    // `subagent.Table.gpa` is written for; four completions recorded through
    // the one `Lock`, at very nearly the same moment, because none of them may
    // end until all four have arrived; and one drain of all four at a safe
    // point.
    //
    // The parent writes turns of its own between the spawns, so its log is
    // being appended to while its children run. **That is the parent's own
    // single writer rule under load**: no child writes this log, whatever else
    // is happening.
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
    // All four were drained in one call and all four were recorded by the
    // parent, which is the table's own bookkeeping holding under four threads.
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "joined=4") != null);
    try testing.expectEqual(@as(usize, 4), root.completions);

    // Every one of them met the other three, so all four really were alive
    // together. One that had been started after another ended could not have.
    var met: usize = 0;
    for (root.session.children.items) |one| {
        var kid = try tree.fold(gpa, one.session);
        defer kid.deinit(gpa);
        try testing.expectEqualStrings(root_session, kid.parent_session);
        try testing.expectEqual(@as(usize, 1), kid.ends);
        if (std.mem.eql(u8, kid.answer.items, "rendezvous=met")) met += 1;
    }
    try testing.expectEqual(@as(usize, 4), met);

    // **And the parent's own log holds the parent's own work.** Eighty turns of
    // it, written while the four were running, so this is a parent that carried
    // on rather than a parent that waited four times over.
    try testing.expect(root.turns >= 80);
}

test "the same two children run one at a time say so, which is what the handshake is worth" {
    // The negative control for the test above. Nothing about the children
    // changes: only the parent's instruction does, from "go and do that while I
    // work" to "do this and tell me". The first child then waits for a sibling
    // that has not been started and says it never met it.
    //
    // The bound is small here on purpose. The sibling it waits for does not
    // exist yet, so no number of tries would find it, and a large bound would
    // only make this test slow.
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

    // The second one finds the file the first left behind, so the handshake is
    // about two agents being alive at once and not about a file existing.
    var second = try tree.fold(gpa, root.session.children.items[1].session);
    defer second.deinit(gpa);
    try testing.expectEqualStrings("rendezvous=met", second.answer.items);
}

/// Every agent of the tree, in the order the processes ended. Read out of the
/// one file each agent appends its own line to as its very last act, so this is
/// an order and not a set of timestamps: see `test/core/tree_child.zig`.
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
    // **`Table.deinit` waits, and that is not optional.** A child writes below
    // its parent's scratchpad, and the parent removes that whole tree when its
    // run ends, so a child left running past the end of its parent is an agent
    // with no parent writing into a path that is gone. A grandchild is one
    // level further down again, and nothing had ever run one.
    //
    // Nothing here is a clock. Every agent appends its own line to one file as
    // its very last act, after its own table has been torn down, so the file is
    // a total order of process endings. **Deepest first is the whole claim.**
    //
    // No level joins its child, so `deinit` is the only thing that can be
    // waiting: `join` would have waited already, and the point is what happens
    // to an agent that never asked.
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

    // Every level really ended, which is what the order below is an order of.
    // A grandchild the tree walked away from would have no `session.end` at
    // all, which is exactly what its parent would read as `died`.
    try testing.expectEqual(@as(usize, 1), grandchild.ends);
    try testing.expectEqualStrings("I am the last to finish", grandchild.answer.items);

    const order = try endingOrder(gpa, &tree);
    defer freeOrder(gpa, order);
    try testing.expectEqual(@as(usize, 3), order.len);
    try testing.expectEqualStrings(grandchild.id, order[0]);
    try testing.expectEqualStrings(child.id, order[1]);
    try testing.expectEqualStrings(root_session, order[2]);

    // **And nothing was drained, which is the other half of what `deinit`
    // does.** No level joined its child, so no level appended an
    // `agent.complete`: the completion the table held was freed with the table.
    // The child's own log is still the whole record either way, which is why
    // that is safe.
    try testing.expectEqual(@as(usize, 1), root.session.children.items.len);
    try testing.expectEqual(@as(usize, 0), root.completions);
    try testing.expectEqual(@as(usize, 0), child.completions);
}

test "the width bound counts a reviewer, so the child after it is refused" {
    // A reviewer is a real child process, and until recently the width bound
    // could not see one. Here it is one of two children a project allows: the
    // reviewer is started, recorded in its parent's own log under its own kind,
    // and the ordinary child after it is refused by the fold that counted it.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);
    try tree.writeConfig(".{ .subagents = .{ .max_depth = 6, .max_width = 2 } }");

    // The kind is read from `chock_broker.review.default_kind`, the one place
    // it is written, so a rename cannot leave this test spelling the old name.
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

    // Two children and not three. The third was refused by the width, and the
    // refusal names the limit that answered.
    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);
    try testing.expectEqualStrings(
        chock_broker.review.default_kind,
        root.session.children.items[0].agent_kind,
    );
    try testing.expectEqualStrings("worker", root.session.children.items[1].agent_kind);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "refused=max_width") != null);
    try testing.expect(std.mem.indexOf(u8, root.answer.items, "width=2") != null);

    // The reviewer really ran, so the count above is a count of children that
    // exist. A reviewer refused before it started would leave the same number
    // in the log and nothing on disk.
    var reviewer = try tree.fold(gpa, root.session.children.items[0].session);
    defer reviewer.deinit(gpa);
    try testing.expectEqualStrings("the diff is the fix the task asked for", reviewer.answer.items);
    try testing.expectEqualStrings(root_session, reviewer.parent_session);

    // **Without the reviewer in the count the third child would have been the
    // second.** The same limit, the same fold, one child fewer: this is what
    // says the refusal above is about the reviewer being counted.
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

/// What the whole tree below `id` spent, and what it promised its children.
/// Walks the real logs, which is the only record there is: **a child's spending
/// never reaches its parent's log.**
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
        // Zero is a child that was given no cap at all, which is what a project
        // with none hands every agent of its tree. There is nothing to measure
        // that child against, and reading it as a cap of nothing would make
        // every spend it made a fault.
        const below = try addUp(
            gpa,
            tree,
            one.session,
            if (one.budget_max_cost > 0) one.budget_max_cost else null,
        );
        out.spent += below.spent;
        out.agents += below.agents;
    }

    // **The invariant, at every node of the tree.** What one agent spent plus
    // every slice it promised is no more than what it was given. Nothing in the
    // tree shares memory, so this has to hold with no agent telling any other
    // agent anything.
    if (cap) |limit| {
        try testing.expect(folded.session.spend.amount + promised <= limit + 0.000001);
    }
    return out;
}

test "the money a whole tree spends stays inside the cap the root was given" {
    // The cap is on the tree and not on each agent in it. A slice is divided
    // out of what is left, a slice of a slice is divided again, and no agent
    // can be told what another one spent.
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

    // The first slice: four less the one the root spent, divided by the two
    // children the width still allows.
    try testing.expectApproxEqAbs(
        @as(f64, 1.5),
        root.session.children.items[0].budget_max_cost,
        0.000001,
    );
    try testing.expectEqualStrings("USD", root.session.children.items[0].budget_currency);

    // **The second slice comes off the same remainder, not off the whole of
    // it.** The first child's spending never reaches this log, so the promise
    // is what the parent subtracts, and the two together are exactly what was
    // left.
    try testing.expectApproxEqAbs(
        @as(f64, 1.5),
        root.session.children.items[1].budget_max_cost,
        0.000001,
    );

    var child = try tree.fold(gpa, root.session.children.items[0].session);
    defer child.deinit(gpa);
    // The child was told what it holds, and it is the slice its parent recorded.
    try testing.expect(std.mem.indexOf(u8, child.answer.items, "budget=1.5USD") != null);

    // **A slice of a slice.** One and a half, less the quarter the child spent,
    // divided by the two children it may still start.
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
    // The subtlety the slice was designed around, and the one that had never
    // been run: **a child's spending never reaches its parent's log**, so a
    // parent that counted from zero after a resume would hand the same money
    // out twice.
    //
    // The resume here is real. The second run is a second process, with the
    // same session identifier and nothing in memory from the first: everything
    // it knows about what it already promised, it folds off its own log.
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

    // The same session, a second process, one more child.
    try tree.run(gpa, root_session, "main",
        \\spawn worker
        \\> report-budget
    , cap);

    var root = try tree.fold(gpa, root_session);
    defer root.deinit(gpa);
    // One session and not two: the resumed run appended to the log it found.
    try testing.expectEqual(@as(usize, 1), root.starts);
    try testing.expectEqual(@as(usize, 2), root.session.children.items.len);

    const first = root.session.children.items[0].budget_max_cost;
    const second = root.session.children.items[1].budget_max_cost;

    // **Four, less the one that was spent, less the one and a half already
    // promised, and one child left to give it to.** A resumed parent that
    // counted only its own spending would have divided three by one and handed
    // out three, and the tree would have been promised five and a half against
    // a cap of four.
    try testing.expectApproxEqAbs(@as(f64, 1.5), second, 0.000001);
    try testing.expect(second < 3.0);
    try testing.expectApproxEqAbs(
        @as(f64, cap.max_cost),
        root.session.spend.amount + first + second,
        0.000001,
    );

    // And the two children really ran under the slices the log records, so the
    // numbers above are what an agent was given and not only what was written.
    for (root.session.children.items) |one| {
        var kid = try tree.fold(gpa, one.session);
        defer kid.deinit(gpa);
        try testing.expect(std.mem.indexOf(u8, kid.answer.items, "budget=1.5USD") != null);
    }
}

test "a parent with nothing left starts no child at all" {
    // The other end of the same arithmetic. A slice of nothing is not a child
    // with no cap: `nothingLeft` is what tells the two apart, and a parent that
    // read them the same way would start a child with no cap on a session that
    // has already spent everything it had.
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

    // The same tree with money left starts the child, so the refusal above is
    // about the spending and not about the script.
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
    // **The one thing in this file that a reader cannot see is wrong.** Every
    // other agent of every tree here chooses its own identifier and the shape of
    // that is the helper's business; the root's is written here by hand.
    // `src/run.zig`'s own walk up the tree refuses an identifier that is not
    // twenty six characters of Crockford base32 before it builds a path from it,
    // and a root the walk refuses would make every promise stop at the level
    // below it with nothing saying so.
    try testing.expectEqual(@as(usize, 26), root_session.len);
    for (root_session) |character| {
        try testing.expect(std.mem.indexOfScalar(
            u8,
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
            character,
        ) != null);
    }
}
