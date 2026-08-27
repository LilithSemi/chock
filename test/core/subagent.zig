//! One subagent, as a real second process, with a log of its own on disk.
//!
//! Everything in `lib/chock-core/subagent.zig`'s own tests is about what a
//! parent reads out of a log; everything in `lib/chock-core/Loop.zig`'s is
//! about the two events a parent writes around a child. **Neither one starts a
//! process**, and a subagent that is not a process is not a subagent: `fork`
//! carries only the calling thread, which is the whole reason a child is a
//! process and not a thread.
//!
//! So this suite drives the boundary itself. The parent side builds the child's
//! argument vector with `chock_core.subagent.commandLine`, the real function
//! `src/run.zig` uses, and starts `test/core/subagent_child.zig` with it. The
//! child writes a real session log through `chock_proto.log.Log`. The parent
//! then reads it with `chock_core.subagent.readReport`, and writes its own log
//! the way `Loop.runSpawn` does.
//!
//! **What each test pins is named in the test.** The four that matter most:
//! a child's turns are in the child's log and not the parent's and both replay
//! independently; a killed child leaves a log its parent reads as `died`; a
//! child cannot hold a permission its parent lacks, through a child that really
//! ran and really asked; and the shape the parent asked for is checked by the
//! parent and never by the child.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const subagent = chock_core.subagent;

// Zig 0.16's test runner panics on an argv it does not recognize, so the
// helper's path cannot come in as an argument. `build.zig` embeds it as a
// build time constant, the same way it does for every other helper program in
// this project.
const child_path = @import("subagent_child_path").subagent_child_path;

const testing = std.testing;

/// Where the child writes its log, named through the environment. See
/// `test/core/subagent_child.zig`: a real child works this out from the
/// project and its own identifier, through `src/session.zig`, which is program
/// code and not library code.
const log_path_variable = "CHOCK_TEST_CHILD_LOG";

/// A project directory, a parent log, and a child log, all in one fresh temp
/// directory.
const Tree = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    parent_log_path: [:0]u8,
    child_log_path: [:0]u8,
    parent_backing: chock_proto.storage.JsonLines,

    const parent_session = "01PARENT" ++ "A" ** 18;

    fn init(gpa: std.mem.Allocator) !Tree {
        var tmp = testing.tmpDir(.{});
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const root = try gpa.dupe(u8, buffer[0..len]);

        const parent_log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/parent.jsonl", .{root}, 0);
        const child_log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/child.jsonl", .{root}, 0);

        return .{
            .tmp = tmp,
            .root = root,
            .parent_log_path = parent_log_path,
            .child_log_path = child_log_path,
            .parent_backing = .{
                .log = try chock_proto.log.Log.open(testing.io, parent_log_path, parent_session),
            },
        };
    }

    fn deinit(self: *Tree, gpa: std.mem.Allocator) void {
        self.parent_backing.log.close(testing.io);
        gpa.free(self.root);
        gpa.free(self.parent_log_path);
        gpa.free(self.child_log_path);
        self.tmp.cleanup();
    }

    /// Write a `chock.zon` into the project the child will read.
    fn writePolicy(self: *Tree, source: []const u8) !void {
        var file = try self.tmp.dir.createFile(testing.io, "chock.zon", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, source);
    }

    fn parentStorage(self: *Tree) chock_proto.storage.Storage {
        return self.parent_backing.storage();
    }

    /// Append one event to the parent's own log, the way the loop does.
    fn parentAppend(self: *Tree, gpa: std.mem.Allocator, one: event.Event) !void {
        const storage = self.parentStorage();
        var locked = try storage.lock(testing.io);
        defer locked.unlock(testing.io) catch {};
        _ = try locked.append(gpa, testing.io, one, 1000);
    }
};

/// Start the child, wait for it, and read its own log the way a parent does.
/// The caller frees the report with `subagent.freeReport`.
///
/// **The argument vector is the real one.** `commandLine` is what `src/run.zig`
/// builds a child's command line with, so a flag it stopped writing, or wrote
/// under another name, fails here rather than in a session nobody is watching.
fn runChild(
    gpa: std.mem.Allocator,
    tree: *Tree,
    request: subagent.Request,
    parent_kind: []const u8,
) !subagent.Report {
    const prepared = try prepareChild(gpa, tree);
    defer subagent.freePrepared(gpa, prepared);
    return startAndRead(gpa, tree, request, prepared, parent_kind);
}

/// The `Prepared` a parent builds before it starts one child. The caller frees
/// it with `subagent.freePrepared`.
fn prepareChild(gpa: std.mem.Allocator, tree: *Tree) !subagent.Prepared {
    return .{
        .child_session = try gpa.dupe(u8, "01CHILD" ++ "A" ** 19),
        .log_path = try gpa.dupe(u8, tree.child_log_path),
        .scratchpad_path = try std.fmt.allocPrint(gpa, "{s}/agents/01CHILD", .{tree.root}),
    };
}

/// Start the child from a `Prepared` the caller already holds, wait for it, and
/// read its own log. Split out of `runChild` so a `subagent.Spawner` can use
/// the same two steps a parent takes.
fn startAndRead(
    gpa: std.mem.Allocator,
    tree: *Tree,
    request: subagent.Request,
    prepared: subagent.Prepared,
    parent_kind: []const u8,
) !subagent.Report {
    // One agent above this child, or none at all when the caller asked for a
    // child at the top of a tree. A longer chain is what `test/core/tree.zig`
    // drives, through agents that really are three levels deep.
    const above = [_]event.SpawnLink{.{ .agent_kind = parent_kind, .reason = request.reason }};
    const argv = try subagent.commandLine(gpa, .{
        // The program that stands in for `chock run`. Everything else on the
        // command line is what a real parent writes.
        .exe_path = child_path,
        .project_root = tree.root,
        .parent_session = Tree.parent_session,
        .parent_chain = if (parent_kind.len == 0) &.{} else &above,
    }, request, prepared);
    defer subagent.freeCommandLine(gpa, argv);

    var env = try std.testing.environ.createMap(gpa);
    defer env.deinit();
    try env.put(log_path_variable, tree.child_log_path);

    var child = try std.process.spawn(testing.io, .{
        .argv = argv,
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .ignore,
        // A child that aborts prints a trace, which is noise the test does not
        // need and which would look like a failure of this suite.
        .stderr = .ignore,
    });
    _ = child.wait(testing.io) catch {};

    var log = try chock_proto.log.Log.open(testing.io, tree.child_log_path, prepared.child_session);
    defer log.close(testing.io);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    return subagent.readReport(gpa, testing.io, backing.storage(), request.shape);
}

/// How many events of `kind` one log holds, and what the last message in it
/// said. Read through a real replay, so a log a replay cannot read fails here.
const Replayed = struct {
    events: usize = 0,
    assistant_turns: usize = 0,
    session_ends: usize = 0,
    parent_session: []u8 = &.{},
    /// Every word of every message, joined, so a test can ask whether one log
    /// holds what another log's turns said.
    text: std.ArrayList(u8) = .empty,

    fn deinit(self: *Replayed, gpa: std.mem.Allocator) void {
        gpa.free(self.parent_session);
        self.text.deinit(gpa);
    }
};

fn replay(
    gpa: std.mem.Allocator,
    storage: chock_proto.storage.Storage,
) !Replayed {
    var out = Replayed{};
    errdefer out.deinit(gpa);

    var stream = try storage.replay(gpa, testing.io, 0);
    defer stream.deinit();
    while (try stream.next(testing.io)) |parsed| {
        defer parsed.deinit();
        out.events += 1;
        switch (parsed.value.event) {
            .session_start => |start| {
                gpa.free(out.parent_session);
                out.parent_session = try gpa.dupe(u8, start.parent_session);
            },
            .session_end => out.session_ends += 1,
            .message => |said| {
                if (said.role == .assistant) out.assistant_turns += 1;
                for (said.content) |part| {
                    if (part == .text) try out.text.appendSlice(gpa, part.text);
                }
            },
            else => {},
        }
    }
    return out;
}

test "a subagent's turns are in the subagent's own log, and both logs replay on their own" {
    // The fact the whole two log design rests on. Each session stays
    // independently replayable, which is what `chockd` serves and what a
    // resume reads, and the tree is rebuilt from the two links: the parent's
    // `session.spawn` names the child, and the child's `session.start` names
    // the parent.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    const request = subagent.Request{
        .agent_kind = "reviewer",
        .task = "FINISH: read the parser and say what it refuses",
        .reason = "review the parser",
    };

    // What the loop writes before the child runs.
    try tree.parentAppend(gpa, .{ .session_spawn = .{
        .child_session = "01CHILD" ++ "A" ** 19,
        .child_agent_kind = request.agent_kind,
        .reason = request.reason,
    } });

    const report = try runChild(gpa, &tree, request, "main");
    defer subagent.freeReport(gpa, report);
    try testing.expectEqual(event.AgentOutcome.finished, report.outcome);
    try testing.expectEqualStrings("the parser refuses an empty file", report.result);

    // And what it writes after.
    try tree.parentAppend(gpa, .{ .agent_complete = .{
        .child_session = "01CHILD" ++ "A" ** 19,
        .child_agent_kind = request.agent_kind,
        .outcome = report.outcome,
        .result = report.result,
        .scratchpad_path = "",
    } });

    var child_log = try chock_proto.log.Log.open(
        testing.io,
        tree.child_log_path,
        "01CHILD" ++ "A" ** 19,
    );
    defer child_log.close(testing.io);
    var child_backing = chock_proto.storage.JsonLines{ .log = child_log };

    var child_side = try replay(gpa, child_backing.storage());
    defer child_side.deinit(gpa);
    var parent_side = try replay(gpa, tree.parentStorage());
    defer parent_side.deinit(gpa);

    // The child took two turns of its own, and its log holds them.
    try testing.expectEqual(@as(usize, 2), child_side.assistant_turns);
    try testing.expect(std.mem.indexOf(u8, child_side.text.items, "reading the parser now") != null);
    // The child's log names its parent, which is one half of the link.
    try testing.expectEqualStrings(Tree.parent_session, child_side.parent_session);

    // **The parent's log holds no turn of the child's.** Not the intermediate
    // one, and not the task the child was given: a parent that folded a
    // child's transcript into its own context would hold both.
    try testing.expectEqual(@as(usize, 0), parent_side.assistant_turns);
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, parent_side.text.items, "reading the parser now"),
    );
    try testing.expectEqual(@as(usize, 2), parent_side.events);

    // Both replay on their own, which is what the counts above already show:
    // each stream was read end to end through the real reader, and neither
    // needed the other to make sense.
    try testing.expect(child_side.events > parent_side.events);
}

test "a killed child leaves a log its parent reads as died, and never as finished" {
    // A child can be killed at any moment, and a log that stops is the only
    // thing left of it. A parent that read a truncated log as a finished child
    // with an empty answer would act on nothing at all.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    const report = try runChild(gpa, &tree, .{
        .agent_kind = "reviewer",
        .task = "DIE: stop partway through",
        .reason = "review the parser",
    }, "main");
    defer subagent.freeReport(gpa, report);

    try testing.expectEqual(event.AgentOutcome.died, report.outcome);
    try testing.expect(std.mem.indexOf(u8, report.result, "session.end") != null);

    // The child really did write turns before it died, and really did not
    // write an ending. So the reading turns on the missing `session.end` and
    // not on an empty log.
    var child_log = try chock_proto.log.Log.open(
        testing.io,
        tree.child_log_path,
        "01CHILD" ++ "A" ** 19,
    );
    defer child_log.close(testing.io);
    var child_backing = chock_proto.storage.JsonLines{ .log = child_log };
    var child_side = try replay(gpa, child_backing.storage());
    defer child_side.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), child_side.assistant_turns);
    try testing.expectEqual(@as(usize, 0), child_side.session_ends);
    try testing.expect(std.mem.indexOf(u8, child_side.text.items, "I read the first file and") != null);
}

test "a real spawned child cannot hold a permission its parent lacks" {
    // Driven through a child that really ran and really asked, rather than
    // through the policy layer alone. The chain the
    // child asks with comes from the command line its parent wrote, and a
    // child writes no command line of its own.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    // The child's own kind is allowed to push. Its parent's kind is not.
    try tree.writePolicy(
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    );

    const under_a_parent = try runChild(gpa, &tree, .{
        .agent_kind = "reviewer",
        .task = "POLICY: say what you may do",
        .reason = "review the parser",
    }, "main");
    defer subagent.freeReport(gpa, under_a_parent);

    try testing.expectEqual(event.AgentOutcome.finished, under_a_parent.outcome);
    // **Both halves in one answer.** Asked about its own kind alone the child
    // is told it may push, and the answer that binds it is the intersection
    // over the chain, which denies it. A test that only read the second number
    // would pass against a table that denied everything.
    try testing.expectEqualStrings("alone=allow chain=deny links=2", under_a_parent.result);
}

test "the same child at the top of a tree keeps what the chain took away" {
    // The other side of the intersection, and what stops the test above from
    // passing for the wrong reason. The kind is the same and the policy file is
    // the same; only the parent link differs.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    try tree.writePolicy(
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    );

    const on_its_own = try runChild(gpa, &tree, .{
        .agent_kind = "reviewer",
        .task = "POLICY: say what you may do",
        .reason = "review the parser",
    }, "");
    defer subagent.freeReport(gpa, on_its_own);

    try testing.expectEqualStrings("alone=allow chain=allow links=1", on_its_own.result);
}

test "the parent checks the shape it asked for, and the child is never asked whether it complied" {
    // The caller chooses prose or a schema, and the caller is what decides
    // whether the answer is one. Two children, the same policy, the same
    // parent: only the shape the parent asked for differs.
    const gpa = testing.allocator;
    const wanted = [_][]const u8{ "verdict", "notes_path" };

    {
        var tree = try Tree.init(gpa);
        defer tree.deinit(gpa);
        const report = try runChild(gpa, &tree, .{
            .agent_kind = "reviewer",
            .task = "SCHEMA: review the parser",
            .reason = "review the parser",
            .shape = .{ .schema = &wanted },
        }, "main");
        defer subagent.freeReport(gpa, report);

        try testing.expectEqual(event.AgentOutcome.finished, report.outcome);
        // The answer comes back as the object the parent named, so the parent
        // parses it rather than reading English to decide.
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, report.result, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings("safe", parsed.value.object.get("verdict").?.string);
    }

    {
        // The same child, answering prose to a spawn that asked for an object.
        // Refused, with no retry, and the near miss still comes back: only the
        // parent can tell whether the question was the wrong one.
        var tree = try Tree.init(gpa);
        defer tree.deinit(gpa);
        const report = try runChild(gpa, &tree, .{
            .agent_kind = "reviewer",
            .task = "WRONG: review the parser",
            .reason = "review the parser",
            .shape = .{ .schema = &wanted },
        }, "main");
        defer subagent.freeReport(gpa, report);

        try testing.expectEqual(event.AgentOutcome.refused, report.outcome);
        try testing.expect(std.mem.indexOf(u8, report.result, "It looks fine to me") != null);
    }

    {
        // And the very same answer, asked for as prose, is a finished child.
        // Nothing about the child changed.
        var tree = try Tree.init(gpa);
        defer tree.deinit(gpa);
        const report = try runChild(gpa, &tree, .{
            .agent_kind = "reviewer",
            .task = "WRONG: review the parser",
            .reason = "review the parser",
        }, "main");
        defer subagent.freeReport(gpa, report);

        try testing.expectEqual(event.AgentOutcome.finished, report.outcome);
        try testing.expectEqualStrings("It looks fine to me, honestly.", report.result);
    }
}

test "everything the parent decided reaches the child, and the child decides none of it" {
    // The command line is the whole of a child's confinement: its kind, its
    // parent's kind, its budget slice, and the directory it may write in. A
    // flag that stopped being written would be a narrowing that quietly went
    // away, and this drives the real builder, not a copy of it.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    const report = try runChild(gpa, &tree, .{
        .agent_kind = "reviewer",
        .task = "FINISH: read the parser",
        .reason = "review the parser",
        .budget = .{ .max_cost = 1.25, .currency = "USD" },
    }, "main");
    defer subagent.freeReport(gpa, report);

    // The child read its own kind and its parent's off the command line and
    // wrote them into its log. A child that had been given neither could not
    // have written either.
    var child_log = try chock_proto.log.Log.open(
        testing.io,
        tree.child_log_path,
        "01CHILD" ++ "A" ** 19,
    );
    defer child_log.close(testing.io);
    var child_backing = chock_proto.storage.JsonLines{ .log = child_log };

    var stream = try child_backing.storage().replay(gpa, testing.io, 0);
    defer stream.deinit();
    var saw_start = false;
    while (try stream.next(testing.io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_start) continue;
        saw_start = true;
        try testing.expectEqualStrings("reviewer", parsed.value.event.session_start.agent_kind);
        try testing.expectEqualStrings(
            Tree.parent_session,
            parsed.value.event.session_start.parent_session,
        );
    }
    try testing.expect(saw_start);
}

/// A `subagent.Spawner` that starts the real helper process, so a test of
/// `subagent.Table` drives a child and not a double. The same two steps a
/// parent takes, split the way the seam splits them.
const RealSpawner = struct {
    tree: *Tree,
    parent_kind: []const u8 = "main",

    fn spawner(self: *RealSpawner) subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn prepareFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
    ) subagent.Error!subagent.Prepared {
        _ = io;
        _ = request;
        const self: *RealSpawner = @ptrCast(@alignCast(ptr));
        return prepareChild(gpa, self.tree) catch return error.ChildNotStarted;
    }

    fn runFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
        prepared: subagent.Prepared,
    ) subagent.Error!subagent.Report {
        _ = io;
        const self: *RealSpawner = @ptrCast(@alignCast(ptr));
        return startAndRead(gpa, self.tree, request, prepared, self.parent_kind) catch
            return error.ChildNotStarted;
    }
};

test "a real child runs while its parent works, and the parent records it afterwards" {
    // **The fact that makes a tree worth more than a sequence.** Everything
    // else in this file waits for its child, which is a parent that could just
    // as well have done the work itself. Here the parent starts a real second
    // process through `subagent.Table` and carries straight on.
    //
    // **The child is what proves the two ran side by side**, and no clock is
    // involved. A `WAIT` child does not end until the parent puts a file in the
    // project, and the parent puts it there only after it has written its own
    // work into its own log. A parent that had been blocked inside `start`
    // could never reach that line, so this test can only finish if the child
    // really was running while the parent worked.
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    var real = RealSpawner{ .tree = &tree };
    var table = subagent.Table{ .gpa = gpa, .spawner = real.spawner() };
    defer table.deinit();

    const request = subagent.Request{
        .agent_kind = "reviewer",
        .task = "WAIT: read the parser while I read the tests",
        .reason = "review the parser",
    };

    // The parent prepares the child and records the spawn before anything
    // starts, which is the order `Loop.runSpawn` keeps.
    const prepared = try real.spawner().prepare(gpa, testing.io, request);
    defer subagent.freePrepared(gpa, prepared);
    try tree.parentAppend(gpa, .{ .session_spawn = .{
        .child_session = prepared.child_session,
        .child_agent_kind = request.agent_kind,
        .reason = request.reason,
        .budget_max_cost = 0,
        .budget_currency = "",
    } });

    try table.start(testing.io, request, prepared);

    // **The parent's own work, while the child is still running.** Two events
    // of the parent's own, in the parent's own log, between the spawn and
    // anything the child produced.
    try tree.parentAppend(gpa, .{ .tool_call = .{
        .call_id = "own-work",
        .tool = "read_file",
        .arguments = "{\"path\":\"tests.zig\"}",
    } });
    try tree.parentAppend(gpa, .{ .tool_result = .{
        .call_id = "own-work",
        .output = "the tests read the parser",
        .is_error = false,
        .truncated = false,
    } });

    // Only now may the child end. Reaching this line at all is the proof.
    {
        var file = try tree.tmp.dir.createFile(testing.io, "go", .{});
        file.close(testing.io);
    }

    table.waitAll();
    const finished = try table.take(gpa);
    defer subagent.freeCompletions(gpa, finished);
    try testing.expectEqual(@as(usize, 1), finished.len);
    try testing.expectEqual(event.AgentOutcome.finished, finished[0].outcome);
    try testing.expectEqualStrings(
        "my parent got on with its own work while I ran",
        finished[0].result,
    );

    // **The parent appends the completion, because the child cannot write the
    // parent's log.** The child wrote its own, and this is the parent's.
    try tree.parentAppend(gpa, .{ .agent_complete = .{
        .child_session = finished[0].child_session,
        .child_agent_kind = finished[0].agent_kind,
        .outcome = finished[0].outcome,
        .result = finished[0].result,
        .scratchpad_path = finished[0].scratchpad_path,
    } });

    // The order in the parent's own log: asked for, then a piece of the
    // parent's own work done and read, then told.
    var spawn_at: ?usize = null;
    var call_at: ?usize = null;
    var result_at: ?usize = null;
    var complete_at: ?usize = null;
    var index: usize = 0;
    var stream = try tree.parentStorage().replay(gpa, testing.io, 0);
    defer stream.deinit();
    while (try stream.next(testing.io)) |parsed| : (index += 1) {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_spawn => spawn_at = index,
            .tool_call => call_at = index,
            .tool_result => result_at = index,
            .agent_complete => complete_at = index,
            else => {},
        }
    }
    try testing.expect(spawn_at != null and call_at != null);
    try testing.expect(result_at != null and complete_at != null);
    try testing.expect(spawn_at.? < call_at.?);
    try testing.expect(call_at.? < result_at.?);
    try testing.expect(result_at.? < complete_at.?);

    // And the child's turns are in the child's own log, not in this one: the
    // rule the two log design rests on, and a table that ran the child changes
    // nothing about it.
    var parent_read = try replay(gpa, tree.parentStorage());
    defer parent_read.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, parent_read.text.items, "I am working while my parent works") == null);
}
