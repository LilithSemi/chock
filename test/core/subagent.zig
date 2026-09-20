//! One subagent, as a real second process, with a log of its own on disk.
//! `fork` carries only the calling thread, so a subagent is a process and not a
//! thread, and nothing above this file starts one.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const subagent = chock_core.subagent;

// Zig 0.16's test runner panics on argv it does not know, so build.zig embeds
// the helper path at build time.
const child_path = @import("subagent_child_path").subagent_child_path;

const testing = std.testing;

/// A real child works its log path out through `src/session.zig`, which is
/// program code and not library code, so the helper is told through the
/// environment instead.
const log_path_variable = "CHOCK_TEST_CHILD_LOG";

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

    fn writePolicy(self: *Tree, source: []const u8) !void {
        var file = try self.tmp.dir.createFile(testing.io, "chock.zon", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, source);
    }

    fn parentStorage(self: *Tree) chock_proto.storage.Storage {
        return self.parent_backing.storage();
    }

    fn parentAppend(self: *Tree, gpa: std.mem.Allocator, one: event.Event) !void {
        const storage = self.parentStorage();
        var locked = try storage.lock(testing.io);
        defer locked.unlock(testing.io) catch {};
        _ = try locked.append(gpa, testing.io, one, 1000);
    }
};

/// The caller frees the report with `subagent.freeReport`.
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

/// The caller frees the result with `subagent.freePrepared`.
fn prepareChild(gpa: std.mem.Allocator, tree: *Tree) !subagent.Prepared {
    return .{
        .child_session = try gpa.dupe(u8, "01CHILD" ++ "A" ** 19),
        .log_path = try gpa.dupe(u8, tree.child_log_path),
        .scratchpad_path = try std.fmt.allocPrint(gpa, "{s}/agents/01CHILD", .{tree.root}),
    };
}

fn startAndRead(
    gpa: std.mem.Allocator,
    tree: *Tree,
    request: subagent.Request,
    prepared: subagent.Prepared,
    parent_kind: []const u8,
) !subagent.Report {
    // One agent above, or none when the caller asked for a child at the top of
    // a tree. `test/core/tree.zig` drives a longer chain.
    const above = [_]event.SpawnLink{.{ .agent_kind = parent_kind, .reason = request.reason }};
    const argv = try subagent.commandLine(gpa, .{
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
        // A child that aborts prints a trace, which would read as a failure of
        // this suite.
        .stderr = .ignore,
    });
    _ = child.wait(testing.io) catch {};

    var log = try chock_proto.log.Log.open(testing.io, tree.child_log_path, prepared.child_session);
    defer log.close(testing.io);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    return subagent.readReport(gpa, testing.io, backing.storage(), request.shape);
}

/// Read through a real replay, so a log a replay cannot read fails here.
const Replayed = struct {
    events: usize = 0,
    assistant_turns: usize = 0,
    session_ends: usize = 0,
    parent_session: []u8 = &.{},
    /// Every message joined, so one log can be asked what another log said.
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
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    const request = subagent.Request{
        .agent_kind = "reviewer",
        .task = "FINISH: read the parser and say what it refuses",
        .reason = "review the parser",
    };

    try tree.parentAppend(gpa, .{ .session_spawn = .{
        .child_session = "01CHILD" ++ "A" ** 19,
        .child_agent_kind = request.agent_kind,
        .reason = request.reason,
    } });

    const report = try runChild(gpa, &tree, request, "main");
    defer subagent.freeReport(gpa, report);
    try testing.expectEqual(event.AgentOutcome.finished, report.outcome);
    try testing.expectEqualStrings("the parser refuses an empty file", report.result);

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

    try testing.expectEqual(@as(usize, 2), child_side.assistant_turns);
    try testing.expect(std.mem.indexOf(u8, child_side.text.items, "reading the parser now") != null);
    try testing.expectEqualStrings(Tree.parent_session, child_side.parent_session);

    try testing.expectEqual(@as(usize, 0), parent_side.assistant_turns);
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, parent_side.text.items, "reading the parser now"),
    );
    try testing.expectEqual(@as(usize, 2), parent_side.events);

    try testing.expect(child_side.events > parent_side.events);
}

test "a killed child leaves a log its parent reads as died, and never as finished" {
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

    // The reading turns on the missing `session.end` and not on an empty log.
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
    const gpa = testing.allocator;
    var tree = try Tree.init(gpa);
    defer tree.deinit(gpa);

    // The child's own kind may push. Its parent's kind may not.
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
    try testing.expectEqualStrings("alone=allow chain=deny links=2", under_a_parent.result);
}

test "the same child at the top of a tree keeps what the chain took away" {
    // Same kind and same policy file. Only the parent link differs.
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
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, report.result, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings("safe", parsed.value.object.get("verdict").?.string);
    }

    {
        // Prose against a spawn that asked for an object. The near miss still
        // comes back, so the parent can tell the question was wrong.
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

/// A `subagent.Spawner` that starts the real helper process.
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
    // No clock is involved. A `WAIT` child does not end until the parent puts
    // a file in the project, and the parent does that only after it writes its
    // own work, so a parent blocked inside `start` never reaches that line.
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

    // Only now may the child end.
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

    try tree.parentAppend(gpa, .{ .agent_complete = .{
        .child_session = finished[0].child_session,
        .child_agent_kind = finished[0].agent_kind,
        .outcome = finished[0].outcome,
        .result = finished[0].result,
        .scratchpad_path = finished[0].scratchpad_path,
    } });

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

    var parent_read = try replay(gpa, tree.parentStorage());
    defer parent_read.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, parent_read.text.items, "I am working while my parent works") == null);
}
