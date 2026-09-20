//! A stand-in subagent process. Not `chock run`: only the parent and child
//! boundary is real here, which is the command line, the child's own log, and
//! the policy table. The first word of the task picks the mode.
//!
//! * `FINISH` writes two turns and ends `finished`.
//! * `SCHEMA` answers with the JSON object the task asked for.
//! * `WRONG` answers with prose when the task asked for JSON.
//! * `POLICY` writes what the table answers for its own kind and for the chain.
//! * `DIE` writes one turn and aborts, leaving a log with no `session.end`.
//! * `WAIT` ends only after its parent puts a file called `go` in the project.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const flag = chock_core.subagent.flag;

/// Where this child writes its log. Named by the test, not by the parent.
const log_path_variable = "CHOCK_TEST_CHILD_LOG";

const asked_action = "git.push";

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(arena, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    const args = try init.args.toSlice(arena);
    const env = try init.environ.createMap(arena);

    const log_path = env.get(log_path_variable) orelse {
        std.debug.print("subagent_child: {s} names no path\n", .{log_path_variable});
        return 2;
    };

    const session = valueOf(args, flag.session) orelse {
        std.debug.print("subagent_child: the parent named no session\n", .{});
        return 2;
    };
    const agent_kind = valueOf(args, flag.agent_kind) orelse "";
    const parent_session = valueOf(args, flag.parent_session) orelse "";
    const parent_kind = valueOf(args, flag.parent_kind) orelse "";
    const project = valueOf(args, flag.project) orelse "";
    const task = args[args.len - 1];

    const path = try arena.dupeZ(u8, log_path);
    var log = try chock_proto.log.Log.open(io, path, session);
    defer log.close(io);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const storage = backing.storage();

    var writer = Writer{ .arena = arena, .io = io, .storage = storage };
    try writer.append(.{
        .session_start = .{
            .agent_kind = agent_kind,
            .model_alias = "test",
            .parent_session = parent_session,
        },
    });

    try writer.say(.user, task);

    if (std.mem.startsWith(u8, task, "DIE")) {
        try writer.say(.assistant, "I read the first file and");
        std.process.abort();
    }

    if (std.mem.startsWith(u8, task, "WAIT")) {
        try writer.say(.assistant, "I am working while my parent works");
        // The two answers differ, so a blocked parent fails the test on the words.
        try writer.say(.assistant, if (waitForGo(io, project))
            "my parent got on with its own work while I ran"
        else
            "my parent never got to its own work, so it was waiting for me");
        try writer.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });
        return 0;
    }

    if (std.mem.startsWith(u8, task, "POLICY")) {
        try writer.say(.assistant, try policyAnswer(arena, io, project, parent_kind, agent_kind));
        try writer.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });
        return 0;
    }

    if (std.mem.startsWith(u8, task, "SCHEMA")) {
        try writer.say(.assistant, "first I will read the parser");
        try writer.say(
            .assistant,
            "{\"verdict\":\"safe\",\"notes_path\":\"/run/chock/scratch/notes.md\"}",
        );
        try writer.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });
        return 0;
    }

    if (std.mem.startsWith(u8, task, "WRONG")) {
        try writer.say(.assistant, "It looks fine to me, honestly.");
        try writer.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });
        return 0;
    }

    try writer.say(.assistant, "reading the parser now");
    try writer.say(.assistant, "the parser refuses an empty file");
    try writer.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });
    return 0;
}

const go_leaf = "go";

/// A count of tries and never a length of time.
const go_tries: usize = 200_000;

/// True when the file appeared, false when this gave up on it.
fn waitForGo(io: std.Io, project: []const u8) bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buffer, "{s}/{s}", .{ project, go_leaf }) catch return false;
    var tries: usize = 0;
    while (tries < go_tries) : (tries += 1) {
        var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch {
            std.Thread.yield() catch std.atomic.spinLoopHint();
            continue;
        };
        file.close(io);
        return true;
    }
    return false;
}

/// The chain comes from the command line and from nowhere else. The answer that
/// binds this process is the intersection over every kind above it.
fn policyAnswer(
    arena: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    parent_kind: []const u8,
    agent_kind: []const u8,
) ![]const u8 {
    const table = chock_policy.table.Table.load(arena, io, project, null) catch |err| {
        return std.fmt.allocPrint(arena, "the policy could not be read: {t}", .{err});
    };
    defer chock_policy.table.Table.destroy(arena, table);

    const key = chock_policy.table.Key{
        .agent_kind = agent_kind,
        .model = "test-model",
        .tool = "request_action",
        .action = asked_action,
    };

    const alone = table.evaluateKindAlone(key);

    var chain: std.ArrayList([]const u8) = .empty;
    if (parent_kind.len != 0) try chain.append(arena, parent_kind);
    try chain.append(arena, agent_kind);
    const together = table.evaluateChain(chain.items, key, null);

    return std.fmt.allocPrint(
        arena,
        "alone={s} chain={s} links={d}",
        .{ @tagName(alone), @tagName(together), chain.items.len },
    );
}

const Writer = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,

    fn append(self: *Writer, one: event.Event) !void {
        var locked = try self.storage.lock(self.io);
        defer locked.unlock(self.io) catch {};
        _ = try locked.append(
            self.arena,
            self.io,
            one,
            std.Io.Timestamp.now(self.io, .real).toMilliseconds(),
        );
    }

    fn say(self: *Writer, role: event.Role, text: []const u8) !void {
        const content = [_]event.ContentPart{.{ .text = text }};
        try self.append(.{ .message = .{ .role = role, .content = &content } });
    }
};

fn valueOf(args: []const []const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |one, index| {
        if (std.mem.eql(u8, one, name) and index + 1 < args.len) return args[index + 1];
    }
    return null;
}
