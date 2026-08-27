//! A real subagent, as far as its parent can tell: a second process that reads
//! the command line its parent wrote, keeps a session log of its own, and ends
//! in whichever of the ways a session can end that the test asked for.
//!
//! **This is not `chock run`, and it is deliberately not.** A real child needs
//! a model, a credential, a workspace and a sandbox, and none of those is the
//! thing under test here. What is under test is the boundary between a parent
//! and a child: **what the parent puts on the command line, what the child can
//! do with it, and what the parent can read back out of the child's own log.**
//! Everything on this side of that boundary is real: a real process, a real
//! argument vector built by `chock_core.subagent.commandLine`, a real log
//! written through `chock_proto.log.Log`, and a real policy table read off
//! disk.
//!
//! The mode is the first word of the task, because the task is what the parent
//! writes and this program is standing in for the model that would read it:
//!
//! * `FINISH` writes two turns and ends `finished`.
//! * `SCHEMA` answers with the JSON object the task asked for.
//! * `WRONG` answers with prose when the task asked for JSON.
//! * `POLICY` writes down what the policy table answers for its own kind alone
//!   and for the whole chain its parent gave it, then ends `finished`. That is
//!   the child half of "a child cannot hold a permission its parent lacks".
//! * `DIE` writes one turn and is killed where it stands, leaving a log with no
//!   `session.end`.
//! * `WAIT` does not end until its parent puts a file in the project called
//!   `go`, and then ends `finished`. That is the child half of "the parent
//!   worked while the child ran": a parent that was blocked on this child could
//!   never make the file, so the test can only finish if the two really ran side
//!   by side. **A handshake and never a pause**: nothing here waits for a
//!   length of time, and the bound below is a count.
//!
//! Where the log goes comes from the environment and not from the command line,
//! because a real child works that out from the project and the session
//! identifier through `src/session.zig`, which is program code and not library
//! code. Everything a parent decides still arrives the way a parent sends it.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const flag = chock_core.subagent.flag;

/// Where this child writes its log. Named by the test, not by the parent: see
/// this file's own top comment.
const log_path_variable = "CHOCK_TEST_CHILD_LOG";

/// The action the `POLICY` mode asks the table about. Any action does; this one
/// is what a subagent most obviously must not hold when its parent does not.
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
    // The task is the last argument, after `--`, which is where `chock run`
    // reads a session's first message from.
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
            // The child's own half of the two way link.
            .parent_session = parent_session,
        },
    });

    // The task, as the child's first message, exactly as a real session
    // records the message it was started with.
    try writer.say(.user, task);

    if (std.mem.startsWith(u8, task, "DIE")) {
        try writer.say(.assistant, "I read the first file and");
        // Killed where it stands, so the log really does stop mid session.
        // A clean exit would leave the same log, and this is the case a parent
        // has to read right: a child that was killed, not one that chose to
        // stop.
        std.process.abort();
    }

    if (std.mem.startsWith(u8, task, "WAIT")) {
        try writer.say(.assistant, "I am working while my parent works");
        // **The two answers differ, and that is the whole point.** A parent
        // that was blocked on this child could never make the file, so it gives
        // up and says so, and the test waiting on it fails on the words rather
        // than passing on a child that only looked as though it had run beside
        // its parent.
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
        // The parent asked for one JSON object, and the requirement is in the
        // task this child was given. It answers with one.
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

    // FINISH, and anything else. Two turns of its own, so a parent that took a
    // child's transcript into its own log would have something to take.
    try writer.say(.assistant, "reading the parser now");
    try writer.say(.assistant, "the parser refuses an empty file");
    try writer.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });
    return 0;
}

/// The name of the file the parent makes to let a `WAIT` child end.
const go_leaf = "go";

/// How many times a `WAIT` child looks for the file before it gives up and ends
/// anyway.
///
/// **A count of tries and never a length of time**, so a busier machine does
/// not change what this reaches. It is a release valve: a healthy run finds the
/// file after a handful of tries, and a parent that never makes it fails the
/// test that is waiting rather than hanging it.
const go_tries: usize = 200_000;

/// Do not come back until the parent has made the file, which it can only do
/// while this process is still running. True when the file appeared, false when
/// this gave up on it. See this file's own top comment on `WAIT`.
fn waitForGo(io: std.Io, project: []const u8) bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buffer, "{s}/{s}", .{ project, go_leaf }) catch return false;
    var tries: usize = 0;
    while (tries < go_tries) : (tries += 1) {
        var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch {
            // Give the processor to whatever is doing the real work rather
            // than spinning on it.
            std.Thread.yield() catch std.atomic.spinLoopHint();
            continue;
        };
        file.close(io);
        return true;
    }
    return false;
}

/// What the policy table answers for this child's own kind alone, and for the
/// whole chain its parent gave it. Both, in one line, so a test can show that
/// the two differ.
///
/// **The chain comes from the command line and from nowhere else.** This
/// process could ask the table whatever it liked about its own kind, and the
/// answer that binds it is the intersection over every kind above it, which
/// only its parent can state.
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

/// Appends to the child's own log, taking the lock for each append the way any
/// writer of a session log does.
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
