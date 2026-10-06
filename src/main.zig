//! The `chock` program: CLI dispatcher over pre-built libraries.

const std = @import("std");
const builtin = @import("builtin");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const plugin_host_cmd = @import("plugin-host.zig");
const run_cmd = @import("run.zig");
const login_cmd = @import("login.zig");
const daemon_cmd = @import("daemon.zig");
const acp_cmd = @import("acp.zig");
const serve_cmd = @import("serve.zig");
const detach_cmd = @import("detach.zig");
const memory_cmd = @import("memory.zig");
const cache_cmd = @import("cache.zig");
const workspace_cmd = @import("workspace.zig");
const usage_cmd = @import("usage.zig");
const plan_cmd = @import("plan.zig");
const sessions_cmd = @import("sessions.zig");
const migrate_cmd = @import("migrate.zig");
const approve_cmd = @import("approve.zig");
const doctor_cmd = @import("doctor.zig");
const askpass_cmd = @import("askpass.zig");
const guest_cmd = @import("guest.zig");
const tty = @import("tty.zig");
const ui = @import("ui.zig");

pub const session = @import("session.zig");

pub const daemon = @import("daemon.zig");

pub const std_options: std.Options = .{ .logFn = ui.logMessage };

pub const version = @import("chock-version").text;

pub const version_line = versionLine(version);

fn versionLine(comptime text: []const u8) []const u8 {
    return "chock " ++ text;
}

pub const Exit = enum(u8) {
    finished = 0,
    usage = 1,
    faulted = 2,
    refused = 3,
    turn_limit = 4,
    not_implemented = 5,
    no_progress = 6,
    budget = 7,
    handed_over = 8,
    audit_gap = 9,
    empty_response = 10,
    model_refused = 11,
    rate_limited = 12,

    pub fn code(self: Exit) u8 {
        return @intFromEnum(self);
    }
};

pub fn exitFor(reason: chock_proto.event.SessionEndReason) Exit {
    return switch (reason) {
        .finished => .finished,
        .canceled_by_user => .refused,
        .budget_reached => .budget,
        .no_progress => .no_progress,
        .turn_limit => .turn_limit,
        .errored => .faulted,
        .handed_over => .handed_over,
        .empty_response => .empty_response,
        .refused_by_model => .model_refused,
        .rate_limited => .rate_limited,
        // A reason a newer Chock wrote and this one does not know. Treated as
        // a fault, never as finished: an absent answer is never permissive.
        .unknown => .faulted,
    };
}

pub fn printUsage(stream: tty.Stream) void {
    tty.say(stream, .plain,
        \\{s}: a sandbox first AI coding harness
        \\
        \\Usage: chock <command> [options]
        \\       chock [options] -- <the task, in words>
        \\
        \\A first word is a command name, so a task goes after `--`. A task also comes
        \\from standard input: `echo "fix the parser" | chock`. Bare `chock` with no
        \\task at all brings the interface up on a terminal that can draw it.
        \\
        \\Commands:
        \\
    , .{version_line});
    for (commands) |entry| {
        tty.say(stream, .plain, "  {s: <9}  {s}{s}\n", .{
            entry.name,
            entry.summary,
            if (entry.run == null) "  (not implemented yet)" else "",
        });
    }
    tty.say(stream, .plain, "\nEvery command also takes:\n\n{s}", .{tty.options_text});
    tty.say(stream, .plain, "\nRun `chock <command> --help` for what one command takes.\n", .{});
}

fn setUpOutput(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    args: []const []const u8,
) !?[]const []const u8 {
    const taken = tty.takeGlobalFlags(arena, args) catch |err| switch (err) {
        // Already reported by takeGlobalFlags, which names the bad value.
        error.BadColorValue => return null,
        else => |e| return e,
    };

    tty.configure(.{
        .choice = taken.choice,
        .verbose = taken.verbose,
        .stdout_is_tty = std.Io.File.stdout().isTty(io) catch false,
        .stderr_is_tty = std.Io.File.stderr().isTty(io) catch false,
        .no_color = env.get("NO_COLOR"),
        .clicolor_force = env.get("CLICOLOR_FORCE"),
        .term = env.get("TERM"),
    });
    return taken.args;
}

pub const Run = *const fn (
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8;

pub const Command = struct {
    name: []const u8,
    summary: []const u8,
    run: ?Run = null,
    why: []const u8 = "",
    landed: ?*const fn () bool = null,
};

pub const commands = [_]Command{
    .{
        .name = "run",
        .summary = "Run one agent session in the current project.",
        .run = run_cmd.main,
    },
    .{
        .name = "login",
        .summary = "Store a credential for a provider instance.",
        .run = login_cmd.main,
    },
    .{
        .name = "daemon",
        .summary = "Own sessions, and answer every client that asks about one.",
        .run = daemon_cmd.main,
    },
    .{
        .name = "serve",
        .summary = "Put a browser in front of a daemon. Owns no session itself.",
        .run = serve_cmd.main,
    },
    .{
        .name = "acp",
        .summary = "Speak the agent client protocol, so an editor can drive Chock.",
        .run = acp_cmd.main,
    },
    .{
        .name = "memory",
        .summary = "Read or clear the notes agents wrote about this project.",
        .run = memory_cmd.main,
    },
    .{
        .name = "cache",
        .summary = "Show or empty the toolchain cache this project's tool calls write.",
        .run = cache_cmd.main,
    },
    .{
        .name = "workspace",
        .summary = "Show or remove the workspaces sessions that ended badly left behind.",
        .run = workspace_cmd.main,
    },
    .{
        .name = "usage",
        .summary = "Show what this project's sessions cost.",
        .run = usage_cmd.main,
    },
    .{
        .name = "plan",
        .summary = "Show the task list an agent kept while it worked.",
        .run = plan_cmd.main,
    },
    .{
        .name = "sessions",
        .summary = "List this project's sessions, say which are running, and remove one.",
        .run = sessions_cmd.main,
    },
    .{
        .name = "doctor",
        .summary = "Say whether this machine can contain a session, before one starts.",
        .run = doctor_cmd.main,
    },
    .{
        .name = "migrate",
        .summary = "Read another AI coding harness's configuration and write a chock.zon for it.",
        .run = migrate_cmd.main,
    },
    .{
        .name = "approve",
        .summary = "Answer the questions a running session asks.",
        .run = approve_cmd.main,
    },
    .{
        .name = "detach",
        .summary = "Hand a session to the daemon, which becomes its owner.",
        .run = detach_cmd.main,
    },
    .{
        .name = "askpass",
        .summary = "Answer a password prompt from git or ssh.",
        .run = askpass_cmd.main,
    },
    .{
        .name = "guest",
        .summary = "Sandbox tool calls inside a microVM. Started by a guest's own init.",
        .run = guest_cmd.main,
    },
};

comptime {
    for (commands) |entry| {
        if (entry.run != null) continue;
        const landed = entry.landed orelse @compileError("chock " ++ entry.name ++
            " is not built and names nothing to check its reason against. Give it a `landed`.");
        if (landed()) @compileError("chock " ++ entry.name ++ " still answers \"not implemented yet\", " ++
            "and the thing its `why` says it is waiting on has landed. Build the command, " ++
            "or write a reason that is still true.");
    }
}

const stdout_buffer_size = 8 * 1024;

const plugin_host_verb = chock_core.plugin_host.verb;

comptime {
    for (commands) |entry| {
        if (std.mem.eql(u8, entry.name, plugin_host_verb)) @compileError("chock " ++
            entry.name ++ " is both a command in the table and the hidden plugin host verb, " ++
            "so the command could never run. Rename the command.");
    }
}

comptime {
    var found = false;
    for (commands) |entry| {
        if (std.mem.eql(u8, entry.name, chock_broker.askpass.link_name)) found = true;
    }
    if (!found) @compileError("the askpass link is named " ++ chock_broker.askpass.link_name ++
        ", and no command in the table has that name, so the link would reach nothing.");
}

const own_words = [_][]const u8{ "--help", "-h", "help", "--version", "version" };

fn namesNoCommand(first: []const u8) bool {
    if (first.len == 0 or first[0] != '-') return false;
    for (own_words) |one| {
        if (std.mem.eql(u8, first, one)) return false;
    }
    return true;
}

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();

    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = switch (builtin.mode) {
        .Debug, .ReleaseSafe => debug_allocator.allocator(),
        .ReleaseFast, .ReleaseSmall => std.heap.smp_allocator,
    };

    const args = try init.minimal.args.toSlice(arena);

    // Answered before the buffered writer below exists: a plugin host writes
    // its own wire on standard output, and a second writer on that
    // descriptor would corrupt it.
    if (args.len >= 2 and std.mem.eql(u8, args[1], plugin_host_verb)) {
        return plugin_host_cmd.main(arena, gpa, init.io, args[2..]);
    }

    var stdout_buffer: [stdout_buffer_size]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &stdout_buffer);
    var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
    tty.useStreams(init.io, &stdout.interface, &stderr.interface);
    defer tty.flushOut();

    if (std.mem.eql(u8, std.fs.path.basename(args[0]), chock_broker.askpass.link_name)) {
        return askpass_cmd.main(arena, gpa, init.minimal.environ, args[0], args[1..]);
    }

    if (args.len < 2 or namesNoCommand(args[1])) {
        const rest = (try setUpOutput(arena, init.io, init.environ_map, args[1..])) orelse
            return Exit.usage.code();
        return ui.start(arena, gpa, init.io, init.minimal.environ, init.environ_map, args[0], rest);
    }

    const command = args[1];
    const rest = (try setUpOutput(arena, init.io, init.environ_map, args[2..])) orelse
        return Exit.usage.code();

    if (std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h") or
        std.mem.eql(u8, command, "help"))
    {
        printUsage(.out);
        return Exit.finished.code();
    }

    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "version")) {
        tty.out(.plain, "{s}\n", .{version_line});
        return Exit.finished.code();
    }

    for (commands) |entry| {
        if (!std.mem.eql(u8, command, entry.name)) continue;
        if (entry.run) |go| return go(arena, gpa, init.minimal.environ, args[0], rest);
        tty.print(.err, "chock {s}: not implemented yet, because {s}\n", .{ entry.name, entry.why });
        return Exit.not_implemented.code();
    }

    tty.print(.err, "chock: there is no command named \"{s}\"\n", .{command});
    tty.print(.err, "chock: to run it as a task instead, write `chock -- {s}`\n\n", .{
        try std.mem.join(arena, " ", args[1..]),
    });
    printUsage(.err);
    return Exit.usage.code();
}

const testing = std.testing;

test "the version line carries whatever number it is given" {
    try testing.expectEqualStrings("chock 0.1.0", versionLine("0.1.0"));
    try testing.expectEqualStrings("chock 1.0.0-rc.1", versionLine("1.0.0-rc.1"));
    try testing.expectEqualStrings("chock 0.0.0-0123456", versionLine("0.0.0-0123456"));
}

test "the exit code for a refused session says refused, and never says fault" {
    try testing.expectEqual(Exit.refused, exitFor(.canceled_by_user));
    try testing.expect(exitFor(.canceled_by_user) != .faulted);
    try testing.expect(exitFor(.canceled_by_user) != .finished);
}

test "each session end reason gets its own exit code, and none of them is zero except finished" {
    try testing.expectEqual(Exit.finished, exitFor(.finished));
    try testing.expectEqual(Exit.faulted, exitFor(.errored));
    try testing.expectEqual(Exit.faulted, exitFor(.{ .unknown = "some-newer-reason" }));

    const not_finished = [_]chock_proto.event.SessionEndReason{
        .canceled_by_user,
        .errored,
        .budget_reached,
        .no_progress,
        .turn_limit,
        .handed_over,
        .empty_response,
        .refused_by_model,
        .{ .unknown = "some-newer-reason" },
    };
    for (not_finished) |reason| {
        try testing.expect(exitFor(reason).code() != 0);
    }
}

test "a model backend refusal is neither a fault nor a person saying no" {
    const declined = exitFor(.refused_by_model);
    try testing.expectEqual(Exit.model_refused, declined);
    try testing.expect(declined != Exit.faulted);
    try testing.expect(declined != Exit.refused);
    try testing.expect(declined != Exit.finished);
    try testing.expect(declined != Exit.empty_response);
    try testing.expect(declined.code() != 0);
}

test "the agent giving up, running out of money, and crashing are three different exit codes" {
    const gave_up = exitFor(.no_progress);
    const out_of_money = exitFor(.budget_reached);
    const crashed = exitFor(.errored);
    const stopped_at_a_count = exitFor(.turn_limit);

    try testing.expectEqual(Exit.no_progress, gave_up);
    try testing.expectEqual(Exit.budget, out_of_money);
    try testing.expectEqual(Exit.faulted, crashed);
    try testing.expectEqual(Exit.turn_limit, stopped_at_a_count);

    const codes = [_]u8{ gave_up.code(), out_of_money.code(), crashed.code(), stopped_at_a_count.code() };
    for (codes, 0..) |code, index| {
        for (codes[index + 1 ..]) |other| try testing.expect(code != other);
    }
}

test "every session end reason has an exit code, so a new one cannot be forgotten" {
    const named = [_]chock_proto.event.SessionEndReason{
        .finished,
        .canceled_by_user,
        .errored,
        .budget_reached,
        .no_progress,
        .turn_limit,
        .handed_over,
        .empty_response,
        .refused_by_model,
        .rate_limited,
        .{ .unknown = "" },
    };
    try testing.expectEqual(
        @typeInfo(chock_proto.event.SessionEndReason).@"union".fields.len,
        named.len,
    );
    for (named) |reason| _ = exitFor(reason);
}

test "no two exit codes are the same, so a script can tell every outcome apart" {
    var seen = std.EnumSet(Exit).initEmpty();
    const field_count = @typeInfo(Exit).@"enum".fields.len;
    var codes: [field_count]u8 = undefined;
    var count: usize = 0;
    inline for (@typeInfo(Exit).@"enum".fields) |field| {
        const value: Exit = @enumFromInt(field.value);
        try testing.expect(!seen.contains(value));
        seen.insert(value);
        for (codes[0..count]) |code| try testing.expect(code != value.code());
        codes[count] = value.code();
        count += 1;
    }
    try testing.expectEqual(@as(usize, 13), count);
}

test {
    testing.refAllDecls(@This());
}

test "every command is either built or says why it is not, and never both" {
    for (commands) |entry| {
        try testing.expect(entry.name.len != 0);
        try testing.expect(entry.summary.len != 0);
        if (entry.run == null) {
            try testing.expect(entry.why.len != 0);
            try testing.expect(entry.landed != null);
            try testing.expect(!entry.landed.?());
        } else {
            try testing.expectEqualStrings("", entry.why);
            try testing.expect(entry.landed == null);
        }
    }
}

test "a command that is not built exits non zero, so a script never reads success for work nobody did" {
    try testing.expect(Exit.not_implemented.code() != 0);

    for (commands) |entry| {
        if (entry.run != null) continue;
        try testing.expect(entry.why.len != 0);
        try testing.expect(entry.landed != null);
    }
}

fn editDistance(a: []const u8, b: []const u8) usize {
    var previous: [64]usize = undefined;
    var current: [64]usize = undefined;
    std.debug.assert(b.len + 1 <= previous.len);

    for (0..b.len + 1) |column| previous[column] = column;
    for (a, 1..) |from, row| {
        current[0] = row;
        for (b, 1..) |to, column| {
            const substitute = previous[column - 1] + @intFromBool(from != to);
            const delete = previous[column] + 1;
            const insert = current[column - 1] + 1;
            current[column] = @min(substitute, @min(delete, insert));
        }
        @memcpy(previous[0 .. b.len + 1], current[0 .. b.len + 1]);
    }
    return previous[b.len];
}

test "the edit distance helper counts the three edits it says it counts" {
    try testing.expectEqual(@as(usize, 0), editDistance("run", "run"));
    try testing.expectEqual(@as(usize, 1), editDistance("run", "ruv"));
    try testing.expectEqual(@as(usize, 1), editDistance("run", "ru"));
    try testing.expectEqual(@as(usize, 1), editDistance("run", "rung"));
    try testing.expectEqual(@as(usize, 3), editDistance("", "run"));
    try testing.expectEqual(@as(usize, 3), editDistance("plan", "plugin"));
}

test "a person cannot reach the plugin host verb by mistyping a word chock answers to" {
    for (commands) |entry| {
        try testing.expect(editDistance(entry.name, plugin_host_verb) >= 3);
    }
    for (own_words) |word| {
        try testing.expect(editDistance(word, plugin_host_verb) >= 3);
    }
}

test "the plugin host verb is in no command table and in no usage text" {
    for (commands) |entry| {
        try testing.expect(!std.mem.eql(u8, entry.name, plugin_host_verb));
    }
    for (own_words) |word| {
        try testing.expect(!std.mem.eql(u8, word, plugin_host_verb));
    }
}

test "the command table names each command exactly once" {
    for (commands, 0..) |entry, index| {
        for (commands[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, entry.name, other.name));
        }
    }
}

test "the three commands this milestone builds are all in the table and all built" {
    const built = [_][]const u8{ "run", "login", "daemon" };
    for (built) |name| {
        var found = false;
        for (commands) |entry| {
            if (!std.mem.eql(u8, entry.name, name)) continue;
            found = true;
            try testing.expect(entry.run != null);
        }
        try testing.expect(found);
    }
}

test "the daemon and the frontend are two commands, and neither is a mode of the other" {
    var found_daemon = false;
    var found_serve = false;
    for (commands) |entry| {
        if (std.mem.eql(u8, entry.name, "daemon")) {
            found_daemon = true;
            try testing.expect(entry.run != null);
            try testing.expect(entry.run.? == daemon_cmd.main);
        }
        if (std.mem.eql(u8, entry.name, "serve")) {
            found_serve = true;
            try testing.expect(entry.run != null);
            try testing.expect(entry.run.? == serve_cmd.main);
            try testing.expect(entry.run.? != daemon_cmd.main);
        }
    }
    try testing.expect(found_daemon);
    try testing.expect(found_serve);
}

test "chock usage is built and says nothing about waiting on anything" {
    for (commands) |entry| {
        if (!std.mem.eql(u8, entry.name, "usage")) continue;
        try testing.expect(entry.run != null);
        try testing.expectEqualStrings("", entry.why);
        return;
    }
    return error.TestUnexpectedResult;
}

test "an option is not a command name, and this file's own two words still are" {
    for ([_][]const u8{
        "--verbose",
        "--color=never",
        "--allow-dirty",
        "--project",
        "--session",
        "--continue",
        "--adopt",
        "--max-turns",
        "--no-notices",
        "--no-such-option",
        "-x",
    }) |first| try testing.expect(namesNoCommand(first));

    for ([_][]const u8{ "run", "sessions", "usage", "plan", "nonesuch", "" }) |first| {
        try testing.expect(!namesNoCommand(first));
    }

    for (own_words) |one| try testing.expect(!namesNoCommand(one));
}
