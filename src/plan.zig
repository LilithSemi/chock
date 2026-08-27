//! `chock plan`: the task list an agent kept, read back after the session.
//!
//! The same shape `src/cache.zig`, `src/memory.zig`, `src/workspace.zig` and
//! `src/usage.zig` have, and deliberately not a sixth shape: a user who has
//! learned one of these has learned all five. Nothing here starts a session,
//! opens a sandbox, or touches the project.
//!
//! ## What this command is not
//!
//! It is not a report on whether the agent did its job. The list is the
//! agent's own statement of intent and nothing holds it to it, per
//! `chock_proto.event.PlanUpdate`. A plan that changed is a plan the agent
//! changed on purpose, and the log holds every version of it in order for
//! anybody who wants to read the change rather than the result.

const std = @import("std");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const state = chock_proto.state;
const event = chock_proto.event;

/// What a session log is called: the session identifier, then this. The same
/// name `src/usage.zig` reads, from the same layout `session.zig` builds.
const log_suffix = ".jsonl";

const usage_text =
    \\Usage: chock plan [list|show <session>] [options]
    \\
    \\With no subcommand, says which sessions of this project kept a task list.
    \\A step an agent decided not to do reads as "abandoned" and stays on the
    \\list, so a step that was given up never looks like one that was finished.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
    session: []const u8 = "",
};

const Action = enum { list, show };

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = gpa;
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const project_root = try resolveProject(arena, io, options.project);
    const dir = session_paths.projectDir(arena, &env, project_root) catch |err| {
        tty.print(.err, "chock plan: the session directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    return switch (options.action) {
        .list => listSessions(arena, io, dir),
        .show => showSession(arena, io, dir, options.session),
    };
}

/// The task list one session kept, folded from its own log.
pub const Kept = struct {
    /// The session identifier, which is the log's own name without its suffix.
    id: []const u8,
    plan: state.Plan = .{},
    /// False when the log could not be read all the way to its end: a torn
    /// tail from a crash mid write, or a line that would not decode. **The
    /// list is then the plan as it was part way through**, and the report says
    /// so, because a partial list that looks whole is worse than none.
    complete: bool = true,

    pub fn counts(self: Kept) state.Plan.Counts {
        return self.plan.counts();
    }
};

/// Fold every `plan.update` event of one session's log. Null when this project
/// has no session of that identifier.
///
/// **The file is checked before the log is opened**, the same rule
/// `src/usage.zig` keeps and for the same reason: `chock_proto.log.Log.open`
/// creates the file and writes a header into it when there is none, so asking
/// about a session that never existed would otherwise bring one into being.
pub fn fold(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!?Kept {
    std.debug.assert(session_paths.isValidId(id));
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;

    const log = chock_proto.log.Log.open(io, path, id) catch return null;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var kept = Kept{ .id = try allocator.dupe(u8, id) };

    var replay = store.replay(allocator, io, 0) catch {
        kept.complete = false;
        return kept;
    };
    defer replay.deinit();

    while (true) {
        const parsed = replay.next(io) catch {
            // A line that will not decode stops the fold here. Everything
            // before it is real, and `complete` is what stops a reader taking
            // a part of the plan for the whole of it.
            kept.complete = false;
            break;
        } orelse {
            // A torn tail is a crash mid write, not a clean end of log, and an
            // update may have gone with it.
            if (replay.truncated()) kept.complete = false;
            break;
        };
        defer parsed.deinit();
        if (parsed.value.event != .plan_update) continue;
        // **The same `Plan.apply` the running session folds with**, so what
        // this command reports and what the terminal showed are one fold and
        // not two. Every string it keeps is duplicated into `allocator`.
        try kept.plan.apply(allocator, parsed.value.event.plan_update);
    }
    return kept;
}

/// Every session of `dir` that kept a task list, oldest first. Caller owns the
/// slice and everything in it, which for a real caller is an arena.
///
/// **Oldest first**, because a session identifier starts with its own
/// timestamp: see `session.zig`'s own `newId`. The list a user reads is then in
/// the order the sessions ran.
pub fn list(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    without_a_list: *usize,
) std.mem.Allocator.Error![]Kept {
    without_a_list.* = 0;
    var handle = std.Io.Dir.openDirAbsolute(io, dir, .{ .iterate = true }) catch return &.{};
    defer handle.close(io);

    var found: std.ArrayList(Kept) = .empty;
    var walker = handle.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, log_suffix)) continue;
        const stem = entry.name[0 .. entry.name.len - log_suffix.len];
        // A name this build did not write is never turned into a path: the
        // same rule `session.zig` keeps, and the reason `isValidId` exists.
        if (!session_paths.isValidId(stem)) continue;

        const kept = try fold(allocator, io, dir, stem) orelse continue;
        // **A session with no list is counted and not printed.** Most sessions
        // have none, by design, and a page of "no task list" would bury the
        // few that do. The count is what keeps that honest.
        if (kept.plan.isEmpty()) {
            without_a_list.* += 1;
            continue;
        }
        try found.append(allocator, kept);
    }

    const sessions = try found.toOwnedSlice(allocator);
    std.mem.sort(Kept, sessions, {}, olderFirst);
    return sessions;
}

fn olderFirst(_: void, a: Kept, b: Kept) bool {
    return std.mem.order(u8, a.id, b.id) == .lt;
}

/// How a list reads in one line: what is left, what was finished, and what was
/// given up. Caller owns the result.
///
/// **The abandoned steps have a number of their own.** Folding them into
/// "done" would make a list of given up work read as a list of finished work,
/// which is the one wrong answer this command must never give.
pub fn summaryText(
    allocator: std.mem.Allocator,
    counts: state.Plan.Counts,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.print(allocator, "{d} {s}: {d} left, {d} done", .{
        counts.total(),
        if (counts.total() == 1) "step" else "steps",
        counts.left(),
        counts.done,
    });
    if (counts.abandoned != 0) try text.print(allocator, ", {d} abandoned", .{counts.abandoned});
    if (counts.unrecognized != 0) {
        try text.print(
            allocator,
            ", {d} at a status this build does not know",
            .{counts.unrecognized},
        );
    }
    return text.toOwnedSlice(allocator);
}

fn listSessions(arena: std.mem.Allocator, io: std.Io, dir: []const u8) !u8 {
    var without: usize = 0;
    const sessions = try list(arena, io, dir, &without);
    if (sessions.len == 0) {
        if (without == 0) {
            tty.print(.plain, "chock plan: this project has no sessions ({s})\n", .{dir});
        } else {
            tty.print(
                .plain,
                "chock plan: no session of this project kept a task list ({d} {s} ran without one)\n",
                .{ without, if (without == 1) "session" else "sessions" },
            );
        }
        return Exit.finished.code();
    }

    // A `--verbose` line. Where the logs are kept answers no question this
    // command was asked, and a person who ran it knows which project they are
    // in.
    tty.detail("{s}\n\n", .{dir});
    for (sessions) |one| {
        tty.out(.plain, "{s}  {s}{s}\n", .{
            one.id,
            try summaryText(arena, one.counts()),
            if (one.complete) "" else "  (the log ends mid write, so this is the list part way through)",
        });
    }

    tty.out(.plain, "\n{d} {s} with a task list", .{
        sessions.len,
        if (sessions.len == 1) "session" else "sessions",
    });
    if (without != 0) {
        // Said out loud, because a task list is not mandatory and most work
        // needs none. A reader who did not know that would read a short list
        // as a missing one.
        tty.out(.plain, ", and {d} that kept none", .{without});
    }
    tty.out(.plain, ".\n", .{});
    return Exit.finished.code();
}

fn showSession(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8) !u8 {
    if (id.len == 0) {
        tty.print(.err, "chock plan show: which session?\n", .{});
        return Exit.usage.code();
    }
    if (!session_paths.isValidId(id)) {
        tty.print(.err, "chock plan show: \"{s}\" is not a session identifier\n", .{id});
        return Exit.usage.code();
    }

    const kept = try fold(arena, io, dir, id) orelse {
        tty.print(.err, "chock plan show: this project has no session {s} ({s})\n", .{ id, dir });
        // Never `finished`: a command that did nothing must not report
        // success. See `src/main.zig`'s own top comment.
        return Exit.usage.code();
    };

    // The identifier is the answer's heading. The log path under it is a
    // `--verbose` line: `tty.options_text` names the log path as exactly that.
    tty.out(.plain, "{s}\n", .{kept.id});
    tty.detail("{s}/{s}{s}\n", .{ dir, kept.id, log_suffix });
    tty.out(.plain, "\n", .{});
    if (kept.plan.isEmpty()) {
        // An ordinary answer and not a fault. A task list is not mandatory,
        // and a one step task with one is noise.
        tty.out(.plain, "  This session kept no task list.\n", .{});
        if (!kept.complete) {
            tty.print(.warn, "  Its log ends mid write, so it may have written one that was lost.\n", .{});
        }
        return Exit.finished.code();
    }

    for (kept.plan.steps.items) |step| {
        tty.out(.plain, "  [{s: <11}] {s}  {s}", .{ step.status.wireName(), step.id, step.subject });
        if (step.blocked_by.len != 0) tty.out(.plain, "  (waiting on: {s})", .{step.blocked_by});
        tty.out(.plain, "\n", .{});
    }

    tty.out(.plain, "\n  {s}\n", .{try summaryText(arena, kept.counts())});
    if (kept.counts().abandoned != 0) {
        tty.out(
            .plain,
            "  An abandoned step is one the agent decided not to do and said so.\n",
            .{},
        );
    }
    if (!kept.complete) {
        tty.print(.warn, "  The log ends mid write, so this is the list part way through.\n", .{});
    }
    return Exit.finished.code();
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    var saw_action = false;

    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (!saw_action) {
            options.action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
            saw_action = true;
            continue;
        }
        if (options.session.len != 0) return error.BadArguments;
        options.session = argument;
    }

    if (options.action == .show and options.session.len == 0) return error.BadArguments;
    return options;
}

/// The project this command is about, as an absolute path. **The same call
/// `chock run`, `chock cache`, `chock memory`, `chock workspace` and
/// `chock usage` make**, for the same reason: a session directory is keyed by
/// the project's real path, so a spelling this command resolved differently
/// would read a different directory from the one the session wrote.
fn resolveProject(arena: std.mem.Allocator, io: std.Io, given: ?[]const u8) ![]const u8 {
    if (given) |path| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return arena.dupe(u8, path);
        defer dir.close(io);
        const len = dir.realPath(io, &buffer) catch return arena.dupe(u8, path);
        return arena.dupe(u8, buffer[0..len]);
    }
    return std.process.currentPathAlloc(io, arena);
}

const testing = std.testing;

test "the command line names an action and at most one session" {
    try testing.expectEqual(Action.list, (try parseOptions(&.{})).action);
    try testing.expectEqual(Action.list, (try parseOptions(&.{"list"})).action);

    const shown = try parseOptions(&.{ "show", "01JQ" ++ "A" ** 22 });
    try testing.expectEqual(Action.show, shown.action);
    try testing.expectEqualStrings("01JQ" ++ "A" ** 22, shown.session);

    const with_project = try parseOptions(&.{ "--project", "/somewhere", "show", "01JQ" ++ "B" ** 22 });
    try testing.expectEqualStrings("/somewhere", with_project.project.?);
    try testing.expectEqualStrings("01JQ" ++ "B" ** 22, with_project.session);

    // `show` needs a session, and a word this command does not know is never
    // read as one.
    try testing.expectError(error.BadArguments, parseOptions(&.{"show"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"steps"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "show", "a", "b" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

/// A session directory holding one log per identifier, each carrying the
/// events it was given. The events go in by hand, so what comes out is
/// checkable step by step.
fn makeLog(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    events: []const event.Event,
) !void {
    std.Io.Dir.createDirAbsolute(io, dir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);

    const log = try chock_proto.log.Log.open(io, path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};
    _ = try locked.append(arena, io, .{ .session_start = .{
        .agent_kind = "coder",
        .model_alias = "main",
        .parent_session = "",
    } }, 0);
    for (events) |one| _ = try locked.append(arena, io, one, 0);
}

fn scratchDir(arena: std.mem.Allocator, tmp: *testing.TmpDir, leaf: []const u8) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ buffer[0..len], leaf });
}

test "the list this command reads back is the list the session ended with" {
    // **The whole point of keeping it in the log.** A list held in the running
    // process is gone when the process is, so a person reading a night's work
    // in the morning would have nothing. This folds the file and nothing else.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .in_progress },
            .{ .id = "s2", .subject = "write the command", .status = .pending },
            .{ .id = "s3", .subject = "measure it on Darwin", .status = .pending, .blocked_by = "s2" },
        } } },
        .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "working" }} } },
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .done },
            .{ .id = "s3", .subject = "measure it on Darwin", .status = .abandoned },
        } } },
    });

    const kept = (try fold(arena, testing.io, dir, id)).?;
    try testing.expect(kept.complete);
    try testing.expectEqual(@as(usize, 3), kept.plan.steps.items.len);

    // In the order they were first named, whatever order the later update
    // named them in.
    try testing.expectEqualStrings("s1", kept.plan.steps.items[0].id);
    try testing.expectEqualStrings("s2", kept.plan.steps.items[1].id);
    try testing.expectEqualStrings("s3", kept.plan.steps.items[2].id);

    const counts = kept.counts();
    try testing.expectEqual(@as(usize, 1), counts.done);
    try testing.expectEqual(@as(usize, 1), counts.abandoned);
    try testing.expectEqual(@as(usize, 1), counts.left());
}

test "a step that was given up reads as given up, and is never counted as done" {
    // The fault this command exists to make visible. A summary that folded
    // `abandoned` into `done` would report finished work nobody did, which is
    // exactly what a list with a step quietly missing already reads as.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var plan = state.Plan{};
    try plan.apply(arena, .{ .steps = &.{
        .{ .id = "s1", .subject = "port the driver", .status = .done },
        .{ .id = "s2", .subject = "rewrite the build script", .status = .abandoned },
        .{ .id = "s3", .subject = "write the escape test", .status = .pending },
    } });

    const text = try summaryText(arena, plan.counts());
    try testing.expect(std.mem.indexOf(u8, text, "3 steps") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1 done") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1 abandoned") != null);
    try testing.expect(std.mem.indexOf(u8, text, "1 left") != null);

    // And a list with nothing given up does not print a zero for it: a column
    // of zeroes is a column nobody reads.
    var clean = state.Plan{};
    try clean.apply(arena, .{ .steps = &.{
        .{ .id = "s1", .subject = "port the driver", .status = .done },
    } });
    const clean_text = try summaryText(arena, clean.counts());
    try testing.expect(std.mem.indexOf(u8, clean_text, "abandoned") == null);
    try testing.expect(std.mem.indexOf(u8, clean_text, "1 step:") != null);
}

test "a session that kept no list is an ordinary answer, and is not listed as one that did" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const plain = "01JQ" ++ "A" ** 22;
    const planned = "01JQ" ++ "B" ** 22;
    try makeLog(arena, testing.io, dir, plain, &.{
        .{ .message = .{ .role = .assistant, .content = &.{.{ .text = "renamed the field" }} } },
    });
    try makeLog(arena, testing.io, dir, planned, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .done },
        } } },
    });

    const no_list = (try fold(arena, testing.io, dir, plain)).?;
    try testing.expect(no_list.plan.isEmpty());
    try testing.expectEqual(@as(usize, 0), no_list.counts().total());

    var without: usize = 0;
    const sessions = try list(arena, testing.io, dir, &without);
    try testing.expectEqual(@as(usize, 1), sessions.len);
    try testing.expectEqualStrings(planned, sessions[0].id);
    try testing.expectEqual(@as(usize, 1), without);
}

test "asking about a session this project never had answers null and creates nothing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");
    try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);

    const never = "01JQ" ++ "Z" ** 22;
    try testing.expectEqual(@as(?Kept, null), try fold(arena, testing.io, dir, never));

    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, never }, 0);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );
}
