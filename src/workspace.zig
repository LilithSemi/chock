//! `chock workspace`: look at the workspaces sessions left behind, and remove
//! them.
//!
//! **A session that ends badly keeps its workspace**, because the alternative
//! is deleting work nothing else has a copy of: see `src/run.zig`'s own
//! `cleanupFor`, and the session measured on 2026-08-22 that met a rate limit
//! and lost 105 changed files. That decision is only half an answer on its
//! own. A directory nobody removes is a disk that fills, so there has to be
//! one obvious way to see what is there and one obvious way to be rid of it.
//!
//! The same shape `src/cache.zig` and `src/memory.zig` have, and deliberately
//! not a third shape: the three directories carry the same class of state, so
//! a user who has learned one command has learned all three.
//!
//! ## `clear` asks, because a kept workspace is not scratch
//!
//! **The question, the `--yes`, and the refusal are all `src/sessions.zig`'s.**
//! `canAsk` is its rule, `agreed` reads the answer, and `approval.saysYes`
//! decides what a yes is. A second style of prompt for the same class of loss
//! would be a second thing for a person to learn and a second thing to get
//! wrong. A caller with nobody at the keyboard, which is what a pipe is, gets
//! no removal at all unless it passes `--yes` and takes the decision itself. A
//! question nobody answers is a refusal.
//!
//! ## A workspace whose session is running is never removed
//!
//! **A lock that could not be tested is skipped too.** An absent answer is
//! never a permissive answer, the rule a policy keeps and `sessions.prunable`
//! keeps for a prune.
//!
//! **Clearing a git project's workspace is two steps, not one.** A worktree is
//! registered in the project's own `.git`, so deleting the directory alone
//! leaves the project believing a worktree exists that does not. `git worktree
//! prune` is what removes that record, and this command runs it once after the
//! deletes. A project with no git of its own has no such record and needs no
//! prune.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_workspace = @import("chock-workspace");

const approval = @import("approval.zig");
const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

/// What a session's workspace directory is called: the session identifier,
/// then this. Read from `session.zig`'s own layout, which is the file that
/// builds the name in the first place.
const work_suffix = ".work";

const usage_text =
    \\Usage: chock workspace [list|clear] [options]
    \\
    \\With no subcommand, says which workspaces this project's sessions left behind.
    \\A session that ends cleanly removes its own. A session that errored, was
    \\refused, reached its budget, made no progress, or was interrupted keeps its
    \\own, so whatever the agent wrote is still there.
    \\
    \\clear removes every one of them. It names them and says how many bytes go
    \\first, and then it asks. Nothing else holds a copy of what is in them, so take
    \\what you want out of them before you answer yes.
    \\
    \\A workspace whose session is running now is never removed, because that session
    \\is writing into it. Such a row is marked with a * at the start.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\  --yes             Do not ask. Only for a caller that has already decided.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
    /// The caller has decided already, so `clear` does not ask. The same option
    /// `chock sessions remove` takes, and it means the same thing.
    yes: bool = false,
};

const Action = enum { list, clear };

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = gpa;
    _ = exe_path;

    // `.environ` is what `Threaded` resolves a bare `argv[0]` against, and the
    // clear path spawns a bare `git`. Left out, a Nix machine finds no `git`
    // at all: the same trap `src/run.zig`'s own phase 1 documents.
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
        tty.print(.err, "chock workspace: the session directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    const kept = try list(arena, io, dir);

    if (options.action == .list) return listWorkspaces(kept, dir);

    // `hasTerminal` reads what standard input really is. It is read here, in
    // the one function no test drives, so that the rule itself stays in
    // `sessions.canAsk` where a test can hold it to account.
    var stdin = approval.Stdin{};
    return clearWorkspaces(
        arena,
        io,
        &env,
        stdin.console(),
        options.yes,
        approval.hasTerminal(io),
        kept,
        project_root,
        dir,
    );
}

/// One workspace a session left behind.
pub const Kept = struct {
    /// The session that made it. The workspace directory's own name without
    /// its suffix, which is how a user joins this to a session log.
    session_id: []const u8,
    /// The absolute path of the directory itself.
    path: []const u8,
    /// What it holds. Measured whole, never up to a bound: this command is
    /// what a user reads to decide whether to remove it, and a number that
    /// stopped counting early would answer a different question.
    size: chock_core.cache.Size,
    /// Whether the session that made it is running now. **Only `idle` may be
    /// removed**: see this file's own top comment, and `livenessFor` for how a
    /// workspace whose log has gone is read.
    live: sessions_cmd.Liveness = .idle,

    /// Whether `clear` may take this one.
    pub fn removable(self: Kept) bool {
        return self.live == .idle;
    }
};

/// Whether the session that made the workspace of `session_id` is running now.
///
/// **The lock on the session's log is the fact**, which is the same fact
/// `chock sessions` reads and the reason it is `sessions.livenessOf` that
/// answers it here rather than a second probe written out again.
///
/// A workspace whose log is not there at all is `idle`. No process holds a lock
/// on a file nothing can open, so nothing owns that directory any more. Every
/// other reason the log could not be read is `unknown`, which `clear` skips: an
/// absent answer is never a permissive answer.
fn livenessFor(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    session_id: []const u8,
) std.mem.Allocator.Error!sessions_cmd.Liveness {
    const log = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.jsonl", .{ dir, session_id }, 0);
    _ = std.Io.Dir.cwd().statFile(io, log, .{}) catch |err| switch (err) {
        error.FileNotFound => return .idle,
        else => return .unknown,
    };
    return sessions_cmd.livenessOf(io, log);
}

/// Every workspace under `dir`, oldest first, with its size. Caller owns the
/// slice and every string in it, which for a real caller is an arena.
///
/// **Oldest first**, because a session identifier starts with its own
/// timestamp: see `session.zig`'s own `newId`. The list a user reads is then
/// in the order the sessions ran.
///
/// A session directory that cannot be read at all answers an empty list. A
/// project that never ran a session has no such directory, and that is an
/// ordinary state rather than a fault.
///
/// The measuring is `chock_core.cache.measure`, which is a plain walk of a
/// directory and knows nothing about a toolchain cache. A second copy of that
/// walk here is how two size reports quietly start disagreeing.
pub fn list(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
) std.mem.Allocator.Error![]Kept {
    var handle = std.Io.Dir.openDirAbsolute(io, dir, .{ .iterate = true }) catch return &.{};
    defer handle.close(io);

    var found: std.ArrayList(Kept) = .empty;
    var walker = handle.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (!std.mem.endsWith(u8, entry.name, work_suffix)) continue;
        const stem = entry.name[0 .. entry.name.len - work_suffix.len];
        // A name this build did not write is never turned into a path: the
        // same rule `session.zig` keeps, and the reason `isValidId` exists.
        if (!session_paths.isValidId(stem)) continue;

        const path = try std.fs.path.join(allocator, &.{ dir, entry.name });
        const session_id = try allocator.dupe(u8, stem);
        try found.append(allocator, .{
            .session_id = session_id,
            .path = path,
            .size = chock_core.cache.measure(allocator, io, path, std.math.maxInt(u64)),
            // Read here, so the listing and the clear can never disagree about
            // which workspace a session still owns.
            .live = try livenessFor(allocator, io, dir, session_id),
        });
    }

    const kept = try found.toOwnedSlice(allocator);
    std.mem.sort(Kept, kept, {}, olderFirst);
    return kept;
}

fn olderFirst(_: void, a: Kept, b: Kept) bool {
    return std.mem.order(u8, a.session_id, b.session_id) == .lt;
}

/// The total of every kept workspace, in bytes.
pub fn totalBytes(kept: []const Kept) u64 {
    var total: u64 = 0;
    for (kept) |one| total += one.size.bytes;
    return total;
}

fn listWorkspaces(kept: []const Kept, dir: []const u8) u8 {
    if (kept.len == 0) {
        tty.print(
            .plain,
            "chock workspace: this project has no kept workspaces ({s})\n",
            .{dir},
        );
        return Exit.finished.code();
    }

    // A `--verbose` line. Where the workspaces are kept is not the question,
    // and `chock workspace clear` removes them without anybody typing a path.
    tty.detail("{s}\n\n", .{dir});
    var running: usize = 0;
    for (kept) |one| {
        if (!one.removable()) running += 1;
        tty.out(.plain, "{s} {s}  {d} bytes in {d} files\n", .{
            // The same mark `chock sessions` puts on a running session, in the
            // same place, because it is the same fact and it changes what a
            // reader may do with the row.
            if (one.removable()) " " else "*",
            one.session_id,
            one.size.bytes,
            one.size.files,
        });
    }
    // **The count and the bytes, and nothing else.** What a kept workspace
    // holds, and that `clear` removes it without asking, are both in
    // `chock workspace --help`. That second half is a real warning and it was
    // in this line before, so it moved rather than went: see the usage text.
    tty.out(.plain, "\n{d} workspaces, {d} bytes in all\n", .{ kept.len, totalBytes(kept) });
    // Why a row is marked, said once and only when there is a marked row. A
    // legend nobody needs is a line paid for on every listing.
    if (running != 0) {
        tty.out(
            .plain,
            "A * marks a workspace whose session is running now. clear leaves it where it is.\n",
            .{},
        );
    }
    return Exit.finished.code();
}

/// The question `clear` ends with. **Word for word `chock sessions prune`'s
/// own**, because it is the same decision about the same class of loss, and a
/// second wording would be a second thing to learn. `approval.saysYes` decides
/// what counts as a yes, so anything else, including nothing at all, is a no.
const clear_question = "\nRemove them all? [y/N] ";

fn clearWorkspaces(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    console: approval.Console,
    assume_yes: bool,
    at_terminal: bool,
    kept: []const Kept,
    project_root: []const u8,
    dir: []const u8,
) u8 {
    if (kept.len == 0) {
        tty.print(
            .warn,
            "chock workspace: this project has no kept workspaces ({s})\n",
            .{dir},
        );
        // Never `finished`: a command that did nothing must not report
        // success. See `src/main.zig`'s own top comment.
        return Exit.usage.code();
    }

    // **Counted before anything is printed, and printed before anything is
    // asked.** A person agreeing to this has to see the same list the command
    // is about to act on, and a running session's workspace is not on it.
    var going: usize = 0;
    var held: usize = 0;
    var went: u64 = 0;
    for (kept) |one| {
        if (!one.removable()) {
            held += 1;
            continue;
        }
        going += 1;
        went += one.size.bytes;
    }

    if (going == 0) {
        tty.print(
            .warn,
            "chock workspace clear: every kept workspace of this project belongs to a session " ++
                "that is running, so none was removed ({s})\n",
            .{dir},
        );
        return Exit.usage.code();
    }

    // Everything that would go is on screen before anything goes, whether or
    // not there is a question after it: `chock sessions prune`'s own rule. A
    // clear that named a count and not the workspaces is one nobody can check.
    tty.out(.plain, "chock workspace clear: this would remove {d} of {d} kept workspaces from {s}\n\n", .{
        going,
        kept.len,
        dir,
    });
    for (kept) |one| {
        if (!one.removable()) continue;
        tty.out(.plain, "  {s}  {d} bytes in {d} files\n", .{
            one.session_id,
            one.size.bytes,
            one.size.files,
        });
    }
    tty.out(
        .plain,
        "\n{d} bytes in all. Every one of these holds work no session carried back into\n" ++
            "the project. Nothing else holds a copy, and no step makes it again.\n",
        .{went},
    );
    for (kept) |one| {
        if (one.removable()) continue;
        tty.out(.warn, "\n{s} is kept: {s}\n", .{ one.session_id, whyKept(one) });
    }

    // Either there is a person to ask, or the caller has already decided.
    // Neither is true here, so nothing goes: a question nobody can answer is a
    // refusal.
    if (!sessions_cmd.canAsk(assume_yes, at_terminal)) {
        tty.print(
            .warn,
            "\nchock workspace: clearing destroys work that no session carried back into the " ++
                "project, and there is nobody here to ask. Nothing was removed. Run this at a " ++
                "terminal, or pass --yes.\n",
            .{},
        );
        return Exit.refused.code();
    }

    if (!assume_yes and !sessions_cmd.agreed(io, console, clear_question)) {
        tty.print(.warn, "\nchock workspace: nothing was removed.\n", .{});
        return Exit.refused.code();
    }

    var removed: usize = 0;
    for (kept) |one| {
        if (!one.removable()) continue;
        std.Io.Dir.cwd().deleteTree(io, one.path) catch |err| {
            tty.print(
                .err,
                "chock workspace: {s} could not be removed: {s}\n",
                .{ one.path, @errorName(err) },
            );
            continue;
        };
        removed += 1;
    }

    // The second half, for a git project: the directory is gone and the
    // project still holds a record of the worktree that was in it. See this
    // file's own top comment.
    pruneWorktrees(arena, io, env, project_root);

    tty.print(.plain, "chock workspace: removed {d} of {d} workspaces, {d} bytes, from {s}\n", .{
        removed,
        going,
        went,
        dir,
    });
    if (held != 0) {
        tty.print(
            .warn,
            "chock workspace: {d} of this project's {d} kept workspaces stayed, because the " ++
                "session is still running or the log's lock could not be tested.\n",
            .{ held, kept.len },
        );
    }
    // A clear that removed nothing it was asked to remove did not do the job,
    // and must not report that it did.
    if (removed == 0) return Exit.usage.code();
    return Exit.finished.code();
}

/// Why `clear` leaves this workspace where it is. **The two reasons are not the
/// same fact**, so they are not the same sentence: one is a session that is
/// running, and the other is a lock this could not test at all.
fn whyKept(one: Kept) []const u8 {
    return switch (one.live) {
        .live => "its session is running now, and that session is writing into this workspace. " ++
            "Its log's lock is held, which is what says a process still owns the session.",
        .unknown => "its log's lock could not be tested, so this cannot tell whether the session " ++
            "is running.",
        // A removable workspace never reaches here: see the caller.
        .idle => unreachable,
    };
}

/// Drop the project's own record of every worktree whose directory has gone.
///
/// Best effort and never fatal: the directories are already removed by the
/// time this runs, and a project that is not a git repository has no record to
/// drop. A prune that fails is worth saying out loud, because the user is then
/// the one who has to run it.
///
/// Public because `chock sessions remove` takes a session's workspace with its
/// log and needs the same second half. A second copy of these two steps in that
/// file is how one command would quietly stop dropping the record the other
/// drops.
pub fn pruneWorktrees(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) void {
    const is_repository = chock_workspace.git.isRepository(arena, io, env, project_root, null) catch return;
    if (!is_repository) return;

    var output = chock_workspace.git.run(arena, io, env, project_root, &.{ "worktree", "prune" }, null) catch |err| {
        tty.print(
            .err,
            "chock workspace: the worktree records in {s} could not be pruned ({s}). " ++
                "Run: git -C {s} worktree prune\n",
            .{ project_root, @errorName(err), project_root },
        );
        return;
    };
    defer output.deinit(arena);
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
        // The same spelling `chock sessions remove` takes. A `--force` here and
        // a `--yes` there would be one decision with two names.
        if (std.mem.eql(u8, argument, "--yes")) {
            options.yes = true;
            continue;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (saw_action) return error.BadArguments;
        options.action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
        saw_action = true;
    }
    return options;
}

/// The project this command is about, as an absolute path. **The same call
/// `chock run`, `chock cache`, and `chock memory` make**, for the same reason:
/// a session directory is keyed by the project's real path, so a spelling this
/// command resolved differently would read a different directory from the one
/// the session wrote.
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

test "the command line names an action and nothing else" {
    try testing.expectEqual(Action.list, (try parseOptions(&.{})).action);
    try testing.expectEqual(Action.list, (try parseOptions(&.{"list"})).action);
    try testing.expectEqual(Action.clear, (try parseOptions(&.{"clear"})).action);

    const with_project = try parseOptions(&.{ "--project", "/somewhere", "clear" });
    try testing.expectEqualStrings("/somewhere", with_project.project.?);
    try testing.expectEqual(Action.clear, with_project.action);

    try testing.expect(!(try parseOptions(&.{"clear"})).yes);
    try testing.expect((try parseOptions(&.{ "clear", "--yes" })).yes);
    try testing.expect((try parseOptions(&.{ "--yes", "clear" })).yes);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "clear", "--force" }));

    try testing.expectError(error.BadArguments, parseOptions(&.{"remove-everything"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "clear", "clear" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

/// A session directory with `count` workspaces in it, each holding one file of
/// `bytes` bytes, plus the things a real session directory also holds and this
/// command must not report.
fn makeSessionDir(arena: std.mem.Allocator, io: std.Io, root: []const u8, ids: []const []const u8) !void {
    try std.Io.Dir.createDirAbsolute(io, root, .default_dir);
    for (ids) |id| {
        const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ root, id });
        try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
        const file = try std.fmt.allocPrint(arena, "{s}/agent-wrote-this.txt", .{work});
        var handle = try std.Io.Dir.createFileAbsolute(io, file, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, "1234567890");
    }
}

test "every kept workspace is listed, oldest first, with what it holds" {
    // What a user reads to decide whether there is anything worth salvaging.
    // The size is the point: a listing with no number cannot answer "is this
    // filling my disk", which is the question a kept directory raises.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const newer = "01JQ" ++ "B" ** 22;
    const older = "01JQ" ++ "A" ** 22;
    try makeSessionDir(arena, testing.io, root, &.{ newer, older });

    // The things a session directory also holds: a log, a sandbox root, and a
    // directory whose name is not a session identifier at all. None of them is
    // a kept workspace, and reporting one would send a user to a directory
    // with nothing in it.
    {
        const log = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ root, older });
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, log, .{});
        handle.close(testing.io);
    }
    try std.Io.Dir.createDirAbsolute(
        testing.io,
        try std.fmt.allocPrint(arena, "{s}/{s}.root", .{ root, older }),
        .default_dir,
    );
    try std.Io.Dir.createDirAbsolute(
        testing.io,
        try std.fmt.allocPrint(arena, "{s}/not-a-session.work", .{root}),
        .default_dir,
    );

    const kept = try list(arena, testing.io, root);

    try testing.expectEqual(@as(usize, 2), kept.len);
    try testing.expectEqualStrings(older, kept[0].session_id);
    try testing.expectEqualStrings(newer, kept[1].session_id);
    try testing.expectEqual(@as(u64, 10), kept[0].size.bytes);
    try testing.expectEqual(@as(u64, 1), kept[0].size.files);
    try testing.expectEqual(@as(u64, 20), totalBytes(kept));
}

/// A `Console` a test scripts. It never touches a terminal.
///
/// **A third copy of this shape, and that is on purpose.** `src/approval.zig`
/// and `src/sessions.zig` each keep one and each is private to its own file. A
/// test that read real standard input would wait for a person nobody is going
/// to send, which is the one thing the whole confirmation is against.
const FakeConsole = struct {
    gpa: std.mem.Allocator,
    /// What `read` answers, in order. The last one is repeated.
    replies: []const approval.Console.Read,
    /// The bytes each `bytes` reply delivers, in the same order.
    lines: []const []const u8 = &.{},
    reads: usize = 0,
    lines_taken: usize = 0,
    /// Everything that was shown, joined.
    shown: std.ArrayList(u8) = .empty,

    fn console(self: *FakeConsole) approval.Console {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = approval.Console.VTable{ .write = writeFn, .read = readFn };

    fn deinit(self: *FakeConsole) void {
        self.shown.deinit(self.gpa);
    }

    fn writeFn(ptr: *anyopaque, io: std.Io, bytes: []const u8) void {
        _ = io;
        const self: *FakeConsole = @ptrCast(@alignCast(ptr));
        self.shown.appendSlice(self.gpa, bytes) catch {};
    }

    fn readFn(ptr: *anyopaque, io: std.Io, buffer: []u8, budget_ms: u64) approval.Console.Read {
        _ = io;
        _ = budget_ms;
        const self: *FakeConsole = @ptrCast(@alignCast(ptr));
        const index = @min(self.reads, self.replies.len - 1);
        self.reads += 1;
        switch (self.replies[index]) {
            .bytes => {
                // A script that ran out of lines has said everything it was
                // going to. Ending is the answer that cannot hang a test.
                if (self.lines_taken >= self.lines.len) return .ended;
                const line = self.lines[self.lines_taken];
                self.lines_taken += 1;
                std.debug.assert(line.len <= buffer.len);
                @memcpy(buffer[0..line.len], line);
                return .{ .bytes = line.len };
            },
            else => |other| return other,
        }
    }
};

/// Whether the file the agent wrote is still in the workspace of `id`.
fn workWasKept(arena: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !bool {
    const file = try std.fmt.allocPrint(arena, "{s}/{s}.work/agent-wrote-this.txt", .{ root, id });
    _ = std.Io.Dir.cwd().statFile(io, file, .{}) catch return false;
    return true;
}

test "clearing asks first, and anything that is not a plain yes leaves every file where it was" {
    // **The fault this pins.** A kept workspace holds work that no session
    // carried back into the project, so it is exactly the work a person cannot
    // get again. `clear` used to remove all of it with no question at all.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const id = "01JQ" ++ "A" ** 22;
    try makeSessionDir(arena, testing.io, root, &.{id});

    // A project directory with no git in it, so the prune is skipped and this
    // test spawns nothing.
    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);

    var env = std.process.Environ.Map.init(arena);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const refusals = [_][]const u8{ "n\n", "\n", "sure\n", "yes please\n" };
    for (refusals) |answer| {
        var no = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{answer} };
        defer no.deinit();
        const kept = try list(arena, testing.io, root);
        try testing.expectEqual(@as(usize, 1), kept.len);
        try testing.expectEqual(
            Exit.refused.code(),
            clearWorkspaces(arena, testing.io, &env, no.console(), false, true, kept, project, root),
        );
        // The question really did reach the console, so the refusal is an
        // answer and not a path that never asked.
        try testing.expect(std.mem.indexOf(u8, no.shown.items, clear_question) != null);
        // **And the files are still there.** A test that only proved the
        // question was printed would pass against a `clear` that asked and then
        // deleted everything anyway.
        try testing.expect(try workWasKept(arena, testing.io, root, id));
    }

    // Every refusal says so, so nobody is left wondering whether the answer was
    // taken.
    try testing.expect(std.mem.indexOf(u8, said.err(), "nothing was removed") != null);

    // How many and how big, before the question, so a person knows the size of
    // what they are agreeing to.
    try testing.expect(std.mem.indexOf(u8, said.out(), "this would remove 1 of 1") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "10 bytes in 1 files") != null);

    // And a plain yes does remove it. Without this the test would pass against
    // a `clearWorkspaces` that never removed anything.
    said.clear();
    var yes = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"Y\n"} };
    defer yes.deinit();
    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.finished.code(),
        clearWorkspaces(arena, testing.io, &env, yes.console(), false, true, kept, project, root),
    );
    // **How many went, and from where.** Removing work an agent left and
    // saying nothing about it is how a person loses it. Captured rather than
    // let through: see `tty.Capture`, and `test/proto/lock.zig`.
    try testing.expect(std.mem.indexOf(u8, said.err(), "removed 1 of 1") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), root) != null);

    // Gone from the filesystem, not merely absent from a second listing.
    try testing.expect(!try workWasKept(arena, testing.io, root, id));
    try testing.expectEqual(@as(usize, 0), (try list(arena, testing.io, root)).len);
}

test "a clear with nobody to answer removes nothing, and --yes is how a script means it" {
    // **Destroying because nobody was there to object is the worst reading of
    // that rule.** A pipe has nobody at the keyboard, so it gets no removal at
    // all unless it says `--yes` and takes the decision itself.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const id = "01JQ" ++ "A" ** 22;
    try makeSessionDir(arena, testing.io, root, &.{id});

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);

    var env = std.process.Environ.Map.init(arena);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // Nobody at the keyboard and no `--yes`. The console is given an input that
    // has ended, which is what a pipe with nothing in it really answers, so a
    // `clear` that asked anyway would still not read a yes here.
    var nobody = FakeConsole{ .gpa = arena, .replies = &.{.ended} };
    defer nobody.deinit();
    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.refused.code(),
        clearWorkspaces(arena, testing.io, &env, nobody.console(), false, false, kept, project, root),
    );
    try testing.expect(try workWasKept(arena, testing.io, root, id));
    // It says what to do instead, so a script's author can fix it.
    try testing.expect(std.mem.indexOf(u8, said.err(), "nobody here to ask") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--yes") != null);
    // And nothing was asked: the refusal comes before the question, so no
    // command with no terminal ever waits on a prompt nobody can see.
    try testing.expectEqual(@as(usize, 0), nobody.reads);

    // The same rule, said as a rule and not only as an outcome.
    try testing.expect(!sessions_cmd.canAsk(false, false));
    try testing.expect(sessions_cmd.canAsk(false, true));
    try testing.expect(sessions_cmd.canAsk(true, false));

    // `--yes` with no terminal is the caller taking the decision, and it does
    // remove. The console is one that never answers, so a `clear` that asked
    // anyway would refuse instead of finishing.
    said.clear();
    var never = FakeConsole{ .gpa = arena, .replies = &.{.ended} };
    defer never.deinit();
    try testing.expectEqual(
        Exit.finished.code(),
        clearWorkspaces(arena, testing.io, &env, never.console(), true, false, kept, project, root),
    );
    try testing.expectEqual(@as(usize, 0), never.reads);
    try testing.expect(!try workWasKept(arena, testing.io, root, id));
}

test "a clear leaves the workspace of a session that is running" {
    // Removing a live session's workspace takes the directory that session is
    // writing into out from under it, and loses the work at the same moment.
    // The lock on its log is what says a process still owns the session, which
    // is the same fact `chock sessions` reads.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const running_id = "01JQ" ++ "A" ** 22;
    const ended_id = "01JQ" ++ "B" ** 22;
    try makeSessionDir(arena, testing.io, root, &.{ running_id, ended_id });

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);

    // A log with its exclusive lock held is exactly what a running session is.
    const log = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ root, running_id });
    var owner = try std.Io.Dir.createFileAbsolute(testing.io, log, .{});
    defer owner.close(testing.io);
    try testing.expect(try owner.tryLock(testing.io, .exclusive));

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(@as(usize, 2), kept.len);
    try testing.expectEqualStrings(running_id, kept[0].session_id);
    try testing.expectEqual(sessions_cmd.Liveness.live, kept[0].live);
    try testing.expect(!kept[0].removable());
    // The other session left no log at all, which is the ordinary state of a
    // workspace whose session is long gone. Nothing can hold a lock on a file
    // that is not there, so it is removable.
    try testing.expectEqual(sessions_cmd.Liveness.idle, kept[1].live);

    var env = std.process.Environ.Map.init(arena);
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var yes = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer yes.deinit();
    try testing.expectEqual(
        Exit.finished.code(),
        clearWorkspaces(arena, testing.io, &env, yes.console(), false, true, kept, project, root),
    );

    try testing.expect(try workWasKept(arena, testing.io, root, running_id));
    try testing.expect(!try workWasKept(arena, testing.io, root, ended_id));

    // And it says which was left and why, rather than quietly reporting a
    // smaller number than the listing showed.
    try testing.expect(std.mem.indexOf(u8, said.err(), "removed 1 of 1") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of this project's 2") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "this would remove 1 of 2") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "its session is running now") != null);
}

test "a clear with nothing to clear does not report success" {
    // A command that did nothing reporting success is the fault
    // `src/main.zig` names as the worst kind this program can have.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});
    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);

    var env = std.process.Environ.Map.init(arena);
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var never = FakeConsole{ .gpa = arena, .replies = &.{.ended} };
    defer never.deinit();
    try testing.expect(clearWorkspaces(
        arena,
        testing.io,
        &env,
        never.console(),
        false,
        true,
        &.{},
        project,
        root,
    ) != Exit.finished.code());
    // **Answered before the question about who is here**, and before anything
    // is asked at all. "Run this at a terminal" for a project that has nothing
    // to clear sends a reader to fix a thing that was never the fault.
    try testing.expectEqual(@as(usize, 0), never.reads);
    // And it says which directory it looked in rather than exiting quietly with
    // a number a person has to look up.
    try testing.expect(std.mem.indexOf(u8, said.err(), root) != null);
    try testing.expectEqualStrings("", said.out());
}

test "a project that never ran a session lists nothing rather than failing" {
    // An ordinary state, not a fault: the session directory is only made when
    // a session runs.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const missing = try std.fmt.allocPrint(arena, "{s}/never-ran", .{buffer[0..len]});

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const kept = try list(arena, testing.io, missing);
    try testing.expectEqual(@as(usize, 0), kept.len);
    try testing.expectEqual(Exit.finished.code(), listWorkspaces(kept, missing));
    // **It says which directory held nothing.** "No kept workspaces" on its own
    // leaves a person unable to tell an empty project from a Chock that looked
    // somewhere else.
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);
}
