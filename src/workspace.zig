//! `chock workspace`: inspect, recover, and remove work sessions left behind.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");
const chock_workspace = @import("chock-workspace");

const approval = @import("approval.zig");
const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const work_suffix = ".work";

const usage_text =
    \\Usage: chock workspace [list|clear|adopt <session>|review <session>] [options]
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
    \\adopt <session> takes the work out of one kept workspace of a project that is
    \\not a git repository, and puts it in .chock-adopted/<session> inside the
    \\project. Nothing of yours is written over and nothing of yours is deleted: the
    \\changed files arrive under files/, and every path the session deleted is named
    \\in deleted for you to act on. A git project needs none of this, because its
    \\work is already at refs/chock/<session>.
    \\
    \\review <session> shows the exact Git patch between the base recorded in the
    \\session log and refs/chock/<session>. Repeat --path to show only named files.
    \\Paths are literal: wildcard and pathspec syntax has no special meaning.
    \\
    \\A workspace whose session is running now is never removed, because that session
    \\is writing into it. Such a row is marked with a * at the start.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\  --yes             Do not ask. Only for a caller that has already decided.
    \\  --path <file>     For review: include this project-relative path. Repeatable.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
    yes: bool = false,
    session: ?[]const u8 = null,
    paths: []const []const u8 = &.{},
};

const Action = enum { list, clear, adopt, review };

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

    const options = parseOptions(arena, args) catch |err| switch (err) {
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

    if (options.action == .review) {
        return reviewWorkspace(arena, io, &env, project_root, dir, options.session, options.paths);
    }

    const kept = try list(arena, io, dir);
    if (options.action == .list) return listWorkspaces(kept, dir);
    if (options.action == .adopt) {
        return adoptWorkspace(arena, io, kept, project_root, dir, options.session);
    }

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

pub const Kept = struct {
    session_id: []const u8,
    path: []const u8,
    size: chock_core.cache.Size,
    live: sessions_cmd.Liveness = .idle,

    pub fn removable(self: Kept) bool {
        return self.live == .idle;
    }
};

// The lock on the session's log is the fact: a workspace with no log is idle, and an absent answer is never a permissive one.
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
        // A name this build did not write is never turned into a path, the reason isValidId exists.
        if (!session_paths.isValidId(stem)) continue;

        const path = try std.fs.path.join(allocator, &.{ dir, entry.name });
        const session_id = try allocator.dupe(u8, stem);
        try found.append(allocator, .{
            .session_id = session_id,
            .path = path,
            .size = chock_core.cache.measure(allocator, io, path, std.math.maxInt(u64)),
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

    tty.detail("{s}\n\n", .{dir});
    var running: usize = 0;
    for (kept) |one| {
        if (!one.removable()) running += 1;
        tty.out(.plain, "{s} {s}  {d} bytes in {d} files\n", .{
            if (one.removable()) " " else "*",
            one.session_id,
            one.size.bytes,
            one.size.files,
        });
    }
    tty.out(.plain, "\n{d} workspaces, {d} bytes in all\n", .{ kept.len, totalBytes(kept) });
    if (running != 0) {
        tty.out(
            .plain,
            "A * marks a workspace whose session is running now. clear leaves it where it is.\n",
            .{},
        );
    }
    return Exit.finished.code();
}

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
        // Never finished: a command that did nothing must not report success.
        return Exit.usage.code();
    }

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
    if (removed == 0) return Exit.usage.code();
    return Exit.finished.code();
}

fn whyKept(one: Kept) []const u8 {
    return switch (one.live) {
        .live => "its session is running now, and that session is writing into this workspace. " ++
            "Its log's lock is held, which is what says a process still owns the session.",
        .unknown => "its log's lock could not be tested, so this cannot tell whether the session " ++
            "is running.",
        .idle => unreachable,
    };
}

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

fn parseOptions(arena: std.mem.Allocator, args: []const []const u8) (ParseError || std.mem.Allocator.Error)!Options {
    var options = Options{};
    var paths: std.ArrayList([]const u8) = .empty;
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
        if (std.mem.eql(u8, argument, "--yes")) {
            options.yes = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--path")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            try paths.append(arena, args[index]);
            continue;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (!saw_action) {
            options.action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
            saw_action = true;
            continue;
        }
        if ((options.action != .adopt and options.action != .review) or options.session != null) return error.BadArguments;
        options.session = argument;
    }
    if (paths.items.len != 0 and options.action != .review) return error.BadArguments;
    options.paths = try paths.toOwnedSlice(arena);
    return options;
}

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

fn reviewWorkspace(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    session_dir: []const u8,
    wanted: ?[]const u8,
    paths: []const []const u8,
) u8 {
    const session_id = wanted orelse {
        tty.print(.err, "chock workspace review: name the session whose work you want to review.\n", .{});
        return Exit.usage.code();
    };
    if (!session_paths.isValidId(session_id)) {
        tty.print(.err, "chock workspace review: {s} is not a session identifier.\n", .{session_id});
        return Exit.usage.code();
    }

    const log_path = std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, session_id }, 0) catch
        return Exit.faulted.code();
    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch {
        tty.print(.err, "chock workspace review: session {s} has no log in this project.\n", .{session_id});
        return Exit.usage.code();
    };
    const opened = lastWorkspaceOpen(arena, io, log_path, session_id) orelse {
        tty.print(
            .err,
            "chock workspace review: the log of session {s} names no workspace to review.\n",
            .{session_id},
        );
        return Exit.usage.code();
    };
    switch (opened.kind) {
        .worktree => {},
        .overlay => {
            tty.print(
                .err,
                "chock workspace review: session {s} used an overlay workspace. " ++
                    "Use `chock workspace adopt {s}` to copy its changes out for review.\n",
                .{ session_id, session_id },
            );
            return Exit.usage.code();
        },
        .unknown => |name| {
            tty.print(
                .err,
                "chock workspace review: session {s} used a {s} workspace, which this build cannot review.\n",
                .{ session_id, name },
            );
            return Exit.usage.code();
        },
    }
    if (opened.base_commit.len == 0) {
        tty.print(.err, "chock workspace review: session {s} recorded no Git base commit.\n", .{session_id});
        return Exit.usage.code();
    }

    var argv: std.ArrayList([]const u8) = .empty;
    argv.appendSlice(arena, &.{
        "diff",
        "--no-ext-diff",
        "--binary",
        "--find-renames",
        "--find-copies",
        opened.base_commit,
        std.fmt.allocPrint(arena, "refs/chock/{s}", .{session_id}) catch return Exit.faulted.code(),
        "--",
    }) catch return Exit.faulted.code();
    for (paths) |path| {
        if (!reviewPathIsSafe(path)) {
            tty.print(
                .err,
                "chock workspace review: {s} is not a project-relative path.\n",
                .{path},
            );
            return Exit.usage.code();
        }
        const literal = std.fmt.allocPrint(arena, ":(top,literal){s}", .{path}) catch return Exit.faulted.code();
        argv.append(arena, literal) catch return Exit.faulted.code();
    }

    var output = chock_workspace.git.run(arena, io, env, project_root, argv.items, null) catch |err| {
        tty.print(.err, "chock workspace review: Git could not read session {s}: {s}.\n", .{ session_id, @errorName(err) });
        return Exit.faulted.code();
    };
    defer output.deinit(arena);
    const code = switch (output.term) {
        .exited => |one| one,
        else => {
            tty.print(.err, "chock workspace review: Git did not finish normally.\n", .{});
            return Exit.faulted.code();
        },
    };
    if (code != 0) {
        tty.print(
            .err,
            "chock workspace review: the work of session {s} could not be read: {s}",
            .{ session_id, output.stderr },
        );
        return Exit.usage.code();
    }
    if (output.stdout.len == 0) {
        tty.print(.plain, "chock workspace review: session {s} has no changes in this selection.\n", .{session_id});
        return Exit.finished.code();
    }
    tty.out(.plain, "{s}", .{output.stdout});
    return Exit.finished.code();
}

fn reviewPathIsSafe(path: []const u8) bool {
    if (path.len == 0 or std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return false;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

pub const adopted_dir_name = ".chock-adopted";

fn adoptWorkspace(
    arena: std.mem.Allocator,
    io: std.Io,
    kept: []const Kept,
    project_root: []const u8,
    dir: []const u8,
    wanted: ?[]const u8,
) u8 {
    const session_id = wanted orelse {
        tty.print(
            .err,
            "chock workspace adopt: name the session whose work you want. " ++
                "`chock workspace` lists the sessions of this project that left one.\n",
            .{},
        );
        return Exit.usage.code();
    };
    if (!session_paths.isValidId(session_id)) {
        tty.print(
            .err,
            "chock workspace adopt: {s} is not a session identifier.\n",
            .{session_id},
        );
        return Exit.usage.code();
    }

    const one = findKept(kept, session_id) orelse {
        tty.print(
            .err,
            "chock workspace adopt: session {s} left no workspace in {s}.\n",
            .{ session_id, dir },
        );
        return Exit.usage.code();
    };
    if (!one.removable()) {
        tty.print(.err, "chock workspace adopt: {s} is kept: {s}\n", .{ session_id, whyKept(one) });
        tty.print(
            .err,
            "chock workspace adopt: nothing was copied. A workspace being written into now " ++
                "gives a copy of half written files.\n",
            .{},
        );
        return Exit.refused.code();
    }

    const log_path = std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, session_id }, 0) catch return Exit.usage.code();
    const opened = lastWorkspaceOpen(arena, io, log_path, session_id) orelse {
        tty.print(
            .err,
            "chock workspace adopt: the log of session {s} names no workspace, so which " ++
                "directory held its work is unknown. Look in {s} yourself.\n",
            .{ session_id, one.path },
        );
        return Exit.usage.code();
    };

    switch (opened.kind) {
        .worktree => {
            tty.print(
                .err,
                "chock workspace adopt: session {s} worked in a git worktree, and its work is " ++
                    "already in this project: the commits are objects in {s} and refs/chock/{s} " ++
                    "names them. Read it with `git log refs/chock/{s}` and take it with " ++
                    "`git merge refs/chock/{s}`.\n",
                .{ session_id, project_root, session_id, session_id, session_id },
            );
            return Exit.usage.code();
        },
        .unknown => |name| {
            tty.print(
                .err,
                "chock workspace adopt: session {s} worked in a {s} workspace, which this build " ++
                    "does not know how to take. Nothing was copied.\n",
                .{ session_id, name },
            );
            return Exit.usage.code();
        },
        .overlay => {},
    }

    const scratch = std.fs.path.join(arena, &.{ one.path, opened.attempt }) catch return Exit.usage.code();
    var diag: ?chock_workspace.Diagnostic = null;
    var overlay = chock_workspace.overlay.adopt(arena, io, project_root, scratch, &diag) catch |err| {
        switch (err) {
            error.NoOverlayToAdopt => tty.print(
                .err,
                "chock workspace adopt: session {s} left no overlay at {s}. Its work is not " ++
                    "there to take.\n",
                .{ session_id, scratch },
            ),
            else => sayFault(session_id, "the overlay could not be taken", err, diag),
        }
        return Exit.usage.code();
    };
    defer overlay.deinit(arena);

    const adopted_root = std.fs.path.join(arena, &.{ project_root, adopted_dir_name }) catch return Exit.usage.code();
    const destination = std.fs.path.join(arena, &.{ adopted_root, session_id }) catch return Exit.usage.code();

    diag = null;
    const carried = overlay.carryOut(arena, io, destination, &diag) catch |err| {
        switch (err) {
            error.WorkAlreadyCarriedOut => tty.print(
                .err,
                "chock workspace adopt: {s} already holds something, so nothing was written " ++
                    "over. The work is still in {s}. Move that directory out of the way and run " ++
                    "this again.\n",
                .{ destination, overlay.upper },
            ),
            else => sayFault(session_id, "the work could not be copied out", err, diag),
        }
        return Exit.refused.code();
    };

    recordAdoption(arena, io, log_path, session_id, opened.attempt, destination, carried);

    tty.print(.plain, "chock workspace adopt: {d} files of session {s} are in {s}/{s}\n", .{
        carried.files,
        session_id,
        destination,
        chock_workspace.overlay.carried_files_name,
    });
    tty.out(
        .plain,
        "Nothing of yours was written over. Take what you want: cp -a {s}/{s}/. {s}/\n",
        .{ destination, chock_workspace.overlay.carried_files_name, project_root },
    );
    tty.out(
        .plain,
        "{d} paths the session deleted are named in {s}/{s}. None of them was removed from " ++
            "the project: that is yours to do.\n",
        .{ carried.deleted, destination, chock_workspace.overlay.carried_deleted_name },
    );
    if (carried.skipped != 0) {
        tty.print(
            .warn,
            "chock workspace adopt: {d} paths could not be carried, each with its reason in " ++
                "{s}/{s}.\n",
            .{ carried.skipped, destination, chock_workspace.overlay.carried_skipped_name },
        );
    }
    tty.detail("The workspace is still in {s}. `chock workspace clear` removes it.\n", .{one.path});
    return Exit.finished.code();
}

fn findKept(kept: []const Kept, session_id: []const u8) ?Kept {
    for (kept) |one| {
        if (std.mem.eql(u8, one.session_id, session_id)) return one;
    }
    return null;
}

const Opened = struct {
    kind: chock_proto.event.WorkspaceKind,
    attempt: []const u8,
    base_commit: []const u8,
};

fn lastWorkspaceOpen(
    arena: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    session_id: []const u8,
) ?Opened {
    const log = chock_proto.log.Log.open(io, log_path, session_id) catch return null;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(arena, io, 0) catch return null;
    defer replay.deinit();

    var found: ?Opened = null;
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .workspace_open) continue;
        const opened = parsed.value.event.workspace_open;
        if (!session_paths.isValidId(opened.attempt)) continue;
        const kind: chock_proto.event.WorkspaceKind = switch (opened.kind) {
            .worktree => .worktree,
            .overlay => .overlay,
            .unknown => |name| .{ .unknown = arena.dupe(u8, name) catch return null },
        };
        found = .{
            .kind = kind,
            .attempt = arena.dupe(u8, opened.attempt) catch return null,
            .base_commit = arena.dupe(u8, opened.base_commit) catch return null,
        };
    }
    return found;
}

fn recordAdoption(
    arena: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    session_id: []const u8,
    attempt: []const u8,
    destination: []const u8,
    carried: chock_workspace.overlay.CarriedOut,
) void {
    const log = chock_proto.log.Log.open(io, log_path, session_id) catch |err| return sayLogFault(session_id, err);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var locked = store.lock(io) catch |err| return sayLogFault(session_id, err);
    defer locked.unlock(io) catch {};
    _ = locked.append(arena, io, .{ .workspace_adopt = .{
        .attempt = attempt,
        .path = destination,
        .files = carried.files,
        .deleted = carried.deleted,
        .skipped = carried.skipped,
    } }, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch |err| sayLogFault(session_id, err);
}

fn sayLogFault(session_id: []const u8, err: anyerror) void {
    tty.print(
        .warn,
        "chock workspace adopt: the files are in place and the log of session {s} could not be " ++
            "written ({s}), so this adoption is not recorded there.\n",
        .{ session_id, @errorName(err) },
    );
}

fn sayFault(
    session_id: []const u8,
    doing: []const u8,
    err: anyerror,
    diag: ?chock_workspace.Diagnostic,
) void {
    if (diag) |fault| {
        var held = fault;
        tty.print(.err, "chock workspace adopt: {s} of session {s}: {f}\n", .{ doing, session_id, &held });
        return;
    }
    tty.print(.err, "chock workspace adopt: {s} of session {s}: {s}\n", .{ doing, session_id, @errorName(err) });
}

const testing = std.testing;

test "the command line names an action and nothing else" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(Action.list, (try parseOptions(arena, &.{})).action);
    try testing.expectEqual(Action.list, (try parseOptions(arena, &.{"list"})).action);
    try testing.expectEqual(Action.clear, (try parseOptions(arena, &.{"clear"})).action);

    const with_project = try parseOptions(arena, &.{ "--project", "/somewhere", "clear" });
    try testing.expectEqualStrings("/somewhere", with_project.project.?);
    try testing.expectEqual(Action.clear, with_project.action);

    try testing.expect(!(try parseOptions(arena, &.{"clear"})).yes);
    try testing.expect((try parseOptions(arena, &.{ "clear", "--yes" })).yes);
    try testing.expect((try parseOptions(arena, &.{ "--yes", "clear" })).yes);
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "clear", "--force" }));

    const taking = try parseOptions(arena, &.{ "adopt", "01JQAAAAAAAAAAAAAAAAAAAAAA" });
    try testing.expectEqual(Action.adopt, taking.action);
    try testing.expectEqualStrings("01JQAAAAAAAAAAAAAAAAAAAAAA", taking.session.?);
    try testing.expectEqual(@as(?[]const u8, null), (try parseOptions(arena, &.{"adopt"})).session);
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "clear", "01JQAAAAAAAAAAAAAAAAAAAAAA" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "adopt", "one", "two" }));

    const review = try parseOptions(arena, &.{
        "review",
        "01JQAAAAAAAAAAAAAAAAAAAAAA",
        "--path",
        "src/main.zig",
        "--path",
        "docs/read me.md",
    });
    try testing.expectEqual(Action.review, review.action);
    try testing.expectEqual(@as(usize, 2), review.paths.len);
    try testing.expectEqualStrings("src/main.zig", review.paths[0]);
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "list", "--path", "README.md" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "review", "id", "--path" }));

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"remove-everything"}));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "clear", "clear" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(arena, &.{"--help"}));
}

test "review paths stay inside the project and are passed as literal pathspecs" {
    try testing.expect(reviewPathIsSafe("src/main.zig"));
    try testing.expect(reviewPathIsSafe("docs/read me.md"));
    try testing.expect(reviewPathIsSafe(":(glob)**"));
    try testing.expect(!reviewPathIsSafe(""));
    try testing.expect(!reviewPathIsSafe("/etc/passwd"));
    try testing.expect(!reviewPathIsSafe("../outside"));
    try testing.expect(!reviewPathIsSafe("src/../../outside"));
}

fn gitForTest(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project: []const u8,
    argv: []const []const u8,
) ![]const u8 {
    var output = try chock_workspace.git.run(arena, io, env, project, argv, null);
    defer output.deinit(arena);
    const code = switch (output.term) {
        .exited => |one| one,
        else => return error.GitDidNotExit,
    };
    if (code != 0) return error.GitFailed;
    return try arena.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

test "review shows the recorded Git change and literal path filters select exact files" {
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    const sessions = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(io, project, .default_dir);
    try std.Io.Dir.createDirAbsolute(io, sessions, .default_dir);
    try writeUnder(arena, io, project, "one.txt", "one before\n");
    try writeUnder(arena, io, project, "two.txt", "two before\n");

    var env = std.process.Environ.Map.init(arena);
    _ = try gitForTest(arena, io, &env, project, &.{"init"});
    _ = try gitForTest(arena, io, &env, project, &.{ "add", "--", "one.txt", "two.txt" });
    _ = try gitForTest(arena, io, &env, project, &.{
        "-c",
        "user.name=Chock Test",
        "-c",
        "user.email=chock@example.invalid",
        "commit",
        "-m",
        "base",
    });
    const base = try gitForTest(arena, io, &env, project, &.{ "rev-parse", "HEAD" });

    try writeUnder(arena, io, project, "one.txt", "one after\n");
    try writeUnder(arena, io, project, "two.txt", "two after\n");
    _ = try gitForTest(arena, io, &env, project, &.{ "add", "--", "one.txt", "two.txt" });
    _ = try gitForTest(arena, io, &env, project, &.{
        "-c",
        "user.name=Chock Test",
        "-c",
        "user.email=chock@example.invalid",
        "commit",
        "-m",
        "result",
    });
    const result = try gitForTest(arena, io, &env, project, &.{ "rev-parse", "HEAD" });

    const id = "01JQ" ++ @as([22]u8, @splat('R'));
    const ref = try std.fmt.allocPrint(arena, "refs/chock/{s}", .{id});
    _ = try gitForTest(arena, io, &env, project, &.{ "update-ref", ref, result });
    _ = try gitForTest(arena, io, &env, project, &.{ "reset", "--hard", base });

    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ sessions, id }, 0);
    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    _ = try locked.append(arena, io, .{ .workspace_open = .{
        .kind = .worktree,
        .attempt = "01JQ" ++ @as([22]u8, @splat('A')),
        .path = "/gone",
        .base_commit = base,
    } }, 1);
    try locked.unlock(io);

    var said: tty.Capture = undefined;
    said.start(io, testing.allocator);
    defer said.stop(io);
    try testing.expectEqual(
        Exit.finished.code(),
        reviewWorkspace(arena, io, &env, project, sessions, id, &.{"one.txt"}),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "one after") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "two after") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "diff --git a/one.txt b/one.txt") != null);
}

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
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const newer = "01JQ" ++ @as([22]u8, @splat('B'));
    const older = "01JQ" ++ @as([22]u8, @splat('A'));
    try makeSessionDir(arena, testing.io, root, &.{ newer, older });

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

const FakeConsole = struct {
    gpa: std.mem.Allocator,
    replies: []const approval.Console.Read,
    lines: []const []const u8 = &.{},
    reads: usize = 0,
    lines_taken: usize = 0,
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

fn workWasKept(arena: std.mem.Allocator, io: std.Io, root: []const u8, id: []const u8) !bool {
    const file = try std.fmt.allocPrint(arena, "{s}/{s}.work/agent-wrote-this.txt", .{ root, id });
    _ = std.Io.Dir.cwd().statFile(io, file, .{}) catch return false;
    return true;
}

test "clearing asks first, and anything that is not a plain yes leaves every file where it was" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    try makeSessionDir(arena, testing.io, root, &.{id});

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
        try testing.expect(std.mem.indexOf(u8, no.shown.items, clear_question) != null);
        try testing.expect(try workWasKept(arena, testing.io, root, id));
    }

    try testing.expect(std.mem.indexOf(u8, said.err(), "nothing was removed") != null);

    try testing.expect(std.mem.indexOf(u8, said.out(), "this would remove 1 of 1") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "10 bytes in 1 files") != null);

    said.clear();
    var yes = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"Y\n"} };
    defer yes.deinit();
    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.finished.code(),
        clearWorkspaces(arena, testing.io, &env, yes.console(), false, true, kept, project, root),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "removed 1 of 1") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), root) != null);

    try testing.expect(!try workWasKept(arena, testing.io, root, id));
    try testing.expectEqual(@as(usize, 0), (try list(arena, testing.io, root)).len);
}

test "a clear with nobody to answer removes nothing, and --yes is how a script means it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    try makeSessionDir(arena, testing.io, root, &.{id});

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);

    var env = std.process.Environ.Map.init(arena);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var nobody = FakeConsole{ .gpa = arena, .replies = &.{.ended} };
    defer nobody.deinit();
    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.refused.code(),
        clearWorkspaces(arena, testing.io, &env, nobody.console(), false, false, kept, project, root),
    );
    try testing.expect(try workWasKept(arena, testing.io, root, id));
    try testing.expect(std.mem.indexOf(u8, said.err(), "nobody here to ask") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--yes") != null);
    try testing.expectEqual(@as(usize, 0), nobody.reads);

    try testing.expect(!sessions_cmd.canAsk(false, false));
    try testing.expect(sessions_cmd.canAsk(false, true));
    try testing.expect(sessions_cmd.canAsk(true, false));

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
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = try std.fmt.allocPrint(arena, "{s}/sessions", .{buffer[0..len]});

    const running_id = "01JQ" ++ @as([22]u8, @splat('A'));
    const ended_id = "01JQ" ++ @as([22]u8, @splat('B'));
    try makeSessionDir(arena, testing.io, root, &.{ running_id, ended_id });

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{buffer[0..len]});
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);

    const log = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ root, running_id });
    var owner = try std.Io.Dir.createFileAbsolute(testing.io, log, .{});
    defer owner.close(testing.io);
    try testing.expect(try owner.tryLock(testing.io, .exclusive));

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(@as(usize, 2), kept.len);
    try testing.expectEqualStrings(running_id, kept[0].session_id);
    try testing.expectEqual(sessions_cmd.Liveness.live, kept[0].live);
    try testing.expect(!kept[0].removable());
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

    try testing.expect(std.mem.indexOf(u8, said.err(), "removed 1 of 1") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of this project's 2") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "this would remove 1 of 2") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "its session is running now") != null);
}

test "a clear with nothing to clear does not report success" {
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
    try testing.expectEqual(@as(usize, 0), never.reads);
    try testing.expect(std.mem.indexOf(u8, said.err(), root) != null);
    try testing.expectEqualStrings("", said.out());
}

fn makeOverlaySession(
    arena: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    id: []const u8,
    attempt: []const u8,
    kind: chock_proto.event.WorkspaceKind,
) ![]const u8 {
    std.Io.Dir.createDirAbsolute(io, root, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ root, id });
    try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
    const scratch = try std.fs.path.join(arena, &.{ work, attempt });
    try std.Io.Dir.createDirAbsolute(io, scratch, .default_dir);
    const upper = try std.fs.path.join(arena, &.{ scratch, "upper" });
    try std.Io.Dir.createDirAbsolute(io, upper, .default_dir);

    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ root, id }, 0);
    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    _ = try locked.append(arena, io, .{ .workspace_open = .{
        .kind = kind,
        .attempt = "01JQ" ++ @as([22]u8, @splat('T')),
        .path = "/gone",
        .base_commit = "",
    } }, 500);
    _ = try locked.append(arena, io, .{ .workspace_open = .{
        .kind = kind,
        .attempt = attempt,
        .path = upper,
        .base_commit = "",
    } }, 1000);
    _ = try locked.append(arena, io, .{ .session_end = .{ .reason = .errored, .detail = "rate limited" } }, 2000);
    try locked.unlock(io);
    return upper;
}

fn writeUnder(arena: std.mem.Allocator, io: std.Io, root: []const u8, relative: []const u8, contents: []const u8) !void {
    const file_path = try std.fs.path.join(arena, &.{ root, relative });
    if (std.fs.path.dirname(file_path)) |parent| try std.Io.Dir.cwd().createDirPath(io, parent);
    var handle = try std.Io.Dir.createFileAbsolute(io, file_path, .{});
    defer handle.close(io);
    try handle.writeStreamingAll(io, contents);
}

fn adoptionRow(
    arena: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    id: []const u8,
) !?chock_proto.event.WorkspaceAdopt {
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ root, id }, 0);
    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);
    var replay = try store.replay(arena, io, 0);
    defer replay.deinit();

    var found: ?chock_proto.event.WorkspaceAdopt = null;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .workspace_adopt) continue;
        const row = parsed.value.event.workspace_adopt;
        found = .{
            .attempt = try arena.dupe(u8, row.attempt),
            .path = try arena.dupe(u8, row.path),
            .files = row.files,
            .deleted = row.deleted,
            .skipped = row.skipped,
        };
    }
    return found;
}

fn makeWhiteoutAt(arena: std.mem.Allocator, upper: []const u8, relative: []const u8) !void {
    const file_path = try std.fs.path.join(arena, &.{ upper, relative });
    const path_z = try arena.dupeSentinel(u8, file_path, 0);
    const rc = std.os.linux.mknod(path_z.ptr, std.os.linux.S.IFCHR | 0o600, 0);
    try testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc));
}

test "an overlay a session left behind is adopted, and what it changed and what it deleted both arrive" {
    if (@import("builtin").os.tag != .linux) return;
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
    try writeUnder(arena, testing.io, project, "tracked.txt", "original\n");
    try writeUnder(arena, testing.io, project, "gone.txt", "the agent deleted me\n");

    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    const attempt = "01JQ" ++ @as([22]u8, @splat('B'));
    const upper = try makeOverlaySession(arena, testing.io, root, id, attempt, .overlay);
    try writeUnder(arena, testing.io, upper, "tracked.txt", "the agent changed this\n");
    try writeUnder(arena, testing.io, upper, "notes/new.md", "the agent made this\n");
    try makeWhiteoutAt(arena, upper, "gone.txt");

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(@as(usize, 1), kept.len);
    try testing.expectEqual(
        Exit.finished.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, id),
    );

    const destination = try std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{ project, adopted_dir_name, id });

    const changed = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ destination, "files", "tracked.txt" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("the agent changed this\n", changed);
    const added = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ destination, "files", "notes", "new.md" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("the agent made this\n", added);

    const deleted = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ destination, "deleted" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("gone.txt\n", deleted);
    const survivor = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ project, "gone.txt" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("the agent deleted me\n", survivor);
    const untouched = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ project, "tracked.txt" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("original\n", untouched);

    try testing.expect(std.mem.indexOf(u8, said.out(), destination) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "None of them was removed") != null);

    const row = (try adoptionRow(arena, testing.io, root, id)) orelse return error.NoAdoptionRecorded;
    try testing.expectEqualStrings(attempt, row.attempt);
    try testing.expectEqualStrings(destination, row.path);
    try testing.expectEqual(@as(u64, 2), row.files);
    try testing.expectEqual(@as(u64, 1), row.deleted);
    try testing.expectEqual(@as(u64, 0), row.skipped);
}

test "a session that worked in a git worktree is refused, and sent to the ref that already holds its work" {
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

    const id = "01JQ" ++ @as([22]u8, @splat('C'));
    const attempt = "01JQ" ++ @as([22]u8, @splat('D'));
    _ = try makeOverlaySession(arena, testing.io, root, id, attempt, .worktree);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.usage.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, id),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "refs/chock/") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "git merge") != null);

    const adopted = try std.fmt.allocPrint(arena, "{s}/{s}", .{ project, adopted_dir_name });
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, adopted, .{}),
    );
    try testing.expectEqual(@as(?chock_proto.event.WorkspaceAdopt, null), try adoptionRow(arena, testing.io, root, id));
}

test "an adoption that would write over an earlier one is refused by name, and nothing is written over" {
    if (@import("builtin").os.tag != .linux) return;
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

    const id = "01JQ" ++ @as([22]u8, @splat('E'));
    const attempt = "01JQ" ++ @as([22]u8, @splat('F'));
    const upper = try makeOverlaySession(arena, testing.io, root, id, attempt, .overlay);
    try writeUnder(arena, testing.io, upper, "tracked.txt", "the agent changed this\n");

    const destination = try std.fmt.allocPrint(arena, "{s}/{s}/{s}", .{ project, adopted_dir_name, id });
    try writeUnder(arena, testing.io, destination, "files/tracked.txt", "a person edited this\n");

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.refused.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, id),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), destination) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "nothing was written over") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), upper) != null);

    const still_there = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ destination, "files", "tracked.txt" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("a person edited this\n", still_there);
    try testing.expectEqual(@as(?chock_proto.event.WorkspaceAdopt, null), try adoptionRow(arena, testing.io, root, id));
}

test "adopt refuses a session nobody named, one that is not an identifier, and one with no workspace" {
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

    const id = "01JQ" ++ @as([22]u8, @splat('G'));
    const attempt = "01JQ" ++ @as([22]u8, @splat('H'));
    _ = try makeOverlaySession(arena, testing.io, root, id, attempt, .overlay);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.usage.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, null),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "name the session") != null);

    try testing.expectEqual(
        Exit.usage.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, "../../etc"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "not a session identifier") != null);

    const never_ran = "01JQ" ++ @as([22]u8, @splat('Z'));
    try testing.expectEqual(
        Exit.usage.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, never_ran),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "left no workspace") != null);

    const adopted = try std.fmt.allocPrint(arena, "{s}/{s}", .{ project, adopted_dir_name });
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, adopted, .{}),
    );
}

test "a workspace whose overlay has already been cleared is refused, and the clearing is named" {
    if (@import("builtin").os.tag != .linux) return;
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

    const id = "01JQ" ++ @as([22]u8, @splat('K'));
    const attempt = "01JQ" ++ @as([22]u8, @splat('M'));
    const upper = try makeOverlaySession(arena, testing.io, root, id, attempt, .overlay);
    try std.Io.Dir.cwd().deleteTree(testing.io, upper);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const kept = try list(arena, testing.io, root);
    try testing.expectEqual(
        Exit.usage.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, id),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "left no overlay") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), attempt) != null);
}

test "a project that never ran a session lists nothing rather than failing" {
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
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);
}
