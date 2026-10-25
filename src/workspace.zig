//! `chock workspace`: inspect, recover, and remove work sessions left behind.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");
const chock_workspace = @import("chock-workspace");
const ziggit = @import("ziggit");

const approval = @import("approval.zig");
const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const work_suffix = ".work";

const usage_text =
    \\Usage: chock workspace [list|clear|adopt <session>|review <session>|select <session>|undo <session>] [options]
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
    \\session log and refs/chock/<session>, or an overlay's change manifest.
    \\Repeat --path to show only named files. Paths are literal: wildcard and
    \\pathspec syntax has no special meaning.
    \\
    \\select <session> creates refs/chock/selected/<session> from accepted files
    \\and hunks without moving the checked-out branch. With no accept selector,
    \\everything is accepted except explicit rejects. A changed patch may instead
    \\be supplied with --patch. undo <session> removes that selected result.
    \\
    \\A workspace whose session is running now is never removed, because that session
    \\is writing into it. Such a row is marked with a * at the start.
    \\
    \\Options:
    \\  --project <dir>   The project. Defaults to the current directory.
    \\  --yes             Do not ask. Only for a caller that has already decided.
    \\  --path <file>     For review: show this path. For select: accept its whole change.
    \\                    Repeatable; paths are literal.
    \\  --hunk <file:n>   For select: accept one numbered text hunk. Repeatable.
    \\  --reject-path <file>  For select: reject a whole file. Repeatable.
    \\  --reject-hunk <file:n> For select: reject one numbered text hunk. Repeatable.
    \\  --patch <file>    For select: apply an edited unified patch instead of selectors.
    \\
++ tty.options_text;

pub const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
    yes: bool = false,
    session: ?[]const u8 = null,
    paths: []const []const u8 = &.{},
    hunks: []const HunkSelector = &.{},
    rejected_paths: []const []const u8 = &.{},
    rejected_hunks: []const HunkSelector = &.{},
    patch: ?[]const u8 = null,
};

pub const HunkSelector = struct { path: []const u8, number: usize };

const Action = enum { list, clear, adopt, review, select, undo };

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
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
        return reviewWorkspace(arena, gpa, io, project_root, dir, options.session, options.paths);
    }
    if (options.action == .select) {
        return selectWorkspace(arena, gpa, io, &env, project_root, dir, options);
    }
    if (options.action == .undo) {
        return undoSelection(arena, io, &env, project_root, dir, options.session);
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
    var hunks: std.ArrayList(HunkSelector) = .empty;
    var rejected_paths: std.ArrayList([]const u8) = .empty;
    var rejected_hunks: std.ArrayList(HunkSelector) = .empty;
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
        if (std.mem.eql(u8, argument, "--hunk") or std.mem.eql(u8, argument, "--reject-hunk")) {
            const reject = std.mem.eql(u8, argument, "--reject-hunk");
            index += 1;
            if (index >= args.len) return error.BadArguments;
            const selector = parseHunkSelector(args[index]) orelse return error.BadArguments;
            if (reject) try rejected_hunks.append(arena, selector) else try hunks.append(arena, selector);
            continue;
        }
        if (std.mem.eql(u8, argument, "--reject-path")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            try rejected_paths.append(arena, args[index]);
            continue;
        }
        if (std.mem.eql(u8, argument, "--patch")) {
            index += 1;
            if (index >= args.len or options.patch != null) return error.BadArguments;
            options.patch = args[index];
            continue;
        }
        if (argument.len != 0 and argument[0] == '-') return error.BadArguments;

        if (!saw_action) {
            options.action = actionOf(argument) orelse return error.BadArguments;
            saw_action = true;
            continue;
        }
        if ((options.action != .adopt and options.action != .review and options.action != .select and options.action != .undo) or options.session != null) return error.BadArguments;
        options.session = argument;
    }
    if (paths.items.len != 0 and options.action != .review and options.action != .select) return error.BadArguments;
    if ((hunks.items.len != 0 or rejected_paths.items.len != 0 or rejected_hunks.items.len != 0 or options.patch != null) and options.action != .select) return error.BadArguments;
    if (options.patch != null and (paths.items.len != 0 or hunks.items.len != 0 or rejected_paths.items.len != 0 or rejected_hunks.items.len != 0)) return error.BadArguments;
    options.paths = try paths.toOwnedSlice(arena);
    options.hunks = try hunks.toOwnedSlice(arena);
    options.rejected_paths = try rejected_paths.toOwnedSlice(arena);
    options.rejected_hunks = try rejected_hunks.toOwnedSlice(arena);
    return options;
}

fn actionOf(text: []const u8) ?Action {
    if (std.mem.eql(u8, text, "list")) return .list;
    if (std.mem.eql(u8, text, "clear")) return .clear;
    if (std.mem.eql(u8, text, "adopt")) return .adopt;
    if (std.mem.eql(u8, text, "review")) return .review;
    if (std.mem.eql(u8, text, "select")) return .select;
    if (std.mem.eql(u8, text, "undo")) return .undo;
    return null;
}

fn parseHunkSelector(text: []const u8) ?HunkSelector {
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return null;
    const path = text[0..colon];
    if (!reviewPathIsSafe(path)) return null;
    const number = std.fmt.parseUnsigned(usize, text[colon + 1 ..], 10) catch return null;
    if (number == 0) return null;
    return .{ .path = path, .number = number };
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
    gpa: std.mem.Allocator,
    io: std.Io,
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
    for (paths) |path| {
        if (!reviewPathIsSafe(path)) {
            tty.print(
                .err,
                "chock workspace review: {s} is not a project-relative path.\n",
                .{path},
            );
            return Exit.usage.code();
        }
    }

    const log_path = std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, session_id }, 0) catch
        return Exit.faulted.code();
    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch {
        tty.print(.err, "chock workspace review: session {s} has no log in this project.\n", .{session_id});
        return Exit.usage.code();
    };
    switch (sessions_cmd.livenessOf(io, log_path)) {
        .idle => {},
        .live => {
            tty.print(
                .err,
                "chock workspace review: session {s} is running, so its work does not have a stable review boundary yet.\n",
                .{session_id},
            );
            return Exit.refused.code();
        },
        .unknown => {
            tty.print(
                .err,
                "chock workspace review: the lock on session {s} could not be tested, so its work may still be changing.\n",
                .{session_id},
            );
            return Exit.refused.code();
        },
    }
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
        .overlay => return reviewOverlay(arena, io, project_root, session_dir, session_id, opened.attempt, paths),
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

    var project = std.Io.Dir.openDirAbsolute(io, project_root, .{ .iterate = true }) catch |err| {
        tty.print(.err, "chock workspace review: the project could not be opened: {s}.\n", .{@errorName(err)});
        return Exit.faulted.code();
    };
    defer project.close(io);

    var diag: ?ziggit.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    var layout = ziggit.discover(gpa, io, project, .{}, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the Git repository could not be found", err, &diag);
        return Exit.usage.code();
    };
    var repo = ziggit.Repository.open(gpa, io, layout, .{}, &diag) catch |err| {
        layout.deinit(io);
        sayGitReviewFault(gpa, session_id, "the Git repository could not be opened", err, &diag);
        return Exit.usage.code();
    };
    defer repo.deinit();

    const base = ziggit.resolve(gpa, &repo, opened.base_commit, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the recorded base commit could not be resolved", err, &diag);
        return Exit.usage.code();
    };
    const ref_name = std.fmt.allocPrint(arena, "refs/chock/{s}", .{session_id}) catch return Exit.faulted.code();
    const tip = repo.refs.resolve(ref_name, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the session ref could not be resolved", err, &diag);
        return Exit.usage.code();
    };
    var diff = ziggit.diffCommits(gpa, &repo.odb, base, tip, .{ .detect_copies = true }, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the session changes could not be read", err, &diag);
        return Exit.faulted.code();
    };
    defer diff.deinit(gpa);

    var rendered: std.Io.Writer.Allocating = .init(gpa);
    defer rendered.deinit();
    var shown: usize = 0;
    for (diff.patches) |patch| {
        if (!patchSelected(paths, patch)) continue;
        patch.writeUnified(&rendered.writer) catch {
            tty.print(.err, "chock workspace review: the patch for session {s} was too large to render.\n", .{session_id});
            return Exit.faulted.code();
        };
        shown += 1;
    }
    if (shown == 0) {
        tty.print(.plain, "chock workspace review: session {s} has no changes in this selection.\n", .{session_id});
        return Exit.finished.code();
    }
    tty.out(.plain, "{s}", .{rendered.written()});
    return Exit.finished.code();
}

fn patchSelected(paths: []const []const u8, patch: ziggit.Patch) bool {
    return pathSelected(paths, patch.old_path) or pathSelected(paths, patch.new_path);
}

pub const ReviewWire = struct {
    kind: enum { git, overlay },
    base: []const u8 = "",
    source: []const u8 = "",
    files: []const File = &.{},

    pub const File = struct {
        path: []const u8,
        old_path: []const u8 = "",
        status: []const u8,
        selectable: bool = true,
        binary: bool = false,
        atomic: bool = false,
        hunks: []const Hunk = &.{},
    };
    pub const Hunk = struct {
        number: usize,
        header: []const u8,
        lines: []const Line,
    };
    pub const Line = struct {
        origin: enum { context, addition, deletion },
        text: []const u8,
    };
};

/// Structured review data for every Phantom frontend. The session log fixes
/// the base and workspace kind; callers never infer either from the worktree.
pub fn reviewJson(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    session_dir: []const u8,
    session_id: []const u8,
) ![]const u8 {
    if (!session_paths.isValidId(session_id)) return error.InvalidSession;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, session_id }, 0);
    if (sessions_cmd.livenessOf(io, log_path) != .idle) return error.SessionNotIdle;
    const opened = lastWorkspaceOpen(arena, io, log_path, session_id) orelse return error.NoWorkspace;

    switch (opened.kind) {
        .unknown => return error.UnknownWorkspace,
        .overlay => {
            const work = try std.fmt.allocPrint(arena, "{s}/{s}{s}", .{ session_dir, session_id, work_suffix });
            const scratch = try std.fs.path.join(arena, &.{ work, opened.attempt });
            var diag: ?chock_workspace.Diagnostic = null;
            var overlay = try chock_workspace.overlay.adopt(gpa, io, project_root, scratch, &diag);
            defer overlay.deinit(gpa);
            var report = try overlay.changedFiles(gpa, io, &diag);
            defer report.deinit(gpa);
            const files = try arena.alloc(ReviewWire.File, report.changed.len + report.skipped.len);
            var at: usize = 0;
            for (report.changed) |one| {
                var hunks: []const ReviewWire.Hunk = &.{};
                var binary = false;
                var atomic = true;
                if (one.kind == .modified) text: {
                    const old_path = try std.fs.path.join(arena, &.{ project_root, one.path });
                    const new_path = try std.fs.path.join(arena, &.{ overlay.upper, one.path });
                    const old_stat = std.Io.Dir.cwd().statFile(io, old_path, .{ .follow_symlinks = false }) catch break :text;
                    const new_stat = std.Io.Dir.cwd().statFile(io, new_path, .{ .follow_symlinks = false }) catch break :text;
                    if (old_stat.kind != .file or new_stat.kind != .file or old_stat.permissions != new_stat.permissions) break :text;
                    const old_bytes = std.Io.Dir.cwd().readFileAlloc(io, old_path, gpa, .limited(16 * 1024 * 1024)) catch break :text;
                    defer gpa.free(old_bytes);
                    const new_bytes = std.Io.Dir.cwd().readFileAlloc(io, new_path, gpa, .limited(16 * 1024 * 1024)) catch break :text;
                    defer gpa.free(new_bytes);
                    var patch = ziggit.diffBlobs(gpa, one.path, one.path, old_bytes, new_bytes, .{}) catch break :text;
                    defer patch.deinit(gpa);
                    binary = patch.binary;
                    atomic = patch.binary;
                    if (!patch.binary) hunks = try wireHunks(arena, patch.hunks);
                }
                files[at] = .{
                    .path = try arena.dupe(u8, one.path),
                    .status = @tagName(one.kind),
                    .binary = binary,
                    .atomic = atomic,
                    .hunks = hunks,
                };
                at += 1;
            }
            for (report.skipped) |one| {
                files[at] = .{
                    .path = try arena.dupe(u8, one.path),
                    .status = try std.fmt.allocPrint(arena, "skipped: {s}", .{one.reason}),
                    .selectable = false,
                    .atomic = true,
                };
                at += 1;
            }
            return std.json.Stringify.valueAlloc(arena, ReviewWire{
                .kind = .overlay,
                .source = scratch,
                .files = files,
            }, .{});
        },
        .worktree => {},
    }
    if (opened.base_commit.len == 0) return error.NoBaseCommit;

    var project = try std.Io.Dir.openDirAbsolute(io, project_root, .{ .iterate = true });
    defer project.close(io);
    var diag: ?ziggit.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    var layout = try ziggit.discover(gpa, io, project, .{}, &diag);
    var repo = ziggit.Repository.open(gpa, io, layout, .{}, &diag) catch |err| {
        layout.deinit(io);
        return err;
    };
    defer repo.deinit();
    const base = try ziggit.resolve(gpa, &repo, opened.base_commit, &diag);
    const source_ref = try std.fmt.allocPrint(arena, "refs/chock/{s}", .{session_id});
    const tip = try repo.refs.resolve(source_ref, &diag);
    var diff = try ziggit.diffCommits(gpa, &repo.odb, base, tip, .{ .detect_copies = true }, &diag);
    defer diff.deinit(gpa);

    const files = try arena.alloc(ReviewWire.File, diff.patches.len);
    for (diff.patches, files) |patch, *file| {
        const hunks = try wireHunks(arena, patch.hunks);
        file.* = .{
            .path = try arena.dupe(u8, patch.new_path),
            .old_path = if (std.mem.eql(u8, patch.old_path, patch.new_path)) "" else try arena.dupe(u8, patch.old_path),
            .status = @tagName(patch.status),
            .binary = patch.binary,
            .atomic = !patchSupportsHunks(patch),
            .hunks = hunks,
        };
    }
    return std.json.Stringify.valueAlloc(arena, ReviewWire{
        .kind = .git,
        .base = opened.base_commit,
        .source = source_ref,
        .files = files,
    }, .{});
}

fn wireHunks(arena: std.mem.Allocator, source: []const ziggit.Hunk) ![]const ReviewWire.Hunk {
    const hunks = try arena.alloc(ReviewWire.Hunk, source.len);
    for (source, hunks, 1..) |hunk, *out, number| {
        const lines = try arena.alloc(ReviewWire.Line, hunk.lines.len);
        for (hunk.lines, lines) |line, *copy| copy.* = .{
            .origin = switch (line.origin) {
                .context => .context,
                .addition => .addition,
                .deletion => .deletion,
            },
            .text = try arena.dupe(u8, line.content),
        };
        out.* = .{
            .number = number,
            .header = try std.fmt.allocPrint(arena, "@@ -{d},{d} +{d},{d} @@", .{
                hunk.old_start,
                hunk.old_lines,
                hunk.new_start,
                hunk.new_lines,
            }),
            .lines = lines,
        };
    }
    return hunks;
}

test "review path selection recognizes either side of a rename" {
    const patch = ziggit.Patch{
        .old_path = "before.txt",
        .new_path = "after.txt",
        .status = .renamed,
    };
    try testing.expect(patchSelected(&.{"before.txt"}, patch));
    try testing.expect(patchSelected(&.{"after.txt"}, patch));
    try testing.expect(!patchSelected(&.{"another.txt"}, patch));
}

fn sayGitReviewFault(
    gpa: std.mem.Allocator,
    session_id: []const u8,
    doing: []const u8,
    err: anyerror,
    diag: *?ziggit.Diagnostic,
) void {
    tty.print(.err, "chock workspace review: {s} for session {s}: {s}", .{ doing, session_id, @errorName(err) });
    if (diag.*) |*fault| {
        if (fault.path) |path| tty.print(.err, ": {s}", .{path});
        if (fault.detail) |detail| tty.print(.err, ": {s}", .{detail});
        fault.deinit(gpa);
        diag.* = null;
    }
    tty.print(.err, ".\n", .{});
}

pub fn selectWorkspace(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    session_dir: []const u8,
    options: Options,
) u8 {
    const session_id = options.session orelse {
        tty.print(.err, "chock workspace select: name the session whose work you want to select.\n", .{});
        return Exit.usage.code();
    };
    if (!session_paths.isValidId(session_id)) {
        tty.print(.err, "chock workspace select: {s} is not a session identifier.\n", .{session_id});
        return Exit.usage.code();
    }
    for (options.paths) |path| if (!reviewPathIsSafe(path)) {
        tty.print(.err, "chock workspace select: {s} is not a project-relative path.\n", .{path});
        return Exit.usage.code();
    };
    for (options.rejected_paths) |path| if (!reviewPathIsSafe(path)) {
        tty.print(.err, "chock workspace select: {s} is not a project-relative path.\n", .{path});
        return Exit.usage.code();
    };
    // Hunk selectors are parsed and logged by the public contract now; their
    // application is handled below once a patch has ordinary text hunks.

    const log_path = std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, session_id }, 0) catch
        return Exit.faulted.code();
    switch (sessions_cmd.livenessOf(io, log_path)) {
        .idle => {},
        .live, .unknown => {
            tty.print(.err, "chock workspace select: session {s} may still be changing, so no selection was made.\n", .{session_id});
            return Exit.refused.code();
        },
    }
    const opened = lastWorkspaceOpen(arena, io, log_path, session_id) orelse {
        tty.print(.err, "chock workspace select: session {s} names no workspace.\n", .{session_id});
        return Exit.usage.code();
    };
    switch (opened.kind) {
        .overlay => return selectOverlay(arena, gpa, io, project_root, session_dir, session_id, opened, options, log_path),
        .worktree => {},
        .unknown => {
            tty.print(.err, "chock workspace select: that workspace kind is not understood.\n", .{});
            return Exit.usage.code();
        },
    }
    if (opened.base_commit.len == 0) {
        tty.print(.err, "chock workspace select: session {s} recorded no Git base commit.\n", .{session_id});
        return Exit.usage.code();
    }

    var project = std.Io.Dir.openDirAbsolute(io, project_root, .{ .iterate = true }) catch return Exit.faulted.code();
    defer project.close(io);
    var diag: ?ziggit.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    var layout = ziggit.discover(gpa, io, project, .{}, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the Git repository could not be found", err, &diag);
        return Exit.usage.code();
    };
    var repo = ziggit.Repository.open(gpa, io, layout, .{}, &diag) catch |err| {
        layout.deinit(io);
        sayGitReviewFault(gpa, session_id, "the Git repository could not be opened", err, &diag);
        return Exit.usage.code();
    };
    defer repo.deinit();
    const base = ziggit.resolve(gpa, &repo, opened.base_commit, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the recorded base commit could not be resolved", err, &diag);
        return Exit.usage.code();
    };
    const source_ref = std.fmt.allocPrint(arena, "refs/chock/{s}", .{session_id}) catch return Exit.faulted.code();
    const tip = repo.refs.resolve(source_ref, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the session ref could not be resolved", err, &diag);
        return Exit.usage.code();
    };
    var diff = ziggit.diffCommits(gpa, &repo.odb, base, tip, .{ .detect_copies = true }, &diag) catch |err| {
        sayGitReviewFault(gpa, session_id, "the session changes could not be read", err, &diag);
        return Exit.faulted.code();
    };
    defer diff.deinit(gpa);

    if (!selectorsExist(diff, options)) {
        tty.print(.err, "chock workspace select: a selector did not name a changed file or hunk.\n", .{});
        return Exit.usage.code();
    }

    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const hex = std.fmt.bytesToHex(nonce, .lower);
    const index_path = std.fmt.allocPrint(arena, "{s}/.{s}-{s}.index", .{ session_dir, session_id, &hex }) catch
        return Exit.faulted.code();
    defer std.Io.Dir.deleteFileAbsolute(io, index_path) catch {};
    var git_env = env.clone(arena) catch return Exit.faulted.code();
    defer git_env.deinit();
    git_env.put("GIT_INDEX_FILE", index_path) catch return Exit.faulted.code();
    git_env.put("GIT_AUTHOR_NAME", "Chock review") catch return Exit.faulted.code();
    git_env.put("GIT_AUTHOR_EMAIL", "review@chock.invalid") catch return Exit.faulted.code();
    git_env.put("GIT_COMMITTER_NAME", "Chock review") catch return Exit.faulted.code();
    git_env.put("GIT_COMMITTER_EMAIL", "review@chock.invalid") catch return Exit.faulted.code();

    _ = selectionGit(arena, io, &git_env, project_root, &.{ "read-tree", opened.base_commit }) catch return Exit.faulted.code();

    var files: usize = 0;
    var hunks: usize = 0;
    var binary_files: usize = 0;
    if (options.patch) |patch_file| {
        _ = selectionGit(arena, io, &git_env, project_root, &.{ "apply", "--cached", "--check", "--", patch_file }) catch return Exit.usage.code();
        _ = selectionGit(arena, io, &git_env, project_root, &.{ "apply", "--cached", "--", patch_file }) catch return Exit.faulted.code();
        const names = selectionGit(arena, io, &git_env, project_root, &.{ "diff", "--cached", "--name-only", opened.base_commit }) catch return Exit.faulted.code();
        var lines = std.mem.splitScalar(u8, names, '\n');
        while (lines.next()) |path| {
            if (path.len == 0) continue;
            var proposed = false;
            for (diff.patches) |candidate| if (patchSelected(&.{path}, candidate)) {
                proposed = true;
                if (candidate.binary) binary_files += 1;
                break;
            };
            if (!proposed) {
                tty.print(.err, "chock workspace select: edited patch path {s} was not part of the session proposal.\n", .{path});
                return Exit.usage.code();
            }
            files += 1;
        }
    } else {
        var partial_text: std.Io.Writer.Allocating = .init(gpa);
        defer partial_text.deinit();
        for (diff.patches) |patch| {
            if (wholePatchSelected(options, patch)) {
                applyWholePatch(arena, io, &git_env, project_root, patch) catch return Exit.faulted.code();
                files += 1;
                if (patch.binary) binary_files += 1;
                continue;
            }
            var chosen: std.ArrayList(ziggit.Hunk) = .empty;
            defer chosen.deinit(gpa);
            for (patch.hunks, 1..) |hunk, number| {
                if (!hunkSelected(options, patch, number)) continue;
                chosen.append(gpa, hunk) catch return Exit.faulted.code();
            }
            if (chosen.items.len == 0) continue;
            if (!patchSupportsHunks(patch)) {
                tty.print(
                    .err,
                    "chock workspace select: {s} can only be accepted or rejected as a whole file " ++
                        "because it is binary, renamed, deleted, a symlink, or changes mode.\n",
                    .{patch.new_path},
                );
                return Exit.usage.code();
            }
            var selected_patch = patch;
            selected_patch.hunks = chosen.items;
            selected_patch.writeUnified(&partial_text.writer) catch return Exit.faulted.code();
            files += 1;
            hunks += chosen.items.len;
        }
        if (partial_text.written().len != 0) {
            const patch_path = std.fmt.allocPrint(arena, "{s}.patch", .{index_path}) catch return Exit.faulted.code();
            defer std.Io.Dir.deleteFileAbsolute(io, patch_path) catch {};
            var patch_file = std.Io.Dir.createFileAbsolute(io, patch_path, .{ .exclusive = true }) catch return Exit.faulted.code();
            patch_file.writeStreamingAll(io, partial_text.written()) catch {
                patch_file.close(io);
                return Exit.faulted.code();
            };
            patch_file.close(io);
            _ = selectionGit(arena, io, &git_env, project_root, &.{ "apply", "--cached", "--check", "--", patch_path }) catch return Exit.usage.code();
            _ = selectionGit(arena, io, &git_env, project_root, &.{ "apply", "--cached", "--", patch_path }) catch return Exit.faulted.code();
        }
    }

    if (files == 0) {
        tty.print(.err, "chock workspace select: the selection accepts no changes.\n", .{});
        return Exit.usage.code();
    }

    const tree = selectionGit(arena, io, &git_env, project_root, &.{"write-tree"}) catch return Exit.faulted.code();
    const message = std.fmt.allocPrint(arena, "chock: selected changes from session {s}", .{session_id}) catch return Exit.faulted.code();
    const commit = selectionGit(arena, io, &git_env, project_root, &.{ "commit-tree", tree, "-p", opened.base_commit, "-m", message }) catch
        return Exit.faulted.code();
    const result_ref = std.fmt.allocPrint(arena, "refs/chock/selected/{s}", .{session_id}) catch return Exit.faulted.code();
    var previous = chock_workspace.git.run(arena, io, &git_env, project_root, &.{ "rev-parse", "--verify", result_ref }, null) catch
        return Exit.faulted.code();
    defer previous.deinit(arena);
    const expected = switch (previous.term) {
        .exited => |code| if (code == 0) std.mem.trimEnd(u8, previous.stdout, "\n") else "",
        else => "",
    };
    _ = selectionGit(arena, io, &git_env, project_root, &.{ "update-ref", result_ref, commit, expected }) catch return Exit.refused.code();

    const accepted = selectionNames(arena, options.paths, options.hunks) catch return Exit.faulted.code();
    const rejected = selectionNames(arena, options.rejected_paths, options.rejected_hunks) catch return Exit.faulted.code();
    recordSelection(arena, io, log_path, session_id, .{
        .source = source_ref,
        .result = result_ref,
        .result_commit = commit,
        .base_commit = opened.base_commit,
        .accepted = accepted,
        .rejected = rejected,
        .files = files,
        .hunks = hunks,
        .binary_files = binary_files,
        .edited_patch = options.patch != null,
    }) catch {
        if (expected.len == 0) {
            _ = selectionGit(arena, io, &git_env, project_root, &.{ "update-ref", "-d", result_ref, commit }) catch {};
        } else {
            _ = selectionGit(arena, io, &git_env, project_root, &.{ "update-ref", result_ref, expected, commit }) catch {};
        }
        tty.print(.err, "chock workspace select: the selection could not be written to the session audit log, so its ref was restored.\n", .{});
        return Exit.faulted.code();
    };
    tty.print(.plain, "chock workspace select: selected result {s} is at {s}.\n", .{ commit, result_ref });
    tty.out(.plain, "The checked-out branch was not moved. Undo with: chock workspace undo {s}\n", .{session_id});
    return Exit.finished.code();
}

fn wholePatchSelected(options: Options, patch: ziggit.Patch) bool {
    const explicit_accept = options.paths.len != 0 or options.hunks.len != 0;
    const accepted = if (explicit_accept)
        options.paths.len != 0 and patchSelected(options.paths, patch)
    else
        true;
    if (!accepted or (options.rejected_paths.len != 0 and patchSelected(options.rejected_paths, patch))) return false;
    for (options.rejected_hunks) |selector| if (patchSelected(&.{selector.path}, patch)) return false;
    return true;
}

fn hunkSelected(options: Options, patch: ziggit.Patch, number: usize) bool {
    if (options.rejected_paths.len != 0 and patchSelected(options.rejected_paths, patch)) return false;
    for (options.rejected_hunks) |selector| {
        if (selector.number == number and patchSelected(&.{selector.path}, patch)) return false;
    }
    if (options.paths.len != 0 and patchSelected(options.paths, patch)) return true;
    for (options.hunks) |selector| {
        if (selector.number == number and patchSelected(&.{selector.path}, patch)) return true;
    }
    return options.paths.len == 0 and options.hunks.len == 0;
}

fn patchSupportsHunks(patch: ziggit.Patch) bool {
    if (patch.binary or patch.status != .modified or patch.old_mode != patch.new_mode) return false;
    const mode = patch.new_mode orelse return false;
    return mode == .blob or mode == .blob_executable;
}

test "only ordinary text modifications expose hunk decisions" {
    const ordinary = ziggit.Patch{
        .old_path = "a",
        .new_path = "a",
        .status = .modified,
        .old_mode = .blob,
        .new_mode = .blob,
    };
    try testing.expect(patchSupportsHunks(ordinary));
    var special = ordinary;
    special.binary = true;
    try testing.expect(!patchSupportsHunks(special));
    special = ordinary;
    special.status = .renamed;
    try testing.expect(!patchSupportsHunks(special));
    special = ordinary;
    special.status = .deleted;
    try testing.expect(!patchSupportsHunks(special));
    special = ordinary;
    special.new_mode = .blob_executable;
    try testing.expect(!patchSupportsHunks(special));
    special = ordinary;
    special.new_mode = .symlink;
    special.old_mode = .symlink;
    try testing.expect(!patchSupportsHunks(special));
}

fn selectionNames(
    arena: std.mem.Allocator,
    paths: []const []const u8,
    hunks: []const HunkSelector,
) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    try names.appendSlice(arena, paths);
    for (hunks) |selector| {
        try names.append(arena, try std.fmt.allocPrint(arena, "{s}:{d}", .{ selector.path, selector.number }));
    }
    return names.toOwnedSlice(arena);
}

fn selectorsExist(diff: ziggit.Diff, options: Options) bool {
    for (options.paths) |path| {
        var found = false;
        for (diff.patches) |patch| if (patchSelected(&.{path}, patch)) {
            found = true;
            break;
        };
        if (!found) return false;
    }
    for (options.rejected_paths) |path| {
        var found = false;
        for (diff.patches) |patch| if (patchSelected(&.{path}, patch)) {
            found = true;
            break;
        };
        if (!found) return false;
    }
    for (options.hunks) |selector| if (!hunkExists(diff, selector)) return false;
    for (options.rejected_hunks) |selector| if (!hunkExists(diff, selector)) return false;
    return true;
}

fn hunkExists(diff: ziggit.Diff, selector: HunkSelector) bool {
    if (selector.number == 0) return false;
    for (diff.patches) |patch| {
        if (!patchSelected(&.{selector.path}, patch)) continue;
        return !patch.binary and selector.number <= patch.hunks.len;
    }
    return false;
}

fn applyWholePatch(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    patch: ziggit.Patch,
) !void {
    if (patch.status == .deleted or patch.status == .renamed) {
        _ = try selectionGit(arena, io, env, project_root, &.{ "update-index", "--force-remove", "--", patch.old_path });
    }
    if (patch.status == .deleted) return;
    var oid_buffer: [ziggit.Oid.max_formatted_length]u8 = undefined;
    const oid = patch.new_oid.?.toHex(&oid_buffer);
    const mode = try std.fmt.allocPrint(arena, "{o}", .{@backingInt(patch.new_mode.?)});
    _ = try selectionGit(arena, io, env, project_root, &.{ "update-index", "--add", "--cacheinfo", mode, oid, patch.new_path });
}

fn selectionGit(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    argv: []const []const u8,
) ![]const u8 {
    var output = try chock_workspace.git.run(arena, io, env, project_root, argv, null);
    defer output.deinit(arena);
    const code = switch (output.term) {
        .exited => |one| one,
        else => return error.GitDidNotExit,
    };
    if (code != 0) {
        tty.print(.err, "chock workspace select: Git refused the selection: {s}", .{output.stderr});
        return error.GitFailed;
    }
    return arena.dupe(u8, std.mem.trimEnd(u8, output.stdout, "\n"));
}

fn recordSelection(
    arena: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    session_id: []const u8,
    selected: chock_proto.event.WorkspaceSelect,
) !void {
    const log = try chock_proto.log.Log.open(io, log_path, session_id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};
    _ = try locked.append(arena, io, .{ .workspace_select = selected }, std.Io.Timestamp.now(io, .real).toMilliseconds());
}

pub const selected_dir_name = ".chock-selected";

fn selectOverlay(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    session_dir: []const u8,
    session_id: []const u8,
    opened: Opened,
    options: Options,
    log_path: [:0]const u8,
) u8 {
    if (options.patch != null) {
        tty.print(.err, "chock workspace select: edited patches require a Git workspace.\n", .{});
        return Exit.usage.code();
    }
    const work = std.fmt.allocPrint(arena, "{s}/{s}{s}", .{ session_dir, session_id, work_suffix }) catch return Exit.faulted.code();
    const scratch = std.fs.path.join(arena, &.{ work, opened.attempt }) catch return Exit.faulted.code();
    var diag: ?chock_workspace.Diagnostic = null;
    var overlay = chock_workspace.overlay.adopt(gpa, io, project_root, scratch, &diag) catch return Exit.usage.code();
    defer overlay.deinit(gpa);
    var report = overlay.changedFiles(gpa, io, &diag) catch return Exit.faulted.code();
    defer report.deinit(gpa);

    for (options.paths) |path| if (!overlayChanged(report.changed, path)) {
        tty.print(.err, "chock workspace select: {s} is not a changed selectable path.\n", .{path});
        return Exit.usage.code();
    };
    for (options.rejected_paths) |path| if (!overlayChanged(report.changed, path)) {
        tty.print(.err, "chock workspace select: {s} is not a changed selectable path.\n", .{path});
        return Exit.usage.code();
    };
    for (options.hunks) |selector| if (selector.number == 0 or !overlayChanged(report.changed, selector.path)) return Exit.usage.code();
    for (options.rejected_hunks) |selector| if (selector.number == 0 or !overlayChanged(report.changed, selector.path)) return Exit.usage.code();

    var selected: std.ArrayList([]const u8) = .empty;
    var partial: std.ArrayList(struct { path: []const u8, patch: ziggit.Patch }) = .empty;
    defer {
        for (partial.items) |*one| one.patch.deinit(gpa);
        partial.deinit(gpa);
    }
    const explicit = options.paths.len != 0 or options.hunks.len != 0;
    var selected_hunks: usize = 0;
    var binary_files: usize = 0;
    for (report.changed) |one| {
        const path_accept = pathSelected(options.paths, one.path) and options.paths.len != 0;
        const path_reject = options.rejected_paths.len != 0 and pathSelected(options.rejected_paths, one.path);
        var has_hunk_selector = false;
        for (options.hunks) |selector| if (std.mem.eql(u8, selector.path, one.path)) {
            has_hunk_selector = true;
            break;
        };
        var has_hunk_reject = false;
        for (options.rejected_hunks) |selector| if (std.mem.eql(u8, selector.path, one.path)) {
            has_hunk_reject = true;
            break;
        };
        if (path_reject or (explicit and !path_accept and !has_hunk_selector)) continue;
        if (!has_hunk_selector and !has_hunk_reject) {
            selected.append(arena, one.path) catch return Exit.faulted.code();
            continue;
        }
        if (one.kind != .modified) {
            tty.print(.err, "chock workspace select: {s} is file-atomic and has no selectable text hunks.\n", .{one.path});
            return Exit.usage.code();
        }
        const old_path = std.fs.path.join(arena, &.{ project_root, one.path }) catch return Exit.faulted.code();
        const new_path = std.fs.path.join(arena, &.{ overlay.upper, one.path }) catch return Exit.faulted.code();
        const old_bytes = std.Io.Dir.cwd().readFileAlloc(io, old_path, arena, .limited(16 * 1024 * 1024)) catch return Exit.usage.code();
        const new_bytes = std.Io.Dir.cwd().readFileAlloc(io, new_path, arena, .limited(16 * 1024 * 1024)) catch return Exit.usage.code();
        var patch = ziggit.diffBlobs(gpa, one.path, one.path, old_bytes, new_bytes, .{}) catch return Exit.usage.code();
        if (patch.binary) {
            patch.deinit(gpa);
            tty.print(.err, "chock workspace select: {s} is binary and must be decided as a whole file.\n", .{one.path});
            return Exit.usage.code();
        }
        for (options.hunks) |selector| if (std.mem.eql(u8, selector.path, one.path) and selector.number > patch.hunks.len) {
            patch.deinit(gpa);
            return Exit.usage.code();
        };
        for (options.rejected_hunks) |selector| if (std.mem.eql(u8, selector.path, one.path) and selector.number > patch.hunks.len) {
            patch.deinit(gpa);
            return Exit.usage.code();
        };
        var any = false;
        for (patch.hunks, 1..) |_, number| if (overlayHunkSelected(options, one.path, number)) {
            any = true;
            selected_hunks += 1;
        };
        if (!any) {
            patch.deinit(gpa);
            continue;
        }
        selected.append(arena, one.path) catch {
            patch.deinit(gpa);
            return Exit.faulted.code();
        };
        partial.append(gpa, .{ .path = one.path, .patch = patch }) catch {
            patch.deinit(gpa);
            return Exit.faulted.code();
        };
    }
    if (selected.items.len == 0) {
        tty.print(.err, "chock workspace select: the selection accepts no changes.\n", .{});
        return Exit.usage.code();
    }
    for (report.changed) |one| {
        if (one.kind == .deleted or !pathSelected(selected.items, one.path)) continue;
        const source_path = std.fs.path.join(arena, &.{ overlay.upper, one.path }) catch continue;
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, source_path, arena, .limited(16 * 1024 * 1024)) catch continue;
        if (std.mem.indexOfScalar(u8, bytes, 0) != null) binary_files += 1;
    }

    const root = std.fs.path.join(arena, &.{ project_root, selected_dir_name }) catch return Exit.faulted.code();
    const destination = std.fs.path.join(arena, &.{ root, session_id }) catch return Exit.faulted.code();
    const carried = overlay.carryOutSelected(gpa, io, destination, selected.items, &diag) catch |err| {
        if (err == error.WorkAlreadyCarriedOut) tty.print(.err, "chock workspace select: {s} already exists; undo it before replacing the selection.\n", .{destination});
        return Exit.refused.code();
    };
    var keep_result = false;
    defer if (!keep_result) std.Io.Dir.cwd().deleteTree(io, destination) catch {};
    for (partial.items) |one| {
        const old_path = std.fs.path.join(arena, &.{ project_root, one.path }) catch return Exit.faulted.code();
        const old_bytes = std.Io.Dir.cwd().readFileAlloc(io, old_path, arena, .limited(16 * 1024 * 1024)) catch return Exit.faulted.code();
        const contents = applySelectedHunks(arena, old_bytes, one.patch.hunks, options, one.path) catch return Exit.faulted.code();
        const target = std.fs.path.join(arena, &.{ destination, chock_workspace.overlay.carried_files_name, one.path }) catch return Exit.faulted.code();
        var file = std.Io.Dir.createFileAbsolute(io, target, .{ .truncate = true }) catch return Exit.faulted.code();
        defer file.close(io);
        file.writeStreamingAll(io, contents) catch return Exit.faulted.code();
    }
    const accepted = selectionNames(arena, options.paths, options.hunks) catch return Exit.faulted.code();
    const rejected = selectionNames(arena, options.rejected_paths, options.rejected_hunks) catch return Exit.faulted.code();
    recordSelection(arena, io, log_path, session_id, .{
        .source = scratch,
        .result = destination,
        .accepted = accepted,
        .rejected = rejected,
        .files = carried.files + carried.deleted,
        .hunks = selected_hunks,
        .binary_files = binary_files,
    }) catch {
        tty.print(.err, "chock workspace select: the selection could not be written to the session audit log, so its directory was removed.\n", .{});
        return Exit.faulted.code();
    };
    keep_result = true;
    tty.print(.plain, "chock workspace select: selected overlay work is in {s}.\n", .{destination});
    tty.out(.plain, "Nothing in the project was overwritten. Undo with: chock workspace undo {s}\n", .{session_id});
    return Exit.finished.code();
}

fn overlayChanged(changed: []const chock_workspace.overlay.ChangedFile, path: []const u8) bool {
    for (changed) |one| if (std.mem.eql(u8, one.path, path)) return true;
    return false;
}

fn overlayHunkSelected(options: Options, path: []const u8, number: usize) bool {
    for (options.rejected_hunks) |one| if (one.number == number and std.mem.eql(u8, one.path, path)) return false;
    if (options.paths.len != 0 and pathSelected(options.paths, path)) return true;
    for (options.hunks) |one| if (one.number == number and std.mem.eql(u8, one.path, path)) return true;
    return options.paths.len == 0 and options.hunks.len == 0;
}

fn applySelectedHunks(
    arena: std.mem.Allocator,
    old: []const u8,
    hunks: []const ziggit.Hunk,
    options: Options,
    path: []const u8,
) ![]const u8 {
    var old_lines: std.ArrayList([]const u8) = .empty;
    defer old_lines.deinit(arena);
    var start: usize = 0;
    for (old, 0..) |byte, at| if (byte == '\n') {
        try old_lines.append(arena, old[start .. at + 1]);
        start = at + 1;
    };
    if (start < old.len) try old_lines.append(arena, old[start..]);
    var out: std.ArrayList(u8) = .empty;
    var cursor: usize = 0;
    for (hunks, 1..) |hunk, number| {
        if (!overlayHunkSelected(options, path, number)) continue;
        const before = hunk.old_start -| 1;
        while (cursor < before and cursor < old_lines.items.len) : (cursor += 1) try out.appendSlice(arena, old_lines.items[cursor]);
        for (hunk.lines) |line| switch (line.origin) {
            .context => {
                try out.appendSlice(arena, line.content);
                cursor += 1;
            },
            .deletion => cursor += 1,
            .addition => try out.appendSlice(arena, line.content),
        };
    }
    while (cursor < old_lines.items.len) : (cursor += 1) try out.appendSlice(arena, old_lines.items[cursor]);
    return out.toOwnedSlice(arena);
}

test "selected overlay hunks preserve every unselected part of the base" {
    const old = "one\nold-a\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\neleven\ntwelve\nthirteen\nfourteen\nfifteen\nsixteen\nseventeen\nold-b\nnineteen\ntwenty\n";
    const changed = "one\nnew-a\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\neleven\ntwelve\nthirteen\nfourteen\nfifteen\nsixteen\nseventeen\nnew-b\nnineteen\ntwenty\n";
    var patch = try ziggit.diffBlobs(testing.allocator, "notes", "notes", old, changed, .{ .context_lines = 1 });
    defer patch.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), patch.hunks.len);
    const result = try applySelectedHunks(testing.allocator, old, patch.hunks, .{
        .hunks = &.{.{ .path = "notes", .number = 1 }},
    }, "notes");
    defer testing.allocator.free(result);
    try testing.expect(std.mem.indexOf(u8, result, "new-a") != null);
    try testing.expect(std.mem.indexOf(u8, result, "old-b") != null);
    try testing.expect(std.mem.indexOf(u8, result, "new-b") == null);
}

pub fn undoSelection(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    session_dir: []const u8,
    wanted: ?[]const u8,
) u8 {
    const session_id = wanted orelse return Exit.usage.code();
    if (!session_paths.isValidId(session_id)) return Exit.usage.code();
    const log_path = std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, session_id }, 0) catch return Exit.faulted.code();
    if (lastSelectionResult(arena, io, log_path, session_id)) |last_result| {
        const overlay_result = std.fs.path.join(arena, &.{ project_root, selected_dir_name, session_id }) catch return Exit.faulted.code();
        if (std.mem.eql(u8, last_result, overlay_result)) {
            const parked = std.fmt.allocPrint(arena, "{s}.undoing", .{overlay_result}) catch return Exit.faulted.code();
            if (std.Io.Dir.cwd().statFile(io, parked, .{ .follow_symlinks = false })) |_| {
                tty.print(.err, "chock workspace undo: the recovery path {s} is already occupied.\n", .{parked});
                return Exit.refused.code();
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => {
                    tty.print(.err, "chock workspace undo: the recovery path {s} is already occupied.\n", .{parked});
                    return Exit.refused.code();
                },
            }
            std.Io.Dir.renameAbsolute(overlay_result, parked, io) catch |err| {
                tty.print(.err, "chock workspace undo: {s} could not be isolated for removal: {s}.\n", .{ overlay_result, @errorName(err) });
                return Exit.refused.code();
            };
            recordSelection(arena, io, log_path, session_id, .{ .source = overlay_result, .result = "", .undone = true }) catch {
                std.Io.Dir.renameAbsolute(parked, overlay_result, io) catch {};
                tty.print(.err, "chock workspace undo: the removal could not be added to the session audit log.\n", .{});
                return Exit.faulted.code();
            };
            std.Io.Dir.cwd().deleteTree(io, parked) catch |err| {
                tty.print(.warn, "chock workspace undo: the result was undone, but temporary {s} could not be removed: {s}.\n", .{ parked, @errorName(err) });
            };
            tty.print(.plain, "chock workspace undo: removed {s}; the project was not changed.\n", .{overlay_result});
            return Exit.finished.code();
        }
    }
    const result_ref = std.fmt.allocPrint(arena, "refs/chock/selected/{s}", .{session_id}) catch return Exit.faulted.code();
    const previous = selectionGit(arena, io, env, project_root, &.{ "rev-parse", "--verify", result_ref }) catch return Exit.usage.code();
    _ = selectionGit(arena, io, env, project_root, &.{ "update-ref", "-d", result_ref, previous }) catch return Exit.refused.code();
    recordSelection(arena, io, log_path, session_id, .{ .source = result_ref, .result = "", .undone = true }) catch {
        _ = selectionGit(arena, io, env, project_root, &.{ "update-ref", result_ref, previous, "" }) catch {};
        tty.print(.err, "chock workspace undo: the removal could not be added to the session audit log.\n", .{});
        return Exit.faulted.code();
    };
    tty.print(.plain, "chock workspace undo: removed {s}; the checked-out branch was not changed.\n", .{result_ref});
    return Exit.finished.code();
}

fn lastSelectionResult(
    arena: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    session_id: []const u8,
) ?[]const u8 {
    const log = chock_proto.log.Log.open(io, log_path, session_id) catch return null;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);
    var replay = store.replay(arena, io, 0) catch return null;
    defer replay.deinit();
    var result: ?[]const u8 = null;
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .workspace_select) continue;
        const selected = parsed.value.event.workspace_select;
        result = if (selected.undone or selected.result.len == 0)
            null
        else
            arena.dupe(u8, selected.result) catch return null;
    }
    return result;
}

fn reviewOverlay(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    session_dir: []const u8,
    session_id: []const u8,
    attempt: []const u8,
    paths: []const []const u8,
) u8 {
    const work = std.fmt.allocPrint(arena, "{s}/{s}{s}", .{ session_dir, session_id, work_suffix }) catch
        return Exit.faulted.code();
    const scratch = std.fs.path.join(arena, &.{ work, attempt }) catch return Exit.faulted.code();
    var diag: ?chock_workspace.Diagnostic = null;
    var overlay = chock_workspace.overlay.adopt(arena, io, project_root, scratch, &diag) catch |err| {
        sayReviewFault(session_id, "the overlay could not be opened", err, diag);
        return Exit.usage.code();
    };
    defer overlay.deinit(arena);
    diag = null;
    var report = overlay.changedFiles(arena, io, &diag) catch |err| {
        sayReviewFault(session_id, "the overlay changes could not be read", err, diag);
        return Exit.faulted.code();
    };
    defer report.deinit(arena);
    std.mem.sort(chock_workspace.overlay.ChangedFile, report.changed, {}, struct {
        fn lessThan(_: void, left: chock_workspace.overlay.ChangedFile, right: chock_workspace.overlay.ChangedFile) bool {
            return std.mem.order(u8, left.path, right.path) == .lt;
        }
    }.lessThan);

    var shown: usize = 0;
    for (report.changed) |one| {
        if (!pathSelected(paths, one.path)) continue;
        tty.out(.plain, "{s} {s}\n", .{ switch (one.kind) {
            .added => "A",
            .modified => "M",
            .deleted => "D",
        }, one.path });
        if (one.kind == .modified) text: {
            const old_path = std.fs.path.join(arena, &.{ project_root, one.path }) catch break :text;
            const new_path = std.fs.path.join(arena, &.{ overlay.upper, one.path }) catch break :text;
            const old_stat = std.Io.Dir.cwd().statFile(io, old_path, .{ .follow_symlinks = false }) catch break :text;
            const new_stat = std.Io.Dir.cwd().statFile(io, new_path, .{ .follow_symlinks = false }) catch break :text;
            if (old_stat.kind != .file or new_stat.kind != .file or old_stat.permissions != new_stat.permissions) break :text;
            const old_bytes = std.Io.Dir.cwd().readFileAlloc(io, old_path, arena, .limited(16 * 1024 * 1024)) catch break :text;
            const new_bytes = std.Io.Dir.cwd().readFileAlloc(io, new_path, arena, .limited(16 * 1024 * 1024)) catch break :text;
            var patch = ziggit.diffBlobs(arena, one.path, one.path, old_bytes, new_bytes, .{}) catch break :text;
            defer patch.deinit(arena);
            var rendered: std.Io.Writer.Allocating = .init(arena);
            defer rendered.deinit();
            patch.writeUnified(&rendered.writer) catch break :text;
            tty.out(.plain, "{s}", .{rendered.written()});
        }
        shown += 1;
    }
    for (report.skipped) |one| {
        if (!pathSelected(paths, one.path)) continue;
        tty.print(.warn, "? {s}: {s}\n", .{ one.path, one.reason });
        shown += 1;
    }
    if (shown == 0) {
        tty.print(.plain, "chock workspace review: session {s} has no changes in this selection.\n", .{session_id});
    }
    return Exit.finished.code();
}

fn pathSelected(paths: []const []const u8, candidate: []const u8) bool {
    if (paths.len == 0) return true;
    for (paths) |path| {
        if (std.mem.eql(u8, path, candidate)) return true;
    }
    return false;
}

fn reviewPathIsSafe(path: []const u8) bool {
    if (path.len == 0 or std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) return false;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }
    return true;
}

fn sayReviewFault(
    session_id: []const u8,
    doing: []const u8,
    err: anyerror,
    diag: ?chock_workspace.Diagnostic,
) void {
    if (diag) |fault| {
        var held = fault;
        tty.print(.err, "chock workspace review: {s} for session {s}: {f}\n", .{ doing, session_id, &held });
        return;
    }
    tty.print(.err, "chock workspace review: {s} for session {s}: {s}\n", .{ doing, session_id, @errorName(err) });
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

    const selected = try parseOptions(arena, &.{
        "select",        "01JQAAAAAAAAAAAAAAAAAAAAAA",
        "--path",        "src/main.zig",
        "--hunk",        "src/other.zig:2",
        "--reject-path", "generated.bin",
        "--reject-hunk", "src/other.zig:3",
    });
    try testing.expectEqual(Action.select, selected.action);
    try testing.expectEqualStrings("src/main.zig", selected.paths[0]);
    try testing.expectEqualStrings("src/other.zig", selected.hunks[0].path);
    try testing.expectEqual(@as(usize, 2), selected.hunks[0].number);
    try testing.expectEqualStrings("generated.bin", selected.rejected_paths[0]);
    try testing.expectEqual(@as(usize, 3), selected.rejected_hunks[0].number);
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "select", "01JQAAAAAAAAAAAAAAAAAAAAAA", "--hunk", "file:0" }));
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "select", "01JQAAAAAAAAAAAAAAAAAAAAAA", "--patch", "one.diff", "--path", "one" }));

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
    try writeUnder(arena, io, project, "delete.txt", "delete me\n");
    try writeUnder(arena, io, project, "rename.txt", "rename me\n");
    try writeUnder(arena, io, project, "mode.sh", "#!/bin/sh\nexit 0\n");
    try writeUnder(arena, io, project, "binary.bin", "old\x00bytes");
    const link_path = try std.fs.path.join(arena, &.{ project, "current-link" });
    try std.Io.Dir.cwd().symLink(io, "one.txt", link_path, .{});

    var env = std.process.Environ.Map.init(arena);
    _ = try gitForTest(arena, io, &env, project, &.{"init"});
    _ = try gitForTest(arena, io, &env, project, &.{ "add", "--", "." });
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
    try writeUnder(arena, io, project, "binary.bin", "new\x00bytes");
    try std.Io.Dir.deleteFileAbsolute(io, link_path);
    try std.Io.Dir.cwd().symLink(io, "two.txt", link_path, .{});
    _ = try gitForTest(arena, io, &env, project, &.{ "rm", "--", "delete.txt" });
    _ = try gitForTest(arena, io, &env, project, &.{ "mv", "--", "rename.txt", "renamed.txt" });
    _ = try gitForTest(arena, io, &env, project, &.{ "add", "--", "." });
    _ = try gitForTest(arena, io, &env, project, &.{ "update-index", "--chmod=+x", "mode.sh" });
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
        reviewWorkspace(arena, testing.allocator, io, project, sessions, id, &.{"one.txt"}),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "one after") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "two after") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "diff --git a/one.txt b/one.txt") != null);

    const selected_code = selectWorkspace(arena, testing.allocator, io, &env, project, sessions, .{
        .action = .select,
        .session = id,
        .paths = &.{"one.txt"},
    });
    try testing.expectEqual(Exit.finished.code(), selected_code);
    const selected_ref = try std.fmt.allocPrint(arena, "refs/chock/selected/{s}", .{id});
    const selected_names = try gitForTest(arena, io, &env, project, &.{ "diff", "--name-only", base, selected_ref });
    try testing.expectEqualStrings("one.txt", selected_names);
    const selected_commit = try gitForTest(arena, io, &env, project, &.{ "rev-parse", selected_ref });
    const audit = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(64 * 1024));
    try testing.expect(std.mem.indexOf(u8, audit, selected_commit) != null);
    try testing.expectEqualStrings(base, try gitForTest(arena, io, &env, project, &.{ "rev-parse", "HEAD" }));

    try testing.expectEqual(Exit.finished.code(), undoSelection(arena, io, &env, project, sessions, id));
    var missing = try chock_workspace.git.run(arena, io, &env, project, &.{ "show-ref", "--verify", selected_ref }, null);
    defer missing.deinit(arena);
    try testing.expect(switch (missing.term) {
        .exited => |code| code != 0,
        else => false,
    });

    try testing.expectEqual(Exit.finished.code(), selectWorkspace(arena, testing.allocator, io, &env, project, sessions, .{
        .session = id,
        .hunks = &.{.{ .path = "one.txt", .number = 1 }},
    }));
    try testing.expectEqualStrings("one.txt", try gitForTest(arena, io, &env, project, &.{ "diff", "--name-only", base, selected_ref }));
    try testing.expectEqual(Exit.finished.code(), undoSelection(arena, io, &env, project, sessions, id));

    try testing.expectEqual(Exit.finished.code(), selectWorkspace(arena, testing.allocator, io, &env, project, sessions, .{
        .session = id,
        .paths = &.{ "delete.txt", "renamed.txt", "mode.sh", "current-link", "binary.bin" },
    }));
    const special_difference = try gitForTest(arena, io, &env, project, &.{
        "diff",       "--name-only", selected_ref,  result,    "--",
        "delete.txt", "rename.txt",  "renamed.txt", "mode.sh", "current-link",
        "binary.bin",
    });
    try testing.expectEqualStrings("", special_difference);
    try testing.expectEqual(Exit.finished.code(), undoSelection(arena, io, &env, project, sessions, id));

    const edited = try gitForTest(arena, io, &env, project, &.{ "diff", base, result, "--", "one.txt" });
    const edited_path = try std.fs.path.join(arena, &.{ project, "edited.patch" });
    const edited_with_newline = try std.fmt.allocPrint(arena, "{s}\n", .{edited});
    try writeUnder(arena, io, project, "edited.patch", edited_with_newline);
    try testing.expectEqual(Exit.finished.code(), selectWorkspace(arena, testing.allocator, io, &env, project, sessions, .{
        .session = id,
        .patch = edited_path,
    }));
    try testing.expectEqualStrings("one.txt", try gitForTest(arena, io, &env, project, &.{ "diff", "--name-only", base, selected_ref }));
    try testing.expectEqual(Exit.finished.code(), undoSelection(arena, io, &env, project, sessions, id));
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

test "review lists an overlay's changes without adopting or modifying the project" {
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
    const old_text = "one\nold-a\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\neleven\ntwelve\nthirteen\nfourteen\nfifteen\nsixteen\nseventeen\nold-b\nnineteen\ntwenty\n";
    const changed_text = "one\nnew-a\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\neleven\ntwelve\nthirteen\nfourteen\nfifteen\nsixteen\nseventeen\nnew-b\nnineteen\ntwenty\n";
    try writeUnder(arena, testing.io, project, "tracked.txt", old_text);

    const id = "01JQ" ++ @as([22]u8, @splat('V'));
    const attempt = "01JQ" ++ @as([22]u8, @splat('W'));
    const upper = try makeOverlaySession(arena, testing.io, root, id, attempt, .overlay);
    try writeUnder(arena, testing.io, upper, "tracked.txt", changed_text);
    try writeUnder(arena, testing.io, upper, "notes/new.md", "new\n");

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);
    try testing.expectEqual(
        Exit.finished.code(),
        reviewWorkspace(arena, testing.allocator, testing.io, project, root, id, &.{"notes/new.md"}),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "A notes/new.md") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "tracked.txt") == null);

    const original = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ project, "tracked.txt" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings(old_text, original);
    const adopted = try std.fmt.allocPrint(arena, "{s}/{s}", .{ project, adopted_dir_name });
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, adopted, .{}));

    var env = std.process.Environ.Map.init(arena);
    try testing.expectEqual(Exit.finished.code(), selectWorkspace(
        arena,
        testing.allocator,
        testing.io,
        &env,
        project,
        root,
        .{ .session = id, .paths = &.{"notes/new.md"} },
    ));
    const selected_file = try std.fs.path.join(arena, &.{ project, selected_dir_name, id, "files", "notes", "new.md" });
    const selected_bytes = try std.Io.Dir.cwd().readFileAlloc(testing.io, selected_file, arena, .limited(64));
    try testing.expectEqualStrings("new\n", selected_bytes);
    const unselected_file = try std.fs.path.join(arena, &.{ project, selected_dir_name, id, "files", "tracked.txt" });
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, unselected_file, .{}));
    try testing.expectEqual(Exit.finished.code(), undoSelection(arena, testing.io, &env, project, root, id));
    const selected_root = try std.fs.path.join(arena, &.{ project, selected_dir_name, id });
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, selected_root, .{}));

    try testing.expectEqual(Exit.finished.code(), selectWorkspace(
        arena,
        testing.allocator,
        testing.io,
        &env,
        project,
        root,
        .{ .session = id, .hunks = &.{.{ .path = "tracked.txt", .number = 1 }} },
    ));
    const partial_file = try std.fs.path.join(arena, &.{ selected_root, "files", "tracked.txt" });
    const partial_bytes = try std.Io.Dir.cwd().readFileAlloc(testing.io, partial_file, arena, .limited(4096));
    try testing.expect(std.mem.indexOf(u8, partial_bytes, "new-a") != null);
    try testing.expect(std.mem.indexOf(u8, partial_bytes, "old-b") != null);
    try testing.expect(std.mem.indexOf(u8, partial_bytes, "new-b") == null);
    try testing.expectEqual(Exit.finished.code(), undoSelection(arena, testing.io, &env, project, root, id));
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
