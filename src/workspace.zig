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
//!
//! ## `adopt` is how a project with no git gets its work back
//!
//! A git project already has one way out of a kept workspace: the session's
//! commits are real git objects in the project's own store and
//! `refs/chock/<session>` names them, so `git log` reads the work and `git
//! merge` takes it. Nothing of the person's moved, and the person decides.
//!
//! A project with no git got the overlay backing and had no way out at all.
//! The work is in the upper layer, which outlives the process that wrote it,
//! and no command reached it: `list` said how many bytes were there and `clear`
//! deleted them. So a person whose project is not a git repository, and whose
//! session died, had work on disk and one command that destroys it.
//!
//! `adopt` is the missing half. It rebuilds the overlay with
//! `chock_workspace.overlay.adopt`, and copies the changed files out to
//! `.chock-adopted/<session>/files` inside the project, beside a `deleted` file
//! naming every path the session removed. **It writes over nothing.** See
//! `chock_workspace.overlay.carryOut`, which holds the reasoning for the shape,
//! and `adoptWorkspace` below for every refusal.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");
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
    \\Usage: chock workspace [list|clear|adopt <session>] [options]
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
    /// Which workspace `adopt` takes. **Named by the person and never chosen
    /// here**: `list` is what says which sessions left one, and a command that
    /// picked for itself would write a directory into the project for a session
    /// nobody named.
    session: ?[]const u8 = null,
};

const Action = enum { list, clear, adopt };

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
    if (options.action == .adopt) {
        return adoptWorkspace(arena, io, kept, project_root, dir, options.session);
    }

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

        if (!saw_action) {
            options.action = std.meta.stringToEnum(Action, argument) orelse return error.BadArguments;
            saw_action = true;
            continue;
        }
        // The second word, and only `adopt` has one: it is the session whose
        // workspace is taken. A second word after any other action is a typo,
        // and a typo that is quietly ignored is the wrong workspace acted on.
        if (options.action != .adopt or options.session != null) return error.BadArguments;
        options.session = argument;
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

/// What `adopt` calls the directory it puts a session's work in, inside the
/// project. One directory per session under it.
///
/// **Inside the project, and named.** The git path lands the work inside the
/// project too, under its own `.git`, and that is what makes `git merge` one
/// step away. A directory somewhere else would be a path the person has to keep
/// hold of, and a directory under Chock's own state is a directory the next
/// `chock cache clear` or a tidy up of a state directory takes away.
pub const adopted_dir_name = ".chock-adopted";

/// Take the work out of one kept overlay workspace and put it in the project,
/// where the person can see it and decide.
///
/// ## Every refusal, and what each one is protecting
///
/// * **No session named.** `list` is what says which sessions left a workspace,
///   and this never picks one: a command that chose for itself would write a
///   directory into the project for a session nobody asked about.
/// * **A session that is running, or whose lock could not be tested.** The
///   same rule `clear` keeps and for a sharper reason: the agent is writing
///   into the upper layer at this moment, so a copy taken now is a copy of a
///   half written file. An absent answer is never a permissive answer.
/// * **A log that names no workspace.** That is a session from a build before
///   `workspace.open` existed. Nothing here can tell which attempt directory
///   held the overlay, and guessing at one would read a directory that belongs
///   to another run.
/// * **A workspace that is a git worktree.** The work is already in the
///   project's own object store at `refs/chock/<session>`, and this says so
///   rather than making a second copy of it that nothing keeps up to date. This
///   is what leaves the git path exactly as it was.
/// * **No overlay under the attempt directory.** `chock workspace clear` has
///   already been run, or the directory never held one.
/// * **A destination that already holds something.** See
///   `chock_workspace.overlay.carryOut`. Nothing at the destination is read or
///   written, and the upper layer still holds every byte, so naming another
///   destination gets the lot.
///
/// ## What lands in the log
///
/// One `workspace.adopt` event on the session's own log, with the attempt, the
/// destination, and the three counts. **Written only after the work is really
/// at the destination**, so a log that says an adoption happened is a log about
/// a directory that is there. The lock is taken for the append and given back,
/// which a running session would hold, and a running session is refused above.
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

    // The same rows `list` and `clear` read, so the three commands can never
    // disagree about which workspace a session still owns.
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
    // **Said even when it is zero**, because the reader has to learn that a
    // deletion is a thing this command never performs, and a line that only
    // appears sometimes teaches nobody that.
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

/// The row `list` already built for this session, or null when it built none.
fn findKept(kept: []const Kept, session_id: []const u8) ?Kept {
    for (kept) |one| {
        if (std.mem.eql(u8, one.session_id, session_id)) return one;
    }
    return null;
}

/// What one `workspace.open` in a session's log said, with the strings copied
/// into the caller's allocator.
const Opened = struct {
    kind: chock_proto.event.WorkspaceKind,
    attempt: []const u8,
};

/// The last `workspace.open` in the log of `session_id`, or null when the log
/// holds none, cannot be read, or names an attempt this build will not join
/// onto a path.
///
/// **The last one, and never the first.** A session that was continued has one
/// `workspace.open` per attempt, and an earlier one names a directory an
/// earlier run worked in. The last is the one that holds the work the session
/// ended with. The same rule `src/detach.zig`'s own `endedHandedOver` keeps for
/// the same reason.
///
/// A replay takes no lock. The caller has already refused a session that is
/// running, so the log is not moving under this.
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
        // **An identifier of another length is never joined onto a path**, the
        // rule `session.zig` keeps and the reason `isValidId` exists. A log a
        // later build wrote is still read for its kind, so the caller can say
        // it does not know that kind rather than say nothing.
        if (!session_paths.isValidId(opened.attempt)) continue;
        // Copied now: the replay owns these bytes only until the next line.
        const kind: chock_proto.event.WorkspaceKind = switch (opened.kind) {
            .worktree => .worktree,
            .overlay => .overlay,
            .unknown => |name| .{ .unknown = arena.dupe(u8, name) catch return null },
        };
        found = .{ .kind = kind, .attempt = arena.dupe(u8, opened.attempt) catch return null };
    }
    return found;
}

/// Write down what this adoption did, on the session's own log.
///
/// **Best effort, and said out loud when it fails.** The work is already at the
/// destination by the time this runs, and a log that could not be appended to
/// is not a reason to pretend the files are not there. What it is a reason for
/// is a line the person can read, because a log with no row is a session whose
/// history stops short of the last thing that happened to it.
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

/// One line naming the step, then the call that failed underneath it. The shape
/// `chock run` uses for the same pair, so a reader gets the command's own
/// sentence and never only a bare error name.
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

    // `adopt` is the one action with a second word, and that word is the
    // session. Mutation check: let any action take a second word and
    // `chock workspace clear 01J...` reads as a clear of everything, with the
    // session a person typed quietly ignored.
    const taking = try parseOptions(&.{ "adopt", "01JQAAAAAAAAAAAAAAAAAAAAAA" });
    try testing.expectEqual(Action.adopt, taking.action);
    try testing.expectEqualStrings("01JQAAAAAAAAAAAAAAAAAAAAAA", taking.session.?);
    try testing.expectEqual(@as(?[]const u8, null), (try parseOptions(&.{"adopt"})).session);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "clear", "01JQAAAAAAAAAAAAAAAAAAAAAA" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "adopt", "one", "two" }));

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

/// A session directory holding one session whose log names an overlay
/// workspace, with `upper` really on disk under the attempt directory.
///
/// Built out of the same pieces the real thing is: the log is a real
/// `chock_proto` log with a real `workspace.open` in it, so a change to that
/// event's own shape breaks this rather than letting it drift.
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
    // **An earlier attempt first, and its directory is never made.** A session
    // that was continued has one `workspace.open` per attempt, and a build that
    // read the first would open a directory that is not there. See
    // `lastWorkspaceOpen`.
    _ = try locked.append(arena, io, .{ .workspace_open = .{
        .kind = kind,
        .attempt = "01JQ" ++ "T" ** 22,
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

/// The one `workspace.adopt` row in the log of `id`, or null when there is
/// none. Read back through a real replay, because a test that checked only the
/// files would pass against a build that never wrote the row.
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

/// A whiteout at `<upper>/<relative>`: the character device 0,0 overlayfs
/// itself makes for a deleted path. An ordinary user may make one, so this
/// needs no namespace and no mount, and a machine that refuses it fails the
/// test rather than skipping it.
fn makeWhiteoutAt(arena: std.mem.Allocator, upper: []const u8, relative: []const u8) !void {
    const file_path = try std.fs.path.join(arena, &.{ upper, relative });
    const path_z = try arena.dupeZ(u8, file_path);
    const rc = std.os.linux.mknod(path_z.ptr, std.os.linux.S.IFCHR | 0o600, 0);
    try testing.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc));
}

test "an overlay a session left behind is adopted, and what it changed and what it deleted both arrive" {
    // **The whole gap, end to end.** A project with no git of its own, a
    // session that ended badly, and work in an upper layer that no command
    // reached. This is the command that reaches it.
    //
    // Three facts, and the second and third are the ones a file count alone
    // would hide: the changed file is at the destination, the deleted path is
    // named rather than acted on, and the log holds a row saying which.
    //
    // Mutation check: make `adoptWorkspace` read the first `workspace.open`
    // rather than the last and it opens an attempt directory that is not there.
    // Drop the `recordAdoption` call and the last block fails, so a session's
    // history would stop before the last thing that happened to it.
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

    const id = "01JQ" ++ "A" ** 22;
    const attempt = "01JQ" ++ "B" ** 22;
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

    // **The deletion is a name, and never an act.**
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
    // And the person's own copy of the changed file is what it was.
    const untouched = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try std.fs.path.join(arena, &.{ project, "tracked.txt" }),
        arena,
        .limited(4096),
    );
    try testing.expectEqualStrings("original\n", untouched);

    // What was said, so a person knows where the files are and that the
    // deletions are theirs to make.
    try testing.expect(std.mem.indexOf(u8, said.out(), destination) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "None of them was removed") != null);

    // **And the log says it happened**, the way `workspace.integrate` says what
    // an apply did.
    const row = (try adoptionRow(arena, testing.io, root, id)) orelse return error.NoAdoptionRecorded;
    try testing.expectEqualStrings(attempt, row.attempt);
    try testing.expectEqualStrings(destination, row.path);
    try testing.expectEqual(@as(u64, 2), row.files);
    try testing.expectEqual(@as(u64, 1), row.deleted);
    try testing.expectEqual(@as(u64, 0), row.skipped);
}

test "a session that worked in a git worktree is refused, and sent to the ref that already holds its work" {
    // **The git path is not changed, and is not copied either.** A worktree
    // session's commits are already objects in the project, and a second copy
    // of them in a directory would be a copy nothing keeps up to date. So this
    // says where the work is and stops.
    //
    // Mutation check: take the `.worktree` arm out and the command builds an
    // overlay path under a worktree checkout, finds no `upper`, and refuses
    // with a sentence about an overlay for a project that has none.
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

    const id = "01JQ" ++ "C" ** 22;
    const attempt = "01JQ" ++ "D" ** 22;
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

    // **And it wrote nothing into the project.** A refusal that had already
    // made a directory would be a refusal that acted.
    const adopted = try std.fmt.allocPrint(arena, "{s}/{s}", .{ project, adopted_dir_name });
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, adopted, .{}),
    );
    try testing.expectEqual(@as(?chock_proto.event.WorkspaceAdopt, null), try adoptionRow(arena, testing.io, root, id));
}

test "an adoption that would write over an earlier one is refused by name, and nothing is written over" {
    // **Not silent.** The destination may already hold a carry out a person has
    // edited since, and nothing can tell those files from the ones this would
    // write. So it names the path, says the work is still in the upper layer,
    // and stops.
    //
    // Mutation check: let `carryOut` merge into a destination that exists and
    // the file a person put there is gone with no word to anybody.
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

    const id = "01JQ" ++ "E" ** 22;
    const attempt = "01JQ" ++ "F" ** 22;
    const upper = try makeOverlaySession(arena, testing.io, root, id, attempt, .overlay);
    try writeUnder(arena, testing.io, upper, "tracked.txt", "the agent changed this\n");

    // An earlier adoption, with a person's own edit in it.
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
    // The upper layer is named too, so the person knows the work did not go.
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
    // Three ways to reach this command with nothing to act on. **None of them
    // picks a session**: a command that chose one for itself would write a
    // directory into the project for a session nobody asked about.
    //
    // Mutation check: make the null arm fall through to the newest kept
    // workspace and the first case adopts something the person never named.
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

    const id = "01JQ" ++ "G" ** 22;
    const attempt = "01JQ" ++ "H" ** 22;
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

    const never_ran = "01JQ" ++ "Z" ** 22;
    try testing.expectEqual(
        Exit.usage.code(),
        adoptWorkspace(arena, testing.io, kept, project, root, never_ran),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "left no workspace") != null);

    // Nothing was written into the project by any of the three.
    const adopted = try std.fmt.allocPrint(arena, "{s}/{s}", .{ project, adopted_dir_name });
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, adopted, .{}),
    );
}

test "a workspace whose overlay has already been cleared is refused, and the clearing is named" {
    // `chock workspace clear` removes the attempt directory and leaves the log
    // alone, so the log still names an overlay that is not there. The refusal
    // says which directory it looked in, because that is the one fact a person
    // needs to tell "cleared" from "this build looked in the wrong place".
    //
    // Mutation check: drop `error.NoOverlayToAdopt` from `overlay.adopt` and
    // this returns a success with zero files, which reads as "the session
    // changed nothing" for a session that may have changed everything.
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

    const id = "01JQ" ++ "K" ** 22;
    const attempt = "01JQ" ++ "M" ** 22;
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
