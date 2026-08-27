//! `chock detach`: hand a session to the daemon, which becomes its owner.
//!
//! ```
//! chock detach             # hand over the newest session of this project
//! chock detach <session>   # hand over that one
//! ```
//!
//! ## Ownership is the log's exclusive lock, so a handover is that lock moving
//!
//! The process that holds a session log's exclusive lock is the owner of that
//! session. So there is no transfer protocol to write and no new mechanism to
//! build. One process lets go, the next takes the lock, and it folds the log to
//! recover what the last owner held. **The fold is already the truth of a
//! session**: compaction, `chock usage`, `chock plan` and `chock sessions` all
//! rebuild state that way, and `chock_core.Loop.run` folds the log at its own
//! start before it appends anything.
//!
//! This command is the person's end of that. It holds no lock, writes nothing to
//! any log, and asks `chock daemon` to run the new owner. The daemon starts
//! `chock run --adopt`, which is the child that actually takes the lock.
//!
//! ## A running session is asked, and it answers at its next turn boundary
//!
//! This command used to refuse a running session by name, and it named the two
//! things that were missing: the loop stopping at a turn boundary on somebody
//! else's word, and a workspace another process can take. **Both are built
//! now**, so a running session is asked rather than refused.
//!
//! The ask goes over `<session dir>/<id>.ctl/h`, beside the approval socket and
//! under the same rules: the socket carries a question and an answer and never
//! a log write. See `chock_broker.handover`, which holds the whole exchange and
//! the reason it takes two round trips. The session answers only at a turn
//! boundary, so this command waits, and a session in the middle of a long turn
//! simply does not answer yet.
//!
//! ## What a running session holds, and what really becomes of each part
//!
//! | What a running session holds | What happens to it |
//! |---|---|
//! | The workspace | **It moves.** The last owner leaves the directory, the log names it, and the next owner adopts it: see below. |
//! | The scratchpad | **It moves.** Keyed by session under `TMPDIR`, so the next owner builds the same path. A run that handed over does not remove it. |
//! | A tool call in flight | **Cannot exist here.** A turn boundary is the point where every tool result of the last turn is already in the log. |
//! | A language server helper | Ends with the process. The new owner starts one on demand, so nothing is lost. |
//! | A background command | **Refuses the handover while one runs.** Its thread is in that process and only that process writes its `task.complete`. |
//! | A live subagent | **Refuses the handover while one runs.** The child has its own log and outlives the parent, but the parent is what writes the `agent.complete` that pairs with the `session.spawn` already in the log. |
//!
//! The last two are the rows that are still losses, and the answer is a
//! refusal, not a silent handover: `chock_broker.handover.Endpoint.look` names
//! the counts and the session carries on. **A handover that claimed to carry
//! them would be a lie**, which is the same reason this command refused
//! everything before.
//!
//! ## The window between one owner and the next, and what is really in it
//!
//! Between the last owner letting go and the new owner taking the lock, any
//! process may take that lock. **Nothing prevents that, and nothing should
//! pretend to.** What matters is what it costs:
//!
//! * **Two owners at once are impossible.** `flock(2)` refuses the second
//!   asker, and `chock_proto.log.Log.lock` turns that refusal into `error.Busy`
//!   at once rather than blocking. That property is the kernel's, not this
//!   command's, and `test/proto/lock.zig` pins it with a real second process.
//! * **A race this command loses is a sentence and not a loss.** The log is
//!   whole at every moment of the handover, because the last owner wrote its
//!   `session.end` before it let go. Whoever won owns a session that is intact,
//!   `chock sessions` says who is running, and the session can change hands
//!   again later.
//!
//! **A live handover has a wider window than a stopped one, and this is what
//! the extra width costs.** A stopped session's window is between this command
//! testing the lock and the daemon's child taking it. A live one adds the time
//! the first owner needs to finish its turn and end its run, which is unbounded
//! from here: a turn is as long as a model call plus its tool calls.
//!
//! What a third process winning that race costs is still one sentence, and the
//! reason is the workspace. The workspace is named by the log, not by this
//! command, so whoever takes the lock adopts the same directory and the same
//! base commit. A third process is then a different owner than the person
//! expected, doing the same work on the same files, and `chock detach` reports
//! that the daemon would not take the session. **Nothing is lost and nothing is
//! done twice**, because two owners cannot exist at once.
//!
//! `waitForEnd` is what keeps this command out of the first part of that
//! window: it waits for the session's own socket to close, which happens after
//! `Loop.run` has released the lock. So this command never asks the daemon to
//! adopt a session whose first owner still holds it.
//!
//! **The ask cannot be taken back, so everything that can refuse runs before
//! it.** A session that agreed has ended. Finding out afterwards that the
//! workspace does not move, or that no daemon is listening, would leave a
//! person with a running session stopped for nothing. So `reportMovableWorkspace`
//! and `reportDaemonListening` both run first. A daemon can still go away in
//! the moment between the two connects, and `stoppedNote` is what says so: a
//! failure after the ask names the fact that the session has already stopped
//! and that `chock run --continue` takes it back.
//!
//! ## The workspace moves, and the log is what carries it
//!
//! `src/run.zig` gives every run a workspace under a fresh attempt identifier,
//! and writes a `workspace.open` event naming that identifier, the directory,
//! and the commit the checkout started at. A run that hands over leaves the
//! directory on disk, and the next owner folds that event and calls
//! `chock_workspace.Workspace.adopt` on the same path.
//!
//! **Measured, by hand, with real git**: a linked worktree holds nothing about
//! the process that made it. The registration is two path pointers, `.git` in
//! the checkout and `gitdir` under `.git/worktrees/<name>`, and there is no
//! pid, no lock file, and no held descriptor anywhere in it. A second process
//! wrote, staged, and committed in a worktree another process created, with no
//! handover step at all. So taking a workspace costs no git command; what it
//! costs is the two facts a second process cannot derive, and the log carries
//! both.
//!
//! **A session that ended some other abnormal way also keeps its workspace**,
//! per `src/run.zig`'s own `cleanupFor`, and that one is still refused by name:
//! this task built the live handover and did not change what an adoption does
//! with a crashed session's leftovers. The refusal points at `chock workspace`,
//! which is the command that lists those directories and removes them.
//!
//! ## Where the daemon is
//!
//! **A unix socket in the state directory, by default.** This command used to
//! reach `127.0.0.1:7373` and nothing else, and that was the only reason
//! `chock daemon` kept a TCP listener in its own default set. Loopback TCP
//! names no peer, so every account on the machine could drive that daemon.
//!
//! So this speaks `chock_proto.control.Address`, which `chock serve` already
//! speaks: `unix:/path` or `host:port`, from `--daemon`, from `$CHOCK_DAEMON`,
//! or from the state directory. `--port <n>` is still here and it means a
//! daemon on loopback at that port, which only a `chock daemon --host` has.
//!
//! ## Answering a detached session
//!
//! `chock daemon` does not relay approvals. A session it owns opens the same
//! unix socket every session opens, at `<session dir>/<id>.ctl/s`, and that
//! path is built from the project and the identifier alone. So `chock approve
//! <id>` in the same project reaches a detached session exactly as it reaches
//! one in a terminal, and this command says so on the way out. **On the same
//! machine**: the socket is a unix socket, and a remote transport is not built.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const sessions_cmd = @import("sessions.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const control = chock_proto.control;

/// The longest answer this reads from the daemon. One line, `ok` or `error`,
/// and the daemon's own reasons are sentences.
pub const max_answer_bytes: usize = 8 * 1024;

const usage_text =
    \\Usage: chock detach [<session>] [options]
    \\
    \\Hands a session to the daemon, which becomes its owner and carries it on
    \\with no terminal. With no session, hands over the newest one of this project.
    \\
    \\The daemon has to be running already. Start one with `chock daemon`.
    \\
    \\A session that is still running is asked, and it answers at its next turn
    \\boundary, so this waits. A session running a background command or a
    \\background subagent refuses, because neither of those moves to another
    \\process. Its workspace and its scratchpad do move.
    \\
    \\Options:
    \\  --project <dir>    The project. Defaults to the current directory.
    \\  --daemon <address> Where the daemon is. `unix:/path` or `host:port`.
    \\                     Default is the socket in the state directory, or
    \\                     $CHOCK_DAEMON when that is set.
    \\  --port <n>         A daemon on 127.0.0.1 at this port, which is the same
    \\                     as `--daemon 127.0.0.1:<n>`. Only a daemon started with
    \\                     --host listens on one.
    \\  --wait <seconds>   How long to wait for a running session to reach a turn
    \\                     boundary. Default 300. A session that does not answer in
    \\                     time keeps running, unchanged.
    \\
++ tty.options_text;

/// How long this waits for a running session to answer, when nobody says
/// otherwise.
///
/// **Five minutes, because a turn is as long as a model call plus its tool
/// calls**, and a build inside one turn is minutes on its own. A shorter
/// default would report "did not reach a turn boundary" for healthy sessions,
/// and that refusal costs nothing but it wastes the person's time. Waiting
/// longer costs nothing either: the session runs the whole time, and Ctrl-C on
/// this command leaves it running.
pub const default_patience_ms: u64 = 300_000;

const Options = struct {
    project: ?[]const u8 = null,
    /// The address a person typed, unparsed. Null for the default, which is the
    /// socket in the state directory.
    daemon: ?[]const u8 = null,
    /// A port on loopback, which is `--daemon 127.0.0.1:<n>` written shorter.
    /// Null when nobody named one.
    port: ?u16 = null,
    session: []const u8 = "",
    patience_ms: u64 = default_patience_ms,
};

/// Where the daemon is, from what the person typed and what the environment
/// says. Null once the reason has been said.
///
/// **The default is a unix socket, and it always was the right one.** This
/// command used to reach `127.0.0.1:7373` and nothing else, which is the only
/// reason `chock daemon` kept a TCP listener in its default set. Loopback TCP
/// names no peer, so that default made a daemon every local account could
/// drive. See `src/daemon.zig`.
///
/// The order is what a person expects: a flag beats the environment, and the
/// environment beats the default. `chock serve` resolves its own daemon the
/// same way and from the same `$CHOCK_DAEMON`.
fn daemonAddress(
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    options: Options,
) std.mem.Allocator.Error!?control.Address {
    if (options.port) |port| {
        if (options.daemon != null) {
            tty.print(
                .err,
                "chock detach: --daemon and --port both name where the daemon is. Write one of " ++
                    "them.\n",
                .{},
            );
            return null;
        }
        return .{ .ip = .{ .host = control.default_host, .port = port } };
    }

    const text = options.daemon orelse env.get(control.address_env) orelse {
        const state = chock_auth.paths.stateDir(arena, env) catch |err| {
            tty.print(.err, "chock detach: the state directory could not be found: {t}\n", .{err});
            return null;
        };
        const path = try control.socketPathIn(arena, state);
        return .{ .unix = path };
    };

    return control.Address.parse(text) catch |err| {
        tty.print(
            .err,
            "chock detach: \"{s}\" is not a daemon address ({t}). Write `unix:/path` or " ++
                "`host:port`.\n",
            .{ text, err },
        );
        return null;
    };
}

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

    const daemon = try daemonAddress(arena, &env, options) orelse return Exit.usage.code();

    const project_root = resolveProject(arena, io, options.project) catch {
        tty.print(.err, "chock detach: the project directory could not be read.\n", .{});
        return Exit.usage.code();
    };

    const id = try chooseSession(arena, io, &env, project_root, options) orelse return Exit.usage.code();

    var paths = session_paths.pathsFor(arena, &env, project_root, id) catch |err| {
        tty.print(.err, "chock detach: the session path could not be built: {t}\n", .{err});
        return Exit.usage.code();
    };
    defer paths.deinit();

    // **A running session is asked, and only then tested again.** A session
    // that agreed to hand over lets go of the lock a moment later, so the
    // readiness test below is the one that has to see it free, and it can only
    // see that after the ask. See `askRunningSession`.
    // Whether a running session was asked to stop, which changes what the
    // failures further down mean: see `report`.
    var stopped_for_this = false;

    switch (sessions_cmd.readinessOf(gpa, io, paths.log, id)) {
        .running => {
            // **Before the ask, because a refusal after a session has stopped
            // is a session stopped for nothing.** See `reportMovableWorkspace`.
            if (!reportMovableWorkspace(gpa, io, paths.log, id)) return Exit.usage.code();
            // **And this is here for the same reason.** The ask cannot be taken
            // back: a session that agreed has ended. Finding out afterwards
            // that there is no daemon to give it to would leave a running
            // session stopped for nothing at all, which is the one outcome a
            // person would not forgive. So the daemon is proved to be there
            // first.
            //
            // It can still go away in the moment between, and `report` says so
            // by name when it does.
            if (!reportDaemonListening(io, daemon, id)) return Exit.usage.code();
            switch (askRunningSession(arena, io, paths.dir, id, options.patience_ms)) {
                .handed_over => stopped_for_this = true,
                // The session finished on its own while this waited. It is now
                // an ordinary stopped session, so it takes the ordinary checks:
                // its workspace was kept by `cleanupFor` for its own reasons
                // and this command has always refused that.
                .ended => {
                    if (!reportReadiness(gpa, io, paths.log, id)) return Exit.usage.code();
                    if (!endedHandedOver(gpa, io, paths.log)) {
                        if (!reportKeptWorkspace(gpa, io, paths.work, id)) return Exit.usage.code();
                    }
                },
                // Every other answer is a session that is still somebody
                // else's, and `askRunningSession` has already said which one it
                // is and what to do about it.
                else => return Exit.usage.code(),
            }
        },
        // Everything else is the stopped session this command always handled,
        // and `reportReadiness` says which case it is.
        else => {
            if (!reportReadiness(gpa, io, paths.log, id)) return Exit.usage.code();
            // **Not for a session that handed over, whose workspace is on disk
            // on purpose and is the thing that moves.**
            //
            // A live handover reaches this on a second run of the command, and
            // a second run is exactly what `stoppedNote` tells a person to do
            // when the daemon went away. Without this test that advice sent
            // them into a refusal about the work their own handover had just
            // preserved, which was measured on a real session on 2026-08-23.
            if (!endedHandedOver(gpa, io, paths.log)) {
                if (!reportKeptWorkspace(gpa, io, paths.work, id)) return Exit.usage.code();
            }
        },
    }

    // Measured before the handover, so the last line this prints is true. See
    // `answerableAt`.
    var socket_paths = chock_broker.socket.pathsFor(arena, paths.dir, id) catch |err| {
        tty.print(.err, "chock detach: the approval socket path could not be built: {t}\n", .{err});
        return Exit.usage.code();
    };
    defer socket_paths.deinit();

    return handOver(
        io,
        project_root,
        id,
        daemon,
        answerableAt(socket_paths.socket),
        stopped_for_this,
    );
}

/// Whether a daemon is listening at `address`. Says so when there is not.
///
/// **A connect and nothing else.** This asks no question, because the answer it
/// wants is only whether there is somebody to ask later. `handOver` opens its
/// own connection and does the real exchange; the daemon reads a line from this
/// one, finds the end of the stream, and drops it, which is the same thing a
/// client that was interrupted leaves.
///
/// **Nothing here knows which transport it got.** A unix socket and a TCP host
/// are two values of one `control.Address`, and the connect is the only place
/// that tells them apart.
fn reportDaemonListening(io: std.Io, address: control.Address, id: []const u8) bool {
    const stream = address.connect(io) catch |err| {
        // **A refusal that is not "nobody is there" says what it really was.**
        // A socket this user may not open is not a daemon nobody started, and
        // telling a person to start one would send them round a loop.
        if (err != error.NotListening) {
            tty.print(
                .err,
                "chock detach: the daemon at {f} could not be reached ({t}), so session {s} was " ++
                    "not handed over and it was not asked to stop. It is still running.\n",
                .{ address, err, id },
            );
            return false;
        }
        tty.print(
            .err,
            "chock detach: nothing is listening on {f} ({t}), so there is no daemon to hand " ++
                "session {s} to, and it was not asked to stop. It is still running. Start a " ++
                "daemon with `chock daemon`, and then run this again.\n",
            .{ address, err, id },
        );
        return false;
    };
    stream.close(io);
    return true;
}

/// Whether a session at this socket path can be answered at all.
///
/// **This is measured, and it was found by hand on Darwin.** A unix socket path
/// is bounded at 103 bytes there and 107 on Linux, see `max_socket_path`, and a
/// session directory below a deep home spends more than that. The session then
/// runs with no approval socket, says so on its own standard error, and a person
/// who ran this command never sees that line: `chock daemon` inherits the
/// child's standard error, and the person is at a different terminal.
///
/// So this command reads the same bound and tells the truth in its own closing
/// line. **It is not a refusal.** A session with no socket still runs, and a
/// question it cannot ask anybody is refused, which is already the safe
/// direction.
fn answerableAt(socket_path: []const u8) bool {
    _ = chock_proto.control.unixAddress(socket_path) catch return false;
    return true;
}

/// The longest unix socket path this machine really accepts.
///
/// **The body is `chock-proto/control.zig`'s.** This file held a second copy of
/// the number until 2026-08-25, and a bound that guards a memory fault is the
/// last thing that may exist twice.
const max_socket_path: usize = chock_proto.control.max_socket_path;

/// The session this hands over, or null when there is none and the reason has
/// been said.
fn chooseSession(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    options: Options,
) std.mem.Allocator.Error!?[]const u8 {
    if (options.session.len != 0) {
        if (!session_paths.isValidId(options.session)) {
            tty.print(.err, "chock detach: {s} is not a session identifier.\n", .{options.session});
            return null;
        }
        return options.session;
    }
    const newest = session_paths.newestId(arena, io, env, project_root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            tty.print(.err, "chock detach: the newest session could not be found: {t}\n", .{err});
            return null;
        },
    } orelse {
        tty.print(.err, "chock detach: this project has no session to hand over.\n", .{});
        return null;
    };
    return try arena.dupe(u8, &newest);
}

/// Whether this session's last ending was a handover.
///
/// **A workspace on disk means two different things**, and only the log tells
/// them apart. A session that crashed left one behind and an adoption would
/// leave that work where it is, so it is refused. A session that handed over
/// left one on purpose and the next owner adopts it, so refusing that one would
/// refuse the very thing this command had just arranged.
///
/// A log this cannot read answers false, which is the refusing side: naming a
/// workspace that may hold work is the safe direction.
fn endedHandedOver(gpa: std.mem.Allocator, io: std.Io, log_path: [:0]const u8) bool {
    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch return false;
    const log = chock_proto.log.Log.open(io, log_path, "") catch return false;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return false;
    defer replay.deinit();

    // **The last one, and never the first.** A session that changed hands and
    // then ran on has an earlier `handed_over` in its log that says nothing
    // about how it ended this time.
    var handed_over = false;
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        handed_over = parsed.value.event.session_end.reason == .handed_over;
    }
    return handed_over;
}

/// Whether the running session's workspace is one another process can take.
/// Says why it is not, when it is not.
///
/// **Asked before the session is, and this order is the whole point.** A
/// session that stopped and then met a refusal here would have stopped for
/// nothing: the ask cannot be taken back, and the person would be left with a
/// session that has ended and nobody owning it.
///
/// A project with no git of its own gets the overlay backing, and that one does
/// not move yet. The upper layer survives the process that made it, so nothing
/// is lost by rebuilding, but `overlay.create` cannot be called a second time
/// on the same scratch directory: the Linux driver refuses a directory that
/// already exists and Darwin's clone refuses the same. What is missing is an
/// `overlay.adopt` beside `overlay.create`, one per driver, and until it exists
/// a handover of one of those sessions would leave the agent's work in a
/// directory the next owner never opens.
///
/// **A log that says nothing about a workspace is not a refusal.** That is a
/// session from a build before `workspace.open` existed, and the next owner
/// does with it exactly what it always did.
fn reportMovableWorkspace(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
) bool {
    const log = chock_proto.log.Log.open(io, log_path, "") catch return true;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    // A replay takes no lock, which is what makes this safe against a session
    // that is running: see `chock_broker.socket.Waiter`, which reads the same
    // log the same way from inside the process that holds the lock.
    var replay = store.replay(gpa, io, 0) catch return true;
    defer replay.deinit();

    // The tag alone, and never the value: an `unknown` kind carries a string
    // borrowed from a replay that has already ended by the time this is read.
    var kind: ?std.meta.Tag(chock_proto.event.WorkspaceKind) = null;
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .workspace_open) continue;
        kind = std.meta.activeTag(parsed.value.event.workspace_open.kind);
    }

    const found = kind orelse return true;
    if (found == .worktree) return true;
    tty.print(
        .err,
        "chock detach: session {s} works in a {s} workspace, and only a git worktree moves to " ++
            "another process yet. Stop it with Ctrl-C first: a session that has stopped is handed " ++
            "over the way it always was, and its work stays where it is.\n",
        .{ id, @tagName(found) },
    );
    return false;
}

/// How far the ask to a running session got.
///
/// **A member for each place the exchange can stop, and not a boolean.** Only
/// one of them lets this command carry on, and the rest are different things
/// for a person to do about it. A boolean would also make the tests below say
/// nothing: every failure reads as false, so a build that answered the wrong
/// failure would pass every one of them.
const Asked = enum {
    /// The session agreed, confirmed, and let go of the log lock. **The only
    /// answer that lets this command ask the daemon for anything.**
    handed_over,
    /// Nothing is listening. The session is running under a build with no
    /// handover socket, or its session directory makes a path too long for one.
    not_listening,
    /// The session never reached a turn boundary in time. It is running
    /// normally and nothing about it has changed.
    silent,
    /// The session's run ended on its own while this waited, so nobody owns it
    /// now. **Not a failure**: the session that was running is now a session
    /// that has stopped, which is the case this command has always handled.
    ended,
    /// The session said no, and said why. It is running normally.
    refused,
    /// The session answered something this build cannot read.
    unreadable,
    /// The session agreed and then did not confirm that it is stopping.
    /// **Whether it is still running is unknown**, which is why this is not
    /// `silent`.
    uncertain,
    /// The session agreed, confirmed, and has not let go of the lock yet.
    still_holding,
};

/// Ask a running session to stop at its next turn boundary, and wait for it to
/// let go.
///
/// **Every step of this can stop, and each stop leaves the session running
/// normally.** That is the whole promise of the exchange: this command never
/// changes anything about a session that did not agree, in that order, to be
/// changed. See `chock_broker.handover` for the two round trips and why the
/// confirm is what makes a client that gave up safe.
fn askRunningSession(
    arena: std.mem.Allocator,
    io: std.Io,
    session_dir: []const u8,
    id: []const u8,
    patience_ms: u64,
) Asked {
    var paths = chock_broker.handover.pathsFor(arena, session_dir, id) catch {
        tty.print(.err, "chock detach: the handover socket path could not be built.\n", .{});
        return .not_listening;
    };
    defer paths.deinit();

    const address = chock_proto.control.unixAddress(paths.socket) catch {
        // **The refusal is here and not at `connect`.** A path over the bound
        // reaches an `@memcpy` past the end of `sun_path`, see
        // `max_socket_path`, and one under it that still failed to connect
        // would get the sentence below about nothing listening, which sends a
        // person looking for a session that was never able to open a socket.
        tty.print(
            .err,
            "chock detach: session {s} is running, and its session directory makes a handover " ++
                "socket path longer than a unix socket allows, so it opened none. Stop it with " ++
                "Ctrl-C and run this again, or give Chock a shorter state directory.\n",
            .{id},
        );
        return .not_listening;
    };
    const stream = address.connect(io) catch {
        // **The old refusal, and it is still the right one here.** A running
        // session with no handover socket is one built before this existed, or
        // one whose socket could not be opened. Either way nothing can ask it.
        tty.print(
            .err,
            "chock detach: session {s} is running and is not listening for a handover, so it " ++
                "cannot be taken from the process that owns it. Stop it first with Ctrl-C, which " ++
                "writes the session end, and then run this again.\n",
            .{id},
        );
        return .not_listening;
    };
    defer stream.close(io);

    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(stream.socket.handle, &answers);
    if (!client.sendAsk()) {
        tty.print(.err, "chock detach: session {s} closed the connection before it was asked.\n", .{id});
        return .not_listening;
    }

    // A turn is as long as a model call plus its tool calls, so this is the
    // wait a person sees. Said out loud, because a command that goes quiet for
    // a minute reads as a command that has hung.
    tty.detail(
        "chock detach: waiting for session {s} to reach a turn boundary.\n",
        .{id},
    );

    switch (client.readOffer(patience_ms)) {
        .offered => {},
        .busy => |said| {
            tty.print(
                .err,
                "chock detach: session {s} will not hand over: {s}\n",
                .{ id, said },
            );
            return .refused;
        },
        // **Nothing changed, and this says so.** The session never answered
        // `ready`, so it never got a `take`, so it cannot stop later for an ask
        // this command has given up on.
        .silent => {
            tty.print(
                .err,
                "chock detach: session {s} did not reach a turn boundary in time, so it was not " ++
                    "handed over and it is still running normally. Give it longer with " ++
                    "--wait <seconds>, or stop it with Ctrl-C.\n",
                .{id},
            );
            return .silent;
        },
        // **Said out loud, and not silently retried.** A person who asked to
        // move a running session should learn that it finished on its own,
        // because what happens to its work is a different thing from here on:
        // a session that ended is handed over the way it always was.
        .ended => {
            tty.detail(
                "chock detach: session {s} ended on its own while this waited, so it is handed " ++
                    "over the way a stopped session always was.\n",
                .{id},
            );
            return .ended;
        },
        .unreadable => |said| {
            tty.print(
                .err,
                "chock detach: session {s} answered something this build cannot read ({s}), so it " ++
                    "was not handed over.\n",
                .{ id, said },
            );
            return .unreadable;
        },
    }

    if (!client.sendTake()) {
        tty.print(
            .err,
            "chock detach: session {s} closed the connection before it was told to hand over, so " ++
                "it is still running.\n",
            .{id},
        );
        return .uncertain;
    }
    switch (client.readFinal(patience_ms)) {
        .handed_over => {},
        else => {
            // **Never reported as a handover.** A session that agreed and then
            // said nothing may still be running, and telling a person their
            // session moved would send them looking for it in the wrong place.
            tty.print(
                .err,
                "chock detach: session {s} did not confirm that it is stopping, so whether it is " ++
                    "still running is unknown. `chock sessions` says which sessions are running.\n",
                .{id},
            );
            return .uncertain;
        },
    }

    // **The one event that orders the two processes.** The session closes this
    // socket after `Loop.run` has released the log's exclusive lock, so the end
    // of this stream is proof the lock is free. See `Client.waitForEnd`.
    if (!client.waitForEnd(patience_ms)) {
        tty.print(
            .err,
            "chock detach: session {s} agreed to hand over and has not let go yet. It is writing " ++
                "its session end. Run this again in a moment; `chock sessions` says which " ++
                "sessions are running.\n",
            .{id},
        );
        return .still_holding;
    }
    return .handed_over;
}

/// Whether the session may change hands. Says why it may not, in this command's
/// own words. See `sessions_cmd.readinessOf` for the one reading all three
/// commands share, and for why none of it is what stops two owners.
fn reportReadiness(gpa: std.mem.Allocator, io: std.Io, log_path: [:0]const u8, id: []const u8) bool {
    switch (sessions_cmd.readinessOf(gpa, io, log_path, id)) {
        .ready => return true,
        .no_such_session => tty.print(
            .err,
            "chock detach: this project has no session {s}. `chock sessions` lists the ones it " ++
                "does have.\n",
            .{id},
        ),
        .nothing_to_carry_on => tty.print(
            .err,
            "chock detach: session {s} holds no conversation to carry on from, so there is " ++
                "nothing for the daemon to take over.\n",
            .{id},
        ),
        // **Reached only by a session that took the lock back after it was
        // asked**, because `main` sends a running session down
        // `askRunningSession` instead. That is a race this command lost: the
        // first owner let go and something else took it. See this file's own
        // top comment on the window.
        .running => tty.print(
            .err,
            "chock detach: session {s} is running now, and a session is not taken from the " ++
                "process that owns it. Another process took it between this one asking and the " ++
                "daemon being told. `chock sessions` says which sessions are running.\n",
            .{id},
        ),
        .unknown => tty.print(
            .err,
            "chock detach: session {s} could not be read, or its lock could not be tested, so " ++
                "it was not handed over.\n",
            .{id},
        ),
    }
    return false;
}

/// Whether the session's workspace is empty enough to hand over. Says what is in
/// it when it is not.
///
/// **A session that ended badly keeps its workspace**, per `src/run.zig`'s own
/// `cleanupFor`, and an adopted session builds a new one from the project's
/// committed state. So the work in a kept workspace would stay on disk with
/// nothing pointing at it. See this file's own top comment.
fn reportKeptWorkspace(gpa: std.mem.Allocator, io: std.Io, work_path: []const u8, id: []const u8) bool {
    const size = chock_core.cache.measure(gpa, io, work_path, std.math.maxInt(u64));
    if (size.files == 0) return true;
    tty.print(
        .err,
        "chock detach: session {s} left a workspace at {s}, which still holds work: {d} files, " ++
            "{d} bytes. A session the daemon adopts builds a new workspace from the project's " ++
            "committed state, the same way `chock run --continue` does, so that work would be " ++
            "left where it is. Take what you want out of it first. `chock workspace` lists it " ++
            "and removes it.\n",
        .{ id, work_path, size.files, size.bytes },
    );
    return false;
}

/// Ask the daemon to adopt the session, and report what it answered.
fn handOver(
    io: std.Io,
    project_root: []const u8,
    id: []const u8,
    address: control.Address,
    answerable: bool,
    /// Whether this command asked a running session to stop to get here. Every
    /// failure below then means something worse: the session has already
    /// ended and nobody owns it. See `stoppedNote`.
    stopped_for_this: bool,
) anyerror!u8 {
    const note = stoppedNote(stopped_for_this);

    // **A handover with nothing to hand to is a plain refusal that names what
    // to do.** Not a silent success, and not a wait: a client that hung here
    // would look exactly like a daemon that was thinking about it.
    const stream = address.connect(io) catch |err| {
        // The same split `reportDaemonListening` keeps: a daemon nobody started
        // and a daemon this user may not reach are two different things to do
        // something about.
        if (err != error.NotListening) {
            tty.print(
                .err,
                "chock detach: the daemon at {f} could not be reached ({t}), so session {s} was " ++
                    "not handed over.{s}\n",
                .{ address, err, id, note },
            );
            return Exit.usage.code();
        }
        tty.print(
            .err,
            "chock detach: nothing is listening on {f} ({t}), so there is no daemon to hand " ++
                "session {s} to. Start one with `chock daemon`, and then run this again.{s}\n",
            .{ address, err, id, note },
        );
        return Exit.usage.code();
    };
    defer stream.close(io);

    var write_buffer: [4 * 1024]u8 = undefined;
    var stream_writer = stream.writer(io, &write_buffer);
    const writer = &stream_writer.interface;

    var read_buffer: [max_answer_bytes]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buffer);
    const reader = &stream_reader.interface;

    // **The greeting first, and the session is not offered until it agrees.** A
    // daemon speaking another control protocol number must not be handed a
    // session it may read differently, and this command is the one place where
    // a wrong reading loses work: the session has already stopped.
    const agreement = control.handshake(reader, writer, control.protocol_version) catch {
        tty.print(
            .err,
            "chock detach: the daemon closed the connection before it was asked.{s}\n",
            .{note},
        );
        return Exit.faulted.code();
    };
    if (!agreement.ok()) {
        reportHandshake(address, agreement, id, note);
        return Exit.usage.code();
    }

    (control.Request{ .adopt = .{ .project = project_root, .session = id } }).write(writer) catch {
        tty.print(
            .err,
            "chock detach: the daemon closed the connection before it was asked.{s}\n",
            .{note},
        );
        return Exit.faulted.code();
    };
    writer.flush() catch {
        tty.print(
            .err,
            "chock detach: the daemon closed the connection before it was asked.{s}\n",
            .{note},
        );
        return Exit.faulted.code();
    };

    const line = (reader.takeDelimiter('\n') catch null) orelse {
        tty.print(
            .err,
            "chock detach: the daemon said nothing about session {s}.{s}\n",
            .{ id, note },
        );
        return Exit.faulted.code();
    };

    return report(line, id, answerable, note);
}

/// Say why the daemon and this build did not agree on a control protocol
/// number, and that the session was not handed over.
///
/// **Nothing was done to the session**, and the line says so: a person whose
/// session has already stopped for this handover needs to know it is waiting for
/// an owner rather than gone. The two numbers come from
/// `control.handshakeRefusal`, which is the one place they are spelled.
fn reportHandshake(
    address: control.Address,
    said: control.Handshake,
    id: []const u8,
    note: []const u8,
) void {
    var buffer: [max_answer_bytes]u8 = undefined;
    var text = std.Io.Writer.fixed(&buffer);
    control.handshakeRefusal(&text, address, said) catch {};
    // **The session first, and the reason after it.** A person reading this
    // needs to know what happened to their work before they need to know which
    // end to update, and the far end's own words are the last thing on the line
    // because they carry their own full stop.
    tty.print(
        .err,
        "chock detach: session {s} was not handed over.{s} {s}\n",
        .{ id, note, std.mem.trimEnd(u8, text.buffered(), "\n") },
    );
}

/// What to add to a failure when a running session was stopped to reach it.
///
/// **A failure after the ask is worse than the same failure before it**, and
/// the difference has to be on screen. Before the ask, a person's session is
/// still running and they lost nothing. After it, the session has ended, its
/// log is whole, its workspace is on disk, and nobody owns it. The two read
/// identically without this, and a person who did not know the difference would
/// walk away from a session that is waiting for an owner.
fn stoppedNote(stopped_for_this: bool) []const u8 {
    if (!stopped_for_this) return "";
    return " Session already stopped at a turn boundary for this handover, so nothing owns it " ++
        "now. Its work is safe: the log is whole and the workspace is on disk. " ++
        "`chock run --continue` in this project takes it back, and so does another " ++
        "`chock detach` once a daemon is running.";
}

/// Turn the daemon's one line into what a person reads and an exit code a
/// script reads. Its own function so a test can drive every answer without a
/// daemon.
///
/// **An answer this build cannot read is a failure and never a success.** A
/// daemon that answered something else did not say it took the session, and
/// reporting a handover that may not have happened is the worst of the three.
fn report(line: []const u8, id: []const u8, answerable: bool, note: []const u8) u8 {
    const answer = std.mem.trimEnd(u8, line, "\r");
    if (std.mem.startsWith(u8, answer, "ok ")) {
        const rest = answer["ok ".len..];
        const tab = std.mem.indexOfScalar(u8, rest, '\t');
        const log_path = if (tab) |at| rest[at + 1 ..] else "";
        tty.out(.plain, "chock detach: the daemon owns session {s} now.\n", .{id});
        if (log_path.len != 0) tty.detail("chock detach: log {s}\n", .{log_path});
        // **What a person has to do next, and only when it is true.** The daemon
        // relays no approvals, so a question this session asks is answered with
        // `chock approve`, on this machine: see this file's own top comment. A
        // session whose socket path does not fit says the other thing instead,
        // because naming a command that cannot work is worse than naming none.
        if (answerable) {
            tty.out(
                .plain,
                "chock detach: answer its questions with `chock approve {s}`, on this machine.\n",
                .{id},
            );
        } else {
            tty.print(
                .warn,
                "chock detach: nobody can answer session {s}. Its session directory makes an " ++
                    "approval socket path longer than a unix socket allows, so it opens none, and " ++
                    "every question it asks is refused. Give Chock a shorter state directory to " ++
                    "change that.\n",
                .{id},
            );
        }
        return Exit.finished.code();
    }
    if (std.mem.startsWith(u8, answer, "error ")) {
        tty.print(
            .err,
            "chock detach: the daemon would not take session {s}: {s}{s}\n",
            .{ id, answer["error ".len..], note },
        );
        return Exit.usage.code();
    }
    tty.print(
        .err,
        "chock detach: the daemon answered something this build cannot read, so whether it " ++
            "took session {s} is unknown. `chock sessions` says which sessions are running.{s}\n",
        .{ id, note },
    );
    return Exit.faulted.code();
}

/// The same resolution `src/approve.zig` and `src/plan.zig` do, and for the same
/// reason: a session directory is keyed on the project's real path, so two names
/// for one directory must not be two projects.
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

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--project")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.project = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--daemon")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.daemon = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--port")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.port = std.fmt.parseInt(u16, args[index], 10) catch return error.BadArguments;
            continue;
        }
        if (std.mem.eql(u8, argument, "--wait")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            // Seconds on the command line and milliseconds inside, because a
            // person writing a wait writes seconds and every socket call takes
            // milliseconds. Zero is allowed: it asks once and reports whatever
            // the session has already said.
            const seconds = std.fmt.parseInt(u32, args[index], 10) catch return error.BadArguments;
            options.patience_ms = @as(u64, seconds) * 1000;
            continue;
        }
        if (std.mem.startsWith(u8, argument, "-")) return error.BadArguments;
        // A second positional is a person who meant something else, and guessing
        // which of the two they meant is worse than saying so. The same rule
        // `chock approve` keeps.
        if (options.session.len != 0) return error.BadArguments;
        options.session = argument;
    }
    return options;
}

const testing = std.testing;

/// A temporary directory for one test, short enough to hold a session's own
/// sockets.
///
/// **`std.testing.tmpDir` makes its directory below the build directory, and
/// on macos that is too deep for a unix socket.** A unix socket path is bounded
/// by the whole path and not by any one part of it: see `max_socket_path`. A
/// session directory carries `/<26 character identifier>.ctl/h`, which is 33
/// bytes before the directory itself is counted.
///
/// Measured on 2026-08-25 on an Apple Silicon Mac, macOS 15.7.9, by binding the
/// exact path shape in each place:
///
/// * Outside a Nix build, with the tree in the person's home, the path was 95
///   bytes and `bind` took it.
/// * Inside a Nix build the build directory was
///   `/nix/var/nix/builds/nix-<pid>-<number>/source`, the same path was 112
///   bytes, and `bind` refused it.
/// * Inside a Nix build on Linux the build directory is `/build/source` and the
///   path is 78 bytes, nowhere near the bound. That is why only macos inside a
///   Nix build ever showed this, and why the two apart both looked healthy.
///
/// So this makes its directory directly below `TMPDIR`. That is 90 bytes inside
/// a Nix build on macos, so the tests below **run** there rather than skip.
/// `open` still gives up when even that is too long, and the test skips, which
/// is the honest answer on a machine that can hold no session socket at all.
const ShortTmp = struct {
    dir: std.Io.Dir,
    parent_dir: std.Io.Dir,
    sub_path: [sub_path_len]u8,
    /// The whole path of `dir`. **Symbolic links are left alone.** What is
    /// bounded is the string `bind` gets, and resolving `/var` to
    /// `/private/var` on macos only makes that string longer.
    whole: [std.fs.max_path_bytes]u8,
    whole_len: usize,

    /// The same count `std.testing.tmpDir` uses, so a name here is as unlikely
    /// to collide as one there.
    const random_bytes_count = 12;
    const sub_path_len = std.base64.url_safe.Encoder.calcSize(random_bytes_count);

    fn path(self: *const ShortTmp) []const u8 {
        return self.whole[0..self.whole_len];
    }

    /// Make the directory, or answer `error.SkipZigTest` when no session socket
    /// could live in it.
    fn open(io: std.Io) !ShortTmp {
        const root = root: {
            const given = std.process.Environ.getPosix(testing.environ, "TMPDIR") orelse "/tmp";
            const trimmed = std.mem.trimEnd(u8, given, "/");
            break :root if (trimmed.len == 0) "/" else trimmed;
        };

        var self: ShortTmp = undefined;
        var random_bytes: [random_bytes_count]u8 = undefined;
        io.random(&random_bytes);
        _ = std.base64.url_safe.Encoder.encode(&self.sub_path, &random_bytes);

        const whole = std.fmt.bufPrint(&self.whole, "{s}/{s}", .{ root, &self.sub_path }) catch
            return error.SkipZigTest;
        self.whole_len = whole.len;

        // **Asked before anything is made, and asked of the same call the
        // command asks.** `answerableAt` is what `chock detach` reads to decide
        // whether a session can be answered at all, so a skip here is a skip at
        // exactly the point the product itself says no.
        var probe: [std.fs.max_path_bytes]u8 = undefined;
        const longest = std.fmt.bufPrint(
            &probe,
            "{s}/{s}" ++ chock_broker.socket.dir_suffix ++ "/" ++ chock_broker.handover.socket_name,
            .{ whole, "0" ** 26 },
        ) catch return error.SkipZigTest;
        // A skip needs no message: a test that writes to standard error and
        // passes still puts a `failed command:` line in the build log. The
        // reason is the comment above this call.
        if (!answerableAt(longest)) return error.SkipZigTest;

        self.parent_dir = try std.Io.Dir.cwd().openDir(io, root, .{});
        errdefer self.parent_dir.close(io);
        self.dir = try self.parent_dir.createDirPathOpen(io, &self.sub_path, .{});
        return self;
    }

    fn cleanup(self: *ShortTmp, io: std.Io) void {
        self.dir.close(io);
        self.parent_dir.deleteTree(io, &self.sub_path) catch {};
        self.parent_dir.close(io);
        self.* = undefined;
    }
};

test "a running session that will not answer is refused, and it keeps running normally" {
    // **The mid turn refusal, and the promise that goes with it.** A session
    // answers only at a turn boundary, and a turn is as long as a model call
    // plus its tool calls. So a person who asks during one waits, gives up, and
    // must be left with a session that is exactly as it was.
    //
    // Two facts, and the second is the one that would be a real loss: the ask
    // is refused, **and** the session can still hand over to somebody who waits
    // long enough. A refusal that left the socket wedged would make a session
    // that nobody can ever move.
    //
    // Mutation check: make `askRunningSession` answer true on `.silent`, and
    // `chock detach` asks the daemon to adopt a session whose owner never
    // agreed and still holds the lock.
    const gpa = testing.allocator;
    const io = testing.io;
    // `ShortTmp` and not `testing.tmpDir`: this test opens a real socket in the
    // directory, and the reason that needs a short path is written there.
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session_dir = tmp.path();
    const id = "01JQ" ++ "R" ** 22;

    // A running session, listening, and in the middle of a turn: it opens the
    // socket and never looks at it.
    const paths = try chock_broker.handover.pathsFor(arena, session_dir, id);
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);
    defer endpoint.close(io);

    // What the command wrote, captured rather than let through: a test that
    // let it reach the terminal would not be reading it, and it would put a
    // `failed command:` line in the build log of a suite that passed. See
    // `tty.Capture`, and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    // A patience of zero is a poll that does not wait, so this test states a
    // budget and measures no time at all.
    try testing.expectEqual(Asked.silent, askRunningSession(arena, io, session_dir, id, 0));
    // **And it says the session is still running, and names the flag that
    // waits longer.** A refusal that only said no would leave a person unsure
    // whether their session survived the attempt.
    try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "still running") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--wait") != null);
    try testing.expectEqualStrings("", said.out());

    // **And the session is untouched.** Its next turn boundary answers the ask
    // that is still in the socket, finds no confirm, and carries on. Then a
    // client that does wait gets the session.
    try testing.expectEqual(
        chock_broker.handover.Decision.carry_on,
        endpoint.look(io, .{}, 0),
    );

    const address = try chock_proto.control.unixAddress(paths.socket);
    const patient = try address.connect(io);
    defer patient.close(io);
    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(patient.socket.handle, &answers);
    // The first client is still in the slot, holding it, so this one is turned
    // away rather than taken. That is the state a person who gave up leaves,
    // and it is why the peer is dropped when the exchange ends.
    try testing.expectEqual(chock_broker.handover.Decision.carry_on, endpoint.look(io, .{}, 0));
    try testing.expect(client.sendAsk());
}

test "a workspace that does not move yet is refused before the session is ever asked" {
    // **Order, and it is the whole reason this check exists separately.** The
    // ask cannot be taken back: a session that agreed has stopped. So a refusal
    // that arrived after the ask would leave a person with a session that ended
    // and nobody owning it. Only a git worktree moves today, so this reads the
    // log and refuses an overlay workspace first.
    //
    // Mutation check: let the overlay case through and a project with no git of
    // its own hands over into a workspace the next owner never opens, which is
    // every uncommitted change in it stranded.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];
    const id = "01JQ" ++ "W" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    defer gpa.free(log_path);

    // See the first test in this file for why every command's lines are
    // captured rather than let through.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    const kinds = [_]chock_proto.event.WorkspaceKind{ .worktree, .overlay };
    for (kinds) |kind| {
        said.clear();
        tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        var locked = try store.lock(io);
        // A fixed time and never a clock: nothing this test reads is a time.
        _ = try locked.append(gpa, io, .{ .workspace_open = .{
            .kind = kind,
            .attempt = "01JQ" ++ "B" ** 22,
            .path = "/state/somewhere",
            .base_commit = "a1b2c3",
        } }, 1);
        try locked.unlock(io);
        store.close(io);

        try testing.expectEqual(
            kind == .worktree,
            reportMovableWorkspace(gpa, io, log_path, id),
        );
        if (kind == .worktree) {
            // A workspace that moves says nothing at all: a healthy path is
            // quiet.
            try testing.expectEqualStrings("", said.err());
        } else {
            // **And the refusal names the kind and what to do instead.** "It
            // cannot move" with no reason reads as a fault in Chock rather than
            // as a limit a person can work around.
            try testing.expect(std.mem.indexOf(u8, said.err(), "overlay") != null);
            try testing.expect(std.mem.indexOf(u8, said.err(), "Ctrl-C") != null);
        }
        try testing.expectEqualStrings("", said.out());
    }

    // **A log that names no workspace is not a refusal.** That is a session
    // from a build before `workspace.open` existed, and refusing it would stop
    // `chock detach` working on sessions it always worked on.
    tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
    }
    try testing.expect(reportMovableWorkspace(gpa, io, log_path, id));
}

test "a running session with no handover socket is refused, and not waited on" {
    // A session started by a build with no handover socket, or one whose socket
    // could not be opened, is a session nothing can ask. That has to read as a
    // refusal with an instruction, and never as a wait: a client that hung here
    // would look exactly like a session thinking about it.
    //
    // Mutation check: fall through to a success when the connect fails, and
    // `chock detach` reports a handover of a session that never heard the ask.
    const gpa = testing.allocator;
    const io = testing.io;
    // `ShortTmp` and not `testing.tmpDir`: what this measures is the refusal
    // for a socket **nothing is listening on**, and a directory too deep for a
    // socket at all gets a different sentence. See `ShortTmp`.
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // See the first test in this file for why the lines are captured.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    // Nothing is listening: no endpoint was ever opened on this path.
    try testing.expectEqual(
        Asked.not_listening,
        askRunningSession(arena, io, tmp.path(), "01JQ" ++ "N" ** 22, 0),
    );
    // **And the instruction is on the line.** This is the refusal that would
    // otherwise read as a wait, so it has to say the session is running, that
    // nothing is listening, and what to do about it.
    try testing.expect(std.mem.indexOf(u8, said.err(), "is running") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "not listening") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "Ctrl-C") != null);
    try testing.expectEqualStrings("", said.out());
}

test "a live handover moves the lock, and never lets two processes hold it at once" {
    // **The fact the whole command rests on, driven over the real exchange.**
    // The exclusive lock on the log is the ownership of the session, so a live
    // handover is that lock moving from one process to the next, with no moment
    // in which both hold it.
    //
    // Every piece here is the real one: a real log with a real `flock`, a real
    // unix socket, and the real client steps `askRunningSession` runs. The
    // steps are apart so the endpoint can look between them, which is what a
    // turn boundary is, and so this test needs no thread and no clock.
    //
    // Mutation check: release the lock before the session answers `handing
    // over`, and the "still held" line below stops holding, which is a window
    // in which the last owner is still writing and the next one has started.
    const gpa = testing.allocator;
    const io = testing.io;
    // `ShortTmp` and not `testing.tmpDir`: this test opens a real socket in the
    // directory, and the reason that needs a short path is written there.
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const session_dir = tmp.path();
    const id = "01JQ" ++ "K" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, id }, 0);

    const first_log = try chock_proto.log.Log.open(io, log_path, id);
    var first_backing = chock_proto.storage.JsonLines{ .log = first_log };
    const first_store = first_backing.storage();
    var first_locked = try first_store.lock(io);
    const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
    _ = try first_locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);

    const paths = try chock_broker.handover.pathsFor(arena, session_dir, id);
    var endpoint = try chock_broker.handover.Endpoint.open(io, paths, null);

    // While it runs, nobody else may have it, and `chock detach` reads exactly
    // that.
    try testing.expectEqual(sessions_cmd.Readiness.running, sessions_cmd.readinessOf(gpa, io, log_path, id));

    const address = try chock_proto.control.unixAddress(paths.socket);
    const stream = try address.connect(io);
    defer stream.close(io);
    var answers: [chock_broker.handover.max_frame_bytes]u8 = undefined;
    var client = chock_broker.handover.Client.over(stream.socket.handle, &answers);

    try testing.expect(client.sendAsk());
    // The turn boundary. Nothing is in flight, so the session agrees.
    try testing.expectEqual(chock_broker.handover.Decision.carry_on, endpoint.look(io, .{}, 0));
    try testing.expectEqual(chock_broker.handover.Offer.offered, client.readOffer(0));
    try testing.expect(client.sendTake());
    try testing.expectEqual(chock_broker.handover.Decision.hand_over, endpoint.look(io, .{}, 0));
    try testing.expectEqual(chock_broker.handover.Answer.handed_over, client.readFinal(0));

    // **Still held, and this is the line that matters.** The session has agreed
    // and has not finished. A client that acted here would be racing the last
    // owner's own `session.end`.
    try testing.expectEqual(sessions_cmd.Readiness.running, sessions_cmd.readinessOf(gpa, io, log_path, id));
    try testing.expect(!client.waitForEnd(0));

    // The order `src/run.zig` phase 3 keeps: the loop releases the lock, then
    // the endpoint closes. So the end of the stream happens strictly after the
    // unlock, which is what makes it proof.
    _ = try first_locked.append(gpa, io, .{ .session_end = .{
        .reason = .handed_over,
        .detail = "",
    } }, 2);
    try first_locked.unlock(io);
    endpoint.close(io);
    first_store.close(io);

    try testing.expect(client.waitForEnd(0));
    try testing.expectEqual(sessions_cmd.Readiness.ready, sessions_cmd.readinessOf(gpa, io, log_path, id));

    const second_log = try chock_proto.log.Log.open(io, log_path, id);
    var second_backing = chock_proto.storage.JsonLines{ .log = second_log };
    const second_store = second_backing.storage();
    defer second_store.close(io);
    var second_locked = try second_store.lock(io);
    defer second_locked.unlock(io) catch {};

    // And a third process is refused while the second holds it, which is the
    // kernel's answer and not this command's. `test/proto/lock.zig` pins the
    // same fact with a genuinely separate process.
    {
        const third_log = try chock_proto.log.Log.open(io, log_path, id);
        var third_backing = chock_proto.storage.JsonLines{ .log = third_log };
        const third_store = third_backing.storage();
        defer third_store.close(io);
        try testing.expectError(error.Busy, third_store.lock(io));
    }

    // The log the new owner folds says the last owner handed over, so the new
    // owner knows to take the workspace rather than build one: see
    // `src/run.zig`'s own `takenOver`.
    var folded = chock_proto.state.Session.init(gpa);
    defer folded.deinit();
    var replay = try second_store.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try folded.apply(parsed.value);
    }
    try testing.expectEqual(
        chock_proto.event.SessionEndReason.handed_over,
        std.meta.activeTag(folded.end_reason),
    );
}

test "the two control sockets share a directory and never share a descriptor" {
    // A session opens both, in the same `0o700` directory, and a client reaches
    // each by the session directory and the identifier alone. **Two descriptors
    // and not one**, because one reader would eat the other's frames: an
    // approval answer read by the handover reader is an approval nobody ever
    // gave, and a handover ask read by `socket.Waiter.readOne` is dropped, since
    // it is not an `approval.response` for the open question.
    //
    // Mutation check: give `handover.socket_name` the value of
    // `socket.socket_name` and the two paths become one, which is that fault.
    const gpa = testing.allocator;
    const io = testing.io;
    // `ShortTmp` and not `testing.tmpDir`: this test opens real sockets in the
    // directory, and the reason that needs a short path is written there.
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    const session_dir = tmp.path();
    const id = "01JQ" ++ "S" ** 22;

    var approval_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer approval_paths.deinit();
    var handover_paths = try chock_broker.handover.pathsFor(gpa, session_dir, id);
    defer handover_paths.deinit();

    // Spelled out, and not compared against a second call to either function.
    const expected_dir = try std.fmt.allocPrint(gpa, "{s}/{s}.ctl", .{ session_dir, id });
    defer gpa.free(expected_dir);
    try testing.expectEqualStrings(expected_dir, approval_paths.dir);
    try testing.expectEqualStrings(expected_dir, handover_paths.dir);
    try testing.expect(!std.mem.eql(u8, approval_paths.socket, handover_paths.socket));

    // Both open at once, on one directory, and each answers its own client.
    var approvals = try chock_broker.socket.Endpoint.open(io, approval_paths, null);
    defer approvals.close(io);
    var handovers = try chock_broker.handover.Endpoint.open(io, handover_paths, null);
    defer handovers.close(io);

    const approval_address = try chock_proto.control.unixAddress(approval_paths.socket);
    const answering = try approval_address.connect(io);
    defer answering.close(io);
    const handover_address = try chock_proto.control.unixAddress(handover_paths.socket);
    const asking = try handover_address.connect(io);
    defer asking.close(io);

    // **A `chock approve` attached to a session is not the client that is
    // asking for it**, so the handover endpoint must not have taken it. This is
    // what pins that the two descriptors are apart: one accept each.
    approvals.acceptPending(io);
    try testing.expectEqual(@as(usize, 1), approvals.attached());
    try testing.expectEqual(chock_broker.handover.Decision.carry_on, handovers.look(io, .{}, 0));
    try testing.expect(handovers.asking());
    try testing.expectEqual(@as(usize, 0), handovers.refused);
    try testing.expectEqual(@as(usize, 0), approvals.refused);
}

test "a session handed over is answered by chock approve at the path it already knew" {
    // `chock daemon` relays no approvals, so a person answers a detached
    // session by running `chock approve`. That works only if the socket the
    // **new** owner opens is the one the client already knows about, and the
    // client knows only the session directory and the identifier.
    //
    // This is the same fact the test further down pins for a session that had
    // already stopped. It is repeated for a live handover because a live one
    // changes when the first owner closes its socket: it closes at the end of
    // its run, which is after the lock is free, so the window in which nobody
    // is listening is the same window in which nobody owns the session.
    //
    // Mutation check: key `handover.pathsFor` or `socket.pathsFor` on anything
    // a running process holds, and the new owner opens a path no client knocks
    // on.
    const gpa = testing.allocator;
    const io = testing.io;
    // `ShortTmp` and not `testing.tmpDir`: this test opens real sockets in the
    // directory, and the reason that needs a short path is written there.
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    const session_dir = tmp.path();
    const id = "01JQ" ++ "T" ** 22;

    // The person's end, computed before either owner exists.
    var client_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer client_paths.deinit();
    const address = try chock_proto.control.unixAddress(client_paths.socket);

    {
        var approval_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
        defer approval_paths.deinit();
        var handover_paths = try chock_broker.handover.pathsFor(gpa, session_dir, id);
        defer handover_paths.deinit();
        var approvals = try chock_broker.socket.Endpoint.open(io, approval_paths, null);
        var handovers = try chock_broker.handover.Endpoint.open(io, handover_paths, null);

        const before = try address.connect(io);
        before.close(io);
        // Phase 3's own order: approvals first, then the handover socket.
        approvals.close(io);
        handovers.close(io);
    }

    var approval_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer approval_paths.deinit();
    var approvals = try chock_broker.socket.Endpoint.open(io, approval_paths, null);
    defer approvals.close(io);

    const after = try address.connect(io);
    after.close(io);
}

test "the command line names one session at most, and no address unless one is typed" {
    // Nobody names a daemon by default, and `daemonAddress` is what turns that
    // into the socket in the state directory: see the test below.
    try testing.expect((try parseOptions(&.{})).port == null);
    try testing.expect((try parseOptions(&.{})).daemon == null);
    try testing.expectEqualStrings("", (try parseOptions(&.{})).session);
    try testing.expectEqualStrings("01ABC", (try parseOptions(&.{"01ABC"})).session);
    try testing.expectEqual(@as(u16, 9191), (try parseOptions(&.{ "--port", "9191" })).port.?);
    try testing.expectEqualStrings(
        "unix:/run/chock/d.sock",
        (try parseOptions(&.{ "--daemon", "unix:/run/chock/d.sock" })).daemon.?,
    );
    try testing.expectError(error.BadArguments, parseOptions(&.{"--daemon"}));
    // Seconds on the command line, milliseconds inside. A person writing a wait
    // writes seconds, and every socket call in this exchange takes
    // milliseconds, so a build that mixed the two would wait a thousand times
    // too long or too little.
    try testing.expectEqual(default_patience_ms, (try parseOptions(&.{})).patience_ms);
    try testing.expectEqual(@as(u64, 90_000), (try parseOptions(&.{ "--wait", "90" })).patience_ms);
    // Zero asks once and reports what the session has already said, which is
    // what a script that does not want to wait needs.
    try testing.expectEqual(@as(u64, 0), (try parseOptions(&.{ "--wait", "0" })).patience_ms);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--wait", "a while" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--wait"}));
    try testing.expectEqualStrings("/tmp/p", (try parseOptions(&.{ "--project", "/tmp/p" })).project.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "01ABC", "01DEF" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--port", "seventy" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--port"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--nope"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "a session that handed over is not refused for the workspace its handover kept" {
    // **Measured on a real session on 2026-08-23.** The live handover stopped
    // the session and left its workspace, exactly as designed, and the daemon
    // had gone away. The command told the person to run it again, and the
    // second run refused with "left a workspace, which still holds work" and
    // pointed at `chock workspace clear`, which would have deleted the work the
    // handover had just preserved.
    //
    // A workspace on disk means two different things and only the log tells
    // them apart. Mutation check: make `endedHandedOver` answer false always
    // and the first line below stops holding, which is that advice again.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];
    const id = "01JQ" ++ "V" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    defer gpa.free(log_path);

    const endings = [_]chock_proto.event.SessionEndReason{ .handed_over, .errored, .finished };
    for (endings) |ending| {
        tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        var locked = try store.lock(io);
        // A fixed time and never a clock: nothing this test reads is a time.
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = ending, .detail = "" } }, 1);
        try locked.unlock(io);
        store.close(io);

        try testing.expectEqual(ending == .handed_over, endedHandedOver(gpa, io, log_path));
    }

    // **The last ending and never the first.** A session that changed hands and
    // then ran on to a crash has an earlier `handed_over` in its log, and that
    // one says nothing about the workspace sitting there now.
    tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .handed_over, .detail = "" } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .errored, .detail = "" } }, 2);
        try locked.unlock(io);
    }
    try testing.expect(!endedHandedOver(gpa, io, log_path));

    // A log that is not there at all is the refusing side, because naming a
    // workspace that may hold work is the safe direction.
    tmp.dir.deleteFile(io, id ++ ".jsonl") catch {};
    try testing.expect(!endedHandedOver(gpa, io, log_path));
}

test "no daemon is found before a running session is asked, and not after" {
    // **The ask cannot be taken back.** A session that agreed has ended, so a
    // person who then learns there is no daemon has had their session stopped
    // for nothing. This is the check that runs first, and the message it gives
    // says the session was not asked.
    //
    // **Driven over the socket, because the socket is what a person gets.** The
    // path is one inside this test's own temporary directory and nothing ever
    // listened on it, which is a daemon that is not running with no port to
    // guess at.
    //
    // Mutation check: return true when the connect fails, and `chock detach`
    // stops a healthy session and then finds nowhere to put it.
    const gpa = testing.allocator;
    const io = testing.io;
    const id = "01JQ" ++ "A" ** 22;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/d.sock", .{dir_buffer[0..dir_len]});
    defer gpa.free(socket_path);

    // See the first test in this file for why the lines are captured.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try testing.expect(!reportDaemonListening(io, .{ .unix = socket_path }, id));
    // **And the line says the session was not asked**, which is the whole point
    // of running this check first: a person reading it knows their session is
    // still theirs. It also names the command that starts a daemon, and the
    // address it looked at, so a person who has a daemon somewhere else can see
    // that this looked in the wrong place.
    try testing.expect(std.mem.indexOf(u8, said.err(), "was not asked to stop") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "still running") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock daemon") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), socket_path) != null);
    try testing.expectEqualStrings("", said.out());

    // And a daemon that is there is found, so this check does not refuse every
    // live handover there is.
    said.clear();
    var listener = try (control.Address{ .unix = socket_path }).listen(io);
    defer listener.close(io);
    try testing.expect(reportDaemonListening(io, .{ .unix = socket_path }, id));
    // A healthy check is quiet.
    try testing.expectEqualStrings("", said.err());

    // And the same function, over the other transport, with nothing changed
    // about it. **Nothing in this command branches on which one it got**: a
    // port is one value of `control.Address` and a socket path is another.
    said.clear();
    const on_loopback = control.Address{ .ip = .{ .host = control.default_host, .port = 0 } };
    var tcp = try on_loopback.listen(io);
    defer tcp.close(io);
    try testing.expect(reportDaemonListening(io, .{ .ip = .{
        .host = control.default_host,
        .port = tcp.server.socket.address.getPort(),
    } }, id));
    try testing.expectEqualStrings("", said.err());

    // **A socket this user may not open is not a daemon nobody started.** A
    // daemon of another user has a socket this one cannot enter, and telling a
    // person to start a daemon there would send them round a loop.
    //
    // Mutation check: give both failures the one sentence and this fails,
    // which is that loop.
    said.clear();
    const shut = try std.fmt.allocPrint(gpa, "{s}/shut", .{dir_buffer[0..dir_len]});
    defer gpa.free(shut);
    try tmp.dir.createDir(io, "shut", .default_dir);
    const inside = try std.fmt.allocPrint(gpa, "{s}/d.sock", .{shut});
    defer gpa.free(inside);
    {
        var shut_listener = try (control.Address{ .unix = inside }).listen(io);
        defer shut_listener.close(io);
        // No permission on the directory at all, so the connect is refused
        // before anything reaches the daemon.
        try tmp.dir.setFilePermissions(io, "shut", .fromMode(0o000), .{});
        defer tmp.dir.setFilePermissions(io, "shut", .fromMode(0o700), .{}) catch {};

        try testing.expect(!reportDaemonListening(io, .{ .unix = inside }, id));
        try testing.expect(std.mem.indexOf(u8, said.err(), "could not be reached") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "still running") != null);
        // And it does not tell a person to start a daemon, because there is one.
        try testing.expect(std.mem.indexOf(u8, said.err(), "chock daemon`") == null);
    }
}

test "the daemon a person did not name is the socket in the state directory" {
    // **Fault one, from this end.** This command reached `127.0.0.1:7373` and
    // nothing else, which is the only reason `chock daemon` kept a TCP listener
    // in its default set, and loopback TCP names no peer. So the default here
    // has to be the socket, or the default there cannot be the socket either.
    //
    // Mutation check: make the last branch answer a loopback address and this
    // fails, which is that default coming back.
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");

    {
        const found = (try daemonAddress(arena, &env, .{})).?;
        try testing.expect(found == .unix);
        // The path itself is `chock_auth.paths.stateDir` and
        // `control.socketPathIn`, which is what `chock daemon` and `chock serve`
        // both build. What this pins is that it is a socket path under the
        // state directory and not an address on a network.
        try testing.expect(std.mem.endsWith(u8, found.unix, control.socket_name));
        try testing.expect(std.mem.startsWith(u8, found.unix, "/home/somebody"));
    }

    // A daemon somewhere else, said once in the environment, is what every
    // client of it reads. `chock serve` reads the same variable.
    try env.put(control.address_env, "10.0.0.4:7373");
    {
        const found = (try daemonAddress(arena, &env, .{})).?;
        try testing.expectEqualStrings("10.0.0.4", found.ip.host);
        try testing.expectEqual(@as(u16, 7373), found.ip.port);
    }

    // And a flag beats the environment, which is the order a person expects.
    {
        const found = (try daemonAddress(arena, &env, .{ .daemon = "unix:/run/chock/d.sock" })).?;
        try testing.expectEqualStrings("/run/chock/d.sock", found.unix);
    }
    {
        const found = (try daemonAddress(arena, &env, .{ .port = 9191 })).?;
        try testing.expectEqualStrings(control.default_host, found.ip.host);
        try testing.expectEqual(@as(u16, 9191), found.ip.port);
    }
    // Nothing above was a fault, so nothing was said.
    try testing.expectEqualStrings("", said.err());

    // Two flags that both name where the daemon is are a person who meant one
    // of them, and guessing which is worse than saying so.
    said.clear();
    try testing.expect(try daemonAddress(arena, &env, .{
        .daemon = "unix:/run/chock/d.sock",
        .port = 9191,
    }) == null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--daemon") != null);

    // An address that is not one is named back, and never guessed at.
    said.clear();
    try testing.expect(try daemonAddress(arena, &env, .{ .daemon = "/run/chock/d.sock" }) == null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/run/chock/d.sock") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "unix:/path") != null);
}

test "a failure after a session was stopped says so, and one before it does not" {
    // **The two failures read identically without this, and they are not the
    // same thing.** Before the ask, a person's session is still running and
    // they lost nothing. After it, the session has ended, its log is whole, its
    // workspace is on disk, and nobody owns it. A person who did not know the
    // difference would walk away from a session that is waiting for an owner.
    //
    // Mutation check: answer the empty string for both and the daemon that went
    // away between the two connects reports the same line as a daemon that was
    // never there, so nobody learns their session has stopped.
    try testing.expectEqualStrings("", stoppedNote(false));
    const note = stoppedNote(true);
    try testing.expect(note.len != 0);
    // It says the session stopped, and it says what to do about it. A note that
    // only said something went wrong would leave a person guessing.
    try testing.expect(std.mem.indexOf(u8, note, "already stopped") != null);
    try testing.expect(std.mem.indexOf(u8, note, "chock run --continue") != null);
}

test "a daemon that took the session is the only answer that exits finished" {
    // The three answers, and the fact that separates them: only `ok` means the
    // daemon owns the session now. An answer this build cannot read must never
    // report a handover, because a person would then stop looking for their
    // session.
    //
    // **And each answer is read as well as counted.** An exit code alone would
    // pass against a build that reported every answer with one sentence. See
    // the first test in this file for why the lines are captured.
    const id = "01JQ" ++ "A" ** 22;
    const note = stoppedNote(false);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(Exit.finished.code(), report("ok " ++ id ++ "\t/state/s.jsonl", id, true, note));
    // A handover says who owns the session now, and how to answer its
    // questions from here on. **On standard output**, because a handover that
    // worked is the command's own answer and not a diagnostic.
    try testing.expect(std.mem.indexOf(u8, said.out(), "the daemon owns session") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "chock approve " ++ id) != null);
    try testing.expectEqualStrings("", said.err());

    said.clear();
    try testing.expectEqual(Exit.usage.code(), report("error that session is running now", id, true, note));
    // The daemon's own words reach the person, so a refusal this build has
    // never seen is still readable.
    try testing.expect(std.mem.indexOf(u8, said.err(), "that session is running now") != null);

    // An answer this build cannot read must say that it is unknown, and never
    // report a handover: a person would stop looking for their session.
    for ([_][]const u8{ "", "okay then" }) |unreadable| {
        said.clear();
        try testing.expectEqual(Exit.faulted.code(), report(unreadable, id, true, note));
        try testing.expect(std.mem.indexOf(u8, said.err(), "unknown") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "chock sessions") != null);
    }

    // `ok` with no log path is still a handover: the identifier is what a
    // person needs, and the path is the detail behind `--verbose`.
    said.clear();
    try testing.expectEqual(Exit.finished.code(), report("ok " ++ id, id, true, note));
    try testing.expect(std.mem.indexOf(u8, said.out(), "the daemon owns session") != null);

    // And a session nobody can answer still changed hands. It runs, and every
    // question it asks is refused, which is the safe direction and not a failed
    // handover. **The line says so, and it is a warning**: a session whose
    // questions are all refused is not one to walk away from, and the handover
    // itself still succeeded on standard output.
    said.clear();
    try testing.expectEqual(Exit.finished.code(), report("ok " ++ id, id, false, note));
    try testing.expect(std.mem.indexOf(u8, said.err(), "nobody can answer") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "the daemon owns session") != null);
    // And it does not name `chock approve`, because that command cannot reach
    // a session with no socket.
    try testing.expect(std.mem.indexOf(u8, said.out(), "chock approve") == null);
}

test "a socket path too long for the machine is measured before the closing advice is given" {
    // **Found by hand on Darwin, not by a test.** A unix socket path is bounded
    // at 103 bytes there and 107 on Linux. A session directory below a deep home
    // spends more, the session opens no approval socket, and it says so on its
    // own standard error, which the person who ran `chock detach` never sees.
    //
    // So this command reads the same bound. Mutation check: make `answerableAt`
    // answer true always, and `chock detach` tells a person to run
    // `chock approve` against a session that opened no socket at all.
    const gpa = testing.allocator;

    const id = "01JQ" ++ "A" ** 22;
    var short = try chock_broker.socket.pathsFor(gpa, "/state/p", id);
    defer short.deinit();
    try testing.expect(answerableAt(short.socket));

    // Long enough to fail on both platforms, and built from the real path
    // shape rather than from a string with the right length: what is bounded is
    // the socket a session opens, and that is what this asks about.
    const deep = try std.fmt.allocPrint(gpa, "/state/{s}", .{"d" ** 120});
    defer gpa.free(deep);
    var over = try chock_broker.socket.pathsFor(gpa, deep, id);
    defer over.deinit();
    try testing.expect(!answerableAt(over.socket));

    // **And the bound is this machine's own, not the one `std.Io.net` keeps.**
    // `UnixAddress.max_len` is a flat 108 everywhere but Windows, and this
    // machine takes one byte less than its own `sun_path` holds. What this half
    // pins is that the two are the same number here and in the socket layer,
    // whatever the platform makes it. See `max_socket_path`.
    //
    // Mutation check: give `answerableAt` a bound of its own, such as
    // `UnixAddress.max_len`, and the two halves disagree with the layer that
    // really binds. Both halves fail if it stops reading a bound at all.
    const at_bound = try boundedPath(gpa, max_socket_path);
    defer gpa.free(at_bound);
    try testing.expect(answerableAt(at_bound));

    const over_bound = try boundedPath(gpa, max_socket_path + 1);
    defer gpa.free(over_bound);
    try testing.expect(!answerableAt(over_bound));
}

/// An absolute path of exactly `length` bytes, for the test above.
fn boundedPath(gpa: std.mem.Allocator, length: usize) std.mem.Allocator.Error![]u8 {
    const path = try gpa.alloc(u8, length);
    @memset(path, 'p');
    path[0] = '/';
    return path;
}

test "a session that is running is refused, and one nobody owns is handed over" {
    // **The fact this whole command rests on**: the exclusive lock on the log
    // is what makes one process the owner, so a session whose lock is held is
    // one this command must not take.
    //
    // The lock here is taken on a second open file description, which is what
    // `flock(2)` contends on. That a genuinely different process is refused as
    // well is pinned by `test/proto/lock.zig`, which spawns one.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    const id = "01JQ" ++ "A" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0);
    defer gpa.free(log_path);

    // A log with one event in it, which is a session there is something to
    // carry on from.
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
    }

    // See the first test in this file for why the lines are captured.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    // Nobody holds it, so it can change hands, and a healthy check is quiet.
    try testing.expect(reportReadiness(gpa, io, log_path, id));
    try testing.expectEqualStrings("", said.err());

    // Somebody does, so it cannot. Mutation check: drop the `.running` case
    // from `reportReadiness`, or make `readinessOf` answer `ready` for a held
    // lock, and this line reports a session that another process owns as one
    // that is free to take.
    {
        var owner = try chock_proto.log.Log.open(io, log_path, id);
        defer owner.close(io);
        var held = try owner.lock(io);
        defer held.unlock(io) catch {};
        try testing.expect(!reportReadiness(gpa, io, log_path, id));
        // **And the refusal names the session and says which command shows who
        // owns it.** "It is running" with no next step leaves a person with
        // nothing to do about it.
        try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "running now") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "chock sessions") != null);
        try testing.expectEqualStrings("", said.out());
    }

    // And it can change hands again once the owner has let go, which is what
    // makes this a handover rather than a one way door.
    said.clear();
    try testing.expect(reportReadiness(gpa, io, log_path, id));
    try testing.expectEqualStrings("", said.err());
}

test "a session whose workspace still holds work is refused, and an empty one is not" {
    // An adopted session builds a new workspace from the project's committed
    // state, so work sitting in the old one would be left with nothing pointing
    // at it. Mutation check: return true unconditionally and the file the agent
    // wrote is handed over into oblivion.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    const id = "01JQ" ++ "A" ** 22;
    const work = try std.fmt.allocPrint(gpa, "{s}/{s}.work", .{ dir, id });
    defer gpa.free(work);

    // See the first test in this file for why the lines are captured.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    // A directory that is not there at all is the ordinary case, and it is not
    // a refusal: a session that ended cleanly had its workspace removed.
    try testing.expect(reportKeptWorkspace(gpa, io, work, id));

    try tmp.dir.createDir(io, id ++ ".work", .default_dir);
    // An empty directory is still nothing to lose. `chock run` makes this
    // directory for every session, so treating its bare existence as work
    // would refuse every handover there is.
    try testing.expect(reportKeptWorkspace(gpa, io, work, id));
    // Neither of those said anything: a healthy check is quiet.
    try testing.expectEqualStrings("", said.err());

    var work_dir = try tmp.dir.openDir(io, id ++ ".work", .{});
    defer work_dir.close(io);
    try work_dir.writeFile(io, .{ .sub_path = "agent-wrote-this.txt", .data = "work nothing else holds\n" });
    try testing.expect(!reportKeptWorkspace(gpa, io, work, id));
    // **And it counts what is there and names where.** The whole reason for
    // this refusal is that the work would be left behind, so a person has to be
    // able to go and get it.
    try testing.expect(std.mem.indexOf(u8, said.err(), work) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 files") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock workspace") != null);
    try testing.expectEqualStrings("", said.out());
}

test "a session folded by the next owner holds what the last owner held" {
    // **The promise this whole command makes.** A handover carries no state of
    // its own: the new owner opens the log, replays it, and folds it, which is
    // exactly what `chock_core.Loop.run` does at its own start. So a handover
    // is honest only if the fold recovers the state the writer held.
    //
    // The writer here keeps a `state.Session` beside the log as it appends, the
    // way `Loop.appendAndApply` does. The reader is a **second open file
    // description** on the same path, which is what a second process has, and it
    // starts from an empty `state.Session` and nothing else.
    //
    // Mutation check: drop any one `apply` case in `chock_proto.state.Session`,
    // or start the reader from the writer's own value instead of an empty one,
    // and one of the comparisons below stops holding.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const id = "01JQ" ++ "H" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir_buffer[0..dir_len], id }, 0);
    defer gpa.free(log_path);

    const child_id = "01JQ" ++ "K" ** 22;
    const user = [_]chock_proto.event.ContentPart{.{ .text = "carry this on" }};
    const answer = [_]chock_proto.event.ContentPart{.{ .text = "reading the parser" }};
    const steps = [_]chock_proto.event.PlanStep{
        .{ .id = "s1", .subject = "read the fold", .status = .done },
        .{ .id = "s2", .subject = "write the test", .status = .in_progress },
    };
    const promises = [_]chock_proto.event.SelfRestriction{
        .{ .action = "git.push", .ceiling = .deny, .reason = "nothing of mine leaves this machine" },
    };
    const written = [_]chock_proto.event.Event{
        .{ .session_start = .{ .agent_kind = "main", .model_alias = "local", .parent_session = "" } },
        .{ .message = .{ .role = .user, .content = &user } },
        .{ .message = .{ .role = .assistant, .content = &answer } },
        .{ .session_spawn = .{
            .child_session = child_id,
            .child_agent_kind = "reviewer",
            .reason = "a second reading of the diff",
            .budget_max_cost = 0.25,
            .budget_currency = "USD",
        } },
        .{ .usage = .{
            .input_tokens = 900,
            .output_tokens = 120,
            .cost = .{ .known = .{ .value = 0.5, .currency = "USD" } },
            .model = "a-model",
            .model_alias = "local",
        } },
        .{ .plan_update = .{ .steps = &steps } },
        .{ .policy_self = .{ .restrictions = &promises } },
    };

    var running = chock_proto.state.Session.init(gpa);
    defer running.deinit();
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        for (written, 1..) |one, time_ms| {
            // A fixed time and never a clock: this suite makes no assertion
            // over one, and the fold does not read it.
            const offset = try locked.append(gpa, io, one, @intCast(time_ms));
            try running.apply(.{ .id = offset, .session = id, .time_ms = @intCast(time_ms), .event = one });
        }
        try locked.unlock(io);
    }

    var recovered = chock_proto.state.Session.init(gpa);
    defer recovered.deinit();
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);

        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};

        var replay = try store.replay(gpa, io, 0);
        defer replay.deinit();
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            try recovered.apply(parsed.value);
        }
    }

    // Which agent this is and which model it speaks to. Without these the new
    // owner would write a second `session.start` and change the session's kind.
    try testing.expectEqualStrings(running.agent_kind, recovered.agent_kind);
    try testing.expectEqualStrings("main", recovered.agent_kind);
    try testing.expectEqualStrings(running.model_alias, recovered.model_alias);

    // The conversation itself, which is what the next request is built from.
    try testing.expectEqual(running.context.items.len, recovered.context.items.len);
    try testing.expectEqual(@as(usize, 2), recovered.context.items.len);

    // The children it already handed budget to. A parent that counted from zero
    // could hand the same money out twice.
    try testing.expectEqual(running.children.items.len, recovered.children.items.len);
    try testing.expectEqual(@as(usize, 1), recovered.children.items.len);
    try testing.expectEqualStrings(child_id, recovered.children.items[0].session);
    try testing.expectEqualStrings("reviewer", recovered.children.items[0].agent_kind);
    try testing.expectEqual(@as(f64, 0.25), recovered.children.items[0].budget_max_cost);
    try testing.expectEqualStrings("USD", recovered.children.items[0].budget_currency);

    // The money already spent, which is what a cap is measured against.
    try testing.expectEqual(running.spend.input_tokens, recovered.spend.input_tokens);
    try testing.expectEqual(running.spend.output_tokens, recovered.spend.output_tokens);
    try testing.expectEqual(running.spend.turns, recovered.spend.turns);
    try testing.expectEqual(running.spend.amount, recovered.spend.amount);
    try testing.expectEqualStrings("USD", recovered.spend.currency);
    // How full the context is. Zero here would make the new owner believe it
    // has a whole context free and skip a compaction it needs.
    try testing.expectEqual(@as(u64, 900), recovered.last_input_tokens);

    // The task list the agent kept, so a handover does not drop a task.
    const running_counts = running.plan.counts();
    const recovered_counts = recovered.plan.counts();
    try testing.expectEqual(running_counts.done, recovered_counts.done);
    try testing.expectEqual(running_counts.in_progress, recovered_counts.in_progress);
    try testing.expectEqual(@as(usize, 1), recovered_counts.done);
    try testing.expectEqual(@as(usize, 1), recovered_counts.in_progress);

    // And the promises the agent made about itself. A promise the new owner
    // forgot is a ratchet that quietly released.
    try testing.expectEqual(
        running.self_policy.restrictions.items.len,
        recovered.self_policy.restrictions.items.len,
    );
    try testing.expectEqual(@as(usize, 1), recovered.self_policy.restrictions.items.len);
    try testing.expectEqualStrings("git.push", recovered.self_policy.restrictions.items[0].action);
    try testing.expectEqualStrings("deny", recovered.self_policy.restrictions.items[0].ceiling.wireName());

    // **And the second owner really was second.** The writer released the lock
    // before the reader took it, which is what a handover is. Both held it, and
    // neither held it at the same moment: `test/proto/lock.zig` is what pins
    // that a genuinely different process is refused while one is held.
    const after = try chock_proto.log.Log.open(io, log_path, id);
    var after_backing = chock_proto.storage.JsonLines{ .log = after };
    const after_store = after_backing.storage();
    defer after_store.close(io);
    var third = try after_store.lock(io);
    try third.unlock(io);
}

test "a handover with no daemon to hand to is refused, and it names what to do" {
    // **The refusal that must not be a hang and must not be a silent no.** A
    // client with no daemon there has to say so and name `chock daemon`, because
    // a person who typed this is now waiting for a session that nobody owns.
    //
    // The address is a socket path in this test's own temporary directory that
    // nothing ever listened on, which is a daemon that is not running with no
    // port to guess at.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/d.sock", .{dir_buffer[0..dir_len]});
    defer gpa.free(socket_path);

    // See the first test in this file for why the lines are captured.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    // Mutation check: make the connect failure fall through to a success code,
    // or drop the branch entirely, and this reports a handover that never
    // happened.
    const id = "01JQ" ++ "A" ** 22;
    const code = try handOver(io, "/some/project", id, .{ .unix = socket_path }, true, false);
    try testing.expectEqual(Exit.usage.code(), code);
    // **And it names what to do**, which is the half of this the test's own
    // title is about. A refusal that only said "no daemon" would leave a person
    // waiting for a session nobody owns.
    try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "nothing is listening") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "chock daemon") != null);
    try testing.expectEqualStrings("", said.out());
}

/// A daemon that answers one greeting and reads no further. `speaks` is the
/// control protocol number it names, and `lenient` makes it greet back whatever
/// the client offered, which is what a real `pcscd` does.
const FakeDaemon = struct {
    io: std.Io,
    listener: control.Listener,
    speaks: u32,
    lenient: bool,
    thread: std.Thread = undefined,
    /// Whether it ever got as far as reading a request line.
    asked: bool = false,

    fn start(io: std.Io, path: []const u8, speaks: u32, lenient: bool) !*FakeDaemon {
        const self = try testing.allocator.create(FakeDaemon);
        errdefer testing.allocator.destroy(self);
        self.* = .{
            .io = io,
            .listener = try (control.Address{ .unix = path }).listen(io),
            .speaks = speaks,
            .lenient = lenient,
        };
        self.thread = try std.Thread.spawn(.{}, run, .{self});
        return self;
    }

    fn run(self: *FakeDaemon) void {
        var stream = self.listener.server.accept(self.io) catch return;
        defer stream.close(self.io);

        var read_buffer: [4096]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        var write_buffer: [4096]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);
        const writer = &stream_writer.interface;
        defer writer.flush() catch {};

        const line = (stream_reader.interface.takeDelimiter('\n') catch null) orelse return;
        const asked = control.Greeting.parse(.ask, line) catch return;
        if (!self.lenient and !control.accepts(self.speaks, asked.version)) {
            control.writeMismatch(writer, self.speaks, asked.version) catch {};
            writer.flush() catch {};
            return;
        }
        (control.Greeting{ .version = self.speaks }).write(.answer, writer) catch {};
        writer.flush() catch {};

        // Anything after this is a request, and a handshake that did not agree
        // must never reach here.
        if ((stream_reader.interface.takeDelimiter('\n') catch null) != null) self.asked = true;
    }

    fn finish(self: *FakeDaemon) void {
        self.thread.join();
    }

    fn deinit(self: *FakeDaemon) void {
        self.listener.close(self.io);
        testing.allocator.destroy(self);
    }
};

test "a daemon of another control protocol number is never handed a session" {
    // **The worst place for a version to be wrong.** By the time this runs the
    // session has already stopped, so a daemon that read the handover
    // differently would leave work nobody owns. The greeting is what makes that
    // a sentence instead.
    //
    // Mutation check: check only that the daemon answered a greeting shaped
    // line and drop the `control.accepts` call, which is exactly what a real
    // `pcscd` let through and what `lib/chock-pcsc` measured. The first block
    // below then exits finished and the fake daemon reads a request.
    const gpa = testing.allocator;
    const io = testing.io;
    const id = "01JQ" ++ "A" ** 22;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buffer);

    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    const other = control.protocol_version + 1;

    // A daemon that greets back whatever it was offered, carrying its own
    // number. **This client checks the number and not the shape.**
    {
        const path = try std.fmt.allocPrint(gpa, "{s}/lenient.sock", .{dir_buffer[0..dir_len]});
        defer gpa.free(path);
        const fake = try FakeDaemon.start(io, path, other, true);
        defer fake.deinit();

        const code = try handOver(io, "/some/project", id, .{ .unix = path }, true, true);
        fake.finish();

        try testing.expectEqual(Exit.usage.code(), code);
        // **The session was not offered.** Nothing of it reached a daemon this
        // build will not speak to.
        try testing.expect(!fake.asked);
        var ours: [16]u8 = undefined;
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            said.err(),
            try std.fmt.bufPrint(&ours, "{d}", .{control.protocol_version}),
        ) != null);
        try testing.expect(std.mem.indexOf(
            u8,
            said.err(),
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "not handed over") != null);
        // The session was stopped to get here, so the line has to say it is
        // waiting for an owner rather than gone.
        try testing.expect(std.mem.indexOf(u8, said.err(), "already stopped") != null);
    }

    // And a daemon that refuses the greeting itself: its own words reach the
    // person, so a client too old to check anything still learns what to do.
    {
        said.clear();
        const path = try std.fmt.allocPrint(gpa, "{s}/strict.sock", .{dir_buffer[0..dir_len]});
        defer gpa.free(path);
        const fake = try FakeDaemon.start(io, path, other, false);
        defer fake.deinit();

        const code = try handOver(io, "/some/project", id, .{ .unix = path }, true, false);
        fake.finish();

        try testing.expectEqual(Exit.usage.code(), code);
        try testing.expect(!fake.asked);
        var theirs: [16]u8 = undefined;
        try testing.expect(std.mem.indexOf(
            u8,
            said.err(),
            try std.fmt.bufPrint(&theirs, "{d}", .{other}),
        ) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "not handed over") != null);
    }

    // And the greeting really does agree when the numbers do, so none of the
    // above is a client that refuses every daemon there is.
    {
        said.clear();
        const path = try std.fmt.allocPrint(gpa, "{s}/same.sock", .{dir_buffer[0..dir_len]});
        defer gpa.free(path);
        const fake = try FakeDaemon.start(io, path, control.protocol_version, false);
        defer fake.deinit();

        _ = try handOver(io, "/some/project", id, .{ .unix = path }, true, false);
        fake.finish();
        try testing.expect(fake.asked);
    }

    try testing.expectEqualStrings("", said.out());
}

test "a session that changed hands is still answered by chock approve, at the same path" {
    // `chock daemon` relays no approvals, so a person answers a detached session
    // by running `chock approve` on this machine. That only works if the socket
    // the **new** owner opens is the one the client already knows about, and the
    // client knows only the session directory and the identifier.
    //
    // So the client's path is computed first, before either owner exists, and it
    // is the only path the client ever uses.
    const gpa = testing.allocator;
    const io = testing.io;
    // `ShortTmp` and not `testing.tmpDir`: this test opens real sockets in the
    // directory, and the reason that needs a short path is written there.
    var tmp = try ShortTmp.open(io);
    defer tmp.cleanup(io);

    const session_dir = tmp.path();
    const id = "01JQ" ++ "M" ** 22;

    // The person's end. `src/approve.zig` makes exactly this call.
    var client_paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer client_paths.deinit();

    // **Spelled out, and not compared against a second call to the same
    // function.** Two calls agreeing proves nothing about what the path is; this
    // is what pins that it is built from the session directory and the
    // identifier, and from nothing a running process holds.
    const expected = try std.fmt.allocPrint(gpa, "{s}/{s}.ctl/s", .{ session_dir, id });
    defer gpa.free(expected);
    try testing.expectEqualStrings(expected, client_paths.socket);

    const address = try chock_proto.control.unixAddress(client_paths.socket);

    {
        var paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
        defer paths.deinit();
        var first = try chock_broker.socket.Endpoint.open(io, paths, null);
        const before = try address.connect(io);
        before.close(io);
        first.close(io);
    }

    // With nobody there, the client is refused rather than left waiting. This is
    // the state between two owners, and `chock approve` already reports it.
    //
    // **Which error is not pinned, and must not be.** `Endpoint.close` removes
    // the socket file, so a client meets a missing path here and a refused
    // connection where a crash left the file behind. Both mean nobody is
    // listening, and naming one of them would make this test a report of which
    // way the last owner happened to stop.
    if (address.connect(io)) |orphan| {
        orphan.close(io);
        return error.AClientReachedASessionWithNoOwner;
    } else |_| {}

    var paths = try chock_broker.socket.pathsFor(gpa, session_dir, id);
    defer paths.deinit();
    var second = try chock_broker.socket.Endpoint.open(io, paths, null);
    defer second.close(io);

    // Mutation check: change `chock_broker.socket.socket_name` or `dir_suffix`,
    // or key `pathsFor` on anything a running process holds, and the literal
    // above stops matching. That is a detached session nobody can answer,
    // because the client would be knocking on a path the new owner never opened.
    const after = try address.connect(io);
    after.close(io);
}
