//! `chock run`: one agent session against the project in the current
//! directory, from the command line, with no interface.
//!
//! ```
//! cd ~/some-project
//! chock run "add a test for the parser"
//! ```
//!
//! ## Three phases, because one `std.Io` cannot do this job
//!
//! **`Registry.dispatch` calls `Sandbox.spawn`, which calls `fork`, and
//! `fork` carries only the calling thread into the child.** A caller holding
//! a lock on another thread gives a child that deadlocks, which is why every
//! real tool call test in this project runs through a dedicated single
//! threaded probe process. `test/core/tools_probe.zig` is where the shape
//! that works came from: a `std.Io.Threaded` built with
//! `std.mem.Allocator.failing`, which still reads a clock, still opens files,
//! and still talks to a socket, and **cannot start a thread**, because
//! `Threaded` uses its allocator for `async`, `concurrent`, and the group
//! calls and for nothing else.
//!
//! That same `Io` cannot spawn a process: `Threaded`'s own `spawnPosix`
//! builds an arena over that allocator, and a failing allocator fails there.
//! And this command has to spawn `git`, twice, because `Workspace.open`
//! builds a linked worktree and `Workspace.close` removes it again.
//!
//! So the work is in three phases, each with the `Io` its own job needs, and
//! **only one `Io` exists at a time**:
//!
//! | Phase | `Io` | What runs |
//! |---|---|---|
//! | 1. setup | a real allocator | `Workspace.open`, which runs `git` |
//! | 2. the session | `Allocator.failing` | `Loop.run`, which forks |
//! | 3. teardown | a real allocator | `Workspace.close`, which runs `git` |
//!
//! **Phase 3 does not always close the workspace.** A session that ended badly
//! keeps its workspace, and says where it is, because the alternative is
//! deleting work nothing else has a copy of. See `cleanupFor`.
//!
//! Phase 2 is the one that matters. The rest is a consequence.
//!
//! **The allocator the session itself uses is an ordinary one throughout.**
//! It is the `Io`'s allocator that must be unable to start a thread, not the
//! caller's: see `lib/chock-core/tools.zig`'s own top comment on why
//! `spawnCapturing`'s one deliberate thread is safe, and what it promises
//! about the calling thread's allocator while the fork happens.
//!
//! ## There is no flag that approves everything
//!
//! `chock run` has nobody at the keyboard, and that is already answered: an
//! approval that nobody answers before its timeout **is a refusal**, which is
//! the safe direction and needs no new code. The place to say "allowed without
//! asking" is the policy table in `chock.zon`, which is beyond the agent's
//! reach. A rule in a file somebody wrote on purpose beats a flag somebody
//! typed once that now lives in a continuous integration script forever.

const std = @import("std");
const builtin = @import("builtin");
const chock_auth = @import("chock-auth");
const chock_broker = @import("chock-broker");
const chock_container = @import("chock-container");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_cost = @import("chock-cost");
const chock_nix = @import("chock-nix");
const chock_proto = @import("chock-proto");
const chock_provider = @import("chock-provider");
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");

/// The flag names a parent writes onto a child's command line, read from the
/// one file that also builds one. See `chock_core.subagent.flag`: a name
/// spelled here as well as there is a name that can quietly stop matching, and
/// the fault would be a child that ran with no parent in its chain at all.
const subagent = chock_core.subagent;

const approval = @import("approval.zig");
const clock = @import("clock.zig");
const sessions_cmd = @import("sessions.zig");
const tty = @import("tty.zig");
const interrupt = @import("interrupt.zig");
const handover = @import("handover.zig");
const session_paths = @import("session.zig");
const ui = @import("ui.zig");
const Exit = @import("main.zig").Exit;
const exitFor = @import("main.zig").exitFor;

const usage_text =
    \\Usage: chock run [options] [message...]
    \\
    \\With no message on the command line, the message is read from standard input.
    \\
    \\Options:
    \\  --provider <name>   The provider instance to talk to, by its name in the
    \\                      configuration. Defaults to .defaults.provider, or to the
    \\                      only instance when the configuration has exactly one.
    \\  --model <id>        The model on the wire. Defaults to .defaults.model.
    \\  --project <dir>     The project. Defaults to the current directory.
    \\  --allow-dirty       Copy the project's uncommitted work into the workspace.
    \\                      Without this the agent sees the committed state.
    \\  --continue          Continue the newest session of this project.
    \\  --session <id>      Continue this session.
    \\  --adopt             Become the owner of a session that already exists and
    \\                      carry on from what its log holds, with no new message.
    \\                      Needs --session or --continue. This is what
    \\                      `chock detach` asks the daemon to do.
    \\  --agent-kind <kind> The agent kind that selects the policy. Defaults to "main".
    \\  --org-bundle <path> Use this org policy bundle instead of the one this
    \\                      installation holds. The bundle is the layer above
    \\                      chock.zon, and chock.zon may only narrow it. A bundle
    \\                      that has already expired is refused here; one already
    \\                      installed keeps binding whatever its date says.
    \\  --max-turns <n>     Stop after this many turns. Off by default: a session
    \\                      runs until the agent is done, and stops on its own when
    \\                      it repeats the same call over and over.
    \\  --no-notices        Do not tell the agent what the harness knows: the time,
    \\                      the task restated, a call it has already made, a file it
    \\                      has already read, the budget, and the work it cannot see.
    \\                      For measuring whether any of that helps.
    \\  --export-dir <dir>  Ship the session log into this directory as it is
    \\                      written, one file per session. The file is byte for byte
    \\                      the log, so `chock sessions verify` reads it there too.
    \\  --export-syslog <path>
    \\                      Ship each line of the log to this unix datagram socket as
    \\                      an RFC 5424 message. Usually /dev/log on Linux and
    \\                      /var/run/syslog on Darwin. A syslog message is not a copy
    \\                      of the log: use --export-dir for one that verifies.
    \\                      An org policy bundle can require a sink of either kind.
    \\                      These options add to what it requires and can remove
    \\                      none of it. A required sink that this machine cannot
    \\                      reach does not stop the session; it is said at the start
    \\                      and again at the end, and a gap that is still open when
    \\                      the session ends exits 9.
    \\
++ tty.options_text;

/// The largest message `chock run` reads from standard input. A prompt is
/// prose. This bounds a pipe somebody pointed at a disk image.
const max_stdin_bytes: usize = 4 * 1024 * 1024;

/// How much of a tool result is shown on . The whole thing is in the
/// log; this is only what a person watching sees go past.
const shown_result_bytes: usize = 800;

const Options = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
    project: ?[]const u8 = null,
    session: ?[]const u8 = null,
    agent_kind: []const u8 = "main",
    /// The org policy bundle to read instead of the one in the data directory.
    /// See `loadOrgBundle`: the file this names is being handed to Chock now,
    /// so an expired one is refused, which is the one thing an expiry acts on.
    org_bundle: ?[]const u8 = null,
    max_turns: ?usize = null,
    continue_newest: bool = false,
    /// Take over a session that already exists and carry it on from what its
    /// log holds, appending no message of the caller's own.
    ///
    /// **This is the replay half of a handover**: the process holding the log's
    /// exclusive lock is the owner of that session, so becoming the owner is
    /// taking that lock, and recovering what the last owner held is folding the
    /// log. `chock_core.Loop.run` already does both, and it appends no second
    /// `session.start` when the fold found one. So the only thing this flag
    /// changes is that no user message is read and none is written: everything
    /// else about the run is an ordinary run.
    ///
    /// **A session with nothing in it is refused rather than started.** See
    /// `refuseAdoptWithNothingToAdopt`.
    adopt: bool = false,
    /// Copy the project's uncommitted work into the workspace before the
    /// session starts. Off by default: `git worktree add` checks out the
    /// commit, which is reproducible, and a session that starts from a known
    /// commit is easier to reason about. See `handleUncommitted`.
    allow_dirty: bool = false,
    /// Turn off everything the harness tells the agent about itself. On by
    /// default, because the notices are the feature; this is the off side of
    /// the measurement that says whether they earn their place. See
    /// `chock_core.notices`.
    no_notices: bool = false,
    /// Ship this session's log into this directory as it is written, one file
    /// per session. Null for a session that exports nothing, which is every
    /// session that says nothing about it and which runs byte for byte the way
    /// it did before export existed.
    ///
    /// **The file is byte for byte the log**, so the copy verifies at the far
    /// end with `chock sessions verify`. See `lib/chock-proto/ship.zig`.
    export_dir: ?[]const u8 = null,
    /// Ship each line of the log to this unix datagram socket as an RFC 5424
    /// message. Null for a session that exports nothing.
    ///
    /// **A path and not a flag**, so a test never has to reach a real syslog
    /// daemon and so a machine whose socket is somewhere unusual is served by
    /// the same option. `chock_proto.ship.Syslog.defaultPath` names the usual
    /// one for this platform, and the help text says it.
    export_syslog: ?[]const u8 = null,
    /// The session that started this one, when this session is somebody's
    /// subagent. Empty for a session a person started, which is every session
    /// somebody types by hand.
    ///
    /// **A parent writes all six of these onto a child's command line**, and
    /// nothing else does: see `chock_core.subagent.commandLine`. They are not
    /// in the usage text for the same reason: a person has no use for them,
    /// and the values that make them safe come from the parent process.
    parent_session: []const u8 = "",
    /// Every agent above this one, root first, with the reason each started the
    /// one below it. **This is what makes the policy an intersection**:
    /// `chock_policy.table.evaluateChain` folds every kind in the chain, so
    /// this session can hold no permission any agent above it lacks. A child
    /// cannot state one for itself, because a child does not write its own
    /// command line.
    ///
    /// **The whole chain and not the immediate parent alone.** One link was a
    /// real fault: a grandchild folded two kinds, neither of them the root's,
    /// and every session below the first reported depth 2, so `max_depth`
    /// bounded nothing below the second level. `--parent-kind` is repeated once
    /// per link, each followed by its own `--spawn-reason`, and
    /// `chock_core.subagent.commandLine` is what writes them in that order.
    parent_chain: []const chock_proto.event.SpawnLink = &.{},
    /// The session directory this session writes its scratchpad in, given by a
    /// parent. **A session that was given one does not remove it**: it sits
    /// inside the parent's own scratchpad, and the parent removes the whole
    /// tree when its run ends.
    scratchpad: []const u8 = "",
    /// The slice of the parent's budget this session may spend. Never widens
    /// what `chock.zon` allows: the smaller of the two is what this session
    /// runs under. See `budgetFor`.
    max_cost: ?f64 = null,
    currency: []const u8 = "",
    message_words: []const []const u8 = &.{},
    /// Show the session on a display instead of printing it, and on which one.
    ///
    /// **`parseOptions` never sets this, and no command line can.** `chock run`
    /// is the plain command line: it writes lines, it paints them, and it gains
    /// no display whatever standard output is. The interface is bare `chock`,
    /// and `src/ui.zig` is the only caller that turns this on, through
    /// `mainWithInterface`.
    ///
    /// The session itself is identical either way. All this changes is where
    /// `Printer`'s bytes go: to standard output, or to a buffer the display
    /// shows and writes back out when it gives the  up.
    display: ?Display = null,
    /// The caller asked for the usage text. Set by `readOptions` rather than
    /// acted on, because `chock run` and bare `chock` answer it differently.
    help_wanted: bool = false,
};

/// What bare `chock` asks for when it hands the run over: which display to
/// open, and the message it already has, if any.
///
/// **The display is opened by `runSession` and not by the caller**, so the
/// header band has the project, the workspace and the model from its first
/// frame: all three are worked out in phase 1, and the display comes up after
/// it. Phase 1's own diagnostics reach the real terminal for the same reason,
/// rather than the alternate screen that is about to be thrown away.
pub const Display = struct {
    attach: ui.Attach,
    /// A message already on standard input. The display is given it for its
    /// first turn, so a piped run and a typed one take one path.
    first_message: []const u8 = "",
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    return mainWith(arena, gpa, environ, exe_path, args, null);
}

/// `main`, with the session shown on a display. **Only `src/ui.zig` calls
/// this**, and it is what keeps `Options.display` off every command line.
pub fn mainWithInterface(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
    attach: ui.Attach,
    first_message: []const u8,
) !u8 {
    return mainWith(arena, gpa, environ, exe_path, args, .{
        .attach = attach,
        .first_message = first_message,
    });
}

/// Read a `chock run` command line, reporting whatever is wrong with it the way
/// `chock run` reports it. Null when it was reported.
///
/// **Public because bare `chock` takes the same options.** An option is not a
/// command name, so `chock --allow-dirty` is bare `chock` with an option on it
/// and `src/main.zig` hands the whole line here. One parser, one list of
/// options, and one error naming the option that is wrong: see
/// `main.namesNoCommand` for what a second list already cost twice.
///
/// `help_wanted` is set rather than answered, because the two callers answer it
/// differently: `chock run --help` prints the usage and stops, and bare `chock`
/// never gets here with it, since `src/main.zig` owns `--help`.
pub fn readOptions(arena: std.mem.Allocator, args: []const []const u8) !?Options {
    return parseOptions(arena, args) catch |err| switch (err) {
        error.HelpWanted => help: {
            tty.out(.plain, "{s}", .{usage_text});
            var asked = Options{};
            asked.help_wanted = true;
            break :help asked;
        },
        // Already reported by the parser, which names the option and prints the
        // usage that lists the real ones.
        error.BadArguments => null,
        else => |e| return e,
    };
}

fn mainWith(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
    display: ?Display,
) !u8 {
    var options = (try readOptions(arena, args)) orelse return Exit.usage.code();
    if (options.help_wanted) return Exit.finished.code();
    // Set here and never by the parser, so no command line can reach it. See
    // `Options.display`.
    options.display = display;

    // **Words on the line are the display's first message.** `chock
    // --allow-dirty fix the parser` means the same as `chock run --allow-dirty
    // fix the parser`, with a display: the words are what to ask, and without
    // this they would be parsed and then quietly dropped, because a run with a
    // display appends no message of its own. See `Display.first_message`.
    if (options.display) |*wanted| {
        if (options.message_words.len != 0) {
            wanted.first_message = try std.mem.join(arena, " ", options.message_words);
        }
    }

    var env = try environ.createMap(arena);

    // `.environ` is what `Threaded` resolves a bare `argv[0]` against, and
    // `Workspace.open` spawns a bare `git`. Left out, `Threaded` falls back to
    // a compiled in `PATH` of `/usr/local/bin:/bin:/usr/bin`, which finds no
    // `git` on a Nix machine at all: the failure is `error.NotFound` from a
    // workspace that looks like it could not be built.
    var setup_threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    const setup_io = setup_threaded.io();

    var started = start(arena, gpa, setup_io, &env, exe_path, options) catch |err| switch (err) {
        error.Reported => {
            setup_threaded.deinit();
            return Exit.usage.code();
        },
        else => |e| {
            setup_threaded.deinit();
            return e;
        },
    };
    // From here the workspace exists on disk and has to be taken down again,
    // whatever happens next.
    setup_threaded.deinit();

    // See this file's own top comment. Nothing in this phase spawns a
    // process, and everything in it either forks (the tool path) or would be
    // unsafe to run beside a fork.
    // The session `/resume` chose, if any. Read after phase 3, when this
    // session is fully down: see `takeUp`.
    var take_up: ?[]const u8 = null;
    // What the audit sinks of this session came to. Read in phase 3, when the
    // display is down and a line is one a person really reads: see
    // `reportShipping`.
    var shipped: ShippingReport = .{};

    const outcome = phase: {
        var session_threaded = std.Io.Threaded.init(std.mem.Allocator.failing, .{ .environ = environ });
        defer session_threaded.deinit();
        break :phase runSession(gpa, session_threaded.io(), environ, &env, &started, options, &take_up, &shipped);
    };

    var teardown_threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer teardown_threaded.deinit();
    const teardown_io = teardown_threaded.io();

    // **A handover applies nothing, and this is not a shortcut.** `applyWork`
    // asks a person to move a commit into their own repository because the
    // session is over and this is the last chance the work has. A session that
    // handed over is not over: the next owner is about to carry on in the same
    // workspace, and asking now would put a question about half finished work
    // in front of somebody, and would take the log lock this process has just
    // let go of. See `handedOver`.
    const gave_away = handedOver(outcome);
    const applied = if (gave_away) Applied.nothing_to_apply else applyWork(
        gpa,
        teardown_io,
        environ,
        &env,
        &started,
        options,
    ) catch |err| blk: {
        tty.print(.err, "chock run: the session's work could not be applied: {s}\n", .{@errorName(err)});
        break :blk Applied.failed;
    };

    // **Show it.** Memory a user cannot see is memory a user cannot trust,
    // and a note written this session is read by every session after it. So
    // a run that wrote one says so, and names the directory `chock memory`
    // reads and clears.
    reportNotes(teardown_io, &started);

    // **What left this machine, and what did not.** Printed here and not in
    // phase 2, because the display is down by now: a session that lost its audit
    // sink halfway through must say so somewhere a person reads rather than
    // behind an alternate screen. Prints nothing at all for a session that
    // exported nothing, which is every session that asked for none.
    reportShipping(&shipped);

    // After `applyWork`, which is the last thing that asks anybody anything,
    // and before the log closes. Closing it closes every attached client with
    // it, so a `chock approve` somebody left running learns the session is over
    // rather than waiting on a socket nothing will ever write to again.
    if (started.approvals) |endpoint| endpoint.close(teardown_io);

    // And the handover socket, at the same moment and for the same reason: the
    // client that asked for this session is waiting on it, and the end of that
    // stream is how it learns the log lock is free. `disarm` comes first, so
    // nothing can look at a descriptor this has closed.
    started.storage.close(teardown_io);

    // **Last of all, and after the log has closed.** The end of this stream is
    // what tells the process taking over that the log lock is free, so it must
    // not happen while anything here could still hold it. `Loop.run` releases
    // the lock on its own return in phase 2, and closing the log releases it
    // again whatever happened, so a client that reads the end of this stream
    // knows the lock is gone by both routes. `disarm` comes first, so nothing
    // can look at a descriptor this has closed.
    handover.disarm();
    if (started.handovers) |endpoint| endpoint.close(teardown_io);

    // **A clean ending removes the workspace. Any other ending keeps it.** See
    // `cleanupFor`: this used to remove it in every case, and a session that
    // hit a rate limit on 2026-08-22 had 105 changed files deleted with it.
    const session_exit: ?Exit = if (outcome) |value| value else |_| null;
    takeDownWorkspace(
        &started.workspace,
        cleanupFor(session_exit, applied),
        arena,
        teardown_io,
        &env,
        started.paths.work,
    );

    // **"Gone when the run ends" is a promise, so something has to keep it.**
    // The temp directory is emptied by the machine at some point of its own
    // choosing, which is not the same thing: a session that ended an hour ago
    // must not still have its files on disk. Removed in every case, including a
    // session that failed, because ephemeral is the security property this
    // directory is for, and a failed session's leftovers reach the next one
    // exactly as well as a finished session's would. Every background task has
    // already been waited for by then: see `runSession`.
    //
    // **A session that was given its scratchpad by a parent removes nothing.**
    // That directory is inside the parent's own, the parent is what is about to
    // read it, and the parent's own removal takes the whole tree, subagent
    // directories and all.
    //
    // **A session that handed over keeps it, and this is a decision.** The
    // scratchpad is keyed on the session identifier, so the next owner builds
    // the same path and finds whatever is in it: the output file of every
    // background command this session ran, and the notes the agent left itself.
    // Removing it here would take those from a session that has not ended, and
    // the log the next owner folds names those files by path. The next owner
    // removes the directory when the session really does end.
    if (started.scratch_owned and !gave_away) {
        if (started.scratch_dir) |dir| chock_core.scratchpad.remove(teardown_io, dir);
    }

    // After the workspace, because the session is over by now and every
    // string the sandbox config and the tool environment borrowed lives in
    // this arena.
    if (started.dev_shell) |*shell| shell.deinit();
    // And the image, for the same reason and at the same point: it owns the
    // strings the mount set and both environments borrowed.
    //
    // **It also lets go of the image's tree here, and not before.** The
    // extracted tree is shared with every other session on this image, and this
    // one holds a shared lock on it from `Image.load` to here, so that no other
    // session can remove it while a tool call is still binding it. This is the
    // last point at which a tool call of this session can be running: the
    // sandbox is down and the loop is over. A session that ends abnormally
    // never reaches this line and still lets go, because the kernel drops a
    // `flock` when the process ends however it ends.
    if (started.image) |*one| one.deinit(teardown_io);

    const result = outcome catch |err| {
        // **`Busy` is not a fault, it is a second owner.** `Loop.run` takes the
        // exclusive lock on the session log, and the kernel refuses the second
        // asker: see `refuseAdoptWithNothingToAdopt`. Reported by name because
        // "the session failed: Busy" reads as a crash and sends a reader
        // looking at a log that is perfectly healthy.
        if (err == error.Busy) {
            tty.print(.err, "chock run: {s}\n", .{busy_detail});
            return Exit.usage.code();
        }
        tty.print(.err, "chock run: the session failed: {s}\n", .{@errorName(err)});
        return Exit.faulted.code();
    };

    // **Last of all, because everything of this session has to be down first.**
    // Its log is closed, its sockets are closed, its workspace is gone and its
    // terminal is back: see `takeUp` for why each of those matters.
    if (take_up) |id| {
        // Duped from `gpa` by the display, because it has to outlive the phase
        // that produced it. This is the last reader of it.
        defer gpa.free(id);
        return takeUp(teardown_io, &env, started.exe_path, started.project_root, id);
    }

    return exitWithApply(result, applied, &shipped).code();
}

/// Take up another session of this project, in place of this one.
///
/// **A new process, and that is the point.** Phase 1 builds a workspace, opens
/// a log, takes its lock and opens two sockets; phase 3 takes all of that down
/// again. A session taken up needs every one of those done for itself, and the
/// only honest way to get that is to run them, from the top, for the session
/// being taken up. `chock run --session <id> --adopt` is a command that already
/// exists and that was measured by hand on both platforms.
///
/// **A child and not an `execve`.** Zig 0.16's `std.posix` exposes no portable
/// `execve` and this program does not link libc, so the one replacement call
/// available would be `std.os.linux.execve`, which is a platform branch this
/// file may not have. `std.process.spawn` is what every subagent already uses
/// and it reaches the same place: the child owns the terminal, and this process
/// waits for it and exits with its code. What it costs is a waiting parent.
///
/// **The terminal is already restored.** `runSession`'s own `defer` took the
/// display down before phase 3, which left the alternate screen, put raw mode
/// back and showed the cursor. The child brings its own up. Getting that order
/// wrong would leave a broken shell behind if the child never started.
///
/// **This session has already ended cleanly**, with its own `session.end`
/// written by `Loop.run`, exactly as leaving does. Nothing is lost, and there
/// is nothing to return to if the child cannot be started.
fn takeUp(
    io: std.Io,
    env: *const std.process.Environ.Map,
    exe_path: []const u8,
    project_root: []const u8,
    id: []const u8,
) !u8 {
    // `--project` and not the working directory: a child inherits this
    // process's, and this process may have been started anywhere.
    const argv = [_][]const u8{
        exe_path,
        "run",
        "--project",
        project_root,
        "--session",
        id,
        "--adopt",
    };

    var child = std.process.spawn(io, .{
        .argv = &argv,
        .environ_map = env,
    }) catch |err| {
        // The terminal is a person's own again by now, so this lands where they
        // can read it.
        tty.print(
            .err,
            "chock: session {s} could not be taken up ({s}). It was not started, and this one " ++
                "has ended. `chock run --session {s} --adopt` is what this would have run.\n",
            .{ id, @errorName(err), id },
        );
        return Exit.faulted.code();
    };
    return switch (try child.wait(io)) {
        .exited => |code| code,
        // Killed by a signal, which is what a second Ctrl-C does. The child
        // reports its own ending in its own log; this says the run did not end
        // normally, the same way every other abnormal end here does.
        else => Exit.faulted.code(),
    };
}

/// What became of the session's own work at the end of the run.
const Applied = enum {
    /// The session left the workspace at the commit it started from, so
    /// there was nothing to carry back and nothing was asked for.
    nothing_to_apply,
    /// The session left the workspace at the commit it started from **and**
    /// left changed files in it. The work is real, and none of it reaches the
    /// user's repository, because only a commit can be carried back.
    ///
    /// **The workspace is kept for this case**, so the work is somewhere a
    /// person can still get it: see `cleanupFor`. It used to be deleted here,
    /// which is how a session measured on 2026-08-22 lost 105 changed files.
    ///
    /// **A separate answer from `nothing_to_apply`, because a script must be
    /// able to tell them apart.** Before the write tools existed the agent
    /// could not produce this state at all; with them it is the ordinary
    /// shape of a session that forgot to commit, and it was measured on the
    /// first real run of `write_file` and `edit_file`. Reporting it as
    /// "nothing to apply" would be a step reporting success for work it
    /// threw away, which `src/main.zig`'s own top comment names as the worst
    /// kind of failure this program can have.
    uncommitted,
    /// The broker moved the objects and the ref. The work is in the project.
    landed,
    /// The decision did not permit it. The project is unchanged. An approval
    /// nobody answers is a refusal, and that is the safe direction.
    refused,
    /// The apply was permitted and the act itself failed, or the description
    /// of it could not be read. The project may hold the objects and does not
    /// hold the ref: `perform` moves the objects first.
    failed,
};

/// What becomes of the workspace once the run is over.
const Cleanup = enum {
    /// Take it down, the way every run always did.
    remove,
    /// Leave it on disk, and say where it is. See `reportKeptWorkspace`.
    keep,
    /// Leave it on disk for the process that is taking this session over.
    ///
    /// **The same act as `keep` and a different sentence, and the sentence is
    /// the point.** `keep` tells a person their session went wrong and their
    /// work is stranded. A handover left the workspace on purpose, the next
    /// owner is about to work in it, and telling somebody to go and rescue it
    /// would send them to move files out from under a running session.
    hand_on,
};

/// Whether the workspace comes down at the end of this run.
///
/// **A clean ending removes it, and every other ending keeps it.** The rule
/// that only a commit reaches the user's repository is right and is unchanged
/// here: it protected the repository exactly as designed. The loss was the
/// cleanup. `Workspace.close` used to run on every ending, so a session that
/// errored, was refused, reached its budget, made no progress, or was
/// interrupted had whatever it produced deleted along with the worktree. A
/// session measured on 2026-08-22 met a rate limit and lost 105 changed files
/// that way.
///
/// Two conditions, and both have to hold for the workspace to go:
///
/// * **The session itself ended cleanly.** Anything else, including a run
///   whose session could not report an ending at all, keeps it.
/// * **There is nothing left in it.** `landed` means the commit is in the
///   user's repository, and `nothing_to_apply` means the agent changed
///   nothing. `uncommitted` is the measured case: real work, no commit, and
///   nothing carried back, so the workspace is the only copy of it.
fn cleanupFor(session_exit: ?Exit, applied: Applied) Cleanup {
    const ended = session_exit orelse return .keep;
    // **Before the `finished` test, because a handover is neither.** The
    // workspace stays, exactly as it does for every other ending that is not
    // clean, and what changes is what a person is told: see `Cleanup.hand_on`.
    if (ended == .handed_over) return .hand_on;
    if (ended != .finished) return .keep;
    return switch (applied) {
        .nothing_to_apply, .landed => .remove,
        .uncommitted, .refused, .failed => .keep,
    };
}

/// What becomes of the workspace when the session cannot even start.
///
/// **A process that adopted a workspace never removes it.**
/// `chock_workspace.Workspace.close` runs `git worktree remove --force`, and
/// the checkout it would remove is the one another owner left with work in it.
/// A failure in `start` is this process's failure and is not a reason to delete
/// somebody else's files. A workspace this process built is removed as it
/// always was: nothing else has ever looked at it, so leaving it would fill a
/// disk with directories that hold nothing.
///
/// **Its own function so a test can drive the decision**, which the `errdefer`
/// that uses it cannot be made to run from one. A test that only called `keep`
/// and `close` by hand would pin what those two do and say nothing about which
/// one `start` picks.
fn releaseOnFailure(adopted: bool) Cleanup {
    return if (adopted) .keep else .remove;
}

/// Whether this run gave the session to another process.
///
/// **Read out of the exit code, which is read out of the log**, and never out
/// of a flag this process set. `finalExit` folds the log to reach the code, and
/// the log is the truth about a session. A flag would be a second answer that
/// can disagree with the first, and the process taking over reads only the log.
///
/// A run whose session could not report an ending at all did not hand over. It
/// keeps its workspace either way, through `cleanupFor`'s first line.
fn handedOver(outcome: anyerror!Exit) bool {
    const ended = outcome catch return false;
    return ended == .handed_over;
}

/// End the workspace the way `cleanup` says.
///
/// **Its own function so the two arms can be driven from a test.** The
/// decision and the act are separable, and both have to be right: a `keep`
/// that still removed would lose the work it was added to save, and a `remove`
/// that stopped removing would fill the user's disk with every session they
/// ever ran. `workspace` is not valid after this call returns, either way.
fn takeDownWorkspace(
    workspace: *chock_workspace.Workspace,
    cleanup: Cleanup,
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    /// The session's own scratch directory, which the workspace sits inside.
    /// Named in the failure message below rather than `workPath`, because
    /// `close` frees every string the workspace owns before it can fail.
    scratch_path: []const u8,
) void {
    var close_diag: ?chock_workspace.Diagnostic = null;
    switch (cleanup) {
        .remove => workspace.close(arena, io, env, &close_diag) catch |err| {
            // The session already happened and its log is already durable. A
            // workspace that would not come down is worth saying out loud and
            // is not worth throwing the session's own answer away over.
            //
            // Which call failed, and what it answered. The workspace used to
            // print that itself and hand this command `error.Unexpected`.
            if (close_diag) |*fault| {
                tty.print(.err, "chock run: the workspace at {s} could not be removed: {f}\n", .{
                    scratch_path,
                    fault,
                });
            } else {
                tty.print(.err, "chock run: the workspace at {s} could not be removed: {s}\n", .{
                    scratch_path,
                    @errorName(err),
                });
            }
        },
        .keep => {
            // Named before the value is freed: `workPath` borrows from the
            // workspace, and `keep` ends it.
            reportKeptWorkspace(workspace.workPath());
            workspace.keep(arena);
        },
        .hand_on => {
            // The same act, and a sentence that says what really happened.
            tty.detail("chock run: the workspace stays for the next owner: {s}\n", .{workspace.workPath()});
            workspace.keep(arena);
        },
    }
}

/// Say where a kept workspace is, and how to be rid of it.
///
/// **One line of output turns a total loss into something a person can
/// salvage**, and it is the only reason keeping the workspace is worth
/// anything: a directory nobody names is a directory nobody finds. The second
/// half names `chock workspace`, because a directory nobody removes is a disk
/// that fills, and that command is the same shape `chock cache` and
/// `chock memory` already have.
fn reportKeptWorkspace(path: []const u8) void {
    tty.print(
        .warn,
        "chock run: this session did not end cleanly, so its workspace is kept:\n" ++
            "           {s}\n" ++
            "chock run: whatever the agent wrote is still there. `chock workspace` lists every\n" ++
            "           kept workspace of this project with its size, and `chock workspace clear`\n" ++
            "           removes them.\n",
        .{path},
    );
}

/// The exit code of the whole run, which is a statement about the session,
/// about whether its work landed, **and** about whether its record got out.
///
/// A session that finished and whose work was refused did not do what the
/// user asked for, and a script that read 0 there would carry on as though
/// the change was in the repository. So a refused apply lowers a `finished`
/// to `refused`. It never raises anything: a session that faulted still
/// reports the fault, because that is the first thing to act on.
///
/// **The audit fold is inside this one and never beside it.** `run` has one
/// exit fold and calls it once, so an installation's required sink cannot be
/// left out of the answer by a caller that forgot a second call. See
/// `exitWithAudit` for what that fold decides and why it is so narrow.
fn exitWithApply(session_exit: Exit, applied: Applied, shipped: *const ShippingReport) Exit {
    if (session_exit != .finished) return session_exit;
    const landed: Exit = switch (applied) {
        .nothing_to_apply, .landed => .finished,
        .refused => .refused,
        // The agent did work and Chock threw it away. A script that read 0
        // here would carry on as though the project had been changed, which
        // is the same mistake a refused apply would make.
        .uncommitted, .failed => .faulted,
    };
    return exitWithAudit(landed, shipped);
}

/// The exit code of the whole run, once the audit trail is taken into account.
///
/// **This is the part of a required sink an organisation can act on**, and it
/// is the third of the three things `chock_policy.org` decided a required sink
/// changes. A session must not fail because an audit sink is down, so a
/// required sink never stops a session and never refuses to start one; what it
/// does is leave a status a wrapper can read, at the one moment the answer is
/// final.
///
/// **Narrow on purpose.** A sink that went down and came back leaves no gap at
/// all, because the log on disk is the queue, so a run like that exits exactly
/// as it would have. Only a sink that still holds less than the whole log when
/// the session is over reaches this. A transient outage costs nothing, which is
/// what stops this being the refuse-to-start answer wearing a different hat.
///
/// **It never raises anything**, the same rule `exitWithApply` keeps. A session
/// that faulted reports the fault, because a broken session is the first thing
/// to act on and a script that read `audit_gap` there would go looking at the
/// wrong problem.
///
/// **Last, and after `cleanupFor` has read the session's own code.** A
/// workspace is removed because the session finished and its work landed, and
/// an audit sink that could not be reached says nothing about either of those.
/// Folding this in any earlier would keep the workspace of every clean session
/// on a machine whose collector was down.
///
/// **Its own function and still only ever called from `exitWithApply`.** The
/// decision is worth stating on its own, so a test can drive it without an
/// apply; the call is inside the one fold `run` already makes, so nothing has
/// to remember to make a second one.
fn exitWithAudit(session_exit: Exit, report: *const ShippingReport) Exit {
    if (session_exit != .finished) return session_exit;
    return if (report.requiredGap()) .audit_gap else .finished;
}

/// Everything phase 1 built, which phases 2 and 3 use.
const Started = struct {
    /// The `chock` program itself, which is what a subagent of this session
    /// runs. See `SubagentSpawner`.
    exe_path: []const u8,
    /// The project this session works on, which a subagent of this session
    /// works on too: a child is a session with a parent and nothing more.
    project_root: []const u8,
    paths: session_paths.Paths,
    /// This session's own identifier, which names the ref its work lands on.
    /// See `applyRef`.
    session_id: []const u8,
    workspace: chock_workspace.Workspace,
    /// The policy table of `chock.zon`, parsed once when the session started.
    /// **This is the only way to say yes to an approval in `chock run`**: see
    /// `applyWork`. A project with no `chock.zon` gets the safe table, where
    /// every key resolves to `ask`.
    policy: *const chock_policy.table.Table,
    sandbox_config: sandbox.Config,
    /// This project's Nix dev shell, or null when it has none. Owns the
    /// strings `sandbox_config.env` and `tool_env` borrow, so it outlives
    /// the session and comes down in phase 3.
    dev_shell: ?chock_nix.DevShell,
    /// This project's container image, or null when it names none. Owns the
    /// strings `toolchain`, `sandbox_config.env` and `tool_env` borrow, for
    /// the same reason the dev shell above does. A session has one of the two
    /// and never both: see `loadImage`.
    image: ?chock_container.Image,
    /// Where the files a tool call runs come from. See `Toolchain`.
    toolchain: Toolchain,
    /// The environment a tool call resolves `argv[0]` against: the dev
    /// shell's when the project has one, the host's when it does not. See
    /// `toolEnvironment`.
    ///
    /// **Mutable, because a session's toolchain can grow.** A provisioned
    /// program joins this map's own `PATH`, and every tool call after that one
    /// finds it. See `ProvisionToolRunner`.
    tool_env: *std.process.Environ.Map,
    /// What this session needs to add a program to its toolchain with Nix, or
    /// null when it cannot. See `provisioningFor`, which says out loud why a
    /// session has none.
    provisioning: ?Provisioning,
    backing: *chock_proto.storage.JsonLines,
    storage: chock_proto.storage.Storage,
    /// The base URL and the credential of the instance this session talks to.
    base_url: []const u8,
    /// Which wire format that instance speaks. The adapter is not the provider,
    /// so this comes from the instance kind and the user still hears the
    /// instance name everywhere else.
    adapter: chock_provider.Client.Adapter,
    /// What this session may spend, from the `budget` block of `chock.zon`, and
    /// whether the endpoint bills anybody at all. See `lib/chock-cost.zig`.
    budget: ?chock_cost.budget.Budget,
    billing: chock_cost.prices.Billing,
    /// How deep and how wide this project lets a spawn tree grow, from the
    /// `subagents` block of `chock.zon`. A project that named none gets the
    /// default 6 by 6 tree, and the file is kept beyond the agent's reach, so
    /// **the model cannot raise its own limit**.
    subagents: chock_policy.subagents.Limits,
    /// This project's language server, from the `language_servers` block of
    /// `chock.zon`, or null when it named none.
    ///
    /// **From the project and never from the model**, the same road every other
    /// block of this file takes: the project's own copy is bound back over the
    /// agent's read only, so an agent cannot name the program that starts by
    /// editing a file. A project that named none pays nothing at all, and every
    /// write answers as it did before this existed.
    language_server: ?chock_core.lsp_driver.Settings,
    /// This project's MCP servers, from the `mcp_servers` block of
    /// `chock.zon`, or null when it named none.
    ///
    /// **From the project and never from the model**, the same road every
    /// other block of this file takes. Null is the ordinary answer, and a
    /// session with null does not run one line of `chock_core.mcp`: see
    /// `runSession`, where the whole block is behind this one test.
    mcp_servers: ?[]const chock_core.mcp.Settings,
    /// This project's plugins, from the `plugins` block of `chock.zon`, or null
    /// when it named none.
    ///
    /// **From the project and never from the model**, the same road every other
    /// block of this file takes, and the reason the name in every policy key
    /// about a plugin is the project's: see `lib/chock-core/plugin.zig`. Null is
    /// the ordinary answer, and a session with null runs no line of
    /// `chock_core.plugin` at all: see `startPlugins`.
    plugins: ?[]const chock_core.plugin.Settings,
    /// What the system prompt is built from, kept so phase 2 can build it
    /// again once the MCP servers and the plugins have said which tools they
    /// have.
    ///
    /// **Only a project with an `mcp_servers` or a `plugins` block ever uses
    /// these.**
    /// `system_prompt` and `tool_definitions` below are already built, and a
    /// project with no MCP server takes them unchanged, which is what makes
    /// such a session byte for byte the session it was before this existed.
    prompt_project: chock_core.prompt.Project,
    prompt_sources: chock_core.prompt.Sources,
    /// Every parent of this session, root first, and this session left out.
    /// Empty for a session a person started. **Built from the command line the
    /// parent wrote**, so a session cannot state its own parents: see
    /// `Options.parent_kind`.
    spawn_chain: []const chock_proto.event.SpawnLink,
    credential: chock_auth.lookup.Resolved,
    model: []const u8,
    /// The provider instance's own name. A roster of model aliases is wanted
    /// and this milestone has none, so the alias a session records is the
    /// instance name: the only user chosen name there is today. A `message`
    /// event says which one produced it either way, which is what the field is
    /// for.
    model_alias: []const u8,
    system_prompt: []const u8,
    tool_definitions: []chock_core.tools.Definition,
    /// This project's knowledgebase, or null when the directory could not be
    /// made. **The one writable mount outside the workspace**, and only for
    /// the two tool calls that use it: see `lib/chock-core/tools.zig`.
    memory_dir: ?[]const u8,
    /// How many notes this project held when the session started, so the run
    /// can say how many it wrote.
    notes_at_start: usize,
    /// This project's toolchain cache, or null when the directory could not be
    /// made. **The one writable mount a `run_command` call has that outlives
    /// the session**, and no other tool call carries it: see
    /// `lib/chock-core/cache.zig`.
    cache_dir: ?[]const u8,
    /// This session's scratchpad, or null when the directory could not be
    /// made. **It is removed when the run ends**, whatever the ending, which is
    /// what makes it a writable surface outside the workspace that is not a
    /// channel into the next session: see `lib/chock-core/scratchpad.zig`. The
    /// capped temporary area beside it is gone sooner still, with the tool call
    /// that mounted it, and has no host directory at all.
    scratch_dir: ?[]const u8,
    /// Whether this session made its own scratchpad, and so is the one that
    /// removes it. False for a subagent, which was given a directory inside
    /// its parent's own: see `Options.scratchpad`.
    scratch_owned: bool,
    /// The half of the scratchpad a background task's output is written into,
    /// on the host. Null exactly when `scratch_dir` is. **The agent's sandbox
    /// gets this bound read only** and the harness writes it from outside every
    /// sandbox, which is what makes the output a record and not a claim: see
    /// `lib/chock-core/tasks.zig`.
    tasks_dir: ?[]const u8,
    /// How many tokens the model this session talks to can hold, from the
    /// instance's own `context_tokens` in `chock.zon`. Null when the file said
    /// nothing, and null is never a guess: the session then compacts only when
    /// the provider refuses a request as too large. See
    /// `chock_core.compaction.Policy`.
    context_tokens: ?u64,
    /// How many files in the user's own project are not committed, and so are
    /// not in the workspace the agent sees. **The user is already told this
    /// number and the agent was not**, which is what this carries it here for:
    /// see `handleUncommitted` and `chock_core.Loop.Deps.uncommitted_files`.
    ///
    /// Zero for a clean tree, zero for an overlay workspace, which copies the
    /// whole project directory, and zero with `--allow-dirty`, which brings
    /// the work across so that nothing is hidden.
    uncommitted_files: usize,
    /// Where a client attaches to answer this session's approvals, or null when
    /// the socket could not be made. See `lib/chock-broker/socket.zig`.
    ///
    /// **A pointer, because a `Waiter` holds one.** `start` returns a `Started`
    /// by value, so a waiter that pointed into this struct would point at a
    /// copy that has already moved. The endpoint itself lives in the arena and
    /// is closed in phase 3.
    ///
    /// **Null is the old behaviour and never a crash.** A session directory
    /// deeper than a unix socket path may be, or a filesystem that will not
    /// hold one, gives a session with no socket. It still runs, and a question
    /// it cannot ask anybody is still refused, the safe direction.
    approvals: ?*chock_broker.socket.Endpoint,
    /// Where another process asks for this session, or null when the socket
    /// could not be made. See `lib/chock-broker/handover.zig`.
    ///
    /// **A pointer for the reason `approvals` is one**, and null is the old
    /// behaviour: a session no process can take. `src/handover.zig` is what
    /// points the loop at it.
    handovers: ?*chock_broker.handover.Endpoint,
    /// The identifier this run's workspace is named after. Fresh on every
    /// invocation, except for a run that took over a workspace another owner
    /// left: see `takenOver`. Kept so phase 3 can name the directory it is
    /// leaving on disk.
    attempt: []const u8,
    /// Where this session's log goes as it is written, and empty for a session
    /// that exports nowhere. See `auditSinks`: it is what `--export-dir` and
    /// `--export-syslog` asked for **and** what this installation's org policy
    /// bundle requires, with no way for the command line to drop one of the
    /// second kind.
    ///
    /// **Built in phase 1 and read in phase 3**, so it lives in the run's own
    /// arena rather than in anything phase 2 owns.
    audit_sinks: []const PlannedSink,
    /// What must not reach the provider. See `redactionFor`, and
    /// `lib/chock-core/redact.zig` for what redaction is and, just as plainly,
    /// what it is not.
    ///
    /// **Borrowed for the whole session.** Every value in it lives in the run's
    /// own arena, which is what `chock_core.redact.Policy.secrets` asks of a
    /// caller.
    redact: chock_core.redact.Policy,
    /// The same values, in the shape `chock_broker.Broker.redaction` takes.
    /// See `brokerRedaction`: the broker writes into the same log as the loop
    /// and cannot read a `chock_core.redact.Policy`, so the values travel and
    /// the policy does not.
    redact_values: []const []const u8,
};

const StartError = error{Reported} || std.mem.Allocator.Error;

/// The org policy bundle this installation was given, or null for one that was
/// given none.
///
/// **This is the outermost layer of the policy**, the policy rule read one
/// level up: `chock.zon` belongs to the project directory, so the developer who
/// owns that directory writes it, and an organisation that wants to bound every
/// project at once cannot use a file inside the thing it bounds. See
/// `chock_policy.org`, which holds the reader and the whole of the reasoning.
///
/// Two ways in, and they are not the same act:
///
/// * **The installed bundle**, in the data directory beside the credential
///   store. Absent is the ordinary answer and never a fault. An expired one
///   still binds, in full: see `chock_policy.org`, and the reason is that a
///   bundle can only narrow, so dropping one can only widen and can only widen
///   at the moment nobody can be reached.
/// * **`--org-bundle`**, which is somebody handing Chock a file now. A path
///   that names nothing is a fault, because the caller asked for that file. An
///   expired file is refused, because this is the moment of installing and the
///   date is what says whether this file may still be installed. That refusal
///   is the one thing an expiry acts on, and it is what stops the date being
///   decoration.
///
/// The subject and the expiry are printed rather than kept quiet. A session
/// running under a policy nobody can see is the failure this whole layer would
/// otherwise introduce.
fn loadOrgBundle(
    arena: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    options: Options,
) StartError!?*const chock_policy.org.Bundle {
    const named = options.org_bundle;

    // **A subagent reads the installed bundle and never a named one.** A parent
    // writes its child's command line, and `chock_core.subagent.flag` carries
    // no bundle, so a child given a path here would be a child under a
    // different, and possibly wider, org policy than its parent. That is the
    // one direction the subagent limits exist to prevent, so it is refused out
    // loud rather than left to be discovered. The installed bundle is the same
    // file for every session of an installation, which is why it needs no flag.
    if (named != null and options.parent_chain.len != 0) {
        tty.print(
            .err,
            "chock run: --org-bundle names a file for this session alone, and a subagent takes " ++
                "its org policy from the installation, the same file its parent read. Install " ++
                "the bundle instead of naming it.\n",
            .{},
        );
        return error.Reported;
    }

    const path = named orelse
        try std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name });

    var diag: ?chock_policy.org.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);
    const bundle = chock_policy.org.load(arena, io, path, &diag) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NoBundleFile => {
            // An installation with no bundle is the ordinary one, and it is
            // silent. A path the caller typed is not: they asked for that file.
            if (named) |asked| {
                tty.print(.err, "chock run: there is no org policy bundle at {s}.\n", .{asked});
                return error.Reported;
            }
            return null;
        },
        else => {
            if (diag) |*d| {
                tty.print(.err, "chock run: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the org policy bundle at {s} could not be read: {t}\n", .{ path, err });
            }
            return error.Reported;
        },
    };

    // **The one clock read, and it is read here.** Everything the time decides
    // is in the two functions below, which take it as a parameter, so a test
    // can pin every word they write without asserting anything about a wall
    // clock.
    const now_ms = std.Io.Timestamp.now(io, .real).toMilliseconds();

    // A file being handed over now must be a file that may still be handed
    // over. One already on this machine is a different question, and the
    // answer to that one is `reportOrgBundle`.
    if (named) |asked| try refuseUninstallableBundle(bundle, now_ms, asked);
    reportOrgBundle(bundle, now_ms);
    return bundle;
}

/// Refuse a bundle somebody is handing to Chock now, when it is one nobody may
/// hand over any more. See `chock_policy.org.refusalForInstall`: this is the
/// one thing an expiry acts on, and it is what stops the date being decoration.
fn refuseUninstallableBundle(
    bundle: *const chock_policy.org.Bundle,
    now_ms: i64,
    path: []const u8,
) StartError!void {
    const why = chock_policy.org.refusalForInstall(bundle, now_ms) orelse return;
    tty.print(.err, "chock run: {s}\n", .{why});
    tty.print(.err, "  the bundle is {s}\n", .{path});
    return error.Reported;
}

/// Say who this installation's policy belongs to, and say when it went stale.
///
/// **Who**: the organisation issued the credential, so Chock knows the subject
/// without holding an identity of its own. This is the only place a person
/// sees it today, and `src/run.zig` cannot yet put it in the session log: see
/// this file's own note beside `recordWorkspace`.
///
/// **When**: the bundle keeps binding whatever the date says, which is the
/// decision `chock_policy.org` writes out in full, so the date's whole job
/// here is to be seen. An expiry that changed nothing and said nothing would
/// be decoration, and a person under a stale policy has to be able to tell.
fn reportOrgBundle(bundle: *const chock_policy.org.Bundle, now_ms: i64) void {
    if (bundle.subject.len != 0) {
        tty.print(.plain, "chock: org policy for {s}", .{bundle.subject});
        if (bundle.issuer.len != 0) tty.print(.plain, ", issued by {s}", .{bundle.issuer});
        tty.print(.plain, ", {d} rule{s}\n", .{
            bundle.rules.len,
            if (bundle.rules.len == 1) "" else "s",
        });
    }

    const stale_ms = bundle.expiredForMs(now_ms) orelse return;
    const days = daysIn(stale_ms);
    tty.print(
        .warn,
        "chock: this org policy bundle expired {d} day{s} ago. It still binds this session, " ++
            "because dropping it could only widen what the session may do. Ask whoever issued " ++
            "it for a current one.\n",
        .{ days, if (days == 1) "" else "s" },
    );
}

/// Whole days in a span of milliseconds, rounded down. For the one line that
/// tells a person how stale their org policy is.
fn daysIn(span_ms: i64) i64 {
    return @divFloor(span_ms, std.time.ms_per_day);
}

/// This project's policy table, under the org bundle this installation holds.
///
/// `chock.zon` is the project's and the agent cannot reach it, which is what
/// makes it a control the model cannot loosen for itself. A project with no
/// `chock.zon` gets the table where every key resolves to `ask`, which is the
/// safe reading of a project that said nothing.
///
/// **The bundle is one more term of the intersection `evaluateChain` already
/// takes**, so a rule in `chock.zon` can lower an answer and can never raise
/// one: a project cannot widen what an org narrowed. An installation with no
/// bundle hands in an empty rule list, which is the identity of that
/// intersection and changes nothing at all. See
/// `chock_policy.table.parseUnder`.
///
/// **A function rather than a block inside `start`**, because the wiring is
/// the thing that could quietly go missing: a `start` that read the file
/// without the bundle would build a table with no layer above it, and every
/// test of the layers themselves would still pass. This takes the bundle and
/// not a rule list, so there is no rule list a caller could get wrong, and
/// there is one function a test can hold both halves against.
fn loadPolicyUnder(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    org_bundle: ?*const chock_policy.org.Bundle,
) StartError!*const chock_policy.table.Table {
    const org_rules: []const chock_policy.table.Rule =
        if (org_bundle) |bundle| bundle.rules else &.{};

    var policy_diag: ?chock_policy.table.Diagnostic = null;
    defer if (policy_diag) |*d| d.deinit(arena);
    return chock_policy.table.Table.loadUnder(
        arena,
        io,
        project_root,
        org_rules,
        &policy_diag,
    ) catch |err| switch (err) {
        error.NoPolicyFile => chock_policy.table.Table.parseUnder(arena, ".{}", org_rules, null) catch
            return error.OutOfMemory,
        else => {
            // The line, the column and the name of the rule that is wrong.
            // The reader used to print all of that itself and hand this
            // command an error name; now the reason arrives here and is
            // ranked with every other line the command writes.
            if (policy_diag) |*d| {
                tty.print(.err, "chock run: the policy in chock.zon could not be read: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the policy in chock.zon could not be read: {t}\n", .{err});
            }
            return error.Reported;
        },
    };
}

/// Refuse this session when the policy says it may not use this provider
/// instance, or may not use this model at it. See `chock_policy.access` for
/// the two row names and for why only `allow` permits.
///
/// **Folded over the whole spawn chain**, so a subagent cannot use a model its
/// parent could not. The chain is built the same way `provisionDecision`
/// builds it, and for the same reason: a session cannot state its own parents.
///
/// **A project that names no provider row is refused nothing**, because the
/// rows are read as a ceiling and a ceiling nobody wrote is no ceiling. Every
/// configuration that predates these names therefore behaves as it did.
fn refuseProviderAndModel(
    arena: std.mem.Allocator,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    options: Options,
    instance_name: []const u8,
    model: []const u8,
) StartError!void {
    const rows = chock_policy.access.rowsFor(instance_name, model) catch |err| {
        tty.print(
            .err,
            "chock run: the provider {s} and the model {s} cannot be named in a policy rule: {t}. " ++
                "A provider name and a model id are short names, and neither may hold a \"*\".\n",
            .{ instance_name, model, err },
        );
        return error.Reported;
    };

    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = options.agent_kind;

    // A chain this reader cannot fold answers `deny` here, not `ask`: nobody is
    // awake at the moment a session picks a model. Said out loud, because a
    // chain that shape means the log holds something Chock did not write.
    var fault: ?chock_policy.table.ChainFault = null;
    const decision = chock_policy.access.ceiling(policy, .{
        .chain = chain,
        .agent_kind = options.agent_kind,
        // The alias, which is what `table.Key.model` holds everywhere else.
        // Today that is the instance name: see `Started.model_alias`.
        .model_alias = instance_name,
    }, &rows, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});

    if (!chock_policy.access.refusalNeeded(decision)) return;

    tty.print(
        .err,
        "chock run: this session may not use the model {s} at the provider {s}. " ++
            "The policy answers {t} for {s} and {s}.\n",
        .{ model, instance_name, decision, rows.instance(), rows.model() },
    );
    if (chain.len > 1) {
        tty.print(
            .err,
            "  The answer is folded over the whole spawn chain, so an agent holds no model its " ++
                "parent lacks.\n",
            .{},
        );
    }
    return error.Reported;
}

fn start(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    exe_path: []const u8,
    options: Options,
) StartError!Started {
    const project_root = try resolveProject(arena, io, options);

    const config_dir = chock_auth.paths.configDir(arena, env) catch |err| {
        tty.print(.err, "chock run: the configuration directory is unknown: {s}\n", .{@errorName(err)});
        return error.Reported;
    };
    const data_dir = chock_auth.paths.dataDir(arena, env) catch |err| {
        tty.print(.err, "chock run: the data directory is unknown: {s}\n", .{@errorName(err)});
        return error.Reported;
    };

    // The layer above this project's own policy, read before anything else so
    // that a bundle Chock cannot read stops the session rather than being
    // discovered halfway through it. Null for the ordinary installation, which
    // then behaves exactly as it did before bundles existed.
    const org_bundle = try loadOrgBundle(arena, io, data_dir, options);

    var config_diag: ?chock_auth.config.Diagnostic = null;
    defer if (config_diag) |*d| d.deinit(arena);
    var config = chock_auth.config.load(arena, io, config_dir, &config_diag) catch |err| switch (err) {
        error.NoConfigFile => {
            // The fault is ranked and the example is not, the same rule the
            // usage text keeps: a whole block in one colour hides the line
            // that says what went wrong.
            tty.print(
                .err,
                "chock run: there is no configuration at {s}/{s}. Write one, for example:\n\n",
                .{ config_dir, chock_auth.config.file_name },
            );
            tty.print(
                .err,
                "  .{{\n" ++
                    "      .providers = .{{\n" ++
                    "          .{{ .name = \"local\", .kind = \"openai-compat\", " ++
                    ".base_url = \"http://127.0.0.1:5000/v1\", .context_tokens = 65536 }},\n" ++
                    "      }},\n" ++
                    "      .defaults = .{{ .provider = \"local\", .model = \"glm4.7-flash:A3B\" }},\n" ++
                    "  }}\n",
                .{},
            );
            return error.Reported;
        },
        else => {
            // The line, the column, and the provider whose entry is wrong.
            // The reader used to print all of that itself.
            if (config_diag) |*d| {
                tty.print(.err, "chock run: the configuration could not be read: {f}\n", .{d});
            } else {
                tty.print(.err, "chock run: the configuration could not be read: {s}\n", .{@errorName(err)});
            }
            return error.Reported;
        },
    };

    const instance = pick: {
        if (options.provider) |name| {
            break :pick config.find(name) orelse {
                tty.print(
                    .err,
                    "chock run: the configuration names no provider called \"{s}\". It names {d}:\n",
                    .{ name, config.instances.len },
                );
                for (config.instances) |candidate| {
                    tty.print(.err, "  {s} ({s})\n", .{ candidate.name, candidate.kind.wireName() });
                }
                return error.Reported;
            };
        }
        break :pick config.defaultInstance() orelse {
            tty.print(
                .err,
                "chock run: the configuration names {d} providers and no default. " ++
                    "Name one with --provider, or set .defaults.provider in {s}/{s}.\n",
                .{ config.instances.len, config_dir, chock_auth.config.file_name },
            );
            return error.Reported;
        };
    };

    const model = options.model orelse config.default_model orelse {
        tty.print(
            .err,
            "chock run: no model was named. Give --model, or set .defaults.model in {s}/{s}.\n",
            .{ config_dir, chock_auth.config.file_name },
        );
        return error.Reported;
    };

    const driver = chock_auth.store.Driver{ .data_dir = data_dir };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };
    var credential_diag: ?chock_auth.lookup.Diagnostic = null;
    defer if (credential_diag) |*d| d.deinit(arena);
    const credential = chock_auth.lookup.resolve(
        arena,
        io,
        instance,
        config_dir,
        store,
        &credential_diag,
    ) catch |err| {
        // Which of the three sources refused, and the mode or the message
        // that made it refuse. The three readers used to print that between
        // them, so a user saw a line from a library and then a second line
        // from this command that said nothing more.
        if (credential_diag) |*d| {
            tty.print(
                .err,
                "chock run: the credential for the provider {s} could not be read: {f}\n",
                .{ instance.name, d },
            );
        } else {
            tty.print(
                .err,
                "chock run: the credential for the provider {s} could not be read: {s}\n",
                .{ instance.name, @errorName(err) },
            );
        }
        return error.Reported;
    };

    // **The pre-flight, and it is here on purpose: nothing has been built
    // yet.** Below this line come the session directories, the log, the
    // workspace, and on a project with a container image an extraction that
    // costs seconds and real disk. A session that carries no credential to a
    // provider that always needs one dies on that provider's 401 in the first
    // turn, and exit 2 for "Chock never had a key" reads exactly like exit 2
    // for a session that ran and then failed for any other reason.
    //
    // `Source.none` stays a non-failure in the lookup, because an endpoint
    // that needs no key is legitimate. `credentialIsMissing` is what tells the
    // two apart, and only for an address that is known to refuse.
    if (chock_auth.lookup.credentialIsMissing(instance, credential.source)) {
        // **The instance and the address, and never any part of a value.**
        // Nothing here has read a credential: the lookup found none.
        tty.print(
            .err,
            "chock run: the provider {s} has no credential. It talks to {s}, which refuses a " ++
                "request that carries none, so this session would fail on its first turn.\n",
            .{ instance.name, instance.base_url },
        );
        tty.print(
            .err,
            "  Run: chock login --provider {s} --name {s}\n",
            .{ instance.kind.wireName(), instance.name },
        );
        tty.print(
            .err,
            "  Or give that provider .token_file in {s}/{s}, which is how sops-nix and agenix " ++
                "work. See docs/credentials.md.\n",
            .{ config_dir, chock_auth.config.file_name },
        );
        return error.Reported;
    }

    // What this session keeps out of its own log and out of a provider request.
    // **Built here, beside the credentials it borrows**, because
    // `chock_core.redact` is inert until a caller fills it in and this is that
    // caller: see `redactionFor`.
    const redaction = try redactionFor(arena, instance.name, credential.token, config.instances);

    // The identifier. `--session` names one, `--continue` finds the newest,
    // and neither makes a fresh one.
    //
    // Copied into the arena, and not left on this function's own stack:
    // `chock_proto.log.Log` **borrows** the session string and stamps it onto
    // every envelope it appends, for as long as the log is open. A pointer to
    // a local here outlives this function by the whole session, and the log
    // fills up with whatever the stack holds by then. That is what happened
    // before this copy existed, and a log whose `session` field is stack
    // rubbish is a log `chockd` cannot serve and a replay cannot key on.
    const stack_id = try chooseSessionId(arena, io, env, project_root, options);
    const id = try arena.dupe(u8, &stack_id);

    const paths = session_paths.pathsFor(arena, env, project_root, id) catch |err| {
        tty.print(.err, "chock run: the session path could not be built: {s}\n", .{@errorName(err)});
        return error.Reported;
    };

    // **Before `session_paths.create`, and long before the workspace.** A
    // handover that has nothing to take over is a refusal, and a refusal that
    // has already made three directories and a git worktree has left a mess
    // behind for a fault it found afterwards.
    if (options.adopt) try refuseAdoptWithNothingToAdopt(gpa, io, paths.log, id);

    session_paths.create(io, paths) catch return error.Reported;

    // **A session another process handed over keeps the workspace it was
    // working in, and this is where the next owner takes it.** The last owner
    // wrote a `workspace.open` event naming the attempt and the commit that
    // workspace started from, and left the directory on disk. Rebuilding from
    // committed state instead would throw away every uncommitted change the
    // agent had made, which is exactly what makes a live handover honest or a
    // lie. See `takenOver`, and `src/handover.zig` for the other half.
    const resuming = options.adopt or options.continue_newest or options.session != null;
    const taken = if (resuming) takenOver(gpa, io, arena, paths.log, paths.work) else null;

    // The workspace gets an identifier of its own, fresh on every
    // invocation, and never the session identifier. A session that is
    // continued would otherwise ask `git worktree add` for a path the
    // previous run already used, and a previous run that crashed before its
    // own teardown would make every later `--continue` fail.
    const attempt = if (taken) |one| one.attempt else session_paths.newId(io);
    // The arena, not the general purpose allocator: everything a `Workspace`
    // owns lives as long as the process does, and `close` has to be given the
    // same allocator `open` was.
    var open_diag: ?chock_workspace.Diagnostic = null;
    var workspace = if (taken) |one| chock_workspace.Workspace.adopt(
        arena,
        io,
        env,
        project_root,
        paths.work,
        &attempt,
        one.base_commit,
        &open_diag,
    ) catch |err| {
        // **Not a fall back to a fresh workspace, and this is deliberate.** The
        // work is on disk under a path this command has just named, and a run
        // that quietly started from committed state would leave it there with
        // a person believing their session carried on. So this says what it
        // found and stops, and `chock workspace` is what lists the directory.
        if (open_diag) |*fault| {
            tty.print(
                .err,
                "chock run: the workspace of session {s} could not be taken over: {f}\n",
                .{ id, fault },
            );
        } else {
            tty.print(
                .err,
                "chock run: the workspace of session {s} could not be taken over: {s}\n",
                .{ id, @errorName(err) },
            );
        }
        tty.print(
            .err,
            "chock run: that session was handed over and left its work at {s}/{s}. It is still " ++
                "there. `chock workspace` lists it and removes it.\n",
            .{ paths.work, &attempt },
        );
        return error.Reported;
    } else chock_workspace.Workspace.open(
        arena,
        io,
        env,
        project_root,
        paths.work,
        &attempt,
        &open_diag,
    ) catch |err| {
        // Which call failed and what it answered. The workspace builder used
        // to print that for itself and hand this command `error.Unexpected`,
        // so a user read a line with no command name on it and then a second
        // line that said nothing more.
        if (open_diag) |*fault| {
            tty.print(
                .err,
                "chock run: the workspace for {s} could not be built: {f}\n",
                .{ project_root, fault },
            );
        } else {
            tty.print(
                .err,
                "chock run: the workspace for {s} could not be built: {s}\n",
                .{ project_root, @errorName(err) },
            );
        }
        // The three the Darwin clone answers name themselves, and only this
        // command holds the two paths that say what to change.
        switch (err) {
            error.ScratchOnAnotherVolume => tty.print(
                .err,
                "chock run: {s} and the scratch directory {s} are on different volumes, " ++
                    "and a clone cannot cross one. Give Chock a scratch directory on the " ++
                    "project's own volume.\n",
                .{ project_root, paths.work },
            ),
            error.ScratchAlreadyExists => tty.print(
                .err,
                "chock run: the clone destination under {s} already exists, usually from a " ++
                    "session that ended abnormally. Remove it and try again.\n",
                .{paths.work},
            ),
            error.NoOverlayFilesystem => tty.print(
                .err,
                "chock run: the volume that holds {s} has no copy on write clone, so a " ++
                    "workspace cannot be built on it.\n",
                .{project_root},
            ),
            // **The path, because the message above names the file and not
            // where it is.** `chock.zon` is the first thing a person writes
            // with Chock, and a session that will not start over a comma is
            // the first wall they meet. The line and the column are in the
            // diagnostic; this says which file holds them and where a
            // complete one is written out.
            error.ChockZonNotValid, error.DenyBlockNotValid, error.ChockZonTooLarge => tty.print(
                .err,
                "chock run: that file is {s}/chock.zon. docs/configuration.md holds a complete " ++
                    "one, and docs/policy.md holds the policy block.\n",
                .{project_root},
            ),
            else => {},
        }
        return error.Reported;
    };
    // **A process that adopted a workspace never removes it.** `close` runs
    // `git worktree remove --force`, and the checkout it would remove is the
    // one another owner left with work in it. A failure below is this process's
    // failure and not a reason to delete somebody else's files, so an adopted
    // workspace is only let go of. A workspace this process built is removed as
    // it always was: nothing else has ever looked at it.
    //
    // No diagnostic on the removal: it runs while an error is already on its
    // way out, and the fault that error carries is the one worth reporting.
    errdefer switch (releaseOnFailure(taken != null)) {
        .keep => workspace.keep(arena),
        .remove => workspace.close(arena, io, env, null) catch {},
        .hand_on => unreachable,
    };

    var sandbox_config = workspace.sandboxConfig(arena, paths.root) catch |err| {
        tty.print(.err, "chock run: the sandbox could not be described: {s}\n", .{@errorName(err)});
        return error.Reported;
    };

    const backing = try arena.create(chock_proto.storage.JsonLines);
    backing.* = .{ .log = chock_proto.log.Log.open(io, paths.log, id) catch |err| {
        tty.print(.err, "chock run: the session log {s} could not be opened: {s}\n", .{ paths.log, @errorName(err) });
        return error.Reported;
    } };
    const storage = backing.storage();

    // Say which session this is before it starts, so a user who has to find it
    // again does not have to wait for the session to end first. **Before the
    // approval socket, so it is the first line on screen**: every line under it
    // names a path built from this identifier, and a reader wants the
    // identifier first.
    //
    // **One line, and it names the session and the model.** Those two decide
    // what the run does and what the run costs, and the identifier is the key
    // `chock sessions`, `chock usage`, and `chock plan` all take. Everything
    // else this used to print is one command away, so it is behind `--verbose`:
    // the address and the credential are a fact about a healthy start, and the
    // log path is what `chock sessions` lists.
    tty.print(.plain, "chock: session {s}, model {s} via {s}\n", .{ id, model, instance.name });
    tty.detail("chock: log {s}\n", .{paths.log});
    tty.detail("chock: provider {s} ({s}), {s}\n", .{
        instance.name,
        instance.base_url,
        credential.source.describe(),
    });

    // **Written before the first turn, and before the user's own message.** The
    // next owner reads this out of the log and nothing else, so a run that
    // wrote it later would have a window in which it held a workspace no
    // handover could carry. See `recordWorkspace`.
    //
    // **And before the two control sockets, because this is what proves this
    // process owns the session.** It is the first thing in a run that takes the
    // log lock. Opening a socket first was a real fault: `Endpoint.open`
    // removes whatever file is at the path, so a second `chock run --continue`
    // against a session that was already running unlinked the live session's
    // own approval and handover sockets, bound its own, and then found the lock
    // held and exited. The live session was then listening on an inode nothing
    // could reach, so `chock approve` and `chock detach` were both dead for it
    // for the rest of its life, with nothing said. Now a process that does not
    // own the session never reaches the two calls below.
    recordWorkspace(gpa, io, storage, &workspace, &attempt) catch |err| {
        // **`Busy` is a second owner and not a fault**, the same reading
        // `main` gives it when `Loop.run` meets it. This is the first thing in
        // a run that takes the log lock, so it is where a race for the session
        // is now found, and "Busy" on its own reads as a crash.
        if (err == error.Busy) {
            tty.print(.err, "chock run: {s}\n", .{busy_detail});
        } else {
            tty.print(
                .err,
                "chock run: the workspace could not be written to the log: {s}. Without that, a " ++
                    "handover of this session would lose the work in it.\n",
                .{@errorName(err)},
            );
        }
        return error.Reported;
    };

    // The approval socket. **Opened before the first turn**, so a client that
    // wants to answer a question this session has not asked yet can be attached
    // already: `chock_broker.socket.timeoutMs` reads how many are attached at
    // the moment the question is written, because a session nobody is watching
    // has to stop rather than hold the session lock all night.
    const approvals = approvalEndpoint(arena, io, paths.dir, id);

    // Opened here too, and before the first turn, so `chock detach` can reach a
    // session from the moment it starts. A session that has not asked anything
    // yet is exactly the one somebody wants to move to a daemon.
    const handovers = handoverEndpoint(arena, io, paths.dir, id);

    // The project's own toolchain. Two things come out of one evaluation: the
    // environment every tool call runs with, and the store paths the sandbox
    // mounts for it. After the banner, because an evaluation is the slowest
    // thing a session start does and a user watching it should already know
    // which session is waiting.
    const dev_shell_dir = devShellDirFor(arena, io, env, project_root);

    // **The image is read first, and a project that names one never evaluates
    // a dev shell.** A `flake.nix` is a file a project may have for its own
    // build; a `container` block in `chock.zon` is a thing somebody wrote for
    // Chock. So the stated answer wins over the found one, and the evaluation
    // that would be thrown away is never paid for.
    var image = try loadImage(gpa, arena, io, env, project_root);
    errdefer if (image) |*one| one.deinit(io);

    const dev_shell = if (image != null)
        null
    else
        loadDevShell(gpa, io, env, project_root, dev_shell_dir);

    const tool_env = if (image) |*one|
        try imageToolEnvironment(arena, one)
    else
        try toolEnvironment(arena, env, dev_shell);

    if (image) |*one| {
        sandbox_config.env = try imageSandboxEnvironment(arena, sandbox_config.env, one);
    } else if (dev_shell) |shell| {
        sandbox_config.env = try sandboxEnvironment(arena, sandbox_config.env, shell);
    }

    // What every tool call of this session binds, decided here and never at
    // the tool call. See the comment above `Toolchain`: the third answer, the
    // host's own system directories, is what a machine with no Nix and no
    // image gets, and a machine with none of the three is refused right here.
    const toolchain = try toolchainFor(
        arena,
        io,
        project_root,
        dev_shell,
        if (image) |*one| one else null,
        sandbox_config.mounts,
    );

    // Before the first turn, so a user who is about to be told the wrong
    // thing by the agent hears why first. The count comes back so the agent
    // can be told the same fact: before this, the user knew and the agent did
    // not, which is how an agent comes to look for work that is not there.
    // **A workspace this process took over imports nothing, and this is a
    // refusal rather than a silent skip.** `--allow-dirty` copies every path
    // `git status` names in the user's own tree over the same path in the
    // workspace. On a fresh checkout that is the point of the flag. On an
    // adopted one those paths may be files the last owner's agent wrote, so the
    // import would overwrite the very work the handover was built to keep, with
    // nothing said about it.
    if (taken != null and options.allow_dirty) {
        tty.print(
            .err,
            "chock run: session {s} carries on in the workspace its last owner left, and " ++
                "--allow-dirty copies your uncommitted files over the files in it. Those are the " ++
                "agent's own edits. Run this without --allow-dirty.\n",
            .{id},
        );
        return error.Reported;
    }
    const uncommitted_files = if (taken != null)
        0
    else
        try handleUncommitted(gpa, io, env, &workspace, options);

    // The policy table, read once, at the start, under whatever this
    // installation's organisation put above it.
    const policy = try loadPolicyUnder(arena, io, project_root, org_bundle);

    // Whether this session may talk to this provider instance at all, and
    // whether it may use this model there. Before the first turn, because a
    // session that may not use its model has nothing to do.
    try refuseProviderAndModel(arena, policy, spawnChain(options), options, instance.name, model);

    // What this session may spend. The file is the project's, so a mistake in
    // it is the user's to hear about now rather than on the turn it would have
    // bitten. The same file is kept beyond the agent's reach, which is what
    // makes this a control the model cannot raise for itself.
    var budget_diag: ?chock_cost.budget.Diagnostic = null;
    defer if (budget_diag) |*d| d.deinit(arena);
    const from_file = chock_cost.budget.load(arena, io, project_root, &budget_diag) catch |err| {
        // The reason, not only the error name. The reader used to print this
        // itself, which put a library in charge of what a person sees; now it
        // is ranked here like every other line this command writes.
        if (budget_diag) |*d| {
            tty.print(.err, "chock run: the budget in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the budget in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };
    const budget = budgetFor(from_file, options);
    const billing = chock_cost.prices.billingFor(instance.base_url);
    warnUnmeasurableBudget(budget, billing, instance.name, model);

    // How many subagents this project allows, read from the same file and
    // for the same reason. A `max_width` of zero refuses every spawn, which
    // is how a project turns subagents off.
    var subagents_diag: ?chock_policy.subagents.Diagnostic = null;
    defer if (subagents_diag) |*d| d.deinit(arena);
    const subagent_limits = chock_policy.subagents.load(arena, io, project_root, &subagents_diag) catch |err| {
        // The field that is wrong and the value it holds, which the error
        // name alone does not carry.
        if (subagents_diag) |*d| {
            tty.print(.err, "chock run: the subagents block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the subagents block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    // This project's language server, read from the same file and for the
    // same reason. **Null is the ordinary answer**, and it costs the session
    // nothing: see `chock_core.lsp.Session`, whose first rule is that a
    // harness which gets worse when a server is missing is worse than no
    // harness.
    //
    // A mistake in the block is heard now rather than on the first edit of a
    // `.zig` file, which is the same rule the three readers above keep.
    var language_server_diag: ?chock_core.lsp_driver.Diagnostic = null;
    defer if (language_server_diag) |*d| d.deinit(arena);
    const language_server = chock_core.lsp_driver.load(
        arena,
        io,
        project_root,
        &language_server_diag,
    ) catch |err| {
        if (language_server_diag) |*d| {
            tty.print(.err, "chock run: the language_servers block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the language_servers block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    // This project's MCP servers, read from the same file and for the same
    // reason. **Null is the ordinary answer**, and it costs the session
    // nothing: see `chock_core.mcp`, whose first rule is the one
    // `chock_core.lsp` states next door.
    //
    // A mistake in the block is heard now rather than on the turn the model
    // calls a tool, which is the same rule every other reader of this file
    // keeps.
    var mcp_diag: ?chock_core.mcp.Diagnostic = null;
    defer if (mcp_diag) |*d| d.deinit(arena);
    const mcp_servers = chock_core.mcp.load(arena, io, project_root, &mcp_diag) catch |err| {
        if (mcp_diag) |*d| {
            tty.print(.err, "chock run: the mcp_servers block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the mcp_servers block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    // This project's plugins, read from the same file and for the same reason.
    // **Null is the ordinary answer**, and it costs the session nothing: see
    // `chock_core.plugin`, whose first rule is the one `chock_core.lsp` states
    // two blocks up.
    //
    // A mistake in the block is heard now rather than on the turn the model
    // calls a tool, which is the same rule every other reader of this file
    // keeps.
    var plugins_diag: ?chock_core.plugin.Diagnostic = null;
    defer if (plugins_diag) |*d| d.deinit(arena);
    const plugins = chock_core.plugin.load(arena, io, project_root, &plugins_diag) catch |err| {
        if (plugins_diag) |*d| {
            tty.print(.err, "chock run: the plugins block in chock.zon could not be read: {f}\n", .{d});
        } else {
            tty.print(.err, "chock run: the plugins block in chock.zon could not be read: {t}\n", .{err});
        }
        return error.Reported;
    };

    // Which wire this instance speaks. Read once, here, because two things
    // need it: the client below, and the tool list right after, which is only
    // allowed to name a tool this wire can carry.
    const adapter: chock_provider.Client.Adapter = switch (instance.kind) {
        .anthropic => .anthropic,
        .aiand, .openai_compat => .openai_compatible,
    };

    // The tools this session offers. A tool is offered only when the adapter
    // can express it **and** this provider instance does it. A tool the model
    // cannot use costs a turn calling it and a turn reading the failure, which
    // is worse than a tool that is not there. This project's knowledgebase, and
    // the one directory outside the workspace a tool call may write. Made
    // before the session starts, because the two memory tools bind it into the
    // sandbox and a mount source that is not there is a mount that fails.
    const memory_dir = session_paths.memoryDir(arena, env, project_root) catch |err| {
        tty.print(.err, "chock run: the knowledgebase directory is unknown: {s}\n", .{@errorName(err)});
        return error.Reported;
    };
    const memory_ready = if (session_paths.createMemoryDir(io, memory_dir)) true else |_| ready: {
        // Said out loud and not fatal: a session with no knowledgebase is a
        // session that does less, not one that cannot run. `Support.memory`
        // below then keeps the two tools out of the list, so the model is
        // never told about a tool that has nowhere to work.
        tty.print(
            .warn,
            "chock run: the knowledgebase directory {s} could not be made, so this session " ++
                "keeps no notes.\n",
            .{memory_dir},
        );
        break :ready false;
    };

    // This project's toolchain cache: where the compiler writes, since the
    // sandbox is writable in the workspace and nowhere else without it. Made
    // before the session starts, for the same reason the knowledgebase is: a
    // mount source that is not there is a mount that fails.
    // Resolved, because on a build that moves no path this directory's own
    // name is what a sandbox rule matches: see `resolvedForSandbox`.
    const cache_dir = resolvedForSandbox(arena, io, prepareCache(arena, gpa, io, env, project_root));

    // This session's scratchpad: where a tool call puts a file that is not the
    // project, and where a background task's output lands. Made before the
    // session starts, for the same reason the two above are: a mount source
    // that is not there is a mount that fails.
    const scratch_dir = resolvedForSandbox(arena, io, prepareScratchpad(arena, gpa, io, env, id, options));
    const tasks_dir: ?[]const u8 = if (scratch_dir) |dir|
        std.fs.path.join(arena, &.{ dir, chock_core.tasks.host_leaf }) catch return error.OutOfMemory
    else
        null;

    // Provisioning, read before the tool list is built, because whether the
    // model is told `provide_tool` exists is exactly this answer.
    const chain = spawnChain(options);
    const provisioning = try provisioningFor(
        arena,
        io,
        env,
        policy,
        options,
        chain,
        model,
        dev_shell_dir,
    );

    const support = chock_core.tools.Support{
        .adapter = adapter,
        .provider = .{ .images = instance.capabilities.images },
        .memory = memory_ready,
        .provisioning = provisioning != null,
        // A reviewer is offered no tool at all, so the list below comes back
        // empty and the prompt names none: see `agentRole`.
        .role = agentRole(options),
    };

    // The instruction files, the guidance shelf, and the knowledgebase
    // index. Three sources, one mechanism: the prompt carries a bounded
    // block or one line per thing, and a tool fetches the rest. See
    // `lib/chock-core/index.zig`.
    const loaded_instructions = chock_core.instructions.load(arena, io, config_dir, project_root) catch
        return error.OutOfMemory;
    reportInstructions(loaded_instructions);

    const notes = chock_core.memory.list(arena, io, memory_dir) catch return error.OutOfMemory;
    const note_index = chock_core.memory.indexOf(arena, notes) catch return error.OutOfMemory;
    // A count of notes at the start is a fact about a healthy session, and
    // `chock memory` answers it whenever somebody asks. `reportNotes` still
    // says at the end when this session **wrote** one, because that changes
    // every session after it.
    if (notes.len != 0) {
        tty.detail("chock: {d} notes from earlier sessions ({s})\n", .{ notes.len, memory_dir });
    }

    // The prompt. It is kept short, and the tool list in it is read from the
    // same slice that fills `Request.tools`, so the prompt can never name a
    // tool the model cannot call.
    const tool_definitions = chock_core.tools.Registry.definitions(arena, support) catch return error.OutOfMemory;
    // Kept whole, because a project with an `mcp_servers` block builds the
    // prompt a second time in phase 2, once the servers have said which tools
    // they have. **Nothing else reads them**, and a project with no such block
    // takes the prompt below unchanged.
    const prompt_project = projectKind(io, project_root);
    const prompt_sources = chock_core.prompt.Sources{
        .instructions = loaded_instructions,
        .guidance = chock_core.guidance.indexEntries(arena) catch return error.OutOfMemory,
        .memory = note_index,
    };
    const system_prompt = chock_core.prompt.build(
        arena,
        prompt_project,
        tool_definitions,
        prompt_sources,
    ) catch return error.OutOfMemory;

    // The user's own message, appended before `Loop.run` is called: `run`
    // starts from whatever the log already holds. See its own doc comment.
    //
    // **An adoption appends nothing, and reads no standard input.** The log
    // already holds the conversation, and `Loop.run` folds it: a message added
    // here would be a turn nobody asked for, and a read of standard input would
    // block a daemon's child forever on a pipe nothing writes to.
    // **A display appends none either, and for a related reason.** It asks for
    // every message it sends, the first one included, so that a piped message
    // and a typed one take one path: see `runSession`'s own loop.
    if (!options.adopt and options.display == null) {
        const message_text = try readMessage(arena, io, options);
        if (message_text.len == 0) {
            tty.print(.err, "chock run: the message is empty, so there is nothing to ask.\n", .{});
            return error.Reported;
        }
        appendUserMessage(gpa, io, storage, message_text) catch |err| {
            tty.print(.err, "chock run: the message could not be written to the log: {s}\n", .{@errorName(err)});
            return error.Reported;
        };
    }

    return .{
        .exe_path = exe_path,
        .project_root = project_root,
        .paths = paths,
        .session_id = id,
        .workspace = workspace,
        .policy = policy,
        .sandbox_config = sandbox_config,
        .dev_shell = dev_shell,
        .image = image,
        .toolchain = toolchain,
        .tool_env = tool_env,
        .provisioning = provisioning,
        .backing = backing,
        .storage = storage,
        .base_url = instance.base_url,
        .adapter = adapter,
        .credential = credential,
        .budget = budget,
        .billing = billing,
        .subagents = subagent_limits,
        .language_server = language_server,
        .mcp_servers = mcp_servers,
        .plugins = plugins,
        .prompt_project = prompt_project,
        .prompt_sources = prompt_sources,
        .spawn_chain = chain,
        .model = model,
        .model_alias = instance.name,
        .system_prompt = system_prompt,
        .tool_definitions = tool_definitions,
        .memory_dir = if (memory_ready) memory_dir else null,
        .notes_at_start = notes.len,
        .cache_dir = cache_dir,
        .scratch_dir = scratch_dir,
        .scratch_owned = options.scratchpad.len == 0,
        .tasks_dir = tasks_dir,
        .context_tokens = instance.context_tokens,
        .uncommitted_files = uncommitted_files,
        .approvals = approvals,
        .handovers = handovers,
        .attempt = try arena.dupe(u8, &attempt),
        .audit_sinks = try auditSinks(arena, io, options, org_bundle, id),
        .redact = redaction,
        .redact_values = try brokerRedaction(arena, redaction),
    };
}

/// What this session keeps out of its own log and out of a provider request.
///
/// **Every provider credential this configuration holds, and not only the one
/// this session sends with.** `chock_core.redact.Policy` is inert until a caller
/// fills it in, and this is that caller. Two sources reach it:
///
/// 1. The credential this session resolved, whichever of the three sources
///    answered for it.
/// 2. The `token` written in place on any other provider in `config.zon`. A
///    machine set up for a comparison run holds two, and the second one is a
///    live credential that a tool result can echo just as easily as the first.
///    A `token_file` gives a path and not a value, so there is nothing to add
///    for one that this session did not resolve.
///
/// **Three things were left out on purpose, and each has a reason.** A git
/// password in a `chock_broker.askpass.Grants` has no producer: no code in this
/// command opens an `askpass.Endpoint`, so the set is always empty and an entry
/// here would read as cover that is not there. A `chock_broker.secrets.Store`
/// entry is the same, and `Broker.secrets` is never filled either. The
/// heuristics stay off, which is `redact.zig`'s own default and its own
/// argument.
///
/// **Built in phase 1, out of the arena, because the policy borrows.**
/// `redact.Policy.secrets` is kept alive by the caller for the whole session,
/// and both the credential and the parsed configuration already live in that
/// arena.
///
/// **A subagent needs nothing from here.** Each child is a process that resolves
/// its own credential and builds its own `Loop.Deps`, so it reaches this same
/// function for itself.
///
/// **An empty token is not a short credential.** An instance that needs no
/// credential at all, which is every local provider somebody runs without auth,
/// has nothing to protect and nothing to say about it.
///
/// **A credential too short to match is skipped and said out loud, by name.**
/// See `chock_core.redact.min_secret_bytes`: a short value appears inside
/// ordinary words, inside hashes and inside base64, so matching one would fill a
/// request with markers and teach an agent to distrust every marker it sees. The
/// honest answer is to skip it and say which instance it belongs to, rather than
/// leave somebody believing a value is protected when it is not.
///
/// **Nothing here prints a token and nothing may.** The line names the instance
/// and nothing else. A diagnostic carrying the value would put the credential in
/// the very place this exists to keep it out of.
fn redactionFor(
    arena: std.mem.Allocator,
    instance_name: []const u8,
    token: []const u8,
    instances: []const chock_auth.config.Instance,
) std.mem.Allocator.Error!chock_core.redact.Policy {
    // The instance a value came from, so a value too short to match can be
    // named to whoever wrote it. The name is never the value.
    const Named = struct { name: []const u8, value: []const u8 };

    var named: std.ArrayList(Named) = .empty;
    if (token.len != 0) try named.append(arena, .{ .name = instance_name, .value = token });

    for (instances) |one| {
        const inline_token = switch (one.credential) {
            .token => |value| value,
            // A path, not a value. The one this session resolved is already
            // above, and no other instance's file is read.
            .token_file, .absent => continue,
        };
        if (inline_token.len == 0) continue;
        // The same bytes twice would warn twice about one credential.
        var already = false;
        for (named.items) |seen| {
            if (std.mem.eql(u8, seen.value, inline_token)) already = true;
        }
        if (already) continue;
        try named.append(arena, .{ .name = one.name, .value = inline_token });
    }

    const secrets = try arena.alloc(chock_core.redact.Secret, named.items.len);
    for (named.items, secrets) |one, *slot| {
        slot.* = .{ .value = one.value, .source = .credential };
    }

    for (named.items) |one| {
        if (one.value.len >= chock_core.redact.min_secret_bytes) continue;
        tty.print(
            .warn,
            "chock run: the credential for {s} is shorter than {d} bytes. It is not kept out of " ++
                "this session's log, and it is not kept out of what this session sends to the " ++
                "provider. A value that short appears inside ordinary words, so matching it would " ++
                "replace half of every request.\n",
            .{ one.name, chock_core.redact.min_secret_bytes },
        );
    }

    return .{ .secrets = secrets };
}

/// The same values `redactionFor` found, in the shape a `chock_broker.Broker`
/// takes.
///
/// **The broker writes into the same log the loop does, and the loop's own
/// funnel cannot cover it.** `chock-broker` imports no `chock-core`, so a
/// `chock_core.redact.Policy` cannot travel there. The values can, and they
/// travel with no name attached: see `chock_broker.Broker.redaction` for why a
/// name would be a route to the thing the redaction protects.
///
/// **The floor is applied here and the report of what it skipped is already
/// out.** `redactionFor` above names every credential too short to match on,
/// by instance, and says it is kept out of neither the log nor the request.
/// That line covers this path too, so a value dropped here was said out loud
/// once rather than twice.
///
/// **The heuristics do not travel and there is nothing to carry.** They are a
/// pattern and not a value, and `redact.Policy.heuristics` is off in every
/// session this command starts.
fn brokerRedaction(
    arena: std.mem.Allocator,
    policy: chock_core.redact.Policy,
) std.mem.Allocator.Error![]const []const u8 {
    var values: std.ArrayList([]const u8) = .empty;
    for (policy.secrets) |secret| {
        if (secret.value.len < chock_core.redact.min_secret_bytes) continue;
        try values.append(arena, secret.value);
    }
    return values.toOwnedSlice(arena);
}

/// One audit sink this session will write.
///
/// **Where a command line and an org bundle meet, and the only place they do.**
/// See `auditSinks`.
const PlannedSink = struct {
    kind: chock_policy.org.RequiredSink.Kind,
    /// What this sink writes: the file inside the directory for a drop, the
    /// socket for syslog. It is also the name a person reads, so there is one
    /// string and not two that can disagree.
    path: []const u8,
    /// Whether this installation's org policy bundle required it, rather than
    /// somebody asking for it on this command line. **The whole of what
    /// "required" costs at run time is in this flag**: see
    /// `chock_policy.org` for the decision and `reportShipping`,
    /// `Exporter.sayFault` and `exitWithAudit` for the three things it changes.
    required: bool = false,
};

/// Where this session's log is copied to, resolved from `--export-dir`,
/// `--export-syslog` **and** the org policy bundle together.
///
/// **The union of the two, and this is the ratchet a sink can take.** A project
/// may add a sink of its own, because more of the record reaching more places
/// narrows nothing. A project may not drop one the installation named, and it
/// cannot: there is no flag that removes a sink, and the required ones are put
/// in this list before the command line's. `chock_policy.org` carries the whole
/// reading.
///
/// **A function that takes both, so the wiring is what a test drives.** The org
/// policy work extracted `loadPolicyUnder` for exactly this reason: a phase 1
/// that read the flags without the bundle would have passed every test of the
/// bundle reader and of the shipper, and every session in the installation
/// would have exported only what a developer chose to. There is no path here
/// that takes an `Options` alone.
///
/// **A sink named twice is opened once.** An installation that requires
/// `/var/audit/chock` and a developer who types `--export-dir /var/audit/chock`
/// mean one file, and two `FileDrop`s over one file would write the same bytes
/// at the same offsets from two counts and leave a copy that verifies as
/// broken. The required entry is the one that is kept, so a duplicate on the
/// command line cannot demote a sink to optional.
///
/// **Built in phase 1, out of the arena, and this is a lifetime and not a
/// tidiness.** The line phase 3 prints about a sink names this path, and phase
/// 2's own allocations are gone by then. A real run crashed on exactly that:
/// `Sinks.close` freed the path a `ShippingReport` still borrowed, and
/// `reportShipping` read it afterwards.
fn auditSinks(
    arena: std.mem.Allocator,
    io: std.Io,
    options: Options,
    org_bundle: ?*const chock_policy.org.Bundle,
    session_id: []const u8,
) std.mem.Allocator.Error![]const PlannedSink {
    var planned: std.ArrayList(PlannedSink) = .empty;

    // **The installation's first.** A required sink is the one a person did not
    // ask for, so it is the one a report has to name first, and being first is
    // what makes it the entry that survives a duplicate.
    if (org_bundle) |bundle| for (bundle.sinks) |one| {
        try addPlannedSink(arena, &planned, .{
            .kind = one.kind,
            .path = switch (one.kind) {
                .directory => try dropPathIn(arena, io, one.path, session_id),
                .syslog => one.path,
            },
            .required = true,
        });
    };

    if (options.export_dir) |dir| try addPlannedSink(arena, &planned, .{
        .kind = .directory,
        .path = try dropPathIn(arena, io, dir, session_id),
    });
    if (options.export_syslog) |path| try addPlannedSink(arena, &planned, .{
        .kind = .syslog,
        .path = path,
    });

    return planned.toOwnedSlice(arena);
}

/// Add `one` unless this list already writes the same place. See `auditSinks`:
/// the entry already in the list wins, which keeps a required sink required.
fn addPlannedSink(
    arena: std.mem.Allocator,
    planned: *std.ArrayList(PlannedSink),
    one: PlannedSink,
) std.mem.Allocator.Error!void {
    for (planned.items) |held| {
        if (held.kind == one.kind and std.mem.eql(u8, held.path, one.path)) return;
    }
    try planned.append(arena, one);
}

/// The file this session writes inside the drop directory `dir`.
///
/// **The directory is made rather than required.** An operator turning export on
/// names a directory a collector will watch, and refusing to start a session
/// because it is not there yet would be an audit sink stopping work, which is
/// the one thing this must never do. A directory that could not be made shows up
/// as a sink that cannot be reached, which is reported and is still not fatal.
/// That holds for a required sink too: see `chock_policy.org` for why a
/// required sink that cannot be reached does not stop a session.
/// Make `path` and every parent it needs, walking up **once**.
///
/// **The same shape `src/doctor.zig` uses, and for the same reason**: a walk
/// that goes up one level, makes what it can, and comes back down cannot
/// oscillate. `std.Io.Dir.createDirPath` can, which is what this exists to
/// avoid: see `dropPathIn`.
fn makeDirAll(io: std.Io, path: []const u8) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent);
            std.Io.Dir.createDirAbsolute(io, path, .default_dir) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

fn dropPathIn(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    session_id: []const u8,
) std.mem.Allocator.Error![]const u8 {
    // **Not `createDirPath`, which can loop for ever.** Measured 2026-08-24: it
    // answers a `mkdir` of `ENOENT` by walking back to a component it can make
    // and forward again, so a component whose parent exists and which still
    // cannot be made sends it between the same two names without end. A path
    // under `/proc` is exactly that shape, and `chock doctor` spun at most of a
    // core for ninety seconds on one before this was found. Here it would hang
    // a session before its first turn, on a directory an operator named.
    makeDirAll(io, dir) catch {};
    // One file per session, named after it, so a collector watching the
    // directory sees exactly one file appear per run and can tell which session
    // it holds without opening it.
    return try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ dir, session_id });
}

/// The workspace a session that handed over left behind, when there is one
/// still on disk, or null.
///
/// **What is folded, and why each part of it is needed.** Two facts about a
/// workspace cannot be worked out by a second process:
///
/// * **The attempt identifier**, because `start` mints a fresh one on every
///   invocation and it names the checkout, the scratch object store, the
///   pointer file, and the `config.worktree` stand in.
/// * **The commit the checkout started at**, because
///   `chock_workspace.Worktree.headMoved` measures the agent's work against it.
///   A session that committed before it handed over has a `HEAD` that is not
///   its base, so a new owner that read `HEAD` would decide nothing had changed
///   and would never carry that commit back.
///
/// Both are in the log, in the `workspace.open` event the last owner wrote, and
/// `chock_proto.state.Session` folds the newest one.
///
/// **Only a workspace that was opened before the ending that handed it over**,
/// and this is not the same test as "the session ended `handed_over`". A
/// `state.Session` fold never clears `end_reason`, and a resumed session writes
/// no second `session.start`, so once a session has handed over once the fold
/// says `handed_over` for ever, including while its next owner is running.
///
/// That difference was a way to delete live work. A session hands over from A
/// to the daemon's child B, and B writes a `workspace.open` of its own. A person
/// then runs `chock run --continue`: the fold reports A's stale reason and B's
/// live workspace, so C would adopt the checkout B is working in. When B's turn
/// ends and it lets go of the lock, C takes it, and B's own teardown then runs
/// `git worktree remove --force` on the directory C is now using.
///
/// Reading the two positions closes it. B's `workspace.open` comes **after** the
/// newest `session.end`, and A's came **before** it, so a workspace this may
/// take is one whose event is older than the ending that says it was handed
/// over. A session running right now always fails that test.
///
/// A session that ended any other abnormal way also keeps its workspace, per
/// `cleanupFor`, and taking that one over is a separate decision with its own
/// refusal in `src/detach.zig`.
///
/// **A directory that is not there is not a fault.** That is the ordinary
/// adoption of a session which ended cleanly and had its workspace removed, and
/// building a fresh one from committed state is what that session wants.
fn takenOver(
    gpa: std.mem.Allocator,
    io: std.Io,
    arena: std.mem.Allocator,
    log_path: [:0]const u8,
    work_path: []const u8,
) ?struct { attempt: [session_paths.id_length]u8, base_commit: []const u8 } {
    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch return null;
    const log = chock_proto.log.Log.open(io, log_path, "") catch return null;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    // **A replay of its own, and not `foldSession`.** What decides here is where
    // two events sit relative to each other, and a fold keeps values rather than
    // positions.
    var replay = store.replay(gpa, io, 0) catch return null;
    defer replay.deinit();

    var handed_over = false;
    var ended_at: u64 = 0;
    var opened_at: ?u64 = null;
    var attempt: [session_paths.id_length]u8 = undefined;
    // A git object identifier is 40 hexadecimal characters for SHA-1 and 64 for
    // SHA-256. This is room for either with space to spare, and it is a bound on
    // what a log can make this hold rather than a claim about git.
    var base_buffer: [128]u8 = undefined;
    var base_len: usize = 0;

    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        switch (parsed.value.event) {
            .session_end => |end| {
                handed_over = end.reason == .handed_over;
                ended_at = parsed.value.id;
            },
            .workspace_open => |opened| {
                // Copied now, because the replay owns these bytes only until
                // the next line is read.
                if (opened.kind != .worktree) {
                    opened_at = null;
                    continue;
                }
                // An identifier of another length is a log this build cannot
                // act on, and joining it onto a path would be joining whatever
                // a writer put there.
                if (opened.attempt.len != session_paths.id_length) continue;
                if (!session_paths.isValidId(opened.attempt)) continue;
                if (opened.base_commit.len > base_buffer.len) continue;
                @memcpy(&attempt, opened.attempt);
                @memcpy(base_buffer[0..opened.base_commit.len], opened.base_commit);
                base_len = opened.base_commit.len;
                opened_at = parsed.value.id;
            },
            else => {},
        }
    }

    if (!handed_over) return null;
    const opened = opened_at orelse return null;
    // The one that closes the window above. An event written after the ending
    // belongs to an owner that came after it, and that owner may be running.
    if (opened > ended_at) return null;

    // **The disk decides, and not the log.** A person may have run
    // `chock workspace clear` between the two owners, and a run that then asked
    // `adopt` for a directory that is gone would fail where it should simply
    // start again from committed state.
    const path = std.fs.path.join(arena, &.{ work_path, &attempt }) catch return null;
    var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch return null;
    dir.close(io);

    const base_commit = arena.dupe(u8, base_buffer[0..base_len]) catch return null;
    return .{ .attempt = attempt, .base_commit = base_commit };
}

/// Write down which workspace this run is working in, so the process that takes
/// this session over next can find it.
///
/// **This is the whole of the workspace half of a handover.** The log is the
/// only thing a new owner reads, so a workspace the log does not name is a
/// workspace the next owner rebuilds from committed state, which throws away
/// everything the agent has not committed.
///
/// Written on every run and not only before a handover, for the reason every
/// other event is: a fact recorded when it becomes true is a fact a fold can
/// rely on, and a fact recorded when somebody asks for it is a fact that is
/// missing whenever the process ends before the asking.
fn recordWorkspace(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    workspace: *const chock_workspace.Workspace,
    attempt: []const u8,
) !void {
    // **The lock is taken and given back here**, because `Loop.run` has not
    // started yet and takes it for itself. `appendUserMessage` does the same
    // thing a few lines further on and for the same reason.
    var locked = try storage.lock(io);
    defer locked.unlock(io) catch {};
    _ = try locked.append(gpa, io, .{
        .workspace_open = .{
            .kind = switch (workspace.kind) {
                .worktree => .worktree,
                .overlay => .overlay,
            },
            .attempt = attempt,
            .path = workspace.workPath(),
            // Empty for the overlay backing, which has no commit of its own. That
            // is also why `takenOver` refuses to take one over: see
            // `chock_workspace.Workspace.adopt`.
            .base_commit = switch (workspace.kind) {
                .worktree => |wt| wt.base_commit,
                .overlay => "",
            },
        },
    }, std.Io.Timestamp.now(io, .real).toMilliseconds());
}

/// Open this session's handover socket, or answer null and say why.
///
/// **A session with no socket still runs, and no process can take it.** That is
/// the safe direction, and it is what every session did before `chock detach`
/// could reach a running one: `chock detach` then reports that the session is
/// running and will not hand over, which is true. So every failure here is
/// reported and carried on from, exactly as `approvalEndpoint` does.
fn handoverEndpoint(
    arena: std.mem.Allocator,
    io: std.Io,
    session_dir: []const u8,
    id: []const u8,
) ?*chock_broker.handover.Endpoint {
    const paths = chock_broker.handover.pathsFor(arena, session_dir, id) catch return null;
    const endpoint = arena.create(chock_broker.handover.Endpoint) catch return null;
    var socket_diag: ?chock_broker.Diagnostic = null;
    endpoint.* = chock_broker.handover.Endpoint.open(io, paths, &socket_diag) catch |err| {
        if (socket_diag) |*fault| {
            tty.print(
                .warn,
                "chock run: this session has no handover socket ({f}), so `chock detach` cannot " ++
                    "take it while it runs. Stop it first.\n",
                .{fault},
            );
        } else {
            tty.print(
                .warn,
                "chock run: this session has no handover socket ({s}), so `chock detach` cannot " ++
                    "take it while it runs. Stop it first.\n",
                .{@errorName(err)},
            );
        }
        return null;
    };
    tty.detail("chock: handover {s}\n", .{paths.socket});
    return endpoint;
}

/// Open this session's approval socket, or answer null and say why.
///
/// **A session with no socket still runs.** The socket is how somebody who is
/// not at this process's keyboard answers a question, and a session that cannot
/// have one is exactly the session Chock had before this existed: a question it
/// cannot ask anybody is refused, which is already the safe direction. So every
/// failure here is reported and then carried on from, and none of them ends the
/// run.
fn approvalEndpoint(
    arena: std.mem.Allocator,
    io: std.Io,
    session_dir: []const u8,
    id: []const u8,
) ?*chock_broker.socket.Endpoint {
    const paths = chock_broker.socket.pathsFor(arena, session_dir, id) catch return null;
    const endpoint = arena.create(chock_broker.socket.Endpoint) catch return null;
    // Which of the four steps of `open` failed, and what it answered. The
    // socket used to print that itself and hand this command an error name.
    var socket_diag: ?chock_broker.Diagnostic = null;
    endpoint.* = chock_broker.socket.Endpoint.open(io, paths, &socket_diag) catch |err| {
        if (socket_diag) |*fault| {
            tty.print(
                .warn,
                "chock run: this session has no approval socket ({f}), so only a person at this " ++
                    "terminal can answer a question it asks.\n",
                .{fault},
            );
        } else {
            tty.print(
                .warn,
                "chock run: this session has no approval socket ({s}), so only a person at this " ++
                    "terminal can answer a question it asks.\n",
                .{@errorName(err)},
            );
        }
        return null;
    };
    // Where a `chock approve` attaches. A healthy session has one, and the path
    // is derived from the session identifier the first line already gave.
    tty.detail("chock: approvals {s}\n", .{paths.socket});
    return endpoint;
}

/// What this session may spend: the cap in `chock.zon`, the slice a parent
/// gave it, or the smaller of the two.
///
/// **A slice can only ever narrow.** A parent divides what it has left and
/// hands a piece to each child, through `chock_core.subagent.budgetSlice`, and
/// the project's own cap still binds every session of that project. Taking the
/// smaller of the two means neither a parent nor a project file can be worked
/// around by the other.
///
/// A currency the parent did not name is the project's own, and a parent that
/// named one wins: the parent is what divided the number.
fn budgetFor(from_file: ?chock_cost.budget.Budget, options: Options) ?chock_cost.budget.Budget {
    const slice = options.max_cost orelse return from_file;
    const currency = if (options.currency.len != 0)
        options.currency
    else if (from_file) |file| file.currency else chock_cost.budget.default_currency;

    const file_cap = from_file orelse return .{ .max_cost = slice, .currency = currency };
    // Two caps in two currencies cannot be compared at all, and inventing a
    // rate would be worse than not enforcing. The narrower answer is the
    // parent's own, because a parent that hands out a slice has already
    // decided the tree's total.
    if (!std.mem.eql(u8, file_cap.currency, currency)) {
        return .{ .max_cost = slice, .currency = currency };
    }
    return .{ .max_cost = @min(file_cap.max_cost, slice), .currency = currency };
}

/// Every parent of this session, root first. Empty for a session a person
/// started, and one link per agent above a subagent.
///
/// **The whole chain, because a parent writes the whole chain.** It used to be
/// one link, from the single `--parent-kind` a parent wrote, and that was a
/// real fault at three levels: a grandchild folded its own kind and its
/// parent's, the grandparent's row of `chock.zon` never reached the answer, and
/// the depth every session below the first reported was 2 whatever its real
/// depth, so `max_depth` bounded nothing. `test/core/tree.zig` is what found
/// it, by running a tree rather than by reading one.
fn spawnChain(options: Options) []const chock_proto.event.SpawnLink {
    return options.parent_chain;
}

/// What kind of agent this session is, for the one question that decides
/// whether it holds any tool at all.
///
/// **This is the join between the two libraries that each hold half of it.**
/// `chock_broker.review.isArbitrator` names the kind, because the reviewer is
/// the broker's own agent, and `chock_core.tools.Role` is what the tool list,
/// the dispatch and the loop read. `chock-core` imports no `chock-broker` on
/// purpose, so this file is the one place the two meet.
///
/// **Read from the kind on this process's own command line**, which a parent
/// wrote and the child cannot change: a child does not write its own command
/// line, see `SubagentSpawner`. So a reviewer holds no tools whether
/// `applyWork` started it or `SessionArbiter` did.
///
/// **What it is not read from is the log**, and that is worth saying out loud.
/// `chock run --continue` names no kind, so a person who resumed a reviewer's
/// own session would run it as `main` and it would hold tools. That is true of
/// the whole of `agent_kind` today, the policy row included, and not of this
/// field alone. It is also outside what this exists to stop: the agent being
/// reviewed cannot run `chock run`, and a person resuming a session is the
/// person the record is kept for.
fn agentRole(options: Options) chock_core.tools.Role {
    return if (chock_broker.review.isArbitrator(options.agent_kind)) .arbitrator else .worker;
}

/// This session's scratchpad, made, or null when it could not be made at all.
///
/// **Nothing is announced and nothing is measured here**, which is where this
/// differs from `prepareCache` next door, and both differences follow from the
/// same fact: this directory is new every session and gone at the end of one.
/// There is nothing to explain to a user who might find it later, and a fresh
/// directory has nothing in it to measure. The bound is checked before each
/// `run_command` instead, which is the only moment it can have grown: see
/// `chock_core.tools`'s own `boundScratchpad`.
///
/// **A scratchpad that cannot be made is not fatal.** A session with none does
/// less, it does not fail to run: a tool call then keeps whatever `TMPDIR` the
/// dev shell stated, exactly as before this existed, and it can start no
/// background task.
fn prepareScratchpad(
    arena: std.mem.Allocator,
    // Owns the message a failed layout leaves. **Not `arena`**: the message
    // holds a copy of a path the library built in a frame of its own, and the
    // allocator named here is the one that releases it.
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    id: []const u8,
    options: Options,
) ?[]const u8 {
    // A subagent writes inside its parent's own scratchpad, at a path the
    // parent built and made: see `chock_core.subagent.childDir`. The layout is
    // built again here, which is what makes it safe to be given one, and it is
    // the same call a session that made its own directory makes.
    if (options.scratchpad.len != 0) {
        // Which directory could not be made, and why. The library used to
        // print that itself and told this command only that it failed.
        var diag: ?chock_core.Diagnostic = null;
        defer if (diag) |*fault| fault.deinit(gpa);
        chock_core.scratchpad.makeLayout(
            io,
            options.scratchpad,
            chock_core.scratchpad.sinkOf(gpa, &diag),
        ) catch {
            if (diag) |fault| {
                tty.print(
                    .warn,
                    "chock run: the scratchpad {s} this session was given could not be built ({f}), " ++
                        "so it runs with the TMPDIR it was given and can start no command in the " ++
                        "background.\n",
                    .{ options.scratchpad, fault },
                );
            } else {
                tty.print(
                    .warn,
                    "chock run: the scratchpad {s} this session was given could not be built, so it " ++
                        "runs with the TMPDIR it was given and can start no command in the background.\n",
                    .{options.scratchpad},
                );
            }
            return null;
        };
        return options.scratchpad;
    }

    const dir = session_paths.scratchpadDir(arena, env, id) catch {
        tty.print(
            .warn,
            "chock run: the scratchpad directory is unknown, so tool calls have nowhere but " ++
                "the workspace to write and no command can run in the background.\n",
            .{},
        );
        return null;
    };

    var made_diag: ?chock_core.Diagnostic = null;
    defer if (made_diag) |*fault| fault.deinit(gpa);
    chock_core.scratchpad.makeLayout(io, dir, chock_core.scratchpad.sinkOf(gpa, &made_diag)) catch {
        if (made_diag) |fault| tty.print(.warn, "chock run: {f}\n", .{fault});
        tty.print(
            .warn,
            "chock run: the scratchpad {s} could not be made, so this session runs with the " ++
                "TMPDIR it was given and can start no command in the background.\n",
            .{dir},
        );
        return null;
    };
    return dir;
}

/// The spelling of `dir` a sandbox rule can act on, or null for a directory
/// that was never made.
///
/// **A build that moves no path turns a mount into a rule, and a rule matches
/// the path the kernel resolved.** macOS reaches `$TMPDIR` below `/var`, a link
/// to `/private/var`, so a rule on the unresolved spelling matches nothing and
/// every tool call of the session reads as refused. The question is answered by
/// `sandbox.resolvedPath`; this owns the copy, because that function answers
/// into a buffer of the caller's own frame. A build that moves paths gets the
/// caller's own string back untouched.
fn resolvedForSandbox(arena: std.mem.Allocator, io: std.Io, dir: ?[]const u8) ?[]const u8 {
    const path = dir orelse return null;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const resolved = sandbox.resolvedPath(io, path, &buffer);
    if (std.mem.eql(u8, resolved, path)) return path;
    // A copy that cannot be made leaves the unresolved name, which is what
    // this session had before. Slower to fail than to work, and never a
    // session that refuses to start over an allocation.
    return arena.dupe(u8, resolved) catch path;
}

/// This project's toolchain cache, made and measured, or null when it could
/// not be made at all.
///
/// **Three things happen here, and each one answers a rule this feature was
/// given.** See `lib/chock-core/cache.zig`:
///
/// 1. **Announced.** The first time a project gets a cache, the path is
///    printed with what empties it. A persistent directory of Chock's must
///    never be one a user finds later and cannot explain.
/// 2. **Bounded.** A cache grows without limit by nature, so a cache over
///    `cache.max_bytes` is emptied here and the user is told. A cache is
///    rebuildable by definition, which is what makes emptying honest: the
///    only cost is building it again.
/// 3. **Said out loud.** A cache that already holds something is named with
///    its size, so the reuse this whole feature exists for is visible in the
///    session and not only in the wall clock.
///
/// **A cache that cannot be made is not fatal.** A session with none does
/// less, it does not fail to run: the tool calls then get no `HOME`, exactly
/// as before this existed.
fn prepareCache(
    arena: std.mem.Allocator,
    // Owns the message a failed layout leaves. **Not `arena`**: the message
    // holds a copy of a path the library built in a frame of its own, and the
    // allocator named here is the one that releases it.
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const dir = session_paths.cacheDir(arena, env, project_root) catch |err| {
        tty.print(
            .warn,
            "chock run: the toolchain cache directory is unknown ({t}), so tool calls have " ++
                "nowhere but the workspace to write.\n",
            .{err},
        );
        return null;
    };

    // Which directory could not be made, and why. Nothing under `lib/` prints,
    // so a session that carried no sink here threw the reason away and left a
    // person with a name they could not act on.
    var diag: ?chock_core.Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);
    const is_new = session_paths.createCacheDir(
        io,
        dir,
        chock_core.cache.sinkOf(gpa, &diag),
    ) catch {
        if (diag) |fault| {
            tty.print(
                .warn,
                "chock run: the toolchain cache {s} could not be made ({f}), so a compiler in " ++
                    "this session has nowhere but the workspace to write.\n",
                .{ dir, fault },
            );
        } else {
            tty.print(
                .warn,
                "chock run: the toolchain cache {s} could not be made, so a compiler in this " ++
                    "session has nowhere but the workspace to write.\n",
                .{dir},
            );
        }
        return null;
    };

    if (is_new) {
        // Kept on a quiet run, and it fires once for the life of a project. A
        // persistent directory of Chock's must never be one a user finds later
        // and cannot explain, which is a fact about the machine and not about
        // this session.
        tty.print(
            .plain,
            "chock: this project has no toolchain cache yet, so one is made at {s}. " ++
                "`chock cache clear` empties it.\n",
            .{dir},
        );
        return dir;
    }

    // Measured with the bound as the stopping point, so a cache that is
    // already over it is not walked to the end to learn what is already
    // decided.
    const size = chock_core.cache.measure(arena, io, dir, chock_core.cache.max_bytes);
    if (chock_core.cache.verdictFor(size) == .empty) {
        // The same sink the layout above was given, which is still empty
        // because that call answered. Only the layout knows which directory
        // it rebuilt and failed on.
        const went = chock_core.cache.clear(arena, io, dir, chock_core.cache.sinkOf(gpa, &diag)) catch {
            if (diag) |fault| {
                tty.print(
                    .warn,
                    "chock: the toolchain cache {s} is over its bound and could not be emptied ({f})\n",
                    .{ dir, fault },
                );
            } else {
                tty.print(
                    .warn,
                    "chock: the toolchain cache {s} is over its bound and could not be emptied\n",
                    .{dir},
                );
            }
            return dir;
        };
        // Kept on a quiet run: this session builds from nothing, so it is
        // slower than the last one, and a person watching would otherwise have
        // no way to explain that.
        tty.print(
            .warn,
            "chock: the toolchain cache {s} held {d} MiB, over the bound of {d} MiB, so it was " ++
                "emptied. This session builds from nothing.\n",
            .{ dir, went.bytes / (1024 * 1024), chock_core.cache.max_bytes / (1024 * 1024) },
        );
        return dir;
    }
    if (size.files != 0) {
        // A cache that is doing its job. `chock cache` says the same thing
        // whenever somebody wants it.
        tty.detail("chock: toolchain cache {d} MiB in {d} files ({s})\n", .{
            size.bytes / (1024 * 1024),
            size.files,
            dir,
        });
    }
    return dir;
}

/// Read this project's Nix dev shell, and say on screen what the session
/// ended up with. Null is a project that states no toolchain of its own, and
/// `toolchainFor` is what then decides, and says, what a session mounts
/// instead.
///
/// **A dev shell that will not evaluate is reported and is not fatal.** A
/// broken `flake.nix` is often exactly what the user started the session to
/// fix, and refusing to run would leave them with no agent and a broken
/// flake instead of one of the two.
fn loadDevShell(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    cache_dir: ?[]const u8,
) ?chock_nix.DevShell {
    const dir = cache_dir orelse return null;

    // What `nix` said, and the three notices a `load` that succeeded can
    // still leave: a toolchain that could not be rooted, a cache that could
    // not be written, and store paths left out of the mount set. The library
    // used to print all of them itself.
    var diag: ?chock_nix.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    const loaded = chock_nix.DevShell.load(gpa, io, .{
        .project_root = project_root,
        .cache_dir = dir,
        .host_env = env,
        .on_evaluate = reportEvaluatingDevShell,
        .diag = &diag,
    }) catch |err| loaded: {
        if (diag) |*fault| {
            tty.print(.err, "chock: this project's dev shell could not be read: {f}\n", .{fault});
        } else {
            tty.print(.err, "chock: this project's dev shell could not be read ({t})\n", .{err});
        }
        break :loaded null;
    };

    // A notice from a `load` that answered. Not fatal, and worth a line: a
    // session whose toolchain is not rooted breaks under a
    // `nix-collect-garbage` that runs while it does.
    if (loaded != null) {
        if (diag) |*notice| tty.print(.warn, "chock: {f}\n", .{notice});
    }

    if (loaded) |shell| {
        // A dev shell that loaded is the shape a healthy start has, and the two
        // counts are a measurement of it rather than something to act on.
        tty.detail("chock: dev shell {s}: {d} variables, {d} store paths mounted\n", .{
            if (shell.evaluated) "evaluated" else "cached",
            shell.variables.len,
            shell.store_paths.len,
        });
    }
    // **A session with no dev shell says nothing here**, and `toolchainFor`
    // says it instead. This line used to read "the sandbox mounts the whole
    // Nix store", which is false on a machine that has no Nix store: measured
    // on 2026-08-25 on a bare Debian, where it was printed and then every tool
    // call died with `MountTreeFailed`. Only the function that really decides
    // the mount set may state it.
    return loaded;
}

/// Chock's own directory for this project's dev shell, made, or null when it
/// could not be. **Two things live in it**, and both are properties of this
/// project's toolchain rather than of one session: the cached evaluation of
/// the dev shell, and the garbage collector roots, which now cover a
/// provisioned program as well as the shell itself.
fn devShellDirFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) ?[]const u8 {
    const dir = session_paths.devShellDir(arena, env, project_root) catch |err| {
        tty.print(
            .warn,
            "chock: the dev shell directory is unknown ({t}), so this session has no dev shell\n",
            .{err},
        );
        return null;
    };
    session_paths.createDevShellDir(io, dir) catch return null;
    return dir;
}

/// Told before the evaluation, never on a cache hit: a rebuild is an event the
/// user can see, because it can take a while and silence looks like a hang.
fn reportEvaluatingDevShell(project_root: []const u8) void {
    tty.print(.plain, "chock: reading the dev shell of {s} with nix\n", .{project_root});
}

// One question decides this: which programs can a tool call find, and how much
// of this machine does the sandbox mount for them. There are now three answers,
// and a session takes exactly one of them.
//
// 1. **The project's Nix dev shell.** The narrowest answer, and the one this
//    project uses. Every path is the transitive closure of `flake.nix`.
// 2. **A container image the project names.** For a person with no Nix. The
//    image is a source of files exactly as a closure is: it is extracted on
//    the host, before the session, and a tool call still runs in Chock's own
//    sandbox and in no container. See `lib/chock-container.zig`.
// 3. **The host's own system directories.** The fallback, when the project
//    states neither.
//
// ## The fallback is derived and it is not a refusal, and here is why
//
// Measured on 2026-08-25 in a `debian:stable-slim` container with no Nix: the
// old default, `/nix/store`, is a bind source that is not there, so
// `sourceIsDirectory` answers `error.SourceMissing` and every tool call of the
// session dies with `MountTreeFailed`. The session started, the model
// answered, and the first tool call failed. That is the worst of the three
// possible behaviours, because the person had already begun.
//
// Of the two honest replacements, refusing at session start and deriving a set
// from the host, this takes the second:
//
// * **Refusing makes a downloaded Chock unusable on the commonest Linux
//   install** until the person installs a container runtime. On a machine
//   where that runtime is Docker, joining the group that may write its socket
//   is equal to root. Refusing would push a person toward a materially weaker
//   trust position to get anything at all.
// * **It weakens no layer.** Every namespace, Landlock, seccomp, the cgroup
//   and the network namespace are exactly what `chock doctor` measured. What
//   grows is the mount set, read only, and `chock-sandbox` marks a read only
//   bind `NOSUID` and `NODEV` as well.
// * **It is the decision this project already made for Nix.** The documented
//   default has always been the host's whole `/nix/store`, which is that
//   machine's whole toolchain area. `/usr` is the same object on a machine
//   with no Nix. One rule with two answers, depending on which package manager
//   the person happens to use, would not be a rule.
// * **It is not silent.** `reportToolchain` says on screen what was mounted
//   and how to narrow it, and `chock doctor` carries the same row.
// * **The home directory is not in it.** The widest thing the fallback reaches
//   is the system directories every user of that machine can already read.
//
// A machine with none of these directories gets the refusal, at session start,
// with the reason. See `refuseWithNoToolchain`.

/// Where the files a tool call runs come from. Decided once, before the first
/// turn, and read by every tool call of the session.
const Toolchain = struct {
    /// Host paths bound at their own path, each read only. A Nix closure, or
    /// the host's own system directories.
    store_paths: []const []const u8 = &.{},
    /// Host paths bound somewhere else. What a container image gives, because
    /// an image is a whole root filesystem held in one directory.
    mounts: []const chock_core.tools.ToolchainMount = &.{},
    which: Which,

    const Which = enum { dev_shell, image, host };
};

/// The host directories a session mounts when the project states no toolchain
/// of its own. **Every one of them read only**, and every one of them a
/// directory an ordinary user of that machine can already read.
///
/// `/etc` is on the list and it is the only entry that is not obviously a
/// toolchain. Debian resolves `/usr/bin/cc` through `/etc/alternatives`, and
/// glibc reads `/etc/ld.so.cache` to find a shared library, so a session
/// without it gets a compiler that does not start. It holds no secret an
/// unprivileged process can read: `/etc/shadow` and a host key are readable by
/// root alone, and the sandbox has the user's own privilege and no more.
///
/// The list is filtered by what really exists, so a machine with no `/lib64`
/// gets no mount for one. See `hostToolchainPaths`.
/// **Public for `src/doctor.zig`**, which counts the same list so that a
/// report and a session cannot disagree about how wide the fallback is.
pub const host_toolchain_candidates: []const []const u8 = &.{
    // A machine with Nix keeps exactly the behaviour it had. It is first
    // because it is the narrowest thing on the list that is still whole.
    "/nix/store",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/opt",
};

/// Which of `host_toolchain_candidates` this machine really has.
///
/// **A machine with a Nix store gets that and nothing else**, which is exactly
/// what Chock did before this function existed. There is no reason to widen a
/// working machine to fix a broken one, and a Nix store already holds every
/// program such a machine's `PATH` names.
fn hostToolchainPaths(
    arena: std.mem.Allocator,
    io: std.Io,
) std.mem.Allocator.Error![]const []const u8 {
    if (pathIsDirectory(io, host_toolchain_candidates[0])) {
        return arena.dupe([]const u8, host_toolchain_candidates[0..1]);
    }

    var found: std.ArrayList([]const u8) = .empty;
    for (host_toolchain_candidates[1..]) |path| {
        // A symbolic link counts: `/bin` is a link into `/usr` on Debian and
        // on Arch, and a bind mount follows it. Leaving those out would give a
        // sandbox with no `/bin`, and then nothing in it starts.
        if (!pathIsDirectory(io, path)) continue;
        try found.append(arena, path);
    }
    return found.toOwnedSlice(arena);
}

/// True when `path` is a directory, or a link that leads to one. False for
/// everything else, including a path this process may not read: a source it
/// cannot stat is a source the sandbox cannot bind either.
fn pathIsDirectory(io: std.Io, path: []const u8) bool {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

/// The mount set of a container image, in the shape a tool call binds, minus
/// any entry that would sit above something the sandbox puts there itself.
///
/// **The kinds come from the image and are not read again here.** `.dockerenv`
/// is a regular file at the top of a real Debian image tree, and Landlock
/// answers `EINVAL` for a directory right over a file: see
/// `chock_core.tools.ToolchainMount`.
///
/// ## Why an image entry above a sandbox mount has to go
///
/// **Measured on 2026-08-25, with a real `alpine:3.20` in a Debian container.**
/// An image entry is bound read only the moment it is built, and the workspace
/// is bound at the project's own path, which on an ordinary machine is under
/// `/home`. The two orders both break, and neither breaks quietly:
///
/// * The image first: the sandbox then has to make `/home/somebody/project` as
///   a mount target inside a read only `/home`, and `mkdirat` answers `EROFS`.
///   Every tool call ends in `MountTreeFailed`.
/// * The image second: the image's `/home` covers the workspace, so the
///   Landlock rule that names the project's path finds nothing there. Every
///   tool call ends in `LandlockRuleFailed`. This is the one that was really
///   measured, over `/run`, before `Image.sandbox_owns` took that name.
///
/// So an image entry that is a strict ancestor of another mount's target is
/// left out, and the caller says which. **What is lost is small and the loss
/// is stated**: `/home`, `/run` and `/tmp` are empty in every base image,
/// because a real container gets them from the runtime at start.
fn imageToolchainMounts(
    arena: std.mem.Allocator,
    image: *const chock_container.Image,
    sandbox_mounts: []const sandbox.namespace.Mount,
) std.mem.Allocator.Error!ImageMounts {
    var kept: std.ArrayList(chock_core.tools.ToolchainMount) = .empty;
    var dropped: std.ArrayList([]const u8) = .empty;

    for (image.mounts) |one| {
        if (isAboveAMount(one.target, sandbox_mounts)) {
            try dropped.append(arena, one.target);
            continue;
        }
        try kept.append(arena, .{
            .source = one.source,
            .target = one.target,
            .kind = switch (one.kind) {
                .directory => .directory,
                .file => .file,
            },
        });
    }

    return .{
        .mounts = try kept.toOwnedSlice(arena),
        .dropped = try dropped.toOwnedSlice(arena),
    };
}

/// What an image's mount set came to, and what was left out of it.
const ImageMounts = struct {
    mounts: []const chock_core.tools.ToolchainMount,
    /// The targets that were left out, so a caller can say so. Empty is the
    /// ordinary answer.
    dropped: []const []const u8,
};

/// True when `target` is a strict ancestor of the target of one of `mounts`.
/// The comparison is on whole path components, so `/ho` is never read as being
/// above `/home/somebody`.
fn isAboveAMount(target: []const u8, mounts: []const sandbox.namespace.Mount) bool {
    for (mounts) |mount| {
        const other = switch (mount) {
            .bind => |b| b.target,
            .overlay => |o| o.target,
            .proc => |p| p.target,
            .deny => |d| d.target,
        };
        if (other.len <= target.len) continue;
        if (!std.mem.startsWith(u8, other, target)) continue;
        if (other[target.len] != '/') continue;
        return true;
    }
    return false;
}

/// The environment a tool call resolves its own `argv[0]` against, for a
/// session whose files come from an image.
///
/// **`PATH` is rewritten to name the tree on the host.** The image's own
/// `PATH` names paths inside the sandbox, such as `/usr/bin`, and this
/// resolution happens on the host before any sandbox exists. So each entry is
/// joined onto the extracted tree, and `resolveOnPath` then finds the image's
/// own program and not this machine's. `chock_core.tools.prepare` maps it back
/// to the image's own path, because the mount set puts it there: see that
/// file's own `sandboxPathOf`.
///
/// An image that states no `PATH` gets none, and a tool call then has to name
/// an absolute path. That is honest: the image really did not say where its
/// programs are.
fn imageToolEnvironment(
    arena: std.mem.Allocator,
    image: *const chock_container.Image,
) std.mem.Allocator.Error!*std.process.Environ.Map {
    const map = try arena.create(std.process.Environ.Map);
    map.* = std.process.Environ.Map.init(arena);

    for (image.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (equals == 0) continue;
        const key = record[0..equals];
        const value = record[equals + 1 ..];
        if (!std.mem.eql(u8, key, "PATH")) {
            try map.put(key, value);
            continue;
        }
        try map.put(key, try hostSearchPath(arena, image.rootfs, value));
    }
    return map;
}

/// `search`, with every entry joined onto the image tree. An entry that is not
/// absolute is left out: the image's own `PATH` is read before any sandbox
/// exists, and a relative entry would resolve against this process's own
/// working directory, which is the user's project.
fn hostSearchPath(
    arena: std.mem.Allocator,
    rootfs: []const u8,
    search: []const u8,
) std.mem.Allocator.Error![]const u8 {
    var built: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, search, ':');
    while (it.next()) |entry| {
        if (entry.len == 0 or entry[0] != '/') continue;
        if (built.items.len != 0) try built.append(arena, ':');
        try built.appendSlice(arena, rootfs);
        try built.appendSlice(arena, entry);
    }
    return built.toOwnedSlice(arena);
}

/// The environment the sandboxed program itself is given, for a session whose
/// files come from an image: what the workspace already needs, plus what the
/// image states.
///
/// The same two rules `sandboxEnvironment` keeps for a dev shell, for the same
/// reasons. **The workspace's own variables win**, because the workspace's git
/// variables are what make git work at all against a read only object store.
/// **`PATH` is left out**, because a tool call binds the one program it names
/// at an absolute path; the image's `PATH` is honoured one step earlier, in
/// `imageToolEnvironment`.
fn imageSandboxEnvironment(
    arena: std.mem.Allocator,
    workspace_env: []const []const u8,
    image: *const chock_container.Image,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    try entries.appendSlice(arena, workspace_env);

    for (image.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        const key = record[0..equals];
        if (key.len == 0) continue;
        if (std.mem.eql(u8, key, "PATH")) continue;
        if (namesKey(workspace_env, key)) continue;
        try entries.append(arena, record);
    }

    return entries.toOwnedSlice(arena);
}

/// This project's container image, or null when it names none.
///
/// **Every refusal here happens at session start**, before a turn, before a
/// tool call, and with the command to run next in it. Task 48 set that rule
/// for Nix and it is the same rule: nothing fetches during a tool call,
/// because a tool call has no network and no daemon socket. A person who has
/// already begun and then loses every tool call is the fault this whole
/// function exists to avoid.
///
/// The `Image` owns the strings the mount set and both environments borrow, so
/// the caller keeps it for the length of the session.
fn loadImage(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
) !?chock_container.Image {
    const named = switch (chock_container.config.load(arena, io, project_root) catch |err| {
        tty.print(
            .err,
            "chock run: the container block of this project's chock.zon could not be read ({t}). " ++
                "Fix the file, or remove the block to use this machine's own toolchain.\n",
            .{err},
        );
        return error.Reported;
    }) {
        .none => return null,
        .refused => |text| {
            tty.print(.err, "chock run: {s}\n", .{text});
            return error.Reported;
        },
        .named => |reference| reference,
    };

    // **The arena owns the message, and never the library's own working
    // allocator.** `Image.load` builds a private arena and destroys it on
    // every error path, so a message built from that one is read after the
    // free: see `lib/chock-container/diagnostic.zig`. This arena lives as long
    // as the session.
    var diag: ?chock_container.Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);
    const sink = chock_container.sinkOf(arena, &diag);

    const found = switch (chock_container.Runtime.detect(arena, io, env, &diag) catch |err| {
        tty.print(
            .err,
            "chock run: this project names the image {s} and its runtime could not be run ({t}).\n",
            .{ named, err },
        );
        return error.Reported;
    }) {
        .not_installed => {
            tty.print(
                .err,
                "chock run: this project names the image {s}, and {s}\n",
                .{ named, try chock_container.Runtime.notInstalledText(arena) },
            );
            return error.Reported;
        },
        .refused => |refusal| {
            tty.print(.err, "chock run: {s}\n", .{refusal.text});
            return error.Reported;
        },
        .ready => |value| value,
    };

    const dir_name = try chock_container.reference.directoryName(arena, named);
    const cache_dir = session_paths.imageDir(arena, env, dir_name) catch |err| {
        tty.print(
            .err,
            "chock run: the directory for the image {s} is unknown ({t}), so it cannot be read.\n",
            .{ named, err },
        );
        return error.Reported;
    };
    session_paths.createImageDir(io, cache_dir) catch |err| {
        tty.print(
            .err,
            "chock run: the directory {s} could not be made ({t}), so the image {s} cannot be read.\n",
            .{ cache_dir, err, named },
        );
        return error.Reported;
    };

    var host = found.host(env, sink);
    const answer = chock_container.Image.load(gpa, io, .{
        .reference = named,
        .cache_dir = cache_dir,
        .kind = found.kind,
        .trust = found.trust,
        .runner = host.runner(),
        .on_extract = reportExtractingImage,
        .on_wait = reportWaitingForImage,
        .diag = sink,
    }) catch |err| {
        if (diag) |*fault| {
            tty.print(.err, "chock run: the image {s} could not be read: {f}\n", .{ named, fault });
        } else {
            tty.print(.err, "chock run: the image {s} could not be read ({t})\n", .{ named, err });
        }
        return error.Reported;
    };

    switch (answer) {
        .refused => |text| {
            // **Owned by `gpa` and not by the image's own arena**, because a
            // refusal outlives the arena that produced it: see `Image.load`.
            defer gpa.free(text);
            tty.print(.err, "chock run: {s}\n", .{text});
            return error.Reported;
        },
        .provided => |image| {
            // A notice from a load that answered: a cache that could not be
            // written, or one entry of the tree that is not mounted. Neither
            // stops a session and both change what a tool call finds.
            if (diag) |*notice| tty.print(.warn, "chock: {f}\n", .{notice});
            return image;
        },
    }
}

test "a machine with a nix store gets only that, and one without gets its own system directories" {
    // The fallback that replaced the default which broke every tool call on a
    // machine with no Nix. Both halves are asserted against this machine's own
    // filesystem, because the question is what really exists here.
    //
    // Mutation check: make `hostToolchainPaths` answer the whole candidate
    // list without filtering and the branch this machine is not in fails.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const paths = try hostToolchainPaths(arena, std.testing.io);

    if (pathIsDirectory(std.testing.io, "/nix/store")) {
        // **A working machine is not widened to fix a broken one.** This is
        // exactly what Chock bound before the fallback existed.
        try std.testing.expectEqual(@as(usize, 1), paths.len);
        try std.testing.expectEqualStrings("/nix/store", paths[0]);
        return;
    }

    // A machine with no Nix. Something has to be there, or no tool call could
    // run at all, and `/nix/store` must not be one of them.
    try std.testing.expect(paths.len != 0);
    for (paths) |path| try std.testing.expect(!std.mem.eql(u8, path, "/nix/store"));
}

test "every host candidate is absolute, so a session's mount set cannot depend on a working directory" {
    // A relative entry would be resolved against wherever `chock run` was
    // started, which is the user's project, and the sandbox would then bind a
    // directory of the project as the toolchain.
    for (host_toolchain_candidates) |path| {
        try std.testing.expect(std.fs.path.isAbsolute(path));
    }
}

test "an image's own PATH is rewritten to the tree on the host" {
    // The half of the image wiring that is easy to get wrong and silent when
    // it is wrong. `argv[0]` is resolved on the host, before any sandbox
    // exists, and the image's `PATH` names paths inside the sandbox. Without
    // this, `resolveOnPath` would find this machine's own `/usr/bin/ls` and
    // the session would run the host's program with the image's libraries.
    //
    // Mutation check: return `search` unchanged and the first assertion fails.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const built = try hostSearchPath(arena, "/state/images/alpine-3-20/rootfs", "/usr/bin:/bin");
    try std.testing.expectEqualStrings(
        "/state/images/alpine-3-20/rootfs/usr/bin:/state/images/alpine-3-20/rootfs/bin",
        built,
    );

    // A relative entry is left out. It would resolve against this process's
    // own working directory, which is the user's project.
    const filtered = try hostSearchPath(arena, "/tree", "/usr/bin:.:bin");
    try std.testing.expectEqualStrings("/tree/usr/bin", filtered);

    // An image that states an empty `PATH` gets an empty one, and never the
    // tree itself: a bare tree on `PATH` would offer every top level entry of
    // the image as a program.
    const empty = try hostSearchPath(arena, "/tree", "");
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}

test "an image's mount kinds carry through, because landlock refuses a directory right over a file" {
    // Measured on 2026-08-25: `docker export` writes `.dockerenv` as a regular
    // file at the top of a Debian tree. A rule with `read_dir` over it answers
    // EINVAL and takes down every tool call in the session.
    //
    // Mutation check: answer `.directory` for every entry and the second
    // assertion fails.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mounts = [_]chock_container.Image.Mount{
        .{ .source = "/tree/usr", .target = "/usr", .kind = .directory },
        .{ .source = "/tree/.dockerenv", .target = "/.dockerenv", .kind = .file },
    };
    const image = chock_container.Image{
        .arena = undefined,
        .kind = .docker,
        .trust = .root_daemon,
        .reference = "debian:stable-slim",
        .digest = "sha256:aaa",
        .variables = &.{},
        .workdir = "/",
        .rootfs = "/tree",
        .mounts = &mounts,
        .extracted = false,
        // Never loaded, so it holds no tree. The same reason `arena` above is
        // undefined: this image is a value the test built, not a session.
        .in_use = undefined,
    };

    const built = try imageToolchainMounts(arena, &image, &.{});
    try std.testing.expectEqual(@as(usize, 2), built.mounts.len);
    try std.testing.expectEqual(@as(usize, 0), built.dropped.len);
    try std.testing.expectEqual(chock_core.tools.ToolchainMount.Kind.directory, built.mounts[0].kind);
    try std.testing.expectEqual(chock_core.tools.ToolchainMount.Kind.file, built.mounts[1].kind);
    // The source is the host's and the target is the image's own path. That
    // difference is the whole reason `ToolchainMount` exists beside
    // `store_paths`.
    try std.testing.expectEqualStrings("/tree/usr", built.mounts[0].source);
    try std.testing.expectEqualStrings("/usr", built.mounts[0].target);
}

test "an image entry above a mount the sandbox makes itself is left out and said out loud" {
    // Measured on 2026-08-25 in a Debian container with a real alpine:3.20:
    // the image's own empty `/run` covered the git object store the workspace
    // puts at `/run/chock/objects`, and every tool call in the session ended in
    // `LandlockRuleFailed`.
    //
    // Mutation check: drop the `isAboveAMount` guard and the first assertion
    // reads 2, which is the mount set that broke every tool call.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const image_mounts = [_]chock_container.Image.Mount{
        .{ .source = "/tree/home", .target = "/home", .kind = .directory },
        .{ .source = "/tree/usr", .target = "/usr", .kind = .directory },
    };
    const image = chock_container.Image{
        .arena = undefined,
        .kind = .podman,
        .trust = .user_only,
        .reference = "alpine:3.20",
        .digest = "sha256:ccc",
        .variables = &.{},
        .workdir = "/",
        .rootfs = "/tree",
        .mounts = &image_mounts,
        .extracted = false,
        // Never loaded, so it holds no tree. The same reason `arena` above is
        // undefined: this image is a value the test built, not a session.
        .in_use = undefined,
    };

    // The workspace, at the project's own path, which on an ordinary machine
    // is under `/home`.
    const sandbox_mounts = [_]sandbox.namespace.Mount{.{ .bind = .{
        .source = "/state/01.work/wt",
        .target = "/home/somebody/project",
        .read_only = false,
    } }};

    const built = try imageToolchainMounts(arena, &image, &sandbox_mounts);
    try std.testing.expectEqual(@as(usize, 1), built.mounts.len);
    try std.testing.expectEqualStrings("/usr", built.mounts[0].target);
    try std.testing.expectEqual(@as(usize, 1), built.dropped.len);
    try std.testing.expectEqualStrings("/home", built.dropped[0]);

    // A whole path component, so a name that merely starts the same way is not
    // read as being above it.
    try std.testing.expect(!isAboveAMount("/ho", &sandbox_mounts));
    // And a mount is not above itself, or an image could never bind the very
    // path the sandbox already names.
    try std.testing.expect(!isAboveAMount("/home/somebody/project", &sandbox_mounts));
}

test "an image session keeps the workspace's own variables and leaves PATH out" {
    // The same two rules the dev shell half keeps. `GIT_OBJECT_DIRECTORY` is
    // what makes git work against a read only object store, and an image that
    // happened to state that name would otherwise break every git call.
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const workspace_env = [_][]const u8{ "GIT_OBJECT_DIRECTORY=/run/chock/git/objects", "KEEP=me" };
    const variables = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/somewhere/an/image/chose",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "LANG=C.UTF-8",
    };
    const image = chock_container.Image{
        .arena = undefined,
        .kind = .podman,
        .trust = .user_only,
        .reference = "alpine:3.20",
        .digest = "sha256:bbb",
        .variables = &variables,
        .workdir = "/",
        .rootfs = "/tree",
        .mounts = &.{},
        .extracted = true,
        // Never loaded, so it holds no tree. The same reason `arena` above is
        // undefined: this image is a value the test built, not a session.
        .in_use = undefined,
    };

    const built = try imageSandboxEnvironment(arena, &workspace_env, &image);
    try std.testing.expectEqual(@as(usize, 3), built.len);
    try std.testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try std.testing.expectEqualStrings("KEEP=me", built[1]);
    try std.testing.expectEqualStrings("LANG=C.UTF-8", built[2]);
    try std.testing.expect(!namesKey(built, "PATH"));

    // And the tool environment is the other half: `PATH` is the one name it
    // rewrites, and every other variable is the image's own.
    const tool_env = try imageToolEnvironment(arena, &image);
    try std.testing.expectEqualStrings("/tree/usr/local/bin:/tree/usr/bin:/tree/bin", tool_env.get("PATH").?);
    try std.testing.expectEqualStrings("C.UTF-8", tool_env.get("LANG").?);
}

/// Told before an extraction, never on a cache hit. The same rule the dev
/// shell evaluation follows: it takes a while, and silence looks like a hang.
fn reportExtractingImage(reference: []const u8) void {
    tty.print(.plain, "chock: writing the files of {s} to disk, once\n", .{reference});
}

/// **Said before the wait and not after it.** An image cache is shared, so a
/// second session waits for the one that is writing the tree rather than
/// rebuilding it underneath. A minute of silence reads as a hang.
fn reportWaitingForImage(reference: []const u8) void {
    tty.print(
        .plain,
        "chock: another session is writing the files of {s} to disk. Waiting for it\n",
        .{reference},
    );
}

/// Which toolchain this session got, said on screen, and the refusal when
/// there is none.
///
/// **The trust position of an image is its own line and never a layer.** A
/// root daemon that unpacked the image is a weaker trust position, not a
/// broken sandbox, and `chock_sandbox.guarantees` is unchanged either way. See
/// `chock_container.Runtime.Trust`.
fn toolchainFor(
    arena: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    dev_shell: ?chock_nix.DevShell,
    image: ?*const chock_container.Image,
    sandbox_mounts: []const sandbox.namespace.Mount,
) !Toolchain {
    if (image) |one| {
        const built = try imageToolchainMounts(arena, one, sandbox_mounts);
        tty.detail("chock: image {s}: {s}, {d} variables, {d} paths mounted\n", .{
            one.reference,
            if (one.extracted) "extracted" else "already on disk",
            one.variables.len,
            built.mounts.len,
        });
        for (built.dropped) |target| {
            // Said out loud, because a program that looks for something under
            // one of these finds an empty directory and the reason is nowhere
            // else on screen.
            tty.print(
                .warn,
                "chock: the image's own {s} is not mounted, because this session puts its own " ++
                    "directories under it. It is empty in a base image.\n",
                .{target},
            );
        }
        if (one.trust.isPrivileged()) {
            tty.print(
                .warn,
                "chock: {s} unpacked this image and {s}. The sandbox a tool call runs in is " ++
                    "unchanged.\n",
                .{ one.kind.displayName(), one.trust.text() },
            );
        }
        return .{ .mounts = built.mounts, .which = .image };
    }

    if (dev_shell) |shell| {
        return .{ .store_paths = shell.store_paths, .which = .dev_shell };
    }

    const paths = try hostToolchainPaths(arena, io);
    if (paths.len == 0) {
        tty.print(
            .err,
            "chock run: this machine has no directory a tool call could run a program from. " ++
                "None of the usual system directories is there, this project states no dev shell, " ++
                "and its chock.zon names no container image. A session would start and every tool " ++
                "call in it would fail, so it does not start. Give the project a flake.nix with a " ++
                "dev shell, or a chock.zon holding .container = .{{ .image = \"...\" }}.\n",
            .{},
        );
        return error.Reported;
    }

    tty.print(
        .warn,
        "chock: {s} states no toolchain, so tool calls use this machine's own programs and the " ++
            "sandbox mounts {d} of its system directories, read only. Narrow it with a flake.nix " ++
            "dev shell, or with .container = .{{ .image = \"...\" }} in chock.zon.\n",
        .{ project_root, paths.len },
    );
    return .{ .store_paths = paths, .which = .host };
}

/// What a session needs to add a program to its toolchain with Nix.
const Provisioning = struct {
    /// The absolute path of `nix` on the host, found once at the start rather
    /// than on the turn the model asks. A machine with no `nix` has no
    /// `Provisioning` at all, so the tool is never offered.
    nix_program: []const u8,
    /// The absolute path of `nix-store`, which makes the garbage collector
    /// root. Null when it is not on the host: a provisioned program then
    /// works and is not held against `nix-collect-garbage`, which is said out
    /// loud once rather than found out at mount time.
    nix_store_program: ?[]const u8,
    /// Where a program name is looked up. **Not the model's to choose**: see
    /// `chock_nix.provision`'s own top comment, which is where the whole of
    /// the safety argument is written.
    ///
    /// The flake registry entry, so a user who pinned `nixpkgs` with `nix
    /// registry pin` gets programs from the revision they pinned, and a user
    /// who did not gets the one their `nix` already uses. That is the same
    /// answer `nix run nixpkgs#thing` gives the user by hand, which is the
    /// property worth having: Chock resolves what the user's own Nix
    /// resolves.
    registry: []const u8,
    /// Where the garbage collector root links go, or null when this session
    /// has no directory of its own for them. The dev shell's directory, so a
    /// provisioned program is released by exactly the thing that releases the
    /// dev shell: removing Chock's state for this project.
    root_dir: ?[]const u8,
};

/// The name of the broker action a provisioning request is measured against.
/// **The same key `chock_broker.actions.Kind.nix_build` uses**, read from
/// there rather than spelled again, because a policy rule a user wrote for
/// `nix.build` must cover this too.
const provision_action = chock_broker.actions.Kind.nix_build.wireName();

/// Whether this session may add a program to its toolchain, and what it needs
/// to do it. Null when it may not, with the reason already on screen.
///
/// ## Filtered, and by the part of the broker that can run here
///
/// Everything with real consequence goes behind the broker, and running `nix
/// build` on the host, outside the sandbox, with the daemon, is exactly that.
/// So the decision is the broker's own: the policy table of `chock.zon`, under
/// the action `nix.build`, folded over the whole spawn chain by `evaluateChain`
/// so a subagent can hold no permission its parent lacks. The act itself is
/// `chock_broker.actions.perform`, which is where `nix.build` already lived
/// before this existed.
///
/// **What is not here is the question, and the reason is structural.**
/// `Broker.request` appends an `approval.request` to the session log and waits
/// for an `approval.response`, and `Loop.run` holds the exclusive lock on that
/// log for the whole session: nothing can append an answer while a turn is
/// running, so a mid-session question can only ever time out, and a request
/// nobody answers is a refusal. `chock run` already says this about its own end
/// of session approval, in `applyWork`. Asking a question whose answer is
/// decided before it is asked would cost a person's time and change nothing.
///
/// So the decision is read once, at the start, and it decides whether the
/// tool exists at all:
///
/// * `allow` gives the session the tool.
/// * `ask` and `deny` do not, and the model is never told about it, which is
///   the offer rule applied to a tool that could not work.
///
/// **A project with no `chock.zon` therefore cannot provision**, because the
/// empty table answers `ask` for every key. That is the safe direction and it
/// is the one this project already chose everywhere else: the way to say yes is
/// a rule in a file that is kept beyond the agent's reach. What this project's
/// policy says about provisioning, folded over the whole spawn chain so a
/// subagent can hold no permission its parent lacks. See
/// `chock_policy.table.evaluateChain`, which is the one function that applies
/// it.
///
/// Separate from `provisioningFor` because it is the half that is a decision
/// rather than a fact about the machine, and it is the half a test can pin
/// without a `nix` on the host.
fn provisionDecision(
    arena: std.mem.Allocator,
    policy: *const chock_policy.table.Table,
    chain_links: []const chock_proto.event.SpawnLink,
    agent_kind: []const u8,
    model: []const u8,
) std.mem.Allocator.Error!chock_policy.table.Decision {
    // The chain `evaluateChain` wants is the parents and this session, in
    // that order. The same shape `Broker.request` builds from an `Ask`, and
    // for the same reason: a session cannot state its own parents.
    const chain = try arena.alloc([]const u8, chain_links.len + 1);
    defer arena.free(chain);
    for (chain_links, chain[0..chain_links.len]) |link, *slot| slot.* = link.agent_kind;
    chain[chain_links.len] = agent_kind;

    // A chain the policy reader cannot fold answers `ask`, which is already
    // the safe answer. The reason used to reach a terminal from inside the
    // library; it reaches this command instead, which is what ranks a line
    // for a person. Said out loud because a chain this shape means the log
    // holds something Chock did not write.
    var fault: ?chock_policy.table.ChainFault = null;
    const decision = policy.evaluateChain(chain, .{
        .agent_kind = agent_kind,
        .model = model,
        .tool = @tagName(chock_core.tools.Tool.provide_tool),
        .action = provision_action,
    }, &fault);
    if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});
    return decision;
}

fn provisioningFor(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    policy: *const chock_policy.table.Table,
    options: Options,
    chain_links: []const chock_proto.event.SpawnLink,
    model: []const u8,
    dev_shell_dir: ?[]const u8,
) std.mem.Allocator.Error!?Provisioning {
    // **A capability that is off is not worth a paragraph on a quiet run.**
    // This used to print the policy answer, the action name, and a `chock.zon`
    // rule to paste, on every start of every project that had said nothing
    // about `nix.build`. Nobody had asked for a program to be added, so the
    // whole block taught configuration for a thing that had not come up. The
    // fact still reaches anybody who wants it, in one sentence, and the model
    // is told the tool does not exist by the only means that matters: the tool
    // is not in its list.
    const decision = try provisionDecision(arena, policy, chain_links, options.agent_kind, model);
    if (decision != .allow) {
        tty.detail(
            "chock: provide_tool is off, because this project's policy answers {t} for {s}\n",
            .{ decision, provision_action },
        );
        return null;
    }

    const nix_program = chock_nix.proc.resolve(arena, io, env, "nix") catch {
        tty.detail("chock: provide_tool is off, because nix is not on this machine's PATH\n", .{});
        return null;
    };
    // Best effort, and said out loud: a provisioned program with no root
    // works, and a `nix-collect-garbage` during the session can take it away.
    // Kept on a quiet run, because it only prints for a session that **can**
    // provision, so the hazard it names is one this session can really meet.
    const nix_store_program = chock_nix.proc.resolve(arena, io, env, "nix-store") catch null;
    if (nix_store_program == null or dev_shell_dir == null) {
        tty.print(
            .warn,
            "chock: a provisioned program cannot be held against nix-collect-garbage in this " ++
                "session, so one that runs during it can break the toolchain.\n",
            .{},
        );
    }

    return .{
        .nix_program = nix_program,
        .nix_store_program = nix_store_program,
        .registry = chock_nix.provision.default_registry,
        .root_dir = dev_shell_dir,
    };
}

/// The environment a tool call resolves its own `argv[0]` against.
///
/// **The dev shell's, when the project has one**, which is the whole of the
/// rule: the program a tool call runs is the project's, not whichever one this
/// machine happens to have on the user's `PATH`. Before this existed it worked
/// only by accident, and only for a `chock run` typed inside `nix develop`.
///
/// Only `PATH` is read from it, in `lib/chock-core/tools.zig`'s own
/// `resolveOnPath`, and the map carries every variable regardless: a second
/// name read from it later should find the dev shell's answer rather than
/// this function's idea of which names matter.
fn toolEnvironment(
    arena: std.mem.Allocator,
    host_env: *std.process.Environ.Map,
    dev_shell: ?chock_nix.DevShell,
) std.mem.Allocator.Error!*std.process.Environ.Map {
    const shell = dev_shell orelse return host_env;

    const map = try arena.create(std.process.Environ.Map);
    map.* = std.process.Environ.Map.init(arena);
    for (shell.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (equals == 0) continue;
        try map.put(record[0..equals], record[equals + 1 ..]);
    }
    return map;
}

/// The environment the sandboxed program itself is given: what the workspace
/// already needs, plus what the dev shell states.
///
/// **The workspace's own variables win.** The workspace's
/// `GIT_OBJECT_DIRECTORY` and `GIT_ALTERNATE_OBJECT_DIRECTORIES` are what make
/// git work at all against a read only object store, and a flake that happened
/// to set one of those names would otherwise break every git call the agent
/// makes. Written as a skip rather than left to the order of the list, because
/// two entries with one name is undefined in POSIX and "whichever libc reads
/// first" is not a rule to rely on.
///
/// **`PATH` is left out on purpose.** The sandbox has never had one: a tool
/// call binds exactly the one program it names, at an absolute path, which
/// is the per call argv boundary `lib/chock-core/tools.zig`'s own top
/// comment calls the point of `run_command`. The dev shell's `PATH` is still
/// honoured, one step earlier, where `argv[0]` is resolved against it: see
/// `toolEnvironment`.
fn sandboxEnvironment(
    arena: std.mem.Allocator,
    workspace_env: []const []const u8,
    shell: chock_nix.DevShell,
) std.mem.Allocator.Error![]const []const u8 {
    var entries: std.ArrayList([]const u8) = .empty;
    try entries.appendSlice(arena, workspace_env);

    for (shell.variables) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        const key = record[0..equals];
        if (key.len == 0) continue;
        if (std.mem.eql(u8, key, "PATH")) continue;
        if (namesKey(workspace_env, key)) continue;
        try entries.append(arena, record);
    }

    return entries.toOwnedSlice(arena);
}

/// True when one of these `KEY=VALUE` entries has this name.
fn namesKey(entries: []const []const u8, key: []const u8) bool {
    for (entries) |entry| {
        const equals = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
        if (std.mem.eql(u8, entry[0..equals], key)) return true;
    }
    return false;
}

test "the sandbox environment keeps the workspace's own variables and leaves PATH out" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const workspace_env = [_][]const u8{ "GIT_OBJECT_DIRECTORY=/run/chock/git/objects", "KEEP=me" };
    const variables = [_][]const u8{
        "GIT_OBJECT_DIRECTORY=/somewhere/a/flake/chose",
        "PATH=/nix/store/aaa/bin",
        "ZIG_GLOBAL_CACHE_DIR=/nix/store/bbb-cache",
    };
    const shell = chock_nix.DevShell{
        .arena = undefined,
        .variables = &variables,
        .store_paths = &.{},
        .evaluated = true,
    };

    const built = try sandboxEnvironment(arena, &workspace_env, shell);

    try std.testing.expectEqual(@as(usize, 3), built.len);
    try std.testing.expectEqualStrings("GIT_OBJECT_DIRECTORY=/run/chock/git/objects", built[0]);
    try std.testing.expectEqualStrings("KEEP=me", built[1]);
    try std.testing.expectEqualStrings("ZIG_GLOBAL_CACHE_DIR=/nix/store/bbb-cache", built[2]);
    try std.testing.expect(!namesKey(built, "PATH"));
}

test "the tool environment is the dev shell's own, and the host's when there is none" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var host = std.process.Environ.Map.init(allocator);
    defer host.deinit();
    try host.put("PATH", "/host/bin");

    // With no dev shell, `argv[0]` is resolved the way it always was.
    const without = try toolEnvironment(arena, &host, null);
    try std.testing.expectEqualStrings("/host/bin", without.get("PATH").?);

    // With one, the project's toolchain is what a tool call finds, and the
    // host's `PATH` is not in the answer at all.
    const variables = [_][]const u8{"PATH=/nix/store/aaa-zig/bin"};
    const shell = chock_nix.DevShell{
        .arena = undefined,
        .variables = &variables,
        .store_paths = &.{},
        .evaluated = true,
    };
    const with = try toolEnvironment(arena, &host, shell);
    try std.testing.expectEqualStrings("/nix/store/aaa-zig/bin", with.get("PATH").?);
}

/// Say whether this session wrote anything to the knowledgebase.
///
/// Counted at the end against the count at the start, rather than tracked
/// through the loop: a note that replaced an existing one changes no count,
/// and saying "wrote 0 notes" for a session that corrected one would be
/// wrong. So this reports the directory whenever there is anything in it, and
/// the growth when there was any.
fn reportNotes(io: std.Io, started: *const Started) void {
    const dir = started.memory_dir orelse return;
    const now = chock_core.memory.count(io, dir);
    if (now == 0) return;
    if (now > started.notes_at_start) {
        tty.print(.plain, "chock: {d} new notes, {d} in all ({s})\n", .{
            now - started.notes_at_start,
            now,
            dir,
        });
        return;
    }
    tty.print(.plain, "chock: {d} notes ({s}). Read or clear them with: chock memory\n", .{ now, dir });
}

/// Say which instruction files went into the prompt.
///
/// **A user who clones a repository and sees an unexpected four hundred line
/// `AGENTS.md` load has learned something worth knowing.** These files are
/// untrusted input, and the cheapest defence against a surprise is saying that
/// the surprise happened. So this stays on a quiet run.
///
/// **One line for all of them, and the sizes are behind `--verbose`.** The
/// paths are what somebody acts on, because a path is what they open. The layer
/// and the byte count answer a question nobody has until the path has already
/// surprised them.
fn reportInstructions(loaded: chock_core.instructions.Loaded) void {
    if (loaded.files.len != 0) {
        tty.print(.plain, "chock: instructions", .{});
        for (loaded.files, 0..) |file, index| {
            tty.print(.plain, "{s} {s}", .{ if (index == 0) "" else ",", file.path });
        }
        tty.print(.plain, "\n", .{});
    }
    for (loaded.files) |file| {
        tty.detail("chock: instructions {s} ({t}, {d} bytes)\n", .{ file.path, file.layer, file.bytes });
    }
    if (loaded.subtrees_left_out != 0) {
        tty.print(
            .warn,
            "chock: {d} more instruction files are in this project and are not listed to the agent\n",
            .{loaded.subtrees_left_out},
        );
    }
}

/// The ref a session's work lands on, under `refs/chock/`, named after the
/// session.
///
/// **Never the branch the user has checked out.** The worktree is detached
/// exactly so a session cannot move a branch of the user, and moving one here
/// at the end would give back with the right hand what that took away with the
/// left: the user's own working tree would suddenly read as a large diff
/// against a commit they never made. A ref of the session's own is in the
/// project, reachable, and inert until the user merges or cherry-picks it.
fn applyRef(gpa: std.mem.Allocator, session_id: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "refs/chock/{s}", .{session_id});
}

/// Every sandbox layer of this session, in the order the header names them.
///
/// **Two honest sources, and neither is the platform.** `src/ui.zig` may not
/// read `builtin` and neither may this: what a layer is worth comes from the
/// sandbox itself.
///
/// * **`given` is what the driver of this build declares it applies.**
///   `chock_sandbox.Sandbox.guarantees` is the driver's own answer, one member
///   per capability layer, and a layer that is not in it is a layer this build
///   never had. Every one is in it on Linux. Darwin declares four, which are
///   the network, the signals, the IPC and the paths, and it does not declare
///   a system call filter or a mounted workspace: see `darwin/driver.zig`.
/// * **`network` is what this session asked for**, out of the config it will
///   really spawn with. `.host` gives the network layer up, and that is allowed
///   only for an act a user approved.
///
/// **A layer that failed to apply never reaches this, and that is stronger than
/// showing it off.** The Linux driver refuses rather than degrades: every step
/// of `applyLayers` has a member of `SetupError` of its own, a kernel with no
/// Landlock is `SpawnError.LandlockUnavailable`, and each of them fails the
/// whole call. So there is no state in which a tool ran with a layer quietly
/// missing, and `✓` beside a layer the driver gives is a claim about every call
/// that ran, not a guess about one.
///
/// **What is still missing is `unavailable`**, which is a layer this machine
/// could apply and this process was not permitted. Nothing in `chock run` can
/// answer it today: the per call records that hold it, `Sandbox.LimitsReport`
/// and `Sandbox.LandlockReport`, are filled inside `chock_core.tools` and never
/// carried back out. See `ui.Layer.State.unavailable`.
///
/// The result borrows only static strings, so a caller may keep it for as long
/// as it likes.
fn sandboxLayers(
    given: sandbox.Sandbox.Guarantees,
    network: sandbox.namespace.Network,
    workspace: []const u8,
) [layer_names.len]ui.Layer {
    var built: [layer_names.len]ui.Layer = undefined;
    for (layer_names, &built) |named, *slot| {
        const note: []const u8 = switch (named.guarantee) {
            // **The note is the mode's own name, and no longer a word of its
            // own.** It used to read "off" for the closed mode, which was
            // right while a network was on or off and is wrong now that there
            // are three answers: a reader who saw "off" beside a ✓ and
            // "filtered" beside another ✓ had to learn a second vocabulary to
            // tell what either one meant. "none", "filtered" and "host" are
            // the three names of `namespace.Network`, so the header and the
            // code say the same word for the same thing.
            .network_isolated => switch (network) {
                .none => "none",
                .filtered => "filtered",
                .host => "host",
            },
            // The workspace kind goes beside this one.
            .workspace_mounted => workspace,
            else => "",
        };
        const state: ui.Layer.State = if (!given.contains(named.guarantee))
            .unsupported
        else if (named.guarantee == .network_isolated and network == .host)
            .off
        else
            .on;
        slot.* = .{ .name = named.name, .note = note, .state = state };
    }
    return built;
}

/// What each layer of the header is called, and which guarantee it is.
///
/// **The names are the display's and the guarantees are `chock_sandbox`'s**, so
/// this table is the one place the two vocabularies meet. The exhaustive switch
/// below is what makes a seventh guarantee a compile error here rather than a
/// layer that quietly never reaches a screen.
const layer_names = [_]struct {
    name: []const u8,
    guarantee: sandbox.Sandbox.Guarantee,
}{
    .{ .name = "net", .guarantee = .network_isolated },
    .{ .name = "fs", .guarantee = .workspace_mounted },
    .{ .name = "pid", .guarantee = .signal_isolated },
    .{ .name = "ipc", .guarantee = .ipc_isolated },
    .{ .name = "seccomp", .guarantee = .syscall_restricted },
    .{ .name = "landlock", .guarantee = .path_restricted },
};

comptime {
    // Every guarantee reaches the header, and no name is used twice. A
    // guarantee added to `chock_sandbox` and not to the table above would be a
    // layer a person is never told about.
    var seen = sandbox.Sandbox.Guarantees.initEmpty();
    for (layer_names) |named| {
        if (seen.contains(named.guarantee)) @compileError(
            "chock run: two header layers name the same sandbox guarantee",
        );
        seen.insert(named.guarantee);
    }
    if (seen.count() != @typeInfo(sandbox.Sandbox.Guarantee).@"enum".fields.len) @compileError(
        "chock run: a sandbox guarantee has no layer in the header",
    );
}

/// Who asks the person at this machine: the display, the bare prompt, or
/// nobody.
///
/// **Never both, and that is the whole of this function.** `approval.Terminal`
/// reads standard input and writes its prompt straight at the terminal, and
/// `src/ui.zig` holds that same descriptor in raw mode and keeps a copy of every
/// cell. Two readers on one descriptor race for every byte, and a prompt written
/// around a display lands in cells the display believes it owns. A session with
/// a display is a session at a terminal too, so an `or` here would give the
/// broker both.
///
/// Its own function, over two booleans, so the rule is somewhere a test can
/// reach rather than an `if` inside a method that needs a session to build.
fn asksHere(has_display: bool, at_terminal: bool) enum { display, terminal, nobody } {
    if (has_display) return .display;
    if (at_terminal) return .terminal;
    return .nobody;
}

/// Everybody who can answer a question this session asks, and how long one may
/// wait.
///
/// **Two waiters, and a session can have either, both, or neither.** A person
/// at this process's own terminal is `src/approval.zig`, and a client attached
/// to the session's unix socket is `chock_broker.socket`. Both are
/// implementations of the same `Broker.Waiter` seam, both answer through the
/// caller's own `locked` handle, and neither touches the session lock: see
/// `lib/chock-broker/socket.zig`'s own top comment for why the broker does not
/// have to own the log for any of this to work.
///
/// **Built in place and never returned by value.** A `Broker.Waiter` holds a
/// pointer into this struct, so a copy of it is a waiter pointing at a value
/// that has moved.
const Approvers = struct {
    stdin: approval.Stdin,
    terminal: approval.Terminal,
    display: approval.Display,
    socket: chock_broker.socket.Waiter,
    pair: chock_broker.socket.Pair,
    at_terminal: bool,
    /// Whether a display is up. **Never both this and `terminal`**: they are
    /// two readers of one device, and `waiter` is what keeps that true.
    has_display: bool,
    has_socket: bool,
    /// How many clients were attached when this was built. Read once, at the
    /// moment the question is about to be written, because that is the moment
    /// `timeoutMs` is asking about.
    attached: usize,

    fn init(
        self: *Approvers,
        gpa: std.mem.Allocator,
        io: std.Io,
        started: *Started,
        locked: *ApprovalLock,
        /// The display, when one is up. See `waiter`.
        screen: ?*ui.Ui,
    ) void {
        self.at_terminal = approval.hasTerminal(io);
        self.stdin = .{};
        self.terminal = .{
            .gpa = gpa,
            .storage = started.storage,
            .locked = locked,
            .console = self.stdin.console(),
        };

        self.has_display = screen != null;
        if (screen) |one| {
            self.display = .{
                .gpa = gpa,
                .storage = started.storage,
                .locked = locked,
                .screen = one,
            };
        }

        self.has_socket = started.approvals != null;
        self.attached = 0;
        if (started.approvals) |endpoint| {
            // **Before the count is read.** A client that has connected and not
            // been accepted yet is a client the kernel is holding, and a
            // question written before this call would be given a deadline of
            // zero over somebody who is already there.
            endpoint.acceptPending(io);
            self.attached = endpoint.attached();
            self.socket = .{
                .gpa = gpa,
                .storage = started.storage,
                .locked = locked,
                .endpoint = endpoint,
                .stop = interrupt.requested,
            };
        }
    }

    /// The one waiter the broker is given.
    ///
    /// **The display replaces the bare terminal and never joins it.** Both read
    /// the same descriptor, and two readers on one descriptor race for every
    /// byte; the display also holds that device in raw mode and keeps a copy of
    /// every cell, so a prompt written around it lands in cells it believes it
    /// owns. So a session with a display asks in its own approval region, and a
    /// session with none asks at the prompt exactly as it always did. See
    /// `approval.Display`.
    ///
    /// A session with nobody at all gets the plain waiter, which only sleeps,
    /// and `timeoutMs` gives it a deadline that has already passed to go with
    /// it. Building a terminal waiter for a session with no terminal would be a
    /// prompt written to nothing.
    fn waiter(self: *Approvers) chock_broker.Broker.Waiter {
        const here: ?chock_broker.Broker.Waiter = switch (asksHere(self.has_display, self.at_terminal)) {
            .display => self.display.waiter(),
            .terminal => self.terminal.waiter(),
            .nobody => null,
        };

        if (here) |one| {
            if (!self.has_socket) return one;
            self.pair = .{ .first = one, .second = self.socket.waiter() };
            return self.pair.waiter();
        }
        if (self.has_socket) return self.socket.waiter();
        return chock_broker.Broker.SystemWaiter.waiter();
    }

    fn timeoutMs(self: *const Approvers) i64 {
        // A display is a person watching, the same as a terminal is, so the
        // question gets the full deadline rather than the zero of a session
        // nobody can answer.
        return chock_broker.socket.timeoutMs(self.at_terminal or self.has_display, self.attached);
    }

    /// The first fault any half reported, or null. A `Waiter` cannot give an
    /// error back to the broker, so the caller reads it here instead.
    fn failed(self: *const Approvers) ?anyerror {
        if (self.has_display) {
            if (self.display.failed) |err| return err;
        }
        if (self.terminal.failed) |err| return err;
        if (self.has_socket) {
            if (self.socket.failed) |err| return err;
        }
        return null;
    }
};

/// The person at this terminal, as a `chock_core.ask.Console`.
///
/// **A bridge and nothing else, and the two ends are two files apart on
/// purpose.** `chock_core.ask.Prompt` holds every decision about a question: the
/// bounds, the marker that keeps the model's words out of column zero, the
/// filter, and the deadline. It reaches a device through a vtable, because
/// nothing under `lib/` writes to one. `src/approval.zig` owns the real
/// descriptor, the poll with a bound, and the flush an unterminated line needs.
/// This forwards one to the other, so neither has to know the other's type.
///
/// **A question is never asked while a display is up.** The display holds the
/// terminal in raw mode and keeps a copy of every cell, so a prompt written
/// around it lands in cells it believes it owns and two readers race for every
/// byte. That is the rule `asksHere` already keeps for an approval, and the
/// caller below keeps it here by giving `Prompt.at_terminal` a false when a
/// screen is up. **`src/ui.zig` has no region for a question yet**, so such a
/// session tells the agent nobody was asked.
const QuestionConsole = struct {
    stdin: approval.Stdin = .{},

    fn console(self: *QuestionConsole) chock_core.ask.Console {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.ask.Console.VTable{ .write = writeFn, .read = readFn };

    fn writeFn(ptr: *anyopaque, io: std.Io, bytes: []const u8) void {
        const self: *QuestionConsole = @ptrCast(@alignCast(ptr));
        self.stdin.console().write(io, bytes);
    }

    fn readFn(
        ptr: *anyopaque,
        io: std.Io,
        buffer: []u8,
        budget_ms: u64,
    ) chock_core.ask.Console.Read {
        const self: *QuestionConsole = @ptrCast(@alignCast(ptr));
        // No `else`: a way for a read to end that `src/approval.zig` adds and
        // this forgets fails the build rather than becoming a silent `idle`.
        return switch (self.stdin.console().read(io, buffer, budget_ms)) {
            .idle => .idle,
            .bytes => |count| .{ .bytes = count },
            .ended => .ended,
            .canceled => .canceled,
        };
    }
};

/// What keeps a full screen display alive while the session waits.
///
/// **The display used to be frozen for the whole of every wait**, because
/// `src/ui.zig` reads its keyboard and repaints in one place and that place runs
/// only when an event arrives. Between two events nothing read the keyboard, so
/// a person could not scroll while a tool call ran, and could not scroll at all
/// while the harness waited for the first token of a reply. See `ui.Ui.pumpStep`
/// for the whole of the fault and for why a second thread is not the answer.
///
/// **Two seams and one implementation, because two libraries wait.**
/// `chock_core.idle.Idle` is the wait on a sandboxed program's output pipe and
/// `chock_provider.Client.Idle` is the wait on the provider going quiet. Neither
/// library imports the other, so each declares the shape it needs and this
/// bridges both to the one display, which is the same cost
/// `chock_core.ask.Console` pays to stay out of `src/approval.zig`.
///
/// **Built in place and never copied**: both seams hold a pointer into this.
const DisplayPump = struct {
    screen: *ui.Ui,

    fn coreIdle(self: *DisplayPump) chock_core.idle.Idle {
        return .{ .ptr = self, .vtable = &core_vtable };
    }

    fn providerIdle(self: *DisplayPump) chock_provider.Client.Idle {
        return .{ .ptr = self, .vtable = &provider_vtable };
    }

    const core_vtable = chock_core.idle.Idle.VTable{ .step = stepFn };
    const provider_vtable = chock_provider.Client.Idle.VTable{ .step = stepFn };

    fn stepFn(ptr: *anyopaque) void {
        const self: *DisplayPump = @ptrCast(@alignCast(ptr));
        self.screen.pumpStep();
    }
};

/// What puts an `ask_user` question on a display, in the region `src/ui.zig`
/// keeps for it.
///
/// **Before this, a session with a display told the agent nobody was asked.**
/// `chock_core.ask.Prompt` reads `at_terminal` before it writes a byte and comes
/// straight back with `.nobody`, and the caller below gave it a false whenever a
/// screen was up: a prompt written around a display lands in cells the display
/// believes it owns, and two readers on one descriptor race for every byte. That
/// was the honest answer while there was no region to ask in. There is one now.
///
/// **This is not the arbiter and never becomes one.** An ask grants nothing,
/// whatever the person types: there is no member of `ui.Text` or of
/// `chock_core.ask.Answer` that could carry a decision, and this appends nothing
/// to the log at all. `lib/chock-core/ask.zig`'s own top comment says why the two
/// paths stay apart, and `src/ui.zig`'s `Question` says it again beside the
/// approval region that looks so like it.
///
/// **The deadline is measured here and shown by the region**, the same way
/// `approval.Display` moves an approval's countdown, so a person can see how
/// long they have. A question nobody answers ends in `timed_out`, which the model
/// is told to carry on from.
///
/// **Built in place and never copied**: an `Asker` holds a pointer into this.
const DisplayAsker = struct {
    screen: *ui.Ui,
    /// Whether a stop has been asked for. A field for the same reason
    /// `chock_core.ask.Prompt.stop` is one: a test answers it without raising a
    /// real signal at the whole test binary.
    stop: *const fn () bool = interrupt.requested,
    /// How long one question waits. The same five minutes the bare prompt waits.
    timeout_ms: i64 = chock_core.ask.default_timeout_ms,
    /// What the deadline is measured against. A field for the reason `stop` is
    /// one.
    now: *const fn (io: std.Io) i64 = nowMs,
    /// Which agent is asking, as Chock names it. Chock's own word, never the
    /// model's.
    agent_kind: []const u8 = "",

    fn asker(self: *DisplayAsker) chock_core.ask.Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.ask.Asker.VTable{ .ask = askFn };

    fn askFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: chock_core.ask.Question,
    ) chock_core.ask.Error!chock_core.ask.Answer {
        const self: *DisplayAsker = @ptrCast(@alignCast(ptr));
        return self.ask(gpa, io, question);
    }

    /// Put one question up and wait for a line, for at most `timeout_ms`.
    ///
    /// Its own function, taking and giving ordinary values, so a test drives
    /// exactly what the loop drives.
    pub fn ask(
        self: *DisplayAsker,
        gpa: std.mem.Allocator,
        io: std.Io,
        question: chock_core.ask.Question,
    ) chock_core.ask.Error!chock_core.ask.Answer {
        // **First, and before anything is shown.** A person who pressed Ctrl-C
        // is leaving, not answering.
        if (self.stop()) return .stopped;

        self.screen.showQuestion(.{
            .agent_kind = self.agent_kind,
            .text = question.text,
            .options = question.options,
            .left_ms = self.timeout_ms,
        });
        // **On every path out**, including the error one: a region a person can
        // still see and can no longer answer is worse than none.
        defer self.screen.clearQuestion();

        const deadline = self.now(io) + self.timeout_ms;
        while (true) {
            if (self.stop()) return .stopped;

            const left = deadline - self.now(io);
            if (left <= 0) return .timed_out;
            self.screen.questionLeft(left);

            const budget: u64 = @min(
                @as(u64, @intCast(left)),
                chock_core.ask.poll_interval_ms,
            );
            switch (self.screen.awaitText(budget)) {
                .waiting => continue,
                .canceled => return .stopped,
                .declined => return .declined,
                .answered => |said| {
                    // **The number a person typed is the option it names**, the
                    // same rule `chock_core.ask.chosen` keeps at the bare
                    // prompt, so the model reads the same answer whichever way
                    // it was given. Anything that is not a number in range is
                    // the person's own words.
                    const words = chock_core.ask.chosen(said, question.options) orelse said;
                    return .{ .answered = try gpa.dupe(u8, words) };
                },
            }
        }
    }

    fn nowMs(io: std.Io) i64 {
        return std.Io.Timestamp.now(io, .real).toMilliseconds();
    }
};

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public, the same way `src/approval.zig` does.
const ApprovalLock = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// The broker, as `chock_core.Loop` asks a question of one mid session.
///
/// **This is the caller `chock_policy.ratchet.widen_action` and
/// `chock_broker.review.requesterText` did not have.** Both were built, tested,
/// and refused for one reason: `Loop.run` holds the exclusive lock on the
/// session log for the whole session, so no answer could arrive and no question
/// was worth asking. `lib/chock-broker/socket.zig` removes that reason, and this
/// is what joins the loop to the broker now that it is gone.
///
/// ## It runs inside the lock, on purpose
///
/// `decide` is handed the loop's own `locked` handle and passes it straight to
/// `Broker.request`, which writes the question and the answer through it. There
/// is no second open of the log and no second lock: see
/// `lib/chock-broker/socket.zig`'s own top comment on why the broker does not
/// have to own the log for any of this to work.
///
/// ## What it folds, and why it folds it again
///
/// The loop holds a `state.Session` of its own and this seam is handed none, so
/// the log is folded here. That is not a workaround: the fold is the truth of a
/// session, and it is what makes this right about a session that was resumed,
/// handed to the daemon, or compacted. It costs one replay per question, and a
/// widening proposal is rare.
///
/// ## The reviewer, and the honest limit on it
///
/// `agent_review` and `agent_then_human` want a reviewer subagent, and
/// `reviewerFor` builds the same one `applyWork` uses. A session whose limits,
/// budget, or process state will not start one gets `review_unavailable`, which
/// does not permit: that is the rule `lib/chock-broker/review.zig` would be
/// worthless without.
const SessionArbiter = struct {
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
    /// The display, when bare `chock` brought one up. **This is the one thing
    /// that makes a mid session question answerable in the interface**: an
    /// approval arrives during a turn, and during a turn the display is the
    /// only thing reading the terminal. Null for `chock run`, which asks at the
    /// prompt. See `Approvers.waiter`.
    screen: ?*ui.Ui = null,

    fn arbiter(self: *SessionArbiter) chock_core.arbiter.Arbiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.arbiter.Locked,
        ask: chock_core.arbiter.Ask,
    ) chock_core.arbiter.Answer {
        const self: *SessionArbiter = @ptrCast(@alignCast(ptr));

        var session = chock_proto.state.Session.init(gpa);
        defer session.deinit();
        foldSession(gpa, io, self.started.storage, &session);

        var review_child = reviewChild(self.gpa, self.environ, self.env, self.started, self.options);
        var review_spawner = reviewerFor(review_child.spawner(), self.started, &session);

        // The loop's own handle, so a reviewer this decision starts is appended
        // to the log as a child and counted against the width bound: see
        // `ReviewSpawner.locked`.
        review_spawner.locked = locked;

        var approvers: Approvers = undefined;
        approvers.init(gpa, io, self.started, locked, self.screen);

        const broker = chock_broker.Broker{
            .policy = self.started.policy,
            .waiter = approvers.waiter(),
            .reviewer = review_spawner.reviewer(),
            // **The broker writes into the log this loop holds the lock on.**
            // `Loop.appendAndApply` cannot cover what another library appends,
            // so the same values reach both. See `brokerRedaction`.
            .redaction = self.started.redact_values,
        };

        // The promises this session and every session above it made. The same
        // read `applyWork` does, and for the same reason: a promise is enforced
        // in the broker, out of a record nothing can rewrite, and never by the
        // agent about itself.
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const promised = promisesFor(
            gpa,
            arena,
            io,
            self.started.paths.dir,
            self.options.parent_session,
            &session,
        ) catch &.{};

        // Why the broker refused, or could not decide. Released after the
        // answer is written, because a copy in it lives no longer than that.
        var broker_diag: ?chock_broker.Diagnostic = null;
        defer if (broker_diag) |*d| d.deinit(gpa);
        const outcome = broker.request(gpa, io, self.started.storage, locked, .{
            .action = ask.action,
            .summary = ask.summary,
            .detail = ask.detail,
            .reason = ask.reason,
            .agent_kind = self.options.agent_kind,
            .model_alias = self.started.model_alias,
            .tool = ask.tool,
            .tool_call_id = ask.tool_call_id,
            // The decision is the intersection over the whole chain, so a
            // subagent holds no permission its parent lacks.
            .spawn_chain = self.started.spawn_chain,
            .self_policy = promised,
            .timeout_ms = approvers.timeoutMs(),
        }, &broker_diag) catch |err| {
            // A cancelled wait, or a log that cannot be read. Neither is a
            // decision, and the safe reading of "no decision" is that the act
            // does not happen. The question stays open in the log, which is the
            // state a crash at the same moment leaves.
            //
            // The broker used to print its own reason and hand this loop an
            // error name, so a user saw a line from a library and then a
            // second line from Chock that said less.
            if (broker_diag) |*fault| {
                tty.print(
                    .warn,
                    "chock: the request for {s} could not be decided: {f}\n",
                    .{ ask.action, fault },
                );
                return .{ .permitted = false, .outcome = "the question could not be put to anybody" };
            }
            tty.print(
                .warn,
                "chock: the request for {s} could not be decided: {t}\n",
                .{ ask.action, err },
            );
            return .{ .permitted = false, .outcome = "the question could not be put to anybody" };
        };

        if (approvers.failed()) |err| {
            tty.print(
                .warn,
                "chock: the approval of {s} could not be shown or recorded: {t}\n",
                .{ ask.action, err },
            );
        }

        return .{
            .permitted = outcome.permits(),
            .outcome = @tagName(outcome),
            // **The one thing a reviewer's part of this says to the agent that
            // asked.** `requesterText` takes an outcome and nothing else, and a
            // comptime guard in that file keeps it that way, so a reviewer's
            // own words go to the log and never back to the requester.
            .review_text = if (outcome.reviewOutcome()) |review|
                chock_broker.review.requesterText(review)
            else
                "",
        };
    }
};

/// Carry the session's own commit back into the user's repository, through
/// the broker, after an approval.
///
/// **The worktree is thrown away at the end of the run**, so without this the
/// agent's work has no path back at all: Chock could read a project and
/// reason about one, and could not change one.
///
/// `lib/chock-broker/actions.zig` already holds the act itself,
/// `workspace.apply`, which moves exactly the objects the request listed and
/// then moves one ref with a compare and swap. Nothing here widens what the
/// sandbox can do: the act runs in this process, on the host, with the agent
/// already gone. That is the whole separation, and it is why this is wired
/// through the broker rather than given to the agent as a tool.
///
/// **A person at a terminal answers this one.** `Loop.run` holds the exclusive
/// lock on the session log for the whole session and this function takes it
/// again here, so nothing outside this process can append an
/// `approval.response`, and every question used to expire unasked.
/// `src/approval.zig` goes through that wall without touching the lock: it is
/// a `Broker.Waiter`, so it runs **inside** this process, and it appends the
/// answer through the same `locked` handle below. See its own top comment.
///
/// **A session with nobody at all still refuses at once.** A subagent and a
/// daemon session are spawned with `.stdin = .ignore`, and a pipe is not a
/// terminal either. Such a session can still be answered, by a client attached
/// to its approval socket, and `Approvers` is what gives the broker whichever
/// of the two this session has. With neither, the deadline has already passed:
/// an unanswered request is a refusal, and refusing at once is the honest thing
/// when nobody can be asked. The other way to say yes with nobody there is the
/// policy table in `chock.zon`, which is kept beyond the agent's reach: see
/// this file's own top comment.
fn applyWork(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
) !Applied {
    const tree = switch (started.workspace.kind) {
        .worktree => |wt| wt,
        // A project with no git of its own has no commit to carry across and no
        // ref to move.
        .overlay => return .nothing_to_apply,
    };

    const new_id = try tree.headMoved(gpa, io, env, null) orelse return uncommittedWork(gpa, io, env, tree);
    defer gpa.free(new_id);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ref = try applyRef(arena, started.session_id);
    const ctx = chock_broker.actions.Context{ .env = env };
    // What git said, and the one notice a description that succeeded can
    // still leave: a file in the scratch object store that is not an object
    // and therefore does not move. The broker used to print both itself.
    var describe_diag: ?chock_broker.Diagnostic = null;
    defer if (describe_diag) |*d| d.deinit(arena);
    const apply = chock_broker.actions.WorkspaceApply.describing(arena, io, ctx, .{
        .repository = tree.project_root,
        .scratch_object_store = tree.object_store_source,
        .ref = ref,
        .new_id = new_id,
    }, &describe_diag) catch |err| {
        if (describe_diag) |*fault| {
            tty.print(
                .err,
                "chock run: what the session's work would change could not be read: {f}\n",
                .{fault},
            );
        } else {
            tty.print(
                .err,
                "chock run: what the session's work would change could not be read: {s}\n",
                .{@errorName(err)},
            );
        }
        return .failed;
    };
    // Said out loud on a description that answered: a file the apply leaves
    // behind is work the user does not get, and silence about it looks the
    // same as an apply that carried everything.
    if (describe_diag) |*notice| tty.print(.warn, "chock run: {f}\n", .{notice});

    // **The session's own log, folded once, read by two things below.**
    // `Loop.run` has ended, so the `state.Session` it kept is gone and the log
    // is what is left. That is not a fallback: it is what makes both readers
    // right about a session that was resumed, or handed to the daemon, or
    // compacted a dozen times.
    var session = chock_proto.state.Session.init(gpa);
    defer session.deinit();
    foldSession(gpa, io, started.storage, &session);

    // The ratchet. Every promise this decision is bound by: the ones this
    // session made about itself, and the ones every session above it made. An
    // agent that said "I will not apply this work" while it was planning cannot
    // apply it now, whatever the policy table says, and it cannot have taken
    // the promise back: see `chock_policy.ratchet`, and
    // `chock_core.Loop.runRestrictSelf`, which is what refused every attempt
    // to.
    //
    // **The promise is read here and applied in the broker.** The session that
    // made it is over and this process is what asks on its behalf, so the
    // promise reaches the decision the same way the spawn chain does: as a
    // fact about the request, out of a record nothing can rewrite.
    const promised = try promisesFor(
        gpa,
        arena,
        io,
        started.paths.dir,
        options.parent_session,
        &session,
    );

    // A project whose `chock.zon` answers `agent_review` for `workspace.apply`
    // gets a reviewer here, and one that says anything else pays for nothing:
    // the broker asks for a review only where the folded decision asked for
    // one.
    //
    // **This is the one place in `chock run` where a review can happen at
    // all**, and it is the right one: `applyWork` runs after `Loop.run` has
    // ended, so the caller is single threaded again and a child process is
    // something this process can start. This is acceptance of changes, and this
    // is where a change is accepted.
    var review_child = reviewChild(gpa, environ, env, started, options);
    var review_spawner = reviewerFor(review_child.spawner(), started, &session);

    // Before the waiter, because the waiter holds this handle and answers
    // through it. One lock, taken once: see `src/approval.zig`.
    var locked = try started.storage.lock(io);
    defer locked.unlock(io) catch {};

    // The same handle, so a reviewer this approval starts is appended to the
    // log as a child and counted against the width bound. **This is why the
    // lock had to be taken before the reviewer could be recorded**: see
    // `ReviewSpawner.locked`.
    review_spawner.locked = &locked;

    var approvers: Approvers = undefined;
    // **Null, and that is not an oversight.** This runs in phase 3, and
    // `runSession`'s own `defer` took the display down at the end of phase 2:
    // the alternate screen is gone, raw mode is off, and the transcript is back
    // on the real screen. So there is no region to draw a question in and the
    // bare prompt is the right one. See `takeUp`, which relies on the same
    // ordering.
    approvers.init(gpa, io, started, &locked, null);

    const broker = chock_broker.Broker{
        .policy = started.policy,
        .waiter = approvers.waiter(),
        .reviewer = review_spawner.reviewer(),
        // The detail of this one is the commit itself, which is workspace bytes
        // and the likeliest place a credential sits. See `brokerRedaction`.
        .redaction = started.redact_values,
    };

    // Why the broker refused, or why the act itself failed. The broker used
    // to print that and hand this command an error name.
    var apply_diag: ?chock_broker.Diagnostic = null;
    defer if (apply_diag) |*d| d.deinit(gpa);
    var attempt = try chock_broker.actions.run(&broker, gpa, io, started.storage, &locked, ctx, .{
        .action = .{ .workspace_apply = apply },
        .reason = "the session made a commit, and the workspace it is in is about to be removed",
        .agent_kind = options.agent_kind,
        // The decision is the intersection over the whole chain, so a subagent
        // can hold no permission its parent lacks. The chain comes from the
        // command line the parent wrote, and this session cannot add to it.
        .spawn_chain = started.spawn_chain,
        .model_alias = started.model_alias,
        // The tool the agent would have called for this. `chock run` asks on
        // the session's behalf at the end, and the policy key still has to
        // name a tool: see `chock_broker.actions.self_asked_tool`, which a
        // reader of the log rebuilds the same key from.
        .tool = chock_broker.actions.self_asked_tool,
        .tool_call_id = "",
        // What this session promised about itself. Empty for a session that
        // promised nothing, which narrows nothing at all.
        .self_policy = promised,
        // See this function's own doc comment. A terminal waits for the person
        // at it, and so does a session somebody has attached a client to; a
        // session with neither refuses at once rather than holding the lock for
        // five minutes over a question that cannot be answered.
        .timeout_ms = approvers.timeoutMs(),
    }, &apply_diag);

    switch (attempt) {
        .refused => |outcome| {
            tty.print(
                .warn,
                "chock run: the session's commit {s} was not applied ({s}). " ++
                    "Your repository is unchanged.\n",
                .{ new_id, @tagName(outcome) },
            );
            // A reviewer took part, so the record holds a verdict and one line
            // of reasoning. Say where it is: an unread record is the same as
            // no oversight while looking like some, and a person who has just
            // been told "not applied" is exactly the person who wants it.
            if (outcome.reviewOutcome() != null) {
                tty.print(
                    .warn,
                    "chock run: a reviewer agent decided this. The verdict and its reason are in " ++
                        "the approval.response of {s}.\n",
                    .{started.paths.log},
                );
            }
            return .refused;
        },
        .done => |*done| {
            defer done.result.deinit(gpa);
            tty.print(
                .plain,
                "chock run: {d} objects and the ref {s} were applied to {s}.\n" ++
                    "chock run: read it with `git log {s}`, and take it with " ++
                    "`git merge {s}`.\n",
                .{
                    done.result.workspace_apply.objects_moved,
                    ref,
                    tree.project_root,
                    ref,
                    ref,
                },
            );
            return .landed;
        },
    }
}

/// What to answer when the worktree is still at the commit the session
/// started from. Either the agent changed nothing, or it changed files and
/// never committed them, and those are two different things to tell a user.
///
/// **The second case is new with the write tools.** An agent that could only
/// read and run programs left a clean worktree, so "the head did not move"
/// and "there is nothing here" were the same fact. An agent that can write
/// leaves files behind, and `git worktree remove`, a few lines further on,
/// deletes them. Saying nothing there is a run that exits 0 with the
/// project unchanged and the work gone, which is exactly what the first real
/// session with these tools did.
fn uncommittedWork(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    tree: chock_workspace.worktree.Worktree,
) Applied {
    const counts = chock_workspace.worktree.countUncommitted(gpa, io, env, tree.path, null) catch |err| {
        // A count that could not be read is not a reason to claim either
        // answer. Say which check did not happen, the same way
        // `handleUncommitted` does at the other end of the session.
        tty.print(
            .err,
            "chock run: the session made no commit, and the work left in {s} could not be counted: {s}\n",
            .{ tree.path, @errorName(err) },
        );
        return .nothing_to_apply;
    };
    if (!counts.any()) return .nothing_to_apply;

    tty.print(
        .warn,
        "chock run: the agent changed {d} files ({d} modified, {d} new) and made no commit, " ++
            "so there is nothing to carry back.\n" ++
            "chock run: only a commit reaches your project. Your repository is unchanged, and " ++
            "the work itself is kept: see the workspace named below.\n",
        .{ counts.total(), counts.modified, counts.untracked },
    );
    return .uncommitted;
}

/// Deal with the project's uncommitted work, before the session starts.
///
/// **`git worktree add` checks out the commit, not the working tree**, so an
/// agent in a fresh worktree sees `HEAD`. That behaviour stays the default,
/// because a known commit is reproducible. What was wrong was the silence: a
/// user was never told, and so believed the agent could see work it could
/// not. Chock's own repository is the case that exposed it, with three files
/// in `HEAD` and 83 uncommitted.
///
/// So: warn when the tree is dirty and name the flag, or, with the flag,
/// carry the work across and say how much came. **Only when the tree is
/// actually dirty**, or the message becomes noise people learn to skip.
///
/// The overlay kind of workspace copies the whole project directory,
/// uncommitted work included, so nothing there is invisible and nothing here
/// applies to it.
///
/// Returns how many files the agent will not see, which is zero in every case
/// where nothing is hidden: an overlay, a clean tree, a count that could not be
/// read, and `--allow-dirty`, which brings the work across. **The number goes
/// to the agent as well as to the user**: see
/// `chock_core.Loop.Deps.uncommitted_files`.
fn handleUncommitted(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    workspace: *const chock_workspace.Workspace,
    options: Options,
) StartError!usize {
    const tree = switch (workspace.kind) {
        .worktree => |wt| wt,
        .overlay => return 0,
    };

    if (!options.allow_dirty) {
        const counts = chock_workspace.worktree.countUncommitted(gpa, io, env, tree.project_root, null) catch |err| {
            // A count that could not be read is not a reason to refuse the
            // session: the session still runs correctly from the commit. Say
            // so rather than fail, and never stay silent about a check that
            // did not happen. **Zero, and not a guess**: an agent told a made
            // up number is worse off than one told nothing.
            tty.print(
                .warn,
                "chock run: the uncommitted work in {s} could not be counted: {s}. " ++
                    "The agent sees the committed state.\n",
                .{ tree.project_root, @errorName(err) },
            );
            return 0;
        };
        if (!counts.any()) return 0;
        const text = try dirtyWarning(gpa, counts);
        defer gpa.free(text);
        // **The one startup line that is worth interrupting for.** It changes
        // what the agent can see, so it is ranked as a warning and it is the
        // only coloured thing on a healthy start.
        tty.print(.warn, "{s}", .{text});
        return counts.total();
    }

    var import_diag: ?chock_workspace.Diagnostic = null;
    var report = tree.importUncommitted(gpa, io, env, &import_diag) catch |err| {
        // Which call failed and what it answered, which the error name alone
        // does not carry.
        if (import_diag) |*fault| {
            tty.print(
                .err,
                "chock run: the uncommitted work in {s} could not be copied in: {f}\n",
                .{ tree.project_root, fault },
            );
            return error.Reported;
        }
        tty.print(
            .err,
            "chock run: the uncommitted work in {s} could not be copied in: {s}\n",
            .{ tree.project_root, @errorName(err) },
        );
        return error.Reported;
    };
    defer report.deinit(gpa);

    if (report.total() == 0 and report.skipped.items.len == 0) {
        tty.print(.plain, "chock run: there was no uncommitted work to bring across.\n", .{});
        return 0;
    }
    const text = try importSentence(gpa, report);
    defer gpa.free(text);
    tty.print(.plain, "{s}", .{text});
    // A skip the user cannot see is the same silence this whole function
    // exists to end. See `ImportReport.skipped`.
    for (report.skipped.items) |skip| {
        tty.print(.warn, "chock run: {s} was not brought across: {s}\n", .{ skip.path, skip.reason });
    }
    // The work is in the workspace now, so nothing is hidden from the agent
    // and there is nothing to tell it about.
    return 0;
}

/// What a user is told about work the agent will not see. Its own function,
/// not a `tty.print` inside `handleUncommitted`, so a test can pin the
/// sentence: the count, the split, and the name of the flag that changes it
/// are the three things a user acts on, and a message that gets any of them
/// wrong sends somebody looking for files that are not there.
fn dirtyWarning(
    gpa: std.mem.Allocator,
    counts: chock_workspace.worktree.Uncommitted,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "chock run: {d} uncommitted files will not be visible to the agent\n" ++
            "           ({d} modified, {d} untracked). Pass --allow-dirty to include them.\n",
        .{ counts.total(), counts.modified, counts.untracked },
    );
}

/// What a user is told after `--allow-dirty` carried the work across. The
/// same three facts as `dirtyWarning`, from the other side: the two paths
/// give a user the same kind of statement rather than one warning and one
/// silence.
fn importSentence(
    gpa: std.mem.Allocator,
    report: chock_workspace.worktree.ImportReport,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "chock run: {d} files brought across from your working tree " ++
            "({d} modified, {d} new, {d} removed).\n",
        .{
            report.total(),
            report.modified.items.len,
            report.added.items.len,
            report.deleted.items.len,
        },
    );
}

/// Say once, at the start, that a cap cannot be enforced on this session, and
/// name the provider and the model. Decided by the project owner: **Chock does
/// not refuse the session over this.** The user chose the provider and may have
/// good reasons, and a harness that blocks work to protect a number it cannot
/// measure is worse than one that is honest about what it cannot see.
///
/// At the start, and not at the turn where the cap would have bitten: a user
/// who set a cap and heard nothing would fairly assume it was working. A free
/// provider is measurable, so this never fires for a local model.
fn warnUnmeasurableBudget(
    budget: ?chock_cost.budget.Budget,
    billing: chock_cost.prices.Billing,
    provider_name: []const u8,
    model: []const u8,
) void {
    const cap = budget orelse return;
    if (billing == .free) return;
    if (chock_cost.prices.lookup(model) != null) return;
    tty.print(
        .warn,
        "chock: the budget of {d:.2} {s} cannot be enforced: no price is known for model {s} " ++
            "on provider {s}, and an unknown cost is not a zero. The session runs anyway.\n",
        .{ cap.max_cost, cap.currency, model, provider_name },
    );
}

/// A `ToolRunner` that reads a `run_command` call for a git command line
/// before it runs, and answers the subcommands that cannot work inside the
/// sandbox at all itself. Everything else goes straight through to `inner`,
/// unchanged.
///
/// **This is the git shim, wired in where a tool call actually happens.**
/// `lib/chock-broker/git_shim.zig` says at length what it is and what it is
/// not: it prevents a mistake, it is not a boundary, and nothing here treats it
/// as one. The capability layers are what stop an attack, and they stop the
/// same things whether this runner is in the way or not.
///
/// **Only the subcommands that reach another host are answered here, and the
/// approval half of the shim is not wired.** Two reasons, and neither is a
/// plan to leave it:
///
/// * `ToolRunner.dispatch` is handed no lock on the session log, and
///   `Broker.request` needs one to append the `approval.request` and read the
///   answer back. `Loop.run` holds that lock for the whole session: see
///   `applyWork`, which takes it again only after `run` has returned.
/// * Nobody can answer a question `chock run` asks while that lock is held, so
///   an approval here would be a refusal. That would refuse `git commit`, and a
///   commit in the workspace is the only way a session's work reaches the user
///   at all, through the `workspace.apply` `applyWork` asks about at the end.
///
/// A subcommand that reaches a host has neither problem: it fails inside the
/// sandbox whatever anybody answers, so there is nothing to ask about and
/// only something to say. See `chock_broker.git_shim.needs_network`.
const GitToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,

    fn runner(self: *GitToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *GitToolRunner = @ptrCast(@alignCast(ptr));
        if (try gitRefusal(gpa, call)) |output| {
            // The same shape an ordinary refused tool call already has: an
            // `is_error` result the model reads and answers, never an error
            // that ends the session. See `chock_core.Loop.runTool`.
            return .{
                .call_id = try gpa.dupe(u8, call.call_id),
                .output = output,
                .is_error = true,
                .truncated = false,
            };
        }
        return self.inner.dispatch(gpa, io, call);
    }
};

/// What the agent is told instead of running `call`, or null when this call
/// reaches the real git the way it always did. Owned by the caller.
///
/// A call this cannot read at all reads as "not a git call": the argument
/// vector is `run_command`'s own to check, and `chock_core.tools` already says
/// what is wrong with one it cannot parse. Two readers of the same arguments
/// giving two different complaints is worse than one.
fn gitRefusal(gpa: std.mem.Allocator, call: chock_proto.event.ToolCall) std.mem.Allocator.Error!?[]u8 {
    if (!std.mem.eql(u8, call.tool, "run_command")) return null;

    const Args = struct { argv: []const []const u8 };
    const parsed = std.json.parseFromSlice(Args, gpa, call.arguments, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();

    const argv = parsed.value.argv;
    if (argv.len == 0) return null;
    // `argv[0]` is a bare program name resolved on the PATH, and
    // `chock_core.tools` refuses any spelling with a slash in it before this
    // runner is reached, so there is one spelling of git to match here.
    if (!std.mem.eql(u8, argv[0], "git")) return null;

    const ask = switch (chock_broker.git_shim.classify(argv)) {
        .run_the_real_git => return null,
        .ask => |a| a,
    };
    if (!chock_broker.git_shim.needsNetwork(ask.subcommand)) return null;
    return try chock_broker.git_shim.networkRefusal(gpa, ask.subcommand);
}

/// A `ToolRunner` that asks the language server about a file the agent just
/// wrote, and appends what it said to that call's own result. Everything else
/// goes straight through to `inner`, unchanged and untouched.
///
/// **This is the diagnostics half of the language server, wired in where a tool
/// call actually happens**, and `lib/chock-core/lsp.zig` holds every decision
/// behind it: where the server runs, why the agent cannot drive it, how much
/// reaches the model, and what a session with no server costs.
///
/// ## Why here and not inside the registry
///
/// Same reason as `ProvisionToolRunner` next door, one step further along the
/// same argument. `chock_core.tools.Registry` runs one tool call inside a
/// sandbox and knows nothing that outlives one call, and a language server is
/// long lived and stateful by definition: it indexes a project once and answers
/// from that index for the rest of the session. So the thing that holds it is
/// the caller that owns the session, and the registry never hears about it.
///
/// ## What decides whether the seam is reached at all
///
/// **`session.server` is null unless this project's own `chock.zon` names a
/// language server**, and null is the ordinary case. This runner is still
/// reached on every write, answers null before it touches a seam, and hands
/// the tool result back byte for byte as the tool built it: no process starts,
/// nothing waits, and nothing is added to the context. `runSession` fills the
/// three fields in from `chock_core.lsp_driver.Settings` when a project has
/// one, and leaves every one of them at its default when it has not.
///
/// The wiring is also where the argument about **when** diagnostics are
/// collected lives: after the write, before the model's next turn, on the
/// result of the call that made the change.
const DiagnosticToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    /// The session's own language server, and what it has already said. Not
    /// owned: the caller keeps it alive for as long as this value is in use,
    /// the same borrowing every other runner here already asks for.
    session: *chock_core.lsp.Session,

    fn runner(self: *DiagnosticToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *DiagnosticToolRunner = @ptrCast(@alignCast(ptr));
        const result = try self.inner.dispatch(gpa, io, call);

        // **A call that failed wrote nothing**, so there is nothing new to say
        // about the file and the refusal it already carries is the whole
        // answer. Checked before the path is even read, so a failed write costs
        // exactly what it cost before this runner existed.
        if (result.is_error) return result;

        // A result this function does not hand back is a result nobody frees.
        // `chock_core.Loop.runTool` owns exactly these two fields, and it never
        // sees one this runner gave up on part way through.
        errdefer {
            gpa.free(result.call_id);
            gpa.free(result.output);
        }

        const path = (try chock_core.tools.writtenPathIn(gpa, call.tool, call.arguments)) orelse
            return result;
        defer gpa.free(path);

        const block = (try self.session.afterWrite(gpa, io, path)) orelse return result;
        defer gpa.free(block);

        // The one allocation this runner makes to the result. `output` came
        // from this same `gpa`, through every runner below: see
        // `chock_core.Loop.runTool`, which frees exactly these two fields.
        const joined = try std.mem.concat(gpa, u8, &.{ result.output, block });
        gpa.free(result.output);

        var with_diagnostics = result;
        with_diagnostics.output = joined;
        return with_diagnostics;
    }
};

/// Answers a call to a tool an MCP server supplies, and passes every other
/// call straight through to `inner`, unchanged and untouched.
///
/// **Outside every runner that reads a tool name and acts on it**, so a name a
/// third party program chose never reaches the sandbox runner, the git shim or
/// the provisioner. None of those has any reason to see a name Chock does not
/// own. `PluginToolRunner` is one layer further out still, for the same reason
/// and with the same shape, and the two lists cannot collide: see
/// `reservedNames`.
///
/// ## Why a wrapper and not a tool of the registry
///
/// The same reason `DiagnosticToolRunner` next door gives, one step further
/// along. `chock_core.tools.Registry` runs one tool call inside one sandbox
/// and knows nothing that outlives one call. An MCP server is a process that
/// lives as long as the session and holds state, so the thing that holds it is
/// the caller that owns the session, and the registry never hears about it.
///
/// ## A session with no MCP server passes every call through, and that is the
/// whole of what it costs
///
/// `chock_core.mcp.Session.dispatch` answers null for a name no server
/// declared, which every call of such a session is, and null costs one walk of
/// an empty list. See `startMcp`, which builds the empty session for a project
/// that named none.
const McpToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    /// The session's own MCP servers. Not owned: the caller keeps them alive
    /// for as long as this value is in use, the same borrowing every other
    /// runner here already asks for.
    state: *McpState,
    /// Whether a server has already been reported as having changed its tool
    /// list. **Said once**, the rule `chock_core.lsp.Session` keeps for a
    /// server that stopped answering.
    said_changed: bool = false,

    fn runner(self: *McpToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *McpToolRunner = @ptrCast(@alignCast(ptr));

        const outcome = (try self.state.session.dispatch(gpa, io, call.tool, call.arguments)) orelse
            return self.inner.dispatch(gpa, io, call);

        // A server may have said its tools changed while that call was being
        // answered. **Read here and never acted on**: see `startMcp`, and see
        // `lib/chock-core/mcp.zig` on the ratchet.
        self.noteWidening();

        // `chock_core.Loop.runTool` owns exactly `call_id` and `output` and
        // frees both, the same contract every other runner here answers under.
        errdefer gpa.free(outcome.text);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = outcome.text,
            .is_error = outcome.is_error,
            // The cut, when there was one, is already marked inside the text:
            // see `chock_core.mcp.textForModel`. This field says a result was
            // cut short **before it reached the event**, which is a different
            // fact and not this one.
            .truncated = false,
        };
    }

    /// Say, one time, that a server proposed a widening this session cannot
    /// take.
    ///
    /// **A person needs this line and the agent must not.** A project owner
    /// whose server gained a tool has to know why the agent cannot see it, and
    /// telling the agent instead would name a tool it can never call.
    fn noteWidening(self: *McpToolRunner) void {
        if (self.said_changed) return;
        var index: usize = 0;
        while (index < self.state.count) : (index += 1) {
            if (self.state.drivers[index].protocol.list_changed == 0) continue;
            self.said_changed = true;
            tty.print(
                .warn,
                "chock: the MCP server {s} says its tools have changed. This session keeps the " ++
                    "list it started with: a tool that appears now would widen what the agent " ++
                    "may do, and nothing can authorise that while a turn is running.\n",
                .{self.state.records[index].name},
            );
            return;
        }
    }
};

/// Everything this session's MCP servers need to stay alive, in one value the
/// caller owns.
///
/// **The arrays are fixed and never reallocated.** A `chock_core.mcp.Server`
/// points at the driver beside it, and that driver points at the helper beside
/// it, so a list that grew would move both out from under the pointers.
/// `chock_core.mcp.max_servers` is what `chock_core.mcp.parse` already
/// refuses above, so a project cannot ask for more than there is room for.
const McpState = struct {
    /// Every offer, and the decision taken about it once, at the start.
    session: chock_core.mcp.Session,
    /// Where the mount trees, the argv, the tool list and the second system
    /// prompt live. They outlive every tool call and end with the session, the
    /// same reason `provision_arena` next door has one of its own.
    arena: std.heap.ArenaAllocator,

    helpers: [chock_core.mcp.max_servers]chock_core.helper.Helper = undefined,
    drivers: [chock_core.mcp.max_servers]chock_core.mcp_driver.Driver = undefined,
    /// One network broker per server, for the servers this project's policy
    /// let out. See `chock_broker.network.Network`, which decides each
    /// connection, and `startMcp`, which is the caller it was built for.
    networks: [chock_core.mcp.max_servers]chock_broker.network.Network = undefined,
    transports: [chock_core.mcp.max_servers]chock_broker.network.System = undefined,
    records: [chock_core.mcp.max_servers]chock_core.mcp.Server = undefined,
    /// How many of the arrays above are built. **Only these are touched by
    /// `deinit`**, because the rest are `undefined`.
    count: usize = 0,

    fn init(gpa: std.mem.Allocator) McpState {
        return .{ .session = .init(gpa), .arena = .init(gpa) };
    }

    /// **Ends every server, then waits for it.** A helper writes below the
    /// session scratchpad that phase 3 is about to remove, the same hazard the
    /// task table and the language server already wait for: see
    /// `chock_core.helper.Helper.deinit`.
    fn deinit(self: *McpState, io: std.Io) void {
        // **The allocator the brokers were given.** `init` builds the arena on
        // it, so this is the same one, and a network diagnostic is freed with
        // the allocator that filled it.
        const gpa = self.arena.child_allocator;

        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            self.helpers[index].deinit(io);
            self.drivers[index].deinit();

            // **A refused connection has no other moment to be read.** The
            // network broker answers from inside `Sandbox.spawn`, with the
            // session's own loop waiting on that call, so nothing can print
            // when it happens: see `chock_broker.network.Network.diagnostic`,
            // which is the only place a reason goes. Saying nothing here would
            // leave a project owner with a server that quietly reaches nothing
            // and no way to find out which rule is missing.
            const network = &self.networks[index];
            if (network.refused != 0) {
                tty.print(
                    .warn,
                    "chock: the MCP server {s} was refused {d} of {d} connections it asked for.\n",
                    .{ self.records[index].name, network.refused, network.refused + network.granted },
                );
            }
            if (network.diagnostic) |*one| {
                tty.print(.warn, "chock: the first was {f}\n", .{one});
                one.deinit(gpa);
            }
        }
        self.session.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

/// What this project's policy says about one action a third party supplies,
/// folded over the whole spawn chain.
///
/// The same shape and the same reasoning as `provisionDecision` above, through
/// `chock_policy.table.evaluateChain`, which is the one function that applies
/// it. **`chock-core` evaluates no policy table**, which is why this lives here
/// and reaches the library through `chock_core.mcp.Decider`.
///
/// **One of these answers for MCP and for plugins alike.**
/// `chock_core.plugin.Decider` *is* `chock_core.mcp.Decider`, on purpose: the
/// question a policy table answers does not change with who asked it, and a
/// second shape of the same thing would be a second thing to keep in step.
const TablePolicy = struct {
    policy: *const chock_policy.table.Table,
    /// Every agent kind from the root of the spawn tree down to this session,
    /// root first. Built once, because it is the same for every question.
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,

    fn decider(self: *TablePolicy) chock_core.mcp.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.mcp.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        const self: *TablePolicy = @ptrCast(@alignCast(ptr));
        return self.answer(tool, action);
    }

    /// Answer one question. Its own function, taking ordinary values, so
    /// `startMcp` can ask about a server's network without going through a
    /// vtable for it.
    fn answer(
        self: *TablePolicy,
        tool: []const u8,
        action: []const u8,
    ) chock_policy.table.Decision {
        // A chain the policy reader cannot fold answers `ask`, which is
        // already the safe answer. Said out loud because a chain this shape
        // means the log holds something Chock did not write.
        var fault: ?chock_policy.table.ChainFault = null;
        const decision = self.policy.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = tool,
            .action = action,
        }, &fault);
        if (fault) |f| tty.print(.warn, "chock run: {f}\n", .{f});
        return decision;
    }
};

/// Reads a URL for the agent, and is what makes `fetch_url` a tool that does
/// something rather than one that says it cannot.
///
/// **The decision is not here.** `chock_broker.fetch.Session` holds it: which
/// host a policy row permits, which redirect hop may be followed, and what a
/// site's own `robots.txt` says. This is the join between that and
/// `chock_core.fetch.Fetcher`, which is the seam the loop holds because
/// `chock-core` reads no policy table.
///
/// ## Why the loop calls this and not a tool runner
///
/// A promise binds a fetch, and the promises of a session live in the fold of
/// its log. See `chock_core.Loop.runFetch`, and `chock_core.fetch`'s own top
/// comment.
///
/// ## The promises of the sessions above this one are read once
///
/// **A promise a parent made has to reach its children, or it is worth
/// nothing**, which is the whole argument `promisesFor` makes. They are read at
/// session start rather than per call, and that is exact rather than a saving:
/// a parent is blocked inside its own `spawn_agent` call for the whole life of
/// a child, so it can make no new promise while this session runs. This
/// session's own promises are not read here at all. They arrive on every call
/// from the loop's own fold, which is the only reading that is current in the
/// middle of a turn.
///
/// ## The robots cache belongs to the session
///
/// One `robots.txt` per site per session, so reading five pages of one manual
/// costs six requests and not ten. `chock_broker.fetch.Robots` is where it
/// lives, and this value is what keeps it alive.
const SessionFetcher = struct {
    gpa: std.mem.Allocator,
    /// The decision and the hop loop. Owned here, because the `robots.txt`
    /// cache inside it lasts the session.
    session: chock_broker.fetch.Session,
    /// Every promise the sessions above this one made, in an arena that
    /// outlives the session. Empty for a session a person started.
    ancestors: []const chock_policy.ratchet.Restriction = &.{},

    fn deinit(self: *SessionFetcher) void {
        self.session.deinit();
    }

    fn fetcher(self: *SessionFetcher) chock_core.fetch.Fetcher {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.fetch.Fetcher.VTable{ .fetch = fetchFn };

    fn fetchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        ask: chock_core.fetch.Ask,
    ) chock_core.fetch.Error!chock_core.fetch.Answer {
        const self: *SessionFetcher = @ptrCast(@alignCast(ptr));

        // The tool the agent called is one of the four parts of a policy key,
        // and it comes from the call rather than from a constant here, so a
        // rule that names a tool means the tool that really asked.
        self.session.tool = ask.tool;

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // This session's own promises, which the loop folded a moment ago, and
        // the ones every session above it made. Both are ceilings, so the order
        // they are in changes nothing.
        var promised: std.ArrayList(chock_policy.ratchet.Restriction) = .empty;
        try promised.appendSlice(arena, ask.self_policy);
        try promised.appendSlice(arena, self.ancestors);

        // Why a page was not read, for the person watching. The agent is told
        // by `Outcome.refused`, which is a different sentence for a different
        // reader: see `lib/chock-broker/fetch.zig`.
        var diag: ?chock_broker.Diagnostic = null;
        defer if (diag) |*one| one.deinit(self.gpa);

        var outcome = try self.session.fetch(io, .{
            .url = ask.url,
            .self_policy = promised.items,
        }, &diag);
        defer outcome.deinit(self.gpa);

        // **It travels on the result and not to standard error.** It used to
        // be printed here, which put it on a second stream, out of order with
        // the result it explains, and out of the log, so a replay lost it. See
        // `chock_proto.event.ToolResult.note`.
        const note: []u8 = if (diag) |*one|
            try std.fmt.allocPrint(gpa, "{f}", .{one})
        else
            &.{};
        errdefer if (note.len != 0) gpa.free(note);

        return switch (outcome) {
            .refused => |refusal| .{
                .text = try gpa.dupe(u8, refusal.text),
                .is_error = true,
                .note = note,
            },
            .fetched => |page| .{
                .text = try chock_core.fetch.textForModel(gpa, page.url, page.status, page.body),
                .is_error = false,
                .note = note,
            },
        };
    }
};

/// Start this project's MCP servers, ask each one what tools it has, and
/// answer the tool list and the system prompt the session runs with.
///
/// **A project that named no server returns before it does anything**, with
/// the list and the prompt phase 1 already built, unchanged. That is the first
/// rule of `lib/chock-core/mcp.zig` and it is the cheap path, not the
/// exceptional one.
///
/// ## The network is a rule and never a flag
///
/// A server keeps `Sandbox.Config.network` at `none`, which is what a tool
/// call and a language server get and is strictly safer. A server reaches the
/// network only when this project's policy answers `allow` for
/// `mcp.<server>.network`, and even then it reaches nothing until a
/// `net.connect.*` rule names a host: `lib/chock-broker/network.zig` answers
/// every connection against the same table, per connection, for the whole
/// session.
///
/// ## Nothing here fails the session
///
/// A server that could not be prepared, would not start, or was too slow to
/// list its tools is reported once and dropped, and the session runs on with
/// whatever it did get. A fault in a third party program must never end a
/// session that is doing real work, which is the rule
/// `chock_nix.provision.resolve` and `chock_core.lsp` already follow.
/// The spawn chain `chock_policy.table.evaluateChain` wants: the parents and
/// this session, in that order.
///
/// The same shape `provisionDecision` builds, and for the same reason: a
/// session cannot state its own parents. **One function, because two callers
/// need it** and a chain built one link short is a session folding its parent's
/// kind and not its grandparent's.
fn policyChain(
    keep: std.mem.Allocator,
    started: *const Started,
    options: Options,
) std.mem.Allocator.Error![]const []const u8 {
    const chain = try keep.alloc([]const u8, started.spawn_chain.len + 1);
    for (started.spawn_chain, chain[0..started.spawn_chain.len]) |link, *slot| {
        slot.* = link.agent_kind;
    }
    chain[started.spawn_chain.len] = options.agent_kind;
    return chain;
}

fn startMcp(
    gpa: std.mem.Allocator,
    io: std.Io,
    started: *Started,
    options: Options,
    context: *const chock_core.tools.Context,
    state: *McpState,
) std.mem.Allocator.Error!struct { []chock_core.tools.Definition, []const u8 } {
    const settings = started.mcp_servers orelse
        return .{ started.tool_definitions, started.system_prompt };

    const keep = state.arena.allocator();

    const chain = try policyChain(keep, started, options);
    var policy = TablePolicy{
        .policy = started.policy,
        .chain = chain,
        .agent_kind = options.agent_kind,
        .model = started.model,
    };

    for (settings) |one| {
        std.debug.assert(state.count < chock_core.mcp.max_servers);

        // **The same sandbox a tool call gets**, built by the same two
        // functions `chock_core.tools.Registry.dispatchWith` uses, so a server
        // reaches nothing a tool call cannot.
        const prepared = blk: {
            const with_store = chock_core.tools.withStore(
                keep,
                io,
                started.sandbox_config,
                context.store_paths,
                context.toolchain_mounts,
            ) catch break :blk null;
            break :blk chock_core.tools.prepare(
                keep,
                io,
                started.tool_env,
                with_store,
                one.command,
                &.{},
                &.{},
            ) catch |err| {
                tty.print(
                    .warn,
                    "chock: the MCP server {s} ({s}) could not be prepared ({t}), so its tools " ++
                        "are not in this session.\n",
                    .{ one.name, one.command[0], err },
                );
                break :blk null;
            };
        } orelse continue;

        var config = prepared.config;
        const index = state.count;

        // Built for every server, whether it is let out or not, so `deinit`
        // never reads one that was left `undefined`. Attaching it to the
        // config is what gives a server a channel, and that is the line
        // below.
        state.transports[index] = .{};
        state.networks[index] = .{
            .gpa = gpa,
            .io = io,
            .table = started.policy,
            .chain = chain,
            .agent_kind = options.agent_kind,
            .model = started.model,
            // **The server's own name, and not one of its tools.** The socket
            // belongs to the process, which outlives every call through it, so
            // the tool part of a `net.connect` key names the server a rule is
            // about.
            .tool = one.name,
            .transport = state.transports[index].transport(),
        };

        // **`Network.none` unless a rule says otherwise.** See this function's
        // own doc comment: a flag would be a second policy system, and a
        // default of `filtered` would hand a third party program the one thing
        // the sandbox exists to withhold.
        var buffer: [chock_core.mcp.max_action_bytes]u8 = undefined;
        const net_action = chock_core.mcp.networkActionInto(&buffer, one.name).?;
        if (policy.answer(one.name, net_action) == .allow) {
            config.network = .filtered;
            config.net_broker = state.networks[index].netBroker();
            tty.detail(
                "chock: the MCP server {s} may reach the hosts this project's net.connect rules name\n",
                .{one.name},
            );
        }

        // **The page allocator, and never `gpa`.** The helper's own thread is
        // inside `Sandbox.spawn` while this session's threads allocate, and
        // `fork` carries only the calling thread: see
        // `chock_core.helper.Helper.arena`.
        state.helpers[index] = chock_core.helper.Helper.init(std.heap.page_allocator);
        state.drivers[index] = chock_core.mcp_driver.Driver.init(
            gpa,
            &state.helpers[index],
            .{ .config = config, .argv = prepared.argv },
        );
        state.records[index] = .{ .name = one.name, .host = state.drivers[index].host() };
        state.count += 1;
    }

    state.session.servers = state.records[0..state.count];

    // **One round trip per server, before any work, and it is bounded.** A
    // server that is slow to answer delays the start of every session that
    // names it, so it is dropped rather than waited on: see
    // `chock_core.mcp.discovery_budget_ns`.
    var discovery = std.heap.ArenaAllocator.init(gpa);
    defer discovery.deinit();

    for (state.session.servers) |*server| {
        const declared = server.host.list(
            discovery.allocator(),
            io,
            chock_core.mcp.discovery_budget_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Late, error.Gone => {
                server.failure = if (err == error.Late)
                    chock_core.mcp.discovery_late
                else
                    chock_core.mcp.start_failed;
                tty.print(
                    .warn,
                    "chock: the MCP server {s}: {s}\n",
                    .{ server.name, server.failure.? },
                );
                continue;
            },
        };
        try state.session.admit(server, declared, policy.decider());
        if (server.failure) |reason| {
            // The one refusal that takes a whole server with it, and the
            // reason a person most needs to hear: a server that tried to take
            // the name of one of Chock's own tools.
            tty.print(.warn, "chock: the MCP server {s}: {s}\n", .{ server.name, reason });
        }
    }

    reportMcpOffers(&state.session);

    // The built-in list first, in the order the enum gives, and the MCP tools
    // after it. The same slice fills `Request.tools` and the prompt's own tool
    // list, so the model never hears a name it cannot call.
    var list: std.ArrayList(chock_core.tools.Definition) = .empty;
    try list.appendSlice(keep, started.tool_definitions);
    try state.session.appendDefinitions(keep, &list);
    const definitions = try list.toOwnedSlice(keep);

    const prompt = try chock_core.prompt.build(
        keep,
        started.prompt_project,
        definitions,
        started.prompt_sources,
    );
    return .{ definitions, prompt };
}

/// Say what the MCP servers gave this session, and what was turned away.
///
/// **A tool the model can call is a fact a person should see**, because it is
/// a program nobody here wrote acting inside their session. A tool that was
/// refused is worth a line too: a project that wrote a rule and still has no
/// tool needs to know which of the two went wrong.
fn reportMcpOffers(session: *const chock_core.mcp.Session) void {
    if (session.isEmpty()) return;

    var offered: usize = 0;
    for (session.offers.items) |offer| {
        if (offer.refused == null) offered += 1;
    }
    tty.detail("chock: {d} MCP tools in this session\n", .{offered});

    for (session.offers.items) |offer| {
        const reason = offer.refused orelse continue;
        tty.detail(
            "chock: the MCP tool {s} of {s} is not offered, because {s}\n",
            .{ offer.name, offer.server, reason.text() },
        );
    }
}

// A plugin is the second third party that supplies tools, and everything below
// is the shape MCP already has one file up: the same runner, in the same place
// in the chain, over the same `Decider`. What is different is stated where it
// is different, and there are only two things:
//
// * **There is no discovery round trip.** A plugin's tool list is read out of
//   its own module file with no engine at all, so a plugin that is never called
//   starts no process: see `chock_core.plugin_module`.
// * **The host process runs guest code**, and a wasm guest owns the address
//   space of the process that runs it in the engine this project has. So the
//   sandbox it gets is built by taking things away, and `plugin_host.lockdown`
//   is that: see `startPlugins`.

/// Where the plugin host program's module is bound inside its own sandbox.
///
/// **A fixed path and not the project's own.** The module is the only file this
/// process opens by name, and a fixed target means the path a plugin host reads
/// says nothing about where the person keeps their work.
const plugin_module_target = "/plugin.wasm";

/// Where `chock` itself is bound inside a plugin host process's own sandbox.
///
/// **The program one plugin runs inside is this program**, started under
/// `chock_core.plugin_host.verb`. There is no second program to find, which is
/// what makes a plugin survive an install that copies one file: see that
/// declaration for the whole argument.
const plugin_host_target = "/chock";

/// Answers a call to a tool a plugin supplies, and passes every other call
/// straight through to `inner`, unchanged and untouched.
///
/// **The same shape and the same position as `McpToolRunner`**, which is the
/// point: a tool a third party supplies is a tool a third party supplies, and a
/// second shape of the same wrapper would be a second thing to keep in step.
/// This one is outside the MCP runner, so a name a plugin declared reaches
/// nothing else at all.
///
/// **The order of the two is not what keeps them apart.** No plugin tool can
/// take a name an MCP server already declared: `startPlugins` fills
/// `chock_core.plugin.Session.reserved` with what MCP got first, and a plugin
/// tool of that name is refused with a reason the model reads. So the two lists
/// are disjoint before either runner sees a call.
///
/// ## A session with no plugin passes every call through
///
/// `chock_core.plugin.Session.dispatch` answers null for a name no plugin
/// declared, which every call of such a session is, and null costs one walk of
/// an empty list. See `startPlugins`, which builds the empty session for a
/// project that named none.
const PluginToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    /// The session's own plugins. Not owned: the caller keeps them alive for as
    /// long as this value is in use, the same borrowing every other runner here
    /// already asks for.
    state: *PluginState,

    fn runner(self: *PluginToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *PluginToolRunner = @ptrCast(@alignCast(ptr));

        const outcome = (try self.state.session.dispatch(gpa, io, call.tool, call.arguments)) orelse
            return self.inner.dispatch(gpa, io, call);

        // `chock_core.Loop.runTool` owns exactly `call_id` and `output` and
        // frees both, the same contract every other runner here answers under.
        errdefer gpa.free(outcome.text);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = outcome.text,
            .is_error = outcome.is_error,
            // The cut, when there was one, is already marked inside the text:
            // see `chock_core.mcp.textForModel`, which a plugin result goes
            // through as well. This field says a result was cut short **before
            // it reached the event**, which is a different fact and not this
            // one.
            .truncated = false,
        };
    }
};

/// Everything this session's plugins need to stay alive, in one value the
/// caller owns.
///
/// **The arrays are fixed and never reallocated**, for the reason `McpState`
/// gives: a `chock_core.plugin.Loaded` points at the driver beside it, and that
/// driver points at the helper beside it, so a list that grew would move both
/// out from under the pointers. `chock_core.plugin.max_plugins` is what
/// `chock_core.plugin.parse` already refuses above, so a project cannot ask for
/// more than there is room for.
const PluginState = struct {
    /// Every offer, and the decision taken about it once, at the start.
    session: chock_core.plugin.Session,
    /// Where the mount trees, the argv, the tool list and the second system
    /// prompt live. They outlive every tool call and end with the session.
    arena: std.heap.ArenaAllocator,

    helpers: [chock_core.plugin.max_plugins]chock_core.helper.Helper = undefined,
    drivers: [chock_core.plugin.max_plugins]chock_core.plugin_host.Driver = undefined,
    records: [chock_core.plugin.max_plugins]chock_core.plugin.Loaded = undefined,
    /// How many of the arrays above are built. **Only these are touched by
    /// `deinit`**, because the rest are `undefined`.
    count: usize = 0,

    fn init(gpa: std.mem.Allocator) PluginState {
        return .{ .session = .init(gpa), .arena = .init(gpa) };
    }

    /// **Ends every host process, then waits for it.** The same rule `McpState`
    /// keeps, for the same reason: a helper writes below the session scratchpad
    /// that phase 3 is about to remove.
    fn deinit(self: *PluginState, io: std.Io) void {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            self.helpers[index].deinit(io);
            self.drivers[index].deinit();
        }
        self.session.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Read this project's plugins, decide about every tool they declare, and
/// answer the tool list and the system prompt the session runs with.
///
/// **A project that named no plugin returns before it does anything**, with the
/// list and the prompt it was given, unchanged. That is the first rule of
/// `lib/chock-core/plugin.zig`, and it is the cheap path and not the
/// exceptional one.
///
/// `definitions` and `prompt` are what the session has so far, which is phase
/// 1's own pair for a project with no MCP server and `startMcp`'s answer for a
/// project with one. **Plugins come last**, so an MCP server that is already in
/// the session keeps every name it declared: see `reservedNames`.
///
/// ## Nothing here starts a process
///
/// A plugin's tool list, the capabilities each tool declares and the policy
/// decision about each one are all read out of the module's own file, before
/// one byte of guest code has run. `chock_core.plugin_host.Driver` starts the
/// host process on the **first call** of a tool, so a project that names a
/// plugin and never uses it pays for a file read and nothing else.
///
/// ## Nothing here fails the session
///
/// A plugin whose module could not be read, whose name the policy key language
/// refuses, or whose tools the policy denies is reported once and dropped, and
/// the session runs on with whatever it did get. The rule
/// `chock_nix.provision.resolve`, `chock_core.lsp` and `startMcp` already
/// follow.
fn startPlugins(
    gpa: std.mem.Allocator,
    io: std.Io,
    started: *Started,
    options: Options,
    context: *const chock_core.tools.Context,
    state: *PluginState,
    mcp_session: *const chock_core.mcp.Session,
    definitions: []chock_core.tools.Definition,
    prompt: []const u8,
) std.mem.Allocator.Error!struct { []chock_core.tools.Definition, []const u8 } {
    const settings = started.plugins orelse return .{ definitions, prompt };

    // **There is no plugin on Darwin today**, because a plugin host is a
    // sandboxed process and `Sandbox.spawn` refuses there. Said once, at the
    // start, and never as a tool the model is offered and cannot use: a wrong
    // tool costs a turn calling it and a turn reading the failure, which is
    // worse than a tool that is not there. `chock_core.mcp` reaches the same
    // answer by way of a discovery round trip that cannot happen.
    if (builtin.target.os.tag != .linux) {
        tty.print(
            .warn,
            "chock: a plugin runs in a sandbox of its own, and this platform has none, so no " ++
                "plugin is in this session.\n",
            .{},
        );
        return .{ definitions, prompt };
    }

    const keep = state.arena.allocator();

    var policy = TablePolicy{
        .policy = started.policy,
        .chain = try policyChain(keep, started, options),
        .agent_kind = options.agent_kind,
        .model = started.model,
    };

    // **The program a plugin runs inside is this program.** Nothing is looked
    // for beside `chock`, so nothing can be missing: `chock` re-execs itself
    // under a hidden word, the way it already does for a subagent. See
    // `chock_core.plugin_host.verb`.
    //
    // A machine that cannot say where its own program is cannot run a sandbox
    // either, so this is said once and the session goes on without plugins.
    const host_path = try chock_core.plugin_host.selfProgramPath(keep, io, started.exe_path) orelse {
        tty.print(
            .warn,
            "chock: this program's own path could not be resolved, so no plugin is in this " ++
                "session.\n",
            .{},
        );
        return .{ definitions, prompt };
    };

    state.session.reserved = try reservedNames(keep, mcp_session);

    for (settings) |one| {
        std.debug.assert(state.count < chock_core.plugin.max_plugins);

        // **Resolved, and not only joined.** The path is bound into a mount
        // tree, and `chock_sandbox.namespace` takes an absolute path or
        // nothing: a relative one is a hard failure of the whole session rather
        // than one plugin that did not load.
        const named = if (std.fs.path.isAbsolute(one.module))
            one.module
        else
            try std.fs.path.join(keep, &.{ started.project_root, one.module });
        const module_path = std.Io.Dir.cwd().realPathFileAlloc(io, named, keep) catch |err| {
            tty.print(
                .warn,
                "chock: the plugin {s} ({s}) could not be found ({t}), so its tools are not in " ++
                    "this session.\n",
                .{ one.name, named, err },
            );
            continue;
        };

        // The module's own bytes, read on the host with no engine anywhere
        // near them. They are wanted only until `admit` has copied what it
        // keeps, so they live in an arena of this loop's own.
        var reading = std.heap.ArenaAllocator.init(gpa);
        defer reading.deinit();
        const bytes = std.Io.Dir.cwd().readFileAlloc(
            io,
            module_path,
            reading.allocator(),
            .limited(chock_core.plugin_module.max_module_bytes),
        ) catch |err| {
            tty.print(
                .warn,
                "chock: the plugin {s} ({s}) could not be read ({t}), so its tools are not in " ++
                    "this session.\n",
                .{ one.name, module_path, err },
            );
            continue;
        };

        // **The sandbox before the decision.** Everything that can fail is done
        // before the session is told about a tool, so a tool the model is
        // offered always has a host to reach.
        const config = try pluginSandbox(
            keep,
            io,
            started.sandbox_config,
            context.store_paths,
            context.toolchain_mounts,
            host_path,
            module_path,
        );

        var module_refusal: ?chock_core.plugin_module.Refusal = null;
        var failure: ?chock_core.plugin.Failure = null;
        var read = state.session.load(
            gpa,
            one.name,
            bytes,
            policy.decider(),
            &module_refusal,
            &failure,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (module_refusal) |detail| {
                    tty.print(
                        .warn,
                        "chock: the plugin {s} is not in this session: {f}\n",
                        .{ one.name, detail },
                    );
                } else {
                    tty.print(
                        .warn,
                        "chock: the plugin {s} is not in this session: its module could not be " ++
                            "read ({t})\n",
                        .{ one.name, err },
                    );
                }
                continue;
            },
        };
        read.deinit();

        if (failure) |why| {
            // The refusals that take a whole plugin with them, and the one a
            // person most needs to hear: a plugin that tried to take the name
            // of one of Chock's own tools.
            tty.print(
                .warn,
                "chock: the plugin {s} is not in this session, because {s}\n",
                .{ one.name, why.text() },
            );
            continue;
        }

        // **Every capability its offered tools declared, and no other.** The
        // list is fixed on argv before the process exists, so nothing the guest
        // does and nothing on the pipe can widen it: see
        // `chock_core.plugin_engine.gate` and `src/plugin-host.zig`.
        const capabilities = try chock_core.plugin_engine.unionOfCapabilities(
            keep,
            &state.session,
            one.name,
        );
        const argv = try pluginArgv(keep, capabilities);

        const index = state.count;
        // **The page allocator, and never `gpa`.** The helper's own thread is
        // inside `Sandbox.spawn` while this session's threads allocate, and
        // `fork` carries only the calling thread: see
        // `chock_core.helper.Helper.arena`.
        state.helpers[index] = chock_core.helper.Helper.init(std.heap.page_allocator);
        state.drivers[index] = chock_core.plugin_host.Driver.init(
            gpa,
            &state.helpers[index],
            .{ .config = config, .argv = argv },
        );
        state.records[index] = .{ .name = one.name, .host = state.drivers[index].host() };
        state.count += 1;
    }

    state.session.plugins = state.records[0..state.count];
    reportPluginOffers(&state.session);

    if (state.session.isEmpty()) return .{ definitions, prompt };

    // The list the session already had first, in the order it already had, and
    // the plugin tools after it. The same slice fills `Request.tools` and the
    // prompt's own tool list, so the model never hears a name it cannot call.
    var list: std.ArrayList(chock_core.tools.Definition) = .empty;
    try list.appendSlice(keep, definitions);
    try state.session.appendDefinitions(keep, &list);
    const with_plugins = try list.toOwnedSlice(keep);

    return .{
        with_plugins,
        try chock_core.prompt.build(
            keep,
            started.prompt_project,
            with_plugins,
            started.prompt_sources,
        ),
    };
}

/// The tool names this session already holds when the plugins are read: every
/// tool an MCP server declared and the policy allowed.
///
/// **Two suppliers of tools reach one model through one name space.** A name
/// that meant one thing to the runner chain and another to the person reading
/// the list is worse than a tool that is not offered, so the supplier that is
/// already in the session keeps its names and a plugin tool of the same name is
/// refused with a reason the model reads. See
/// `chock_core.plugin.Session.reserved`.
///
/// A refused MCP tool is not in the list: it is offered to nobody, so there is
/// nothing for a plugin to collide with.
fn reservedNames(
    keep: std.mem.Allocator,
    mcp_session: *const chock_core.mcp.Session,
) std.mem.Allocator.Error![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (mcp_session.offers.items) |offer| {
        if (offer.refused != null) continue;
        try names.append(keep, offer.name);
    }
    return names.toOwnedSlice(keep);
}

/// The command line one plugin host process is started with.
///
/// **Every word here is a path inside that process's own sandbox**, and not a
/// path on this machine: `plugin_host_target` is where `chock` itself is bound
/// and `plugin_module_target` is where the plugin's module is.
///
/// **The second word is what makes `chock` a plugin host and not a session.**
/// It is read from `chock_core.plugin_host.verb`, which is also what
/// `src/main.zig` dispatches on, so the two cannot drift apart.
///
/// The capabilities come last, and they are the whole of what the gate in the
/// host process will allow. They are on argv because argv is fixed before that
/// process exists: see `chock_core.plugin_engine.gate`.
fn pluginArgv(
    keep: std.mem.Allocator,
    capabilities: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(keep, plugin_host_target);
    try argv.append(keep, chock_core.plugin_host.verb);
    try argv.append(keep, plugin_module_target);
    try argv.appendSlice(keep, capabilities);
    return argv.toOwnedSlice(keep);
}

/// The sandbox one plugin host process runs in.
///
/// **Built by taking things away from the config a tool call gets**, which is
/// the only way to be sure a plugin reaches nothing a tool call cannot: see
/// `chock_core.plugin_host.lockdown`, which takes the network and every rule
/// away and keeps only what is named here, read only.
///
/// Three paths, and no fourth:
///
/// * **The host program**, bound at `plugin_host_target` with the execute
///   right. Without that right `execve` on it is refused before one instruction
///   runs: the Landlock ruleset handles execute for every path, which is the
///   same fact `test/sandbox/probe.zig` records for its own probe binary.
/// * **The plugin's module**, bound read only at `plugin_module_target`. It is
///   the one file this process opens by name.
/// * **This session's store paths**, read only, exactly as they already are for
///   every tool call. The host program this project builds is statically linked
///   (measured on 2026-08-23), so it needs none of this itself; a build that
///   links it against the store resolves its loader here rather than failing to
///   start with nothing to read.
///
/// **The workspace is not one of them.** Its mounts come through, because the
/// mount tree is the caller's, and a mount with no rule is present and
/// unreachable. So a plugin reads neither the project nor anything the session
/// writes.
fn pluginSandbox(
    keep: std.mem.Allocator,
    io: std.Io,
    workspace_config: sandbox.Config,
    store_paths: []const []const u8,
    toolchain_mounts: []const chock_core.tools.ToolchainMount,
    host_path: []const u8,
    module_path: []const u8,
) std.mem.Allocator.Error!sandbox.Config {
    var base = workspace_config;
    // **Not the project directory.** A plugin host opens the one file it was
    // given, by an absolute path, and a working directory inside the workspace
    // would be a directory this process has no rule for anyway.
    base.cwd = "/";
    base.rules = &.{};

    const with_store = try chock_core.tools.withStore(keep, io, base, store_paths, toolchain_mounts);

    var mounts: std.ArrayList(sandbox.namespace.Mount) = .empty;
    try mounts.appendSlice(keep, with_store.mounts);
    try mounts.append(keep, .{ .bind = .{
        .source = host_path,
        .target = plugin_host_target,
        .read_only = true,
    } });
    try mounts.append(keep, .{ .bind = .{
        .source = module_path,
        .target = plugin_module_target,
        .read_only = true,
    } });

    var reach: std.ArrayList(sandbox.Config.Rule) = .empty;
    try reach.appendSlice(keep, with_store.rules);
    // A file and not a directory, so the rule cannot carry the `read_dir`
    // right: `landlock_add_rule` answers EINVAL for a directory right over a
    // file. See `chock_sandbox.landlock.AccessFs.read_only_file`.
    try reach.append(keep, .{
        .path = plugin_host_target,
        .access = .{ .execute = true, .read_file = true },
    });
    try reach.append(keep, .{
        .path = plugin_module_target,
        .access = .{ .read_file = true },
    });

    var config = try chock_core.plugin_host.lockdown(keep, with_store, reach.items);
    config.mounts = try mounts.toOwnedSlice(keep);
    return config;
}

/// Say what the plugins gave this session, and what was turned away.
///
/// **A tool the model can call is a fact a person should see**, because it is a
/// module nobody here wrote acting inside their session. A tool that was
/// refused is worth a line too: a project that wrote a rule and still has no
/// tool needs to know which of the two went wrong.
fn reportPluginOffers(session: *const chock_core.plugin.Session) void {
    if (session.isEmpty()) return;

    var offered: usize = 0;
    for (session.offers.items) |offer| {
        if (offer.refused == null) offered += 1;
    }
    tty.detail("chock: {d} plugin tools in this session\n", .{offered});

    for (session.offers.items) |offer| {
        const reason = offer.refused orelse continue;
        tty.detail(
            "chock: the plugin tool {s} of {s} is not offered, because {s}\n",
            .{ offer.name, offer.plugin, reason.text() },
        );
    }
}

/// Answers `provide_tool` and passes every other call straight through.
///
/// ## Why this is a wrapper and not a tool of the registry
///
/// `chock_core.tools.Registry` runs one tool call inside a sandbox and knows
/// nothing that outlives one call. Provisioning is the opposite of that: it
/// changes the toolchain of the whole session, and it has to run `nix` on the
/// host, outside every sandbox. So it takes the road `spawn_agent` already
/// takes, one layer further out: the registry refuses the call and says why,
/// and the caller that owns the session answers it. See
/// `chock_core.tools.provision_needs_a_session`, and `GitToolRunner` next
/// door, which is the same shape for a different reason.
///
/// ## The mount set really does change while the session is live, and here is why
///
/// **Measured, not assumed.** There is no long lived sandbox. Every tool call
/// builds its own `sandbox.Config` inside `Registry.dispatchWith`, out of
/// `chock_core.tools.Context.store_paths`, and `Sandbox.spawn` runs once per
/// call. So a store path added between two tool calls is mounted by the
/// second one, with nothing restarted. That is why this holds a pointer to
/// the very `Context` the sandbox runner dispatches with, rather than a copy.
///
/// Three things it does not reach, and each one is said in the answer the
/// model reads rather than left for the model to find out:
///
/// * **A background task already running.** `chock_core.tasks.Table.start`
///   deep copies the `sandbox.Config` on purpose, so a task that started
///   before the program was provisioned runs in the mount set it started
///   with.
/// * **A subagent already running.** A child is its own process with its own
///   dev shell, and its parent's toolchain is not part of what it inherits.
/// * **The next session.** Nothing here is written to the dev shell cache: a
///   provisioned program lasts for this session and no longer. That is a
///   decision. What a project needs every time belongs in `flake.nix`, which is
///   the first rule of a toolchain, and a cache that grew by whatever any agent
///   ever asked for would quietly become the toolchain nobody declared.
///
/// ## An `Io` of its own, for the same reason a subagent gets one
///
/// Phase 2 runs on an `Io` that cannot spawn a process. `nix` is a process,
/// on the host, so this builds one `std.Io.Threaded` of its own for the
/// length of the resolution and takes it down again, **backed by the page
/// allocator**, never by the session's own. See `SubagentSpawner`, which
/// states the reason in full: a background task's thread may be inside
/// `Sandbox.spawn` at that moment, and a lock held by another thread at a
/// `fork` is a lock the child inherits as held forever.
///
/// ## It blocks the turn, and it is not a background task
///
/// `chock_core.tasks` exists and is proven, and a build of minutes is the
/// shape it handles. It is not used here, and the reason is the answer's
/// destination: a background task's result is drained by `Loop` at a safe
/// point and handed to the **model**, and this answer has to reach the
/// **mount set** that the dispatch on this very thread is about to read. A
/// second thread writing `Context.store_paths` while a dispatch reads it is a
/// race on a slice, and the publish would still have to happen at a point
/// this runner does not sit under. A model that has to poll for its own
/// toolchain is also worse to use than one that is told "it is there now".
///
/// So the turn waits, and a line is printed first, which is the same
/// treatment `DevShell.load`'s own slow evaluation gets. **There is no
/// deadline on it**: `Ctrl-C` reaches the `nix` child, because nothing here
/// puts it in a process group of its own, exactly as it reaches a subagent.
const ProvisionToolRunner = struct {
    inner: chock_core.Loop.ToolRunner,
    /// Null when this session cannot provision, which is the case where the
    /// model was never told the tool exists. A call that arrives anyway is
    /// refused here rather than passed down, because the registry below would
    /// answer with `provision_needs_a_session`, which names the wrong reason.
    settings: ?Provisioning,
    /// Where everything a provisioned program leaves behind is kept: the
    /// store paths, the `bin` directories, and the names already asked for.
    /// Owned by `runSession`, and freed when the session ends.
    arena: std.mem.Allocator,
    /// The environment `nix` itself runs with: the host's own, so `nix` reads
    /// the user's own configuration and the user's own flake registry.
    host_env: *const std.process.Environ.Map,
    environ: std.process.Environ,
    /// The environment a tool call resolves `argv[0]` against. **This is the
    /// map the sandbox runner holds a pointer to**, so a `PATH` written here
    /// is the `PATH` the next call resolves against.
    tool_env: *std.process.Environ.Map,
    /// The context the sandbox runner dispatches with. `store_paths` is
    /// repointed at `paths` below every time a program is provisioned.
    context: *chock_core.tools.Context,
    /// Every store path this session mounts: the dev shell's, and one
    /// closure per provisioned program. Grows only.
    ///
    /// **Held with no repeats, and that is not tidiness.** A provisioned
    /// package's closure and the dev shell's overlap almost entirely, because
    /// both start at the same libc, so appending one whole would bind most of
    /// the toolchain a second time. `withStore` builds one bind mount and one
    /// Landlock rule per entry, so a repeat is a mount of the same source on
    /// the same target, on every tool call, for the rest of the session.
    paths: std.ArrayList([]const u8) = .empty,
    /// The membership half of `paths`, so adding a closure of thirty thousand
    /// entries costs one lookup each rather than a walk of the list each.
    mounted: std.StringHashMapUnmanaged(void) = .empty,
    /// Every program name already provisioned, so asking twice costs nothing
    /// and says so.
    already: std.ArrayList([]const u8) = .empty,

    fn runner(self: *ProvisionToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        const self: *ProvisionToolRunner = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, call.tool, @tagName(chock_core.tools.Tool.provide_tool))) {
            return self.inner.dispatch(gpa, io, call);
        }

        const answer = try self.provide(gpa, call);
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = answer.text,
            .is_error = answer.refused,
            .truncated = false,
        };
    }

    const Answer = struct { text: []u8, refused: bool };

    fn provide(
        self: *ProvisionToolRunner,
        gpa: std.mem.Allocator,
        call: chock_proto.event.ToolCall,
    ) std.mem.Allocator.Error!Answer {
        const settings = self.settings orelse return .{
            .text = try gpa.dupe(u8, provisioning_is_off),
            .refused = true,
        };

        const parsed = std.json.parseFromSlice(
            chock_core.tools.ProvideToolArgs,
            gpa,
            call.arguments,
            .{ .ignore_unknown_fields = true },
        ) catch return .{
            .text = try gpa.dupe(u8, "the arguments of provide_tool did not parse. Send one " ++
                "field, \"program\", holding the package name alone."),
            .refused = true,
        };
        defer parsed.deinit();

        const program = parsed.value.program;
        for (self.already.items) |name| {
            if (!std.mem.eql(u8, name, program)) continue;
            return .{
                .text = try std.fmt.allocPrint(
                    gpa,
                    "{s} is already in this session's toolchain, so nothing was done. Run it.",
                    .{program},
                ),
                .refused = false,
            };
        }

        // Before the wait, because a resolution can take minutes and a silent
        // terminal looks like a session that has stopped.
        tty.print(.plain, "chock: resolving {s} with nix, which can take some time\n", .{program});

        const resolved = self.resolveWithNix(settings, program) catch |err| return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s} could not be resolved ({t}), so nothing was added to the toolchain. Do the " ++
                    "work with a program the toolchain already has.",
                .{ program, err },
            ),
            .refused = true,
        };

        const provided = switch (resolved) {
            .refused => |text| {
                tty.print(.warn, "chock: {s} was not provisioned\n", .{program});
                return .{ .text = try gpa.dupe(u8, text), .refused = true };
            },
            .provided => |one| one,
        };

        try self.adopt(program, provided);

        // The closure it needed and the whole mount set, because the two are
        // different numbers and the difference is the point: most of a new
        // package's closure is already there. See `ProvisionToolRunner.paths`.
        tty.print(.plain, "chock: {s} is in the toolchain, {d} store paths, {d} mounted in all\n", .{
            program,
            provided.store_paths.len,
            self.paths.items.len,
        });

        return .{
            .text = try std.fmt.allocPrint(
                gpa,
                "{s} is now in this session's toolchain, from {s}. Every call after this one can " ++
                    "run it. A background task or a subagent that was already running does not " ++
                    "have it, and it is gone at the end of this session: to keep it, tell the " ++
                    "user to add it to flake.nix.",
                .{ program, provided.installable },
            ),
            .refused = false,
        };
    }

    /// Take a resolved program into this session's toolchain.
    ///
    /// **This is the whole of "the mount set changes while the session is
    /// live".** Two writes, and both are read by the next tool call and by
    /// nothing that is already running: the store paths the sandbox binds,
    /// and the `PATH` `argv[0]` is resolved against. See this type's own doc
    /// comment for what those two do not reach.
    fn adopt(
        self: *ProvisionToolRunner,
        program: []const u8,
        provided: chock_nix.provision.Provided,
    ) std.mem.Allocator.Error!void {
        for (provided.store_paths) |path| try self.mount(path);
        // The pointer the sandbox runner reads, repointed at the grown list.
        // A slice of an `ArrayList` is only valid until it grows again, so
        // this is done after every append and never cached anywhere else.
        self.context.store_paths = self.paths.items;
        try self.extendPath(provided.bin_dirs);
        try self.already.append(self.arena, try self.arena.dupe(u8, program));
    }

    /// Add one store path to the mount set, once. See `paths`.
    fn mount(self: *ProvisionToolRunner, path: []const u8) std.mem.Allocator.Error!void {
        const entry = try self.mounted.getOrPut(self.arena, path);
        if (entry.found_existing) return;
        entry.key_ptr.* = path;
        try self.paths.append(self.arena, path);
    }

    /// Take the paths this session starts with: the dev shell's own, or the
    /// whole store for a project that states no toolchain. Called once, by
    /// `runSession`, before the first turn.
    fn start(self: *ProvisionToolRunner, paths: []const []const u8) std.mem.Allocator.Error!void {
        for (paths) |path| try self.mount(path);
    }

    /// Run the two `nix` commands on an `Io` of this call's own. See this
    /// type's own doc comment for why the `Io` is built here and why it is
    /// backed by the page allocator.
    fn resolveWithNix(
        self: *ProvisionToolRunner,
        settings: Provisioning,
        program: []const u8,
    ) chock_nix.provision.Error!chock_nix.provision.Answer {
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const io = threaded.io();

        // Why `nix` could not be run, which the library used to print for
        // itself and this runner could only repeat as an error name.
        var run_diag: ?chock_nix.Diagnostic = null;
        defer if (run_diag) |*d| d.deinit(self.arena);
        var host = chock_nix.provision.Host{
            .nix_program = settings.nix_program,
            .env = self.host_env,
            .diag = &run_diag,
        };
        const answer = chock_nix.provision.resolve(self.arena, io, host.runner(), .{
            .program = program,
            .registry = settings.registry,
        }) catch |err| {
            if (run_diag) |*fault| tty.print(.warn, "chock: {f}\n", .{fault});
            return err;
        };

        // Held against the garbage collector as soon as it exists, and before
        // the model is told it is there. `nix build --no-link` leaves no root
        // of its own, so a `nix-collect-garbage` between now and the next tool
        // call would take a toolchain the agent has already been promised.
        // The same reasoning `chock_nix.store.addRoots` carries for the dev
        // shell, and a failure is said out loud and is not fatal for the same
        // reason.
        if (answer == .provided) self.rootProvided(io, settings, program, answer.provided);
        return answer;
    }

    fn rootProvided(
        self: *ProvisionToolRunner,
        io: std.Io,
        settings: Provisioning,
        program: []const u8,
        provided: chock_nix.provision.Provided,
    ) void {
        const nix_store = settings.nix_store_program orelse return;
        const dir = settings.root_dir orelse return;

        const link_prefix = providedRootPrefix(self.arena, dir, program) catch return;
        // What `nix-store` said, which the library used to print for itself.
        var diag: ?chock_nix.Diagnostic = null;
        defer if (diag) |*d| d.deinit(self.arena);
        chock_nix.store.addRoots(
            self.arena,
            io,
            nix_store,
            self.host_env,
            link_prefix,
            provided.store_paths,
            &diag,
        ) catch |err| {
            if (diag) |*fault| {
                tty.print(
                    .warn,
                    "chock: {s} could not be held against the garbage collector ({f}). A " ++
                        "nix-collect-garbage during this session can break it.\n",
                    .{ program, fault },
                );
            } else {
                tty.print(
                    .warn,
                    "chock: {s} could not be held against the garbage collector ({t}). A " ++
                        "nix-collect-garbage during this session can break it.\n",
                    .{ program, err },
                );
            }
        };
    }

    /// Put `dirs` at the front of the `PATH` a tool call resolves `argv[0]`
    /// against.
    ///
    /// **At the front, so the newest answer wins.** A program that is already
    /// on the path was already found, so the order only decides what happens
    /// when an agent provisions a package that carries a program the dev shell
    /// also has. Taking the provisioned one is the honest reading of a request
    /// that named it.
    fn extendPath(self: *ProvisionToolRunner, dirs: []const []const u8) std.mem.Allocator.Error!void {
        var joined: std.ArrayList(u8) = .empty;
        for (dirs) |dir| {
            try joined.appendSlice(self.arena, dir);
            try joined.append(self.arena, ':');
        }
        try joined.appendSlice(self.arena, self.tool_env.get("PATH") orelse "");
        try self.tool_env.put("PATH", joined.items);
    }
};

/// Where the garbage collector root links of one provisioned program go.
/// Caller owns the result.
///
/// **The program's own name is in it, and that is not decoration.**
/// `nix-store --add-root` names its links after the prefix it is given, so two
/// programs sharing one prefix means the second call replaces the first one's
/// links, and a program the agent is still using stops being held. The name is
/// safe in a path because `chock_nix.provision.checkName` has already refused
/// every character that is not a letter, a digit, `-`, `_`, `+` or `.`.
///
/// The prefix starts with `chock_nix.DevShell.root_link_name`, read from
/// there, so a new evaluation of the dev shell releases these too: see that
/// constant's own doc comment.
fn providedRootPrefix(
    arena: std.mem.Allocator,
    dir: []const u8,
    program: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}-provided-{s}", .{
        dir,
        chock_nix.DevShell.root_link_name,
        program,
    });
}

/// What a `provide_tool` call gets when the session cannot provision at all.
/// The model is not offered the tool in that case, so this is for a model that
/// named it out of nowhere. It says the one thing that is true and useful:
/// stop, and use what is here.
const provisioning_is_off = "no program was provisioned: this session cannot add one. Do the " ++
    "work with a program the toolchain already has, and do not run apt, npm, pip, cargo or " ++
    "brew, because none of them can work in this sandbox.";

/// Starts a subagent: one `chock run` of its own, with the session, the
/// scratchpad, the chain and the budget slice its parent decided. See
/// `chock_core.subagent`, which owns everything about a child except the two
/// events the loop appends around one.
///
/// ## Why a child is a process and not a thread
///
/// `Sandbox.spawn` calls `fork`, and `fork` carries only the calling thread,
/// so an agent tree built from threads deadlocks the moment a child runs a
/// tool. See this file's own top comment, which is where phase 2 comes from,
/// and `chock daemon`, which already runs a child per session for the same
/// reason. **A subagent is a session with a parent and nothing more.**
///
/// ## The parent decides the child's confinement, and the child cannot widen it
///
/// Everything narrowing about a child is on the command line the parent writes
/// here: the kind, the parent's own kind, the budget slice, and the directory
/// it may write in. `chock_policy.table.evaluateChain` then folds every kind in
/// the chain, so the child holds no permission its parent lacks, and the child
/// has no way to state a chain of its own because it does not write its own
/// command line. **A check the child performs on itself would be worth
/// nothing.**
///
/// ## An `Io` of its own, and why that is safe here
///
/// Phase 2 runs on an `Io` that cannot start a thread, which is what makes the
/// tool path's own `fork` safe. Spawning a process needs an allocator that
/// works, so this builds one `std.Io.Threaded` of its own for the length of the
/// child and takes it down again. **Backed by the page allocator**, never by
/// the session's own: a background task's thread may be inside `Sandbox.spawn`
/// at that moment, and a lock held by another thread at a `fork` is a lock the
/// child inherits as held forever. That is the same answer
/// `chock_core.tasks.Table.gpa` already gives, for the reason
/// `lib/chock-core/tools.zig`'s own top comment states in full.
///
/// ## `run` is called on the parent's thread, or on the table's
///
/// A spawn that waits calls `runFn` from the loop itself. A spawn that carries
/// on calls it from a thread of `chock_core.subagent.Table`'s own, beside the
/// parent's own turn. Everything `runFn` reads is either a value of the job's
/// own arena or a field of `started` that nothing writes after phase 1, and the
/// `Io` it spawns the child on is built inside the call, so it is the calling
/// thread's alone. **`prepareFn` is always on the parent's thread**, because
/// the parent appends `session.spawn` from what it answers.
///
/// ## What reaches a child that is still running
///
/// **A Ctrl-C reaches it, and nothing else has to.** The child is one
/// `std.process.spawn` and nothing here puts it in a group of its own, so it
/// stays in this process's group and the terminal signals both together. The
/// child is a `chock run` of its own, so it reads that the same way this one
/// does: it stops at its next safe point and writes its own `session.end`,
/// which its parent then reads as a session that ended rather than as a child
/// that died. **This is not true of a tool call**, because `Sandbox.spawn` does
/// put every process of a call in a group of its own, which is exactly why
/// `chock_core.tools.cancelRunningTool` has to reach those from inside the
/// program: see that function's own doc comment.
const SubagentSpawner = struct {
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *const Started,
    /// The kind this session runs as, which becomes the child's parent link.
    agent_kind: []const u8,
    /// True to give the child no scratchpad at all.
    ///
    /// **This exists for the reviewer agent and for nothing else.**
    /// `lib/chock-core/scratchpad.zig` says plainly that a parent may read a
    /// child's scratchpad, and the parent of a reviewer is the agent whose
    /// request is being reviewed. A reviewer given one is a reviewer whose
    /// working notes the requester can read, which loses the asymmetry
    /// `lib/chock-broker/review.zig` is built around. An arbitrator reads a
    /// case and answers; it has nothing to write down.
    no_scratchpad: bool = false,

    fn spawner(self: *SubagentSpawner) chock_core.subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    /// Choose the child's identifier and say where its log and its scratchpad
    /// will be. **Nothing is created here**: `chock run` builds its own session
    /// directory and its own scratchpad layout, so a child that never starts
    /// leaves nothing behind, and a log that was never opened is exactly the
    /// `died` this parent then reads.
    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
    ) chock_core.subagent.Error!chock_core.subagent.Prepared {
        _ = request;
        const self: *SubagentSpawner = @ptrCast(@alignCast(ptr));

        const id = session_paths.newId(io);
        var paths = session_paths.pathsFor(allocator, self.env, self.started.project_root, &id) catch {
            tty.print(.err, "chock run: the session path for a subagent could not be built\n", .{});
            return error.ChildNotStarted;
        };
        defer paths.deinit();

        const child_session = try allocator.dupe(u8, &id);
        errdefer allocator.free(child_session);
        const log_path = try allocator.dupe(u8, paths.log);
        errdefer allocator.free(log_path);

        // Inside the parent's own scratchpad, under `agents/`. A child sees its
        // own and nothing else, and siblings see nothing of each other: see
        // `chock_core.scratchpad`'s own visibility rule.
        const scratchpad_path = if (self.no_scratchpad)
            try allocator.dupe(u8, "")
        else if (self.started.scratch_dir) |parent_dir|
            chock_core.subagent.childDir(allocator, parent_dir, child_session) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.BadChildId => return error.ChildNotStarted,
            }
        else
            try allocator.dupe(u8, "");

        return .{
            .child_session = child_session,
            .log_path = log_path,
            .scratchpad_path = scratchpad_path,
        };
    }

    /// Run the child to its end, then read its own log to learn what happened.
    ///
    /// **The log is the answer, and the exit status is not.** A child that was
    /// killed and a child that refused its task can exit the same way, and only
    /// the log tells them apart: see `chock_core.subagent.readReport`.
    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
        prepared: chock_core.subagent.Prepared,
    ) chock_core.subagent.Error!chock_core.subagent.Report {
        _ = io;
        const self: *SubagentSpawner = @ptrCast(@alignCast(ptr));

        // **This session's own chain, with this session on the end of it.** A
        // chain that stopped at the immediate parent was the fault
        // `test/core/tree.zig` found: a grandchild held whatever the agent at
        // the top of its own tree was denied.
        const chain = try chock_core.subagent.Command.chainBelow(
            allocator,
            self.started.spawn_chain,
            self.agent_kind,
            request.reason,
        );
        defer allocator.free(chain);

        const argv = try chock_core.subagent.commandLine(allocator, .{
            .exe_path = self.started.exe_path,
            .project_root = self.started.project_root,
            .parent_session = self.started.session_id,
            .parent_chain = chain,
            .provider = self.started.model_alias,
            .model = self.started.model,
        }, request, prepared);
        defer chock_core.subagent.freeCommandLine(allocator, argv);

        tty.print(.plain, "chock: subagent {s} ({s}) started\n", .{ prepared.child_session, request.agent_kind });
        self.runToTheEnd(argv);

        return readChildLog(allocator, prepared, request.shape);
    }

    /// Spawn the child and wait for it. See this type's own doc comment for
    /// the `Io` this builds and why it is backed by the page allocator.
    ///
    /// **Nothing is returned.** Whatever became of the process, the answer
    /// comes out of the child's own log; a child that never started leaves one
    /// that cannot be read, which reads as `died`.
    fn runToTheEnd(self: *SubagentSpawner, argv: []const []const u8) void {
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const io = threaded.io();

        var child = std.process.spawn(io, .{
            .argv = argv,
            .environ_map = self.env,
            .stdin = .ignore,
            // The child's transcript is in the child's own log, which is what
            // the parent reads. Its standard error is where a setup failure is
            // reported, and a person watching wants to see one.
            .stdout = .ignore,
            .stderr = .inherit,
        }) catch |err| {
            tty.print(.err, "chock: the subagent could not be started: {t}\n", .{err});
            return;
        };
        const term = child.wait(io) catch |err| {
            tty.print(.err, "chock: the subagent could not be waited for: {t}\n", .{err});
            return;
        };
        switch (term) {
            .exited => |status| if (status != 0) {
                tty.print(.warn, "chock: the subagent exited {d}\n", .{status});
            },
            else => tty.print(.warn, "chock: the subagent did not exit normally\n", .{}),
        }
    }

    /// Open the child's log and read the outcome out of it. A log that will not
    /// open is a child that died, which is what `readReport` answers for a log
    /// it cannot read either.
    fn readChildLog(
        allocator: std.mem.Allocator,
        prepared: chock_core.subagent.Prepared,
        shape: chock_core.subagent.Shape,
    ) chock_core.subagent.Error!chock_core.subagent.Report {
        // A real allocator's `Io` again, because opening a file is all this
        // does and the process it was waiting for has already ended.
        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const path = try allocator.dupeZ(u8, prepared.log_path);
        defer allocator.free(path);

        var log = chock_proto.log.Log.open(io, path, prepared.child_session) catch {
            return .{
                .outcome = .died,
                .result = try std.fmt.allocPrint(
                    allocator,
                    "the subagent's log at {s} could not be opened, so the subagent never started",
                    .{prepared.log_path},
                ),
            };
        };
        defer log.close(io);

        var backing = chock_proto.storage.JsonLines{ .log = log };
        return chock_core.subagent.readReport(allocator, io, backing.storage(), shape);
    }
};

/// The reviewer agent, as a `chock-broker` asks for one: a subagent that reads
/// one case and answers, and acts on nothing.
///
/// **This is the caller `lib/chock-broker/review.zig` would otherwise not
/// have.** The broker imports no `chock-core` on purpose, so the seam is a
/// vtable and the process that runs a child implements it, which is here.
///
/// ## What the reviewer is given, and what it is not
///
/// * **No scratchpad**, by `SubagentSpawner.no_scratchpad`. See that field.
/// * **No tools at all**, by `agentRole`, which reads the reviewer's kind and
///   answers `chock_core.tools.Role.arbitrator`. An arbitrator is told why an
///   act is guarded, and one that could also act would hold the map and a way
///   to use it: see `lib/chock-broker/review.zig`'s own top comment.
/// * **A slice of what is left of this session's cap.** A review is a whole
///   subagent, and `chock_core.subagent.budgetSlice` is what decides how much
///   of the remainder it may spend. A session with a cap and nothing left of
///   it runs no review at all, and that is a refusal: see `reviewFn`.
/// * **The case, and nothing of the parent's conversation.** A subagent reads
///   its task and nothing else, which is what makes the asymmetry in
///   `review.taskFor` checkable by reading one function.
///
/// ## A reviewer is a child, and the parent's log says so
///
/// `session.spawn` is appended for a reviewer exactly as `Loop.runSpawn`
/// appends one for a subagent the model asked for, and **before the child
/// runs**, which is the rule the whole log keeps: a crash in between still
/// leaves proof that the child was asked for, and a parent that resumes counts
/// that child.
///
/// **Without it a reviewer was a real process the width bound could not see**,
/// so a session could pass its own width bound with nothing noticing.
/// `reviewBounds` measures the standing from the same folded log, so the event
/// this appends is what the next review is measured against.
///
/// The append goes through `locked`, the handle whoever is calling the broker
/// already holds. That was the reason this could not be done: `applyWork` takes
/// the lock for the whole approval and this seam was handed no way to reach it.
/// `lib/chock-broker/socket.zig` settled that pattern for the answer, and both
/// callers of this seam now hold a handle at the moment they build one.
const ReviewSpawner = struct {
    /// What starts the child. `reviewChild` is what every real caller builds
    /// it from, with the scratchpad turned off. **A seam and not a
    /// `SubagentSpawner`**: see `reviewerFor`.
    child: chock_core.subagent.Spawner,
    /// What the reviewer may spend, or null for a session with no cap.
    budget: ?chock_cost.budget.Budget,
    /// True when this session has a cap and has already spent or promised all
    /// of it. **A review nothing can pay for is a review that does not run**,
    /// and that is a refusal rather than an allow.
    nothing_left: bool,
    /// Set when the spawn limits refuse a reviewer at this depth, so a tree
    /// cannot grow one level per approval.
    refused_by_limits: ?chock_policy.subagents.Refusal,
    /// The parent's own log, locked, so `session.spawn` can be appended for the
    /// reviewer. **Null is a caller that cannot record a child, and such a
    /// caller starts none**: see `recordSpawn` and `SpawnNotRecorded`.
    ///
    /// **Set after the lock is taken and never before.** Both callers build a
    /// `ReviewSpawner` first and lock afterwards, because the waiter holds the
    /// same handle: see `applyWork`.
    locked: ?*ApprovalLock = null,

    /// What recording a reviewer as a child can fail with. `NoLog` is a caller
    /// that holds no handle on the session log; the rest is whatever writing to
    /// that log can fail with. **The caller does the same thing with every one
    /// of them**, which is to start nothing: see `reviewFn`.
    const SpawnNotRecorded = error{NoLog} || chock_proto.storage.StorageError;

    fn reviewer(self: *ReviewSpawner) chock_broker.review.Reviewer {
        return .{
            .ptr = self,
            .vtable = &vtable,
            .kind = chock_broker.review.default_kind,
        };
    }

    const vtable = chock_broker.review.Reviewer.VTable{ .review = reviewFn };

    /// Run one review to its end and read the verdict out of the child's own
    /// log.
    ///
    /// **Every way this can fail is `error.ReviewNotRun`**, and the broker
    /// turns every one of those into `review_unavailable`, which refuses. That
    /// is the rule the whole arrangement would be worthless without: the
    /// cheapest attack on a review is to make it fail.
    fn reviewFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        case: chock_broker.review.Case,
    ) chock_broker.review.ReviewError!chock_broker.review.Report {
        const self: *ReviewSpawner = @ptrCast(@alignCast(ptr));

        if (self.refused_by_limits) |refusal| {
            tty.print(
                .warn,
                "chock: no reviewer was started for {s}: chock.zon's {s} does not allow one here\n",
                .{ case.action, refusal.limitName() },
            );
            return error.ReviewNotRun;
        }
        if (self.nothing_left) {
            tty.print(
                .warn,
                "chock: no reviewer was started for {s}: this session has spent the whole budget " ++
                    "in chock.zon, so there is nothing to pay a review with\n",
                .{case.action},
            );
            return error.ReviewNotRun;
        }

        const task = try chock_broker.review.taskFor(gpa, case);
        defer gpa.free(task);

        const request = chock_core.subagent.Request{
            .agent_kind = chock_broker.review.default_kind,
            .task = task,
            // The parent names the members and the parent alone checks the
            // answer: see `chock_core.subagent`'s own top comment.
            .shape = .{ .schema = &chock_broker.review.result_fields },
            .reason = case.action,
            .budget = self.budget,
        };

        const prepared = self.child.prepare(gpa, io, request) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ChildNotStarted => return error.ReviewNotRun,
        };
        defer chock_core.subagent.freePrepared(gpa, prepared);

        // **Before the child runs**, so a crash between the two still leaves
        // proof that this child was asked for, and a parent that resumes counts
        // it. The same order and the same reason as `Loop.runSpawn`.
        //
        // **A reviewer nothing records is the fault this closes**, so a spawn
        // that cannot be written starts nothing at all. That is a refusal, like
        // every other way a review does not happen, and it is the safe
        // direction: a child the width bound cannot see is worse than a review
        // that did not run.
        self.recordSpawn(gpa, io, request, prepared) catch {
            tty.print(
                .warn,
                "chock: no reviewer was started for {s}: the spawn could not be written to this " ++
                    "session's log, and a child nothing counts is a child that does not run\n",
                .{case.action},
            );
            return error.ReviewNotRun;
        };

        const report = self.child.run(gpa, io, request, prepared) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ChildNotStarted => return error.ReviewNotRun,
        };
        defer chock_core.subagent.freeReport(gpa, report);

        // A reviewer that died, ran out of its slice, stopped making progress,
        // or answered in the wrong shape has not decided anything. Reading a
        // half answer as a verdict is the one mistake that turns a broken
        // review into permission.
        if (report.outcome != .finished) {
            tty.print(
                .warn,
                "chock: the reviewer for {s} ended {s}: {s}\n",
                .{ case.action, report.outcome.wireName(), report.result },
            );
            return error.ReviewNotRun;
        }

        return chock_broker.review.readAnswer(gpa, report.result);
    }

    /// Append the `session.spawn` that puts this reviewer in its parent's own
    /// width count.
    ///
    /// **The same event `Loop.runSpawn` writes, and it has to be**, because the
    /// same fold reads both: `chock_proto.state.Session.children` is what
    /// `reviewBounds` measures the next review against and what
    /// `chock_policy.subagents.check` bounds. A reviewer recorded some other
    /// way would be a reviewer neither of them can see.
    ///
    /// The budget members carry the slice this reviewer was given, so a parent
    /// that resumes knows what it has already handed out: see
    /// `chock_core.subagent.committedToChildren`.
    fn recordSpawn(
        self: *ReviewSpawner,
        gpa: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
        prepared: chock_core.subagent.Prepared,
    ) SpawnNotRecorded!void {
        const handle = self.locked orelse return error.NoLog;
        _ = try handle.append(gpa, io, .{ .session_spawn = .{
            .child_session = prepared.child_session,
            .child_agent_kind = request.agent_kind,
            .reason = request.reason,
            .budget_max_cost = if (self.budget) |one| one.max_cost else 0,
            .budget_currency = if (self.budget) |one| one.currency else "",
        } }, std.Io.Timestamp.now(io, .real).toMilliseconds());
    }
};

/// Build the reviewer this session's end of session approval may need.
///
/// **Nothing here starts anything.** A `chock.zon` that answers `allow`, `ask`
/// or `deny` for `workspace.apply` never reaches the seam, so a session under
/// an ordinary policy pays for none of this. What it does do is measure, once,
/// the two facts a review cannot be started without: whether the spawn limits
/// allow one more agent here, and what is left of the budget.
///
/// Both are measured from the session's own log rather than from a counter of
/// this call's own, which is the same rule `Loop.runSpawn` keeps: a session
/// that was resumed counts the children it really has and the money it really
/// spent. `session` is that fold, and the caller owns it: `applyWork` reads
/// the promises out of the same one, so the log is walked once.
/// **`child` is the seam and not a `SubagentSpawner`**, so a test can drive
/// `ReviewSpawner.reviewFn` from end to end with nothing that starts a process.
/// That is what makes "a reviewer that runs is a reviewer the log counted" a
/// tested fact rather than a comment: the two happen in the same function, and
/// only a test that runs the whole of it can see that they both happened. Every
/// real caller passes `reviewChild`.
fn reviewerFor(
    child: chock_core.subagent.Spawner,
    started: *const Started,
    session: *const chock_proto.state.Session,
) ReviewSpawner {
    const bounds = reviewBounds(
        started.subagents,
        // This session's own standing: how deep it is, and how many children it
        // has already started.
        .{ .depth = started.spawn_chain.len + 1, .width = session.children.items.len },
        started.budget,
        session.spend,
        session.children.items,
    );

    return .{
        .child = child,
        .budget = bounds.budget,
        .nothing_left = bounds.nothing_left,
        .refused_by_limits = bounds.refused_by_limits,
    };
}

/// The subagent machinery a reviewer's own child is started with.
///
/// **One function and not two copies**, because the one thing that makes it
/// different from every other child is easy to leave out of the second copy:
/// see `SubagentSpawner.no_scratchpad`. A parent may read a child's scratchpad,
/// and the parent of a reviewer is the agent whose request is being reviewed.
fn reviewChild(
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *const Started,
    options: Options,
) SubagentSpawner {
    return .{
        .gpa = gpa,
        .environ = environ,
        .env = env,
        .started = started,
        .agent_kind = options.agent_kind,
        .no_scratchpad = true,
    };
}

/// The two facts a review cannot be started without. See `reviewBounds`.
const ReviewBounds = struct {
    /// What the reviewer may spend, or null for a session with no cap of its
    /// own and for one with nothing left.
    budget: ?chock_cost.budget.Budget,
    /// Which of the two nulls above this is. **A session with no cap runs a
    /// review; a session that has spent its cap does not**, and a caller that
    /// read the two the same way would start a reviewer on a budget that is
    /// already gone.
    nothing_left: bool,
    /// Which spawn limit refuses a reviewer here, or null when neither does.
    refused_by_limits: ?chock_policy.subagents.Refusal,
};

/// Whether a reviewer may be started here, and what it may spend.
///
/// Separate from `reviewerFor` because it is the half that is a decision
/// rather than a fact about the machine, and a test can pin it with no session
/// directory, no credential and no child process. The same split
/// `provisionDecision` makes, for the same reason.
///
/// **A reviewer is an agent, so it is measured against the same two limits
/// every other agent is.** The limits bound the depth and the width of the
/// tree, and a reviewer started per approval with no such check would grow one
/// level for each one.
fn reviewBounds(
    limits: chock_policy.subagents.Limits,
    standing: chock_policy.subagents.Standing,
    cap: ?chock_cost.budget.Budget,
    spend: chock_proto.state.Spend,
    children: []const chock_proto.state.Child,
) ReviewBounds {
    // What is left, measured the way `chock_core.subagent.budgetSlice` says
    // to: the cap, less what this session spent, less every slice it already
    // promised a child. One reviewer, so the remainder is not divided.
    const committed = chock_core.subagent.committedToChildren(children, cap);
    return .{
        .budget = chock_core.subagent.budgetSlice(cap, spend, committed, 1),
        .nothing_left = chock_core.subagent.nothingLeft(cap, spend, committed),
        .refused_by_limits = chock_policy.subagents.check(limits, standing),
    };
}

/// How far up the spawn tree `promisesFor` walks.
///
/// The longest chain a project can configure, from
/// `chock_policy.subagents.max_settable`, read from there so the two cannot
/// disagree. The walk follows `session.start.parent_session` out of files this
/// process did not write in this run, so a bound is what stops a loop of them
/// turning the end of a session into a walk with no end.
const max_ancestor_sessions: usize = chock_policy.subagents.max_settable;

/// Every promise the end of session decision is bound by: the ones this
/// session made about itself, and the ones every session above it made.
///
/// **A promise a parent made has to reach its children, or it is worth
/// nothing.** An agent that promises not to apply its work and then starts a
/// subagent to apply it has kept the letter of the promise and none of it. A
/// child already holds no more than its parent, and `table.evaluateChain`
/// applies that to the policy file. This applies the same rule to the half of
/// the policy the parent wrote itself.
///
/// **The promises come out of the ancestors' own logs and never off a command
/// line.** The parent could have been asked to pass them down, and then a
/// parent that passed none would be a parent widening its child. The logs sit
/// in this project's session directory, which is outside every workspace and
/// is mounted into no sandbox, so they are records no agent in the tree can
/// reach. See `session.zig`'s own `pathsFor`.
///
/// **A log that cannot be read stops the walk and says so.** Everything read
/// before it still binds, including a part read ancestor's own promises, so
/// the fault costs only what is above the fault. That is the honest reading of
/// a broken installation rather than of an attack: these files sit where no
/// agent in the tree can reach them, so none of them can arrange this. Silence
/// would be the fault, so this prints.
fn promisesFor(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    parent_session: []const u8,
    session: *const chock_proto.state.Session,
) std.mem.Allocator.Error![]const chock_policy.ratchet.Restriction {
    var out: std.ArrayList(chock_policy.ratchet.Restriction) = .empty;
    try appendPromises(arena, &out, session.self_policy.restrictions.items);

    var next: []const u8 = parent_session;
    var walked: usize = 0;
    while (next.len != 0) {
        if (!session_paths.isValidId(next)) {
            tty.print(
                .warn,
                "chock run: {s} is not a session identifier, so the promises of the sessions " ++
                    "above this one were not read.\n",
                .{next},
            );
            break;
        }
        walked += 1;
        if (walked > max_ancestor_sessions) {
            tty.print(
                .warn,
                "chock run: the sessions above this one go more than {d} deep, so the ones " ++
                    "above that were not read.\n",
                .{max_ancestor_sessions},
            );
            break;
        }

        var ancestor = chock_proto.state.Session.init(gpa);
        defer ancestor.deinit();
        const whole = foldSessionById(gpa, io, dir, next, &ancestor);
        // **Whatever was read still binds.** A log with a torn tail holds
        // every promise made before the crash, and dropping those because the
        // last line is half written would be the permissive answer to a fault.
        try appendPromises(arena, &out, ancestor.self_policy.restrictions.items);
        if (!whole) {
            tty.print(
                .warn,
                "chock run: the log of session {s} could not be read to its end, so a promise " ++
                    "it or the sessions above it made may not be applied here.\n",
                .{next},
            );
            break;
        }
        // The ancestor's own arena goes away with it, so the identifier of the
        // one above it is copied out before that happens.
        next = try arena.dupe(u8, ancestor.parent_session);
    }
    return out.toOwnedSlice(arena);
}

/// Add every promise of one folded session to `out`, copied into `arena`,
/// which outlives the session they were folded from.
fn appendPromises(
    arena: std.mem.Allocator,
    out: *std.ArrayList(chock_policy.ratchet.Restriction),
    folded: []const chock_proto.event.SelfRestriction,
) std.mem.Allocator.Error!void {
    const read = try chock_core.self_policy.restrictionsFrom(arena, folded);
    defer arena.free(read);
    for (read) |one| {
        try out.append(arena, .{
            .action = try arena.dupe(u8, one.action),
            .ceiling = one.ceiling,
            .reason = try arena.dupe(u8, one.reason),
        });
    }
}

/// Fold the log of the session `id` of the project whose session directory is
/// `dir`. False when there is no such log, or when it could not be read to its
/// end. **`session` still holds everything that was read**, so a caller that
/// wants the part of a torn log has it.
///
/// **The file is checked before the log is opened**, the same rule
/// `src/plan.zig` keeps and for the same reason: `chock_proto.log.Log.open`
/// creates the file and writes a header into it when there is none, so asking
/// about a session that never existed would otherwise bring one into being.
fn foldSessionById(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    session: *chock_proto.state.Session,
) bool {
    std.debug.assert(session_paths.isValidId(id));
    const path = std.fmt.allocPrintSentinel(gpa, "{s}/{s}.jsonl", .{ dir, id }, 0) catch return false;
    defer gpa.free(path);
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;

    const log = chock_proto.log.Log.open(io, path, id) catch return false;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return false;
    defer replay.deinit();
    while (replay.next(io) catch return false) |parsed| {
        defer parsed.deinit();
        session.apply(parsed.value) catch return false;
    }
    return true;
}

/// Fold one session's whole log into `session`.
///
/// `applyWork` runs after `Loop.run` has ended, so the `state.Session` the
/// loop kept is gone and the log is what is left. **A log this cannot read is
/// not a failure here**: the caller wants two numbers to bound a review with,
/// and an unreadable log leaves them at what has been read so far, which is
/// the smaller and therefore the safer answer.
fn foldSession(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    session: *chock_proto.state.Session,
) void {
    var replay = storage.replay(gpa, io, 0) catch return;
    defer replay.deinit();
    while (replay.next(io) catch null) |parsed| {
        defer parsed.deinit();
        session.apply(parsed.value) catch return;
    }
}

/// Put what the log already holds on the display, oldest event first.
///
/// ## Why a resumed session used to open empty
///
/// The display is built with nothing on it, and every row it draws comes from
/// an event the loop is about to write. A session that was taken up has all of
/// its conversation behind it instead, so the transcript stayed empty and a
/// resume read exactly like a fresh start. That is most of why `/resume` read
/// as broken. `ui.Ui.replay` is the display's half of the answer and this is
/// the caller's half.
///
/// ## Every session and not only a resumed one
///
/// **One path, because a fresh log folds to nothing.** At this point phase 1
/// has written the session's opening events and no turn has run, and none of
/// those events is a row: see `ui.Ui.replay`, which sends everything but a
/// message through the same fold the live session uses, and that fold ignores
/// what it does not draw. A flag saying "this run resumed" would be a second
/// answer to a question the log already answers.
///
/// ## What a very long log costs
///
/// Nothing that grows without bound. `ui.Ui.kept_lines` drops the oldest row
/// once there are too many, so a session of thousands of events leaves the
/// newest screenfuls and the memory each one holds is capped. No frame is drawn
/// while this runs either: see `ui.Ui.replay`.
///
/// ## A log that cannot be read is said out loud
///
/// **A refusal to read is not a reason to refuse the session.** The
/// conversation the model is given is folded from the same log by
/// `chock_core.Loop`, and that fold is what decides whether the session can
/// run. This one only decides what is on the screen, so it reports and carries
/// on. The line reaches the display's own transcript, because the display is
/// already up by the time this runs: see `src/ui.zig`'s `Diagnostics`.
fn replayInto(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    screen: *ui.Ui,
) void {
    var replay = storage.replay(gpa, io, 0) catch |err| {
        tty.print(
            .warn,
            "chock: this session's log could not be read back ({s}), so the display opens " ++
                "empty. The conversation itself is unaffected.\n",
            .{@errorName(err)},
        );
        return;
    };
    defer replay.deinit();

    while (true) {
        const parsed = replay.next(io) catch |err| {
            tty.print(
                .warn,
                "chock: this session's log stops being readable ({s}), so the display shows " ++
                    "only what came before that point.\n",
                .{@errorName(err)},
            );
            return;
        } orelse {
            // A torn tail is a crash part way through a write, not a clean end
            // of log, so the last thing that happened may be missing from what
            // is on screen. Said, because a person who resumed after a crash is
            // the person who most needs to know.
            if (replay.truncated()) tty.print(
                .warn,
                "chock: this session's log ends part way through a line, so the last event " ++
                    "before it is not on the display.\n",
                .{},
            );
            return;
        };
        defer parsed.deinit();
        screen.replay(parsed.value.id, parsed.value.event);
    }
}

/// Phase 2. **No `env` parameter**: the environment a tool call resolves
/// `argv[0]` against is `started.tool_env`, which is the dev shell's when
/// the project has one, and nothing else in this phase reads an environment
/// at all.
fn runSession(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    started: *Started,
    options: Options,
    /// Filled with the session `/resume` chose, when one was. `main` takes it
    /// up once this session's workspace and sockets are down: see `takeUp`.
    take_up: *?[]const u8,
    /// Filled with what each audit sink of this session came to. **Carried out
    /// of phase 2 rather than printed inside it**, because the display is still
    /// up here and a line about a sink that stopped arriving has to be one a
    /// person really reads. See `reportShipping`.
    shipped: *ShippingReport,
) !Exit {
    var http = switch (started.adapter) {
        .openai_compatible => chock_provider.Client.HttpClient.init(gpa, io, started.base_url, started.credential.token),
        .anthropic => chock_provider.Client.HttpClient.initAnthropic(gpa, io, started.base_url, started.credential.token),
    };
    defer http.deinit();

    // The toolchain this session mounts, **always named here and never left
    // at the library's own default**. Phase 1 decided it once, out of the dev
    // shell, the image, or the host's own system directories, and refused the
    // session outright when it could produce none of the three. See
    // `Toolchain`.
    var context = chock_core.tools.Context{
        .memory_dir = started.memory_dir,
        // Only a `run_command` call is given this, inside `dispatchWith`:
        // the compiler is the program that writes a cache, and no other tool
        // call has a reason to reach one. See `chock_core.tools.Context`.
        .cache_dir = started.cache_dir,
        .scratch_dir = started.scratch_dir,
        // The one writable area no cap can bound, so it gets a free space floor
        // read before each writing tool call instead. See
        // `chock_core.tools.default_workspace_free_floor_bytes`, which says
        // plainly how much weaker a floor is than a cap.
        .workspace_dir = started.workspace.workPath(),
        .session_id = started.session_id,
    };
    context.store_paths = started.toolchain.store_paths;
    context.toolchain_mounts = started.toolchain.mounts;
    // Provisioning, read by `notFoundRefusal`: a `run_command` call that names
    // a program nobody has is told to call `provide_tool`, and only when this
    // session really has one.
    context.provisioning = started.provisioning != null;
    // The second of the three places the role is read. This one is a boundary
    // and not a list: an arbitrator that named a tool out of nowhere runs
    // nothing. See `chock_core.tools.Role`.
    context.role = agentRole(options);

    // Where a background command's output is written, and what the loop drains
    // at the top of each turn. Null for a session with no scratchpad, which
    // then refuses a background call and says why: see
    // `chock_core.tools.background_needs_a_session`.
    //
    // **The page allocator, and never `gpa`.** A task's own thread allocates
    // from this beside a thread that may be inside `Sandbox.spawn`, and `fork`
    // carries only the calling thread. See `chock_core.tasks.Table.gpa`.
    var table: ?chock_core.tasks.Table = if (started.tasks_dir) |dir| .{
        .gpa = std.heap.page_allocator,
        .dir = dir,
        .runner = chock_core.tools.backgroundRunner(),
    } else null;
    // **Ends every task still running, then waits for it.** A thread of this
    // table writes into a directory phase 3 is about to remove, so leaving one
    // running is not an option. Waiting alone is not one either: a task is
    // measured against `chock_core.tasks.default_timeout_ns`, and a session
    // that is over must not sit for half an hour on a build whose output
    // nobody will now read. `cancelRunningTool` is the same call a second
    // Ctrl-C makes, and it reaches every running call: see
    // `chock_core.tools.cancelRunningTool`.
    defer if (table) |*one| {
        chock_core.tools.cancelRunningTool();
        one.deinit();
    };
    if (table) |*one| context.tasks = one;

    var tool_runner = chock_core.Loop.SandboxToolRunner{
        // The dev shell's environment, when this project has one: see
        // `toolEnvironment`. The host's is what a project with no dev shell
        // still gets.
        .env = started.tool_env,
        .sandbox_config = started.sandbox_config,
        .context = context,
    };

    // The git shim, in front of the sandbox runner: see `GitToolRunner`. It
    // answers the subcommands that cannot work inside the sandbox at all and
    // passes everything else straight through.
    var git_aware = GitToolRunner{ .inner = tool_runner.runner() };

    // This session's language server, and what it has already said. See
    // `lib/chock-core/lsp.zig` for every decision behind it.
    //
    // **A project that named no server leaves every field at its default**, so
    // `afterWrite` answers null before it reaches a seam, no process starts,
    // nothing waits, and the tool result is the one the tool built, byte for
    // byte. That is the first rule of that whole file and it is the cheap
    // path, not the exceptional one.
    var language_server = chock_core.lsp.Session{};

    // The helper the server runs in, and the driver that speaks to it. Both
    // live for the whole session and both are owned here, beside the workspace
    // and the task table, for the reason `DiagnosticToolRunner` states: the
    // registry is one process per call and a language server is not.
    //
    // **Started on the first ask and not here.** A session that never edits a
    // file the server serves never starts one, which is what makes a project
    // with a server cost nothing until it is used.
    var server_helper = chock_core.helper.Helper.init(std.heap.page_allocator);
    // **Ends the helper, then waits for it.** A helper writes below the
    // session scratchpad that phase 3 is about to remove, the same hazard the
    // task table waits for and with a longer life: see
    // `chock_core.helper.Helper.deinit`.
    defer server_helper.deinit(io);

    var server_driver: ?chock_core.lsp_driver.Driver = null;
    defer if (server_driver) |*one| one.deinit();

    // The mount tree and the argv the helper is started with, which outlive
    // every tool call and end with the session, the same reason
    // `provision_arena` below has one of its own.
    var server_arena = std.heap.ArenaAllocator.init(gpa);
    defer server_arena.deinit();

    if (started.language_server) |settings| {
        // The same sandbox a tool call gets, built by the same two functions
        // `chock_core.tools.Registry.dispatchWith` uses, so a helper reaches
        // nothing a tool call cannot: the session's toolchain, then the mount
        // tree, the Landlock rules and the program binding. See
        // `chock_core.tools.prepare`.
        //
        // **The mount set is the one this session starts with.** A program
        // provisioned later joins `Context.store_paths` and reaches the tool
        // calls after it, and it does not reach a helper that is already
        // running, which is the same honest limit `ProvisionToolRunner`
        // already states for a background task and for a subagent.
        const prepared = blk: {
            const with_store = chock_core.tools.withStore(
                server_arena.allocator(),
                io,
                started.sandbox_config,
                context.store_paths,
                context.toolchain_mounts,
            ) catch break :blk null;
            break :blk chock_core.tools.prepare(
                server_arena.allocator(),
                io,
                started.tool_env,
                with_store,
                settings.command,
                &.{},
                &.{},
            ) catch |err| {
                // The program is the project's, so a project that named one
                // this machine does not have hears it now, once, rather than
                // on every edit. The session runs on with no diagnostics,
                // which is exactly what a session with no server does.
                tty.print(
                    .warn,
                    "chock: the language server {s} could not be prepared ({t}), so nothing " ++
                        "checks this session's edits.\n",
                    .{ settings.command[0], err },
                );
                break :blk null;
            };
        };

        if (prepared) |ready| {
            server_driver = .{
                .gpa = gpa,
                .process = &server_helper,
                .request = .{ .config = ready.config, .argv = ready.argv },
                // The host side of the workspace mount, which is where a tool
                // call's write really landed, and the sandbox side, which is
                // what every URI on the wire is built from. See
                // `chock_core.lsp_driver.Driver`.
                //
                // **For an overlay backing this is the upper layer**, which
                // holds only the files the agent has written. That is exactly
                // the set this driver ever asks about, because it is only
                // reached after a write of the file it names: see
                // `DiagnosticToolRunner`. A file the agent has not touched is
                // not read from here at all, and the server still sees it,
                // because the server reads the merged view inside the sandbox.
                .work_root = started.workspace.workPath(),
                .sandbox_root = started.sandbox_config.cwd,
            };
            language_server = .{
                .program = settings.command[0],
                .suffixes = settings.suffixes,
                .server = server_driver.?.server(),
            };
        }
    }

    // In front of the git shim, so it sees the result of a write that really
    // happened. The registry is one process per call, so a server that outlives
    // a call is held out here: see `DiagnosticToolRunner`.
    var diagnosing = DiagnosticToolRunner{
        .inner = git_aware.runner(),
        .session = &language_server,
    };

    // Provisioning, outermost, because it answers a call the two runners below
    // it have no way to answer and changes what the one below them mounts. See
    // `ProvisionToolRunner`.
    //
    // **Its own arena**, whose contents outlive every tool call and end with
    // the session: a store path the sandbox mounts on the last turn was
    // allocated on the turn the program was provisioned.
    var provision_arena = std.heap.ArenaAllocator.init(gpa);
    defer provision_arena.deinit();

    var provisioning = ProvisionToolRunner{
        .inner = diagnosing.runner(),
        .settings = started.provisioning,
        .arena = provision_arena.allocator(),
        .host_env = env,
        .environ = environ,
        .tool_env = started.tool_env,
        .context = &tool_runner.context,
    };
    // The dev shell's own paths, taken in first, so the list this runner
    // grows is the whole mount set and never only the additions.
    try provisioning.start(context.store_paths);

    // This session's MCP servers, and the tools they supply.
    //
    // **A project that named none pays for nothing at all.** `mcp_servers` is
    // null in that case, `startMcp` returns before it touches anything, the
    // session offers exactly the tools it offered before this existed, and the
    // system prompt below is the one phase 1 already built, byte for byte.
    //
    // **Started here and not in phase 1**, unlike every other block of
    // `chock.zon`. A server has to be asked what tools it has before the model
    // can be offered one, and asking means starting a process, which means a
    // `fork`. Phase 1 runs beside the threads that build the workspace, and a
    // `fork` there carries a lock another thread holds: see
    // `chock_core.helper.Helper.arena`. So the tool list is finished here, and
    // the system prompt is built a second time from the pieces phase 1 kept.
    var mcp_state = McpState.init(gpa);
    defer mcp_state.deinit(io);

    const mcp_definitions, const mcp_prompt = try startMcp(
        gpa,
        io,
        started,
        options,
        &context,
        &mcp_state,
    );

    // This session's plugins, and the tools they supply.
    //
    // **A project that named none pays for nothing at all**, the same rule the
    // MCP block above keeps: `plugins` is null in that case, `startPlugins`
    // returns before it touches anything, and the pair below is the one the
    // line above answered, byte for byte.
    //
    // **After MCP**, because two suppliers of tools reach one model through one
    // name space and the one that is already in the session keeps its names:
    // see `startPlugins`.
    var plugin_state = PluginState.init(gpa);
    defer plugin_state.deinit(io);

    const tool_definitions, const system_prompt = try startPlugins(
        gpa,
        io,
        started,
        options,
        &context,
        &plugin_state,
        &mcp_state.session,
        mcp_definitions,
        mcp_prompt,
    );

    // A name an MCP server supplies must never reach the sandbox runner, the
    // git shim or the provisioner at all. See `McpToolRunner`.
    var mcp_aware = McpToolRunner{
        .inner = provisioning.runner(),
        .state = &mcp_state,
    };

    // Outermost of the tool runners, and a plugin name reaches nothing else.
    // See `PluginToolRunner`, which is the same wrapper one layer out.
    var plugin_aware = PluginToolRunner{
        .inner = mcp_aware.runner(),
        .state = &plugin_state,
    };

    // What starts a subagent. See `SubagentSpawner`: a child is a process,
    // because `fork` carries only the calling thread and a tree built from
    // threads would deadlock the first time a child ran a tool.
    var subagent_spawner = SubagentSpawner{
        .gpa = gpa,
        .environ = environ,
        .env = env,
        .started = started,
        .agent_kind = options.agent_kind,
    };

    // The children this session starts and does not wait for. The same shape
    // the background command table above takes, and the same allocator, for the
    // same reason: a child's own thread allocates from this beside a thread that
    // may be inside `Sandbox.spawn`, and `fork` carries only the calling thread.
    // See `chock_core.subagent.Table.gpa`.
    var children = chock_core.subagent.Table{
        .gpa = std.heap.page_allocator,
        .spawner = subagent_spawner.spawner(),
    };
    // **Waits, and does not cancel.** A child writes into a session directory
    // below this session's own scratchpad, which phase 3 is about to remove, so
    // leaving one running is not an option. Ending it is a different thing from
    // ending a background command: a child holds a log of its own that a person
    // reads afterwards, and a child killed between two turns leaves one with no
    // `session.end`, which its parent then reads as a child that died. A Ctrl-C
    // already reaches it, because a child stays in this process's own process
    // group: see `SubagentSpawner.runToTheEnd`. `Loop.run` has already waited
    // and recorded every child by the time this runs, so this ordinarily has
    // nothing left to wait for.
    defer children.deinit();

    // What the two thread tables lost, if either lost anything. Both fill
    // their slot on a child's own thread at the one moment the allocator has
    // already refused, so neither can give an error back and neither may
    // allocate a message. They kept a plain value instead, and this is where
    // a person is told about it: a subagent whose record was lost is a
    // `session.spawn` with no `agent.complete` after it, and a log that reads
    // that way with nothing said is a session nobody can explain.
    defer {
        if (children.takeLost()) |lost| tty.print(.warn, "chock: {f}\n", .{lost});
        if (table) |*one| {
            if (one.takeLost()) |lost| tty.print(.warn, "chock: {f}\n", .{lost});
        }
    }

    var printer = Printer.init(gpa, io);
    printer.paint = tty.stdoutPainter();
    // The plan fold this holds outlives every event, so it is freed once, here,
    // and never rebuilt when the display takes the printer's output over.
    defer printer.deinit();

    // The display, for bare `chock` and for nothing else: see
    // `Options.display`. **One implementation of `chock_core.Loop.Observer`
    // wrapping another**, so the printer keeps composing every line, into the
    // display's own buffer instead of standard output, and the display shows
    // the tail of that buffer. `chock run` and the interface therefore carry
    // the same bytes by construction and not by two code paths agreeing.
    //
    // **Opened here and not by the caller**, so its header band carries the
    // project, the workspace and the model from its first frame: all three are
    // worked out in phase 1, which has already run. See `Display`.
    var screen: ?*ui.Ui = null;
    // Before phase 3, which prints for a person to read: see `stop`. Freeing is
    // separate, because the transcript outlives the display.
    defer if (screen) |one| one.deinit();

    if (options.display) |wanted| {
        screen = ui.Ui.start(gpa, io, env, wanted.attach) catch |err| open_failed: {
            // A terminal that will not give its size is a reason to print the
            // old way, not a reason to end a session. Nothing was taken: see
            // `Ui.start`.
            tty.print(
                .warn,
                "chock: the display could not start ({s}), printing plainly instead.\n",
                .{@errorName(err)},
            );
            break :open_failed null;
        };
    }

    // The sandbox layers of this session, which the header borrows for as long
    // as it is up. Declared here, before the display, so it outlives it. See
    // `sandboxLayers` for where each one comes from.
    const layers = sandboxLayers(
        sandbox.Sandbox.guarantees,
        started.sandbox_config.network,
        switch (started.workspace.kind) {
            .worktree => "worktree",
            .overlay => "overlay",
        },
    );

    if (screen) |one| {
        // **Unpainted, because the transcript is read twice**: once as text in
        // the cells of the display, where an escape sequence would be a stray
        // sequence at a place on the screen nothing chose, and once on the real
        // screen when the display comes down.
        //
        // **Field by field and not a fresh value**, so the plan fold this
        // printer holds is the same one for the whole session. See `deinit`.
        printer.paint = .off;
        printer.out = .{ .buffer = .{ .gpa = gpa, .bytes = &one.transcript } };
        one.wrap(printer.observer());
        // What the header band says. **Only this file holds these**, which is
        // why they are handed over rather than read: see `ui.Facts`. Every one
        // of them lives in the arena for the whole run, so the display may
        // borrow them.
        one.describe(.{
            .project = std.fs.path.basename(started.project_root),
            .workspace = switch (started.workspace.kind) {
                .worktree => "worktree",
                .overlay => "overlay",
            },
            .model = started.model,
            // The provider instance's own name, which is what `model_alias`
            // holds today: see `Started.model_alias`.
            .provider = started.model_alias,
            // **The part of the header a person is there to see.** See
            // `sandboxLayers`. It ranks above the four facts on the same row.
            .layers = &layers,
        });
        // Where this project keeps its sessions, and which one this is, so
        // `/resume` can offer the others. See `ui.Ui.resumable`.
        one.resumable(started.paths.dir, started.session_id);
        // **After the header and before the first message is asked for.** The
        // order is the whole of it: `describe` fills the band, this fills the
        // transcript under it, and the loop below then asks for a message. The
        // other order shows an empty header over a full transcript.
        replayInto(gpa, io, started.storage, one);
        // A message already on standard input is the first turn's, so a piped
        // run and a typed one take one path through the loop below.
        if (options.display.?.first_message.len != 0) one.prime(options.display.?.first_message);
    }

    // What the harness tells the agent that the agent cannot work out for
    // itself, and the clock the time part of it reads. The offset is read once
    // here, from the machine's own zone database, because a session that is
    // hours long does not cross a summer time boundary often enough to be
    // worth reading again every turn. See `src/clock.zig`.
    const wall = clock.Real{
        .io = io,
        .offset_minutes = clock.localOffsetMinutes(
            gpa,
            io,
            std.Io.Timestamp.now(io, .real).toMilliseconds(),
        ),
    };

    // From here to the end of the session, Ctrl-C asks the session to stop
    // rather than killing the process where it stands. **The point is the
    // `session.end`**: a signal does not run a deferred append, so a killed
    // session left a log that stops mid conversation with nothing saying why,
    // and nothing replaying it, `--continue` included, could tell that apart
    // from a process that died mid write. See `interrupt` and
    // `chock_core.Loop.Deps.canceled`.
    //
    // Installed here and not in phase 1: before the loop exists there is
    // nothing reading the flag, so a Ctrl-C during the workspace build keeps
    // the plain old behaviour of ending the process at once.
    interrupt.install();

    // And from here another process can ask for this session. Armed here for
    // the same reason the signal handler is installed here: before the loop
    // exists there is nothing to read the answer, so a `chock detach` that
    // arrived during the workspace build waits for the first turn boundary,
    // which is the first moment the answer means anything.
    //
    // **Nothing is armed for a session whose socket could not be opened**, and
    // that session simply cannot be taken. See `handoverEndpoint`.
    if (started.handovers) |endpoint| handover.arm(endpoint);
    // Before phase 3 closes the endpoint, and before this phase's `Io` goes.
    defer handover.disarm();

    var session_arbiter = SessionArbiter{
        .gpa = gpa,
        .environ = environ,
        .env = env,
        .started = started,
        .options = options,
        .screen = screen,
    };

    // What answers a `fetch_url` call. **Its own arena**, because the spawn
    // chain and the promises of the sessions above this one are read once here
    // and read again on every call for the rest of the session.
    var fetch_arena = std.heap.ArenaAllocator.init(gpa);
    defer fetch_arena.deinit();

    var fetcher = SessionFetcher{
        .gpa = gpa,
        .session = .{
            .gpa = gpa,
            // Read one time at the start of the session, and it cannot change
            // while the session runs.
            .table = started.policy,
            // The same chain every other policy question folds, so a subagent
            // can read no host its parent may not.
            .chain = try policyChain(fetch_arena.allocator(), started, options),
            .agent_kind = options.agent_kind,
            .model = started.model,
            // Replaced per call with the tool that really asked. See
            // `SessionFetcher.fetchFn`.
            .tool = chock_core.Loop.fetch_tool_name,
            .env = env,
        },
        .ancestors = ancestors: {
            var above = chock_proto.state.Session.init(gpa);
            defer above.deinit();
            // An empty session, so this reads the ancestors and nothing else:
            // this session's own promises arrive on every call from the loop's
            // own fold, which is the only reading that is current in the
            // middle of a turn. See `SessionFetcher`.
            break :ancestors promisesFor(
                gpa,
                fetch_arena.allocator(),
                io,
                started.paths.dir,
                options.parent_session,
                &above,
            ) catch &.{};
        },
    };
    defer fetcher.deinit();

    // The audit sinks of this session, or none at all. **A session that named
    // no sink opens no file and makes no socket**, and the observer the loop is
    // given below is then the printer's or the display's own, which is what
    // makes such a session the very session it was before export existed.
    //
    // Declared before the exporter, so its own `defer` runs after the
    // exporter's last push. The other order would close the file the final
    // `session.end` still has to travel through.
    var sinks = Sinks{};
    defer sinks.close(io);
    sinks.open(options, started.audit_sinks, started.session_id);

    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = started.storage,
        .inner = if (screen) |one| one.observer() else printer.observer(),
        .sinks = sinks.slice(),
    };
    // **On every path out of this function**, a crash included. The last line
    // of a session is its `session.end`, and that is what tells a reader at the
    // far end that they are looking at a whole record rather than one that
    // stopped.
    defer if (sinks.count != 0) exporter.finish(shipped);

    // **A sink this installation requires is reached for now, and not when the
    // first event fails to ship.** See `Exporter.probe`, and `chock_policy.org`
    // for the decision this is one third of. A session that requires nothing
    // does nothing here, which is what keeps an installation with no bundle
    // behaving as it did.
    if (sinks.anyRequired()) exporter.probe();

    // What puts an `ask_user` question to the person. **Declared here so it
    // outlives `deps`**, which holds a pointer into it.
    //
    // **Two of them, and a session has exactly one.** A session with a display
    // asks in the region `src/ui.zig` keeps for it, and a session with none asks
    // at the bare prompt exactly as it always did. Never both: the display holds
    // the terminal in raw mode and keeps a copy of every cell, so a prompt
    // written around it lands in cells it believes it owns and two readers race
    // for every byte. That is the same rule `asksHere` keeps for an approval.
    //
    // **`at_terminal` is the whole refusal rule for the prompt.** A subagent, a
    // session the daemon started, and a `chock run` whose standard input is a
    // pipe all read false there, so the question comes straight back and the
    // agent is told nobody was asked.
    var question_console = QuestionConsole{};
    var question_prompt = chock_core.ask.Prompt{
        .console = question_console.console(),
        .at_terminal = approval.hasTerminal(io) and screen == null,
        .stop = interrupt.requested,
    };
    var display_asker = DisplayAsker{
        // Never read while `screen` is null: see the `asker` line below.
        .screen = screen orelse undefined,
        .agent_kind = options.agent_kind,
    };

    // What keeps the display alive through every wait this session makes.
    // **Declared here so it outlives both the client and `deps`**, each of which
    // holds a pointer into it. A session with no display has none of this, and
    // both waits then behave exactly as they did before it existed.
    var pump = DisplayPump{ .screen = screen orelse undefined };
    if (screen != null) {
        http.idle = pump.providerIdle();
        // The runner's own copy, which is the one a dispatch reads: `context`
        // above was copied into it. See `chock_core.tools.Context.idle`.
        tool_runner.context.idle = pump.coreIdle();
    }

    var deps = chock_core.Loop.Deps{
        .client = http.client(),
        .storage = started.storage,
        .tool_runner = plugin_aware.runner(),
        // The built-in list, plus whatever this project's MCP servers and
        // plugins declared and the policy allowed. Identical to
        // `started.tool_definitions` for a project that named neither: see
        // `startMcp` and `startPlugins`.
        .tool_definitions = tool_definitions,
        .model = started.model,
        .model_alias = started.model_alias,
        .agent_kind = options.agent_kind,
        // The third of the three places the role is read. The loop answers
        // `spawn_agent`, `update_plan` and `restrict_self` itself, so this is
        // what stops an arbitrator starting a subagent: see
        // `chock_core.Loop.Deps.role`.
        .role = agentRole(options),
        .system_prompt = system_prompt,
        // The printer, or the display, or either of those with an exporter in
        // front of it. **The exporter wraps and never replaces**, the same shape
        // the display already takes over the printer, so a session with an audit
        // sink prints exactly what a session without one prints.
        .observer = if (sinks.count != 0) exporter.observer() else exporter.inner,
        .canceled = interrupt.requested,
        // **Only at a turn boundary, which is why this is not `canceled`.** A
        // session that stopped between two tool calls of one turn leaves an
        // assistant message whose `tool_use` parts have no matching results,
        // and the next owner has to send that context to a provider. See
        // `chock_core.Loop.Deps.handover`.
        .handover = handover.requested,
        .budget = started.budget,
        .billing = started.billing,
        // The chain is empty for a session a person started, and holds the
        // parent for a session another agent started: see `spawnChain`, and
        // `Options.parent_kind`, which is what makes the policy an intersection
        // rather than this session's own kind alone.
        .subagents = started.subagents,
        .spawn_chain = started.spawn_chain,
        .parent_session = options.parent_session,
        .spawner = subagent_spawner.spawner(),
        // What a spawn that asked to carry on is started on, and what the loop
        // drains at the top of each turn: see `chock_core.Loop.Deps.children`.
        .children = &children,
        // The threshold trigger. Null here leaves the overflow backstop as the
        // only trigger, which is the honest behaviour for a model whose limit
        // nobody stated: see `chock_core.compaction.Policy`.
        .compaction = .{ .context_limit_tokens = started.context_tokens },
        // The prompt is kept short, and none of this reaches it: a notice goes
        // at the end of the context, on the turn it applies to, so the
        // provider's cache keeps the same prefix it had last turn. See
        // `chock_core.notices`.
        .notices = .{
            .enabled = !options.no_notices,
            .clock = wall.clock(),
        },
        .uncommitted_files = started.uncommitted_files,
        // The same table `context.tasks` above gives the tool runner. The
        // runner fills it and the loop drains it: see
        // `chock_core.Loop.Deps.tasks`.
        .tasks = if (table) |*one| one else null,
        // The ratchet. What the loop asks when an agent proposes to widen a
        // promise it already made. Before the approval socket there was nobody
        // who could answer mid session, so every such proposal was refused
        // unasked: see `SessionArbiter`.
        .arbiter = session_arbiter.arbiter(),
        // What answers a `fetch_url` call. **This line is the difference
        // between a tool the model is offered and a tool that does something**:
        // `chock_core.Loop.Deps.fetcher` defaults to null, and a session with
        // none tells the agent it can read nothing. See `SessionFetcher`, and
        // `lib/chock-broker/fetch.zig` for every decision behind it.
        .fetcher = fetcher.fetcher(),
        // What answers an `ask_user` call. **This line is the difference
        // between a tool the model is offered and a tool that reaches a
        // person**: `chock_core.Loop.Deps.asker` defaults to null, and a session
        // with none tells the agent nobody was asked.
        //
        // **It is not the arbiter and never becomes one.** An ask grants
        // nothing, whatever the person types: see `lib/chock-core/ask.zig`'s own
        // top comment for why the two paths stay apart.
        //
        // **The display when there is one, and the bare prompt otherwise.** See
        // `DisplayAsker`, which is the half of this feature that was missing
        // until now: a session with a display told the agent nobody was asked,
        // however many people were watching it.
        .asker = if (screen != null) display_asker.asker() else question_prompt.asker(),
        // **What keeps this session's own credential out of a provider
        // request**, built in phase 1 beside the credential it borrows: see
        // `redactionFor`. `chock_core.Loop.Deps.redact` defaults inert, so this
        // line is the difference between a mechanism and a running one.
        //
        // **The request is redacted and the log is not**, which is
        // `lib/chock-core/redact.zig`'s own decision: the record stays complete,
        // so `chock sessions verify` and every command that folds a log still
        // mean what they meant.
        .redact = started.redact,
    };
    // Null unless the caller asked for a limit, which is what `Loop.Deps`
    // already defaults to: see its own doc comment on why a turn count is
    // not the stop condition.
    deps.max_turns = options.max_turns;

    // **One turn for `chock run`, and as many as the person asks for in the
    // interface.** `chock run` takes one message on its command line and gets
    // one answer, which is this loop going round once. The interface asks for
    // the next message when the loop comes back and appends it to the log the
    // same way `start` appended the first, so a second turn is the same thing
    // `chock run --continue` does, in one process and without letting the log
    // lock go.
    //
    // **`Loop.run` needs nothing new for this.** It folds the log it is given,
    // appends no second `session.start` when the fold found one, and carries on
    // from whatever is there. A log with several `session.end` events is
    // exactly what a session that was continued looks like, and `finalExit`
    // reads the last of them.
    // **Every message the interface sends is asked for here, the first one
    // included.** `start` appends none when there is a display, so a piped
    // message and a typed one take the same path: see `Ui.prime`.
    var turns: usize = 0;
    while (true) {
        if (screen) |one| {
            switch (try one.askForMessage(gpa)) {
                // An empty line, Ctrl-C at the field, or a display that
                // stopped. See `Ui.askForMessage`.
                .done => break,
                .message => |next| {
                    defer gpa.free(next);
                    try appendUserMessage(gpa, io, started.storage, next);
                },
                // **`/resume`.** This session ends here, cleanly and with its
                // own `session.end`, exactly as leaving does; the identifier is
                // carried out to `main`, which takes the other one up once this
                // one's workspace and sockets are down. See `takeUp`.
                .take_up => |id| {
                    take_up.* = id;
                    break;
                },
            }
        }

        try chock_core.Loop.run(gpa, io, deps);
        turns += 1;
        if (screen == null) break;

        // Read out of the log rather than out of a flag, for one reason: the
        // log is the truth of a session, and whether this turn finished is a
        // statement about the session.
        if (!keepAsking(try finalExit(gpa, io, started.storage), interrupt.requested())) break;
    }

    // **A session nobody asked anything of has no ending to read.** `Loop.run`
    // is what writes a `session.end`, and it never ran, so the log holds a
    // `session.start` and nothing else. That is the same outcome as bare `chock`
    // with no message at all, and it reports the same way.
    if (turns == 0) return .usage;

    return try finalExit(gpa, io, started.storage);
}

/// Whether the interface asks for another message after a turn that ended this
/// way.
///
/// **Only a turn that finished earns the next question.** Every other ending is
/// the session saying it is over: Ctrl-C, a handover to another process, a
/// budget that ran out, a refusal nobody answered, a turn limit, a crash.
/// Putting a field on the screen of a session that is already ending would ask
/// a person for work that nothing would do, and the workspace and the log are
/// being taken down underneath it.
///
/// **`interrupted` is read as well as the ending**, and it is not the same
/// question: a Ctrl-C that landed after this turn's `session.end` was written
/// leaves a finished turn and a person who has asked to stop. It costs one
/// atomic read and it closes that window.
fn keepAsking(ending: Exit, interrupted: bool) bool {
    if (interrupted) return false;
    return ending == .finished;
}

/// The exit code, read back out of the log rather than out of whatever the code
/// happened to return: the log is the truth of a session, and the exit code is
/// a statement about the session.
fn finalExit(gpa: std.mem.Allocator, io: std.Io, storage: chock_proto.storage.Storage) !Exit {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();

    var last: Exit = .faulted;
    var saw_end = false;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .session_end) continue;
        const ended = parsed.value.event.session_end;
        last = exitFor(ended.reason);
        saw_end = true;
    }
    // A log with no `session.end` at all is a session that stopped without
    // saying why, which is a fault however it happened.
    if (!saw_end) return .faulted;
    return last;
}

/// How many audit sinks one session can have: a file drop and a syslog socket
/// from the command line, and every sink the org policy bundle requires. See
/// `lib/chock-proto/ship.zig` for what one over a network would need that this
/// command's own single threaded rule does not allow, and `chock_policy.org`
/// for why a bundle's own count is bounded too.
const max_sinks: usize = chock_policy.org.max_sinks + 2;

/// What each audit sink of one session came to, carried out of phase 2 so phase
/// 3 can say it once the display is down.
///
/// **Fixed size and it allocates nothing.** It is filled on the session's own
/// path, where the `Io` cannot start a thread, and read after that path has
/// gone. A `Health` holds counts, an error, and a literal of
/// `lib/chock-proto/ship.zig`, so nothing in it points at anything phase 2
/// owned.
const ShippingReport = struct {
    entries: [max_sinks]Entry = undefined,
    count: usize = 0,

    const Entry = struct {
        /// What a person calls this sink: the file it writes, or the socket it
        /// speaks to. Lives as long as the run does.
        name: []const u8,
        health: chock_proto.ship.Health,
        /// Whether the installation required this sink. See `PlannedSink`.
        required: bool = false,

        /// Whether this sink holds less than the whole of the session's log,
        /// and will never hold the rest.
        ///
        /// **Two ways, and both are permanent.** A tail nothing was shipped
        /// from is a tail that is on this machine and nowhere else, because the
        /// session is over and nothing will push again. A refused line is one
        /// the sink was there for and would not carry, and retrying it would
        /// send the same bytes to the same sink for ever, so it is a hole in
        /// the record as much as the tail is.
        ///
        /// **A sink that was down and came back is not a gap.** The log on disk
        /// is the queue, so the shipper gave it every line it missed and
        /// `stalled_at` cleared. That is why this is read at the end and never
        /// while the session runs.
        fn gap(self: Entry) bool {
            return self.health.stalled_at != null or self.health.refused != 0;
        }
    };

    fn add(self: *ShippingReport, one: Entry) void {
        if (self.count >= self.entries.len) return;
        self.entries[self.count] = one;
        self.count += 1;
    }

    fn slice(self: *const ShippingReport) []const Entry {
        return self.entries[0..self.count];
    }

    /// Whether a sink this installation **required** holds less than the whole
    /// of this session's log. See `Exit.audit_gap`, which is what this decides,
    /// and `chock_policy.org` for why an organisation gets an exit status here
    /// and never a session that refused to run.
    ///
    /// **Only a required sink.** A `--export-dir` somebody typed is that
    /// person's own business, and a full disk under it must not turn a
    /// developer's own run red.
    fn requiredGap(self: *const ShippingReport) bool {
        for (self.slice()) |one| {
            if (one.required and one.gap()) return true;
        }
        return false;
    }
};

/// Say what left this machine.
///
/// **A line either way, and a rank that tells them apart.** A session whose
/// export worked says so in one plain line, which is what makes the absence of
/// that line mean something; a session whose sink was down says the whole state
/// as a warning. Prints nothing at all for a session that asked for no sink.
///
/// **A sink the installation required says so, and names the installation.**
/// Nobody typed it, so a reader who is told only a path goes looking through a
/// command line that does not hold it. And a gap in a required trail is the one
/// thing here that reaches the exit status, so the line that reports it has to
/// be the line that explains that code.
fn reportShipping(report: *const ShippingReport) void {
    for (report.slice()) |one| {
        if (!one.health.wantsSaying()) {
            tty.print(.plain, "chock run: {d} lines of this session's log reached {s}{s}.\n", .{
                one.health.delivered,
                one.name,
                if (one.required) ", which this installation requires" else "",
            });
            continue;
        }
        if (!one.required) {
            tty.print(.warn, "chock run: the audit sink {s}: {f}\n", .{ one.name, &one.health });
            continue;
        }
        tty.print(
            .warn,
            "chock run: {s} is an audit sink this installation's org policy requires: {f}\n",
            .{ one.name, &one.health },
        );
        if (!one.gap()) continue;
        tty.print(
            .warn,
            "chock run: part of this session's record is on this machine and nowhere else. The " ++
                "session itself is not a failure, because a session must not fail because an " ++
                "audit sink is down. The record is, and a session that otherwise finished " ++
                "reports it as exit {d}.\n",
            .{Exit.audit_gap.code()},
        );
    }
}

/// The audit sinks of one session: every `PlannedSink` `auditSinks` resolved
/// out of the command line and out of the org policy bundle, and nothing at all
/// when there were none.
///
/// **Its own type so the wiring is a fact a test can check.** Three mechanisms
/// in this project have shipped with green tests and no real caller, and a sink
/// built inside a function no test drives would be the fourth.
///
/// **Never moved after `open`.** Each `Sending` holds a `Sink` pointing into
/// this struct's own `drops` or `syslogs`, so a copy of a `Sinks` has shippers
/// aimed at the original. `runSession` keeps one on its own frame and nothing
/// else holds one.
/// **It owns no string.** Every name here is the run's own arena, built in
/// phase 1, because a `ShippingReport` borrows these names and is read in phase
/// 3. See `auditSinks` for the crash that taught this.
const Sinks = struct {
    /// One transport per planned sink, in the slot its `Sending` points at. A
    /// bundle may require several of a kind, so neither of these is a single
    /// value any more.
    drops: [max_sinks]chock_proto.ship.FileDrop = @splat(.{ .path = "" }),
    syslogs: [max_sinks]chock_proto.ship.Syslog = @splat(.{ .path = "" }),
    drop_count: usize = 0,
    syslog_count: usize = 0,
    sending: [max_sinks]Exporter.Sending = undefined,
    count: usize = 0,

    /// Build every sink in `planned`, which is `Started.audit_sinks`.
    ///
    /// **Fails at nothing, and allocates nothing.** An audit sink must never be
    /// a reason a session does not start, the paths are already built, and that
    /// holds for a required sink as much as for one somebody typed: see
    /// `chock_policy.org`.
    fn open(self: *Sinks, options: Options, planned: []const PlannedSink, session_id: []const u8) void {
        // **Whether this run took up a log another run wrote.** A sink that
        // cannot say what it already holds is then given lines it may have, and
        // it is told so; a session nobody continued has nothing that can arrive
        // twice. See `chock_proto.ship.Health.resent_from_start`. `--session` for
        // an identifier that names no log yet is counted here as well, which
        // over-states rather than under-states, and over-stating is the safe
        // direction for a note about duplicates.
        const continued = options.adopt or options.continue_newest or options.session != null;
        for (planned) |one| {
            if (self.count >= self.sending.len) return;
            const sink = switch (one.kind) {
                .directory => made: {
                    if (self.drop_count >= self.drops.len) return;
                    const slot = &self.drops[self.drop_count];
                    self.drop_count += 1;
                    slot.path = one.path;
                    break :made slot.sink();
                },
                .syslog => made: {
                    if (self.syslog_count >= self.syslogs.len) return;
                    const slot = &self.syslogs[self.syslog_count];
                    self.syslog_count += 1;
                    slot.path = one.path;
                    break :made slot.sink();
                },
            };
            self.sending[self.count] = .{
                .name = one.path,
                .required = one.required,
                .shipper = .{ .sink = sink, .session = session_id, .continued = continued },
            };
            self.count += 1;
        }
    }

    fn slice(self: *Sinks) []Exporter.Sending {
        return self.sending[0..self.count];
    }

    /// Whether this installation required any of these. See `Exporter.probe`:
    /// a required sink is reached for before the first turn and an optional one
    /// is not.
    fn anyRequired(self: *const Sinks) bool {
        for (self.sending[0..self.count]) |one| {
            if (one.required) return true;
        }
        return false;
    }

    fn close(self: *Sinks, io: std.Io) void {
        for (self.syslogs[0..self.syslog_count]) |*one| one.close();
        for (self.drops[0..self.drop_count]) |*one| one.close(io);
    }
};

/// Ships each event to an audit sink as the loop appends it, and passes every
/// call on to the observer it wraps.
///
/// **It reads the log and never writes it.** `Loop.run` owns that file and holds
/// its exclusive lock for the whole session, so a second writer of it is the one
/// thing this may not become. See `lib/chock-proto/ship.zig`, which carries the
/// whole argument, and `chock_core.Loop.Observer`, whose `onEvent` returns
/// nothing exactly so that a watcher cannot stop a session.
const Exporter = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    /// The observer this one wraps: the printer, or the display.
    inner: chock_core.Loop.Observer,
    sinks: []Sending,
    /// Whether a fault has already been said.
    ///
    /// **Said once, and not once an event.** A sink that is down is down for
    /// every event after it, and a line per event would bury the session the
    /// lines are about. The end of the run says the whole state again, with the
    /// counts: see `reportShipping`.
    said: bool = false,

    const Sending = struct {
        name: []const u8,
        shipper: chock_proto.ship.Shipper,
        /// Whether this installation required this sink. See `PlannedSink`.
        required: bool = false,
    };

    fn observer(self: *Exporter) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    /// **The inner observer first, and the sinks after.** A person watching sees
    /// the line at the same moment they would have seen it with no export at
    /// all, so turning export on cannot slow the terminal down behind a sink.
    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        const self: *Exporter = @ptrCast(@alignCast(ptr));
        self.inner.onEvent(id, ev);
        self.push();
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Exporter = @ptrCast(@alignCast(ptr));
        self.inner.onPiece(piece);
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *Exporter = @ptrCast(@alignCast(ptr));
        self.inner.onNotice(text);
    }

    /// Ship whatever the log has gained. Fails at nothing: everything that went
    /// wrong is in the shipper's own health record.
    fn push(self: *Exporter) void {
        for (self.sinks) |*one| {
            const before = one.shipper.health.faults;
            one.shipper.push(self.gpa, self.io, self.storage);
            if (one.shipper.health.faults == before or self.said) continue;
            self.said = true;
            self.sayFault(one.*);
        }
    }

    /// Tell whoever is watching, at the moment it happens.
    ///
    /// **Through the observer this wraps and never through `tty`.** A display
    /// may be up, and a line written straight to standard error would land
    /// behind an alternate screen where nobody reads it.
    /// `chock_core.Loop.Observer.onNotice` is the one channel that reaches a
    /// person whichever way they are watching, and it is deliberately not an
    /// event: this says what the harness is doing, not what the session did.
    fn sayFault(self: *Exporter, one: Sending) void {
        var buffer: [512]u8 = undefined;
        const why = @errorName(one.shipper.health.first_fault orelse error.Unexpected);
        // **A required sink names the installation and not a flag.** Nobody
        // typed this path, so a reader told only a path goes looking through a
        // command line that does not hold it.
        const text = if (one.required) std.fmt.bufPrint(
            &buffer,
            "{s} could not be reached ({s}). This installation's org policy requires that sink. " ++
                "The session carries on, because it must not fail because an audit sink is down, " ++
                "and the log keeps every line the sink missed until it comes back.",
            .{ one.name, why },
        ) catch return else std.fmt.bufPrint(
            &buffer,
            "the audit sink {s} could not be reached ({s}). The session carries on, and the log " ++
                "keeps every line the sink missed until it comes back.",
            .{ one.name, why },
        ) catch return;
        self.inner.onNotice(text);
    }

    /// Reach for every sink before the first turn.
    ///
    /// **Only worth doing when a sink is required**, and `runSession` calls it
    /// only then, which is what keeps an installation with no bundle behaving
    /// exactly as it did. An optional sink is a person's own choice and finding
    /// it down when the first event fails to ship is soon enough.
    ///
    /// A required sink is not that: nobody at this keyboard chose it, the
    /// person who did cannot see this machine, and being told before a model
    /// has spent anything is the difference between a fixable morning and a
    /// session whose record does not exist. The push is not extra work either:
    /// the header line has to travel before any event can, so this is the same
    /// bytes at an earlier moment.
    fn probe(self: *Exporter) void {
        self.push();
    }

    /// Ship what is left, make each sink durable, and record what each came to.
    fn finish(self: *Exporter, report: *ShippingReport) void {
        for (self.sinks) |*one| {
            one.shipper.finish(self.gpa, self.io, self.storage);
            report.add(.{
                .name = one.name,
                .health = one.shipper.health,
                .required = one.required,
            });
        }
    }
};

/// Prints what happens, as it happens. See `chock_core.Loop.Observer`: the
/// loop holds the exclusive lock on the log for the whole session, so this is
/// the only way a caller sees anything before the session ends.
/// **What the model says is shown while it says it**, through
/// `chock_core.Loop.Observer.onPiece`: see that method for the measured
/// silence it exists to end. The `message` event that closes a turn then adds
/// only the newline, because every word in it has already been on the screen
/// for however long the turn took. `streamed` is what remembers that.
const Printer = struct {
    io: std.Io,
    /// Feeds `plan_arena` and nothing else. See `plan`.
    gpa: std.mem.Allocator,
    /// Where the bytes go. `.stdout` is every real caller, and the default,
    /// so a session needs to say nothing. A test gives `.buffer` instead, so
    /// what a terminal would have shown becomes a value a test can read: see
    /// the tests named for the blank line at the end of this file.
    out: Out = .stdout,
    /// The escape sequences this printer may use. **`off` by default**, so a
    /// test that builds one and does not ask for colour compares plain bytes,
    /// and so a printer somebody forgets to configure writes what it always
    /// wrote. The real caller passes `tty.stdoutPainter()`, which is off unless
    /// standard output is a terminal that can show colour: see `src/tty.zig`.
    ///
    /// **What the model says is never painted.** The answer is the program's
    /// output, a person may be piping it somewhere, and Chock has no way to
    /// know which words in it matter. Only the lines Chock writes around it
    /// carry a rank.
    paint: tty.Painter = .off,
    /// How many pieces of this turn's answer have been printed as they
    /// arrived. Reset by the `message` event that closes the turn.
    ///
    /// **Without this the answer is printed twice**, once piece by piece and
    /// once whole, and the second copy arrives only when the turn is already
    /// over.
    streamed: usize = 0,
    /// The task list as it stands, folded from every `plan.update` so far.
    ///
    /// **One row for a whole update needs the whole list**, and one event
    /// carries only the steps that moved: see `foldPlan`. Without this fold
    /// the printer can say what changed and cannot say how much of the work is
    /// done, which is the number a person watching wants.
    plan: chock_proto.state.Plan = .{},
    /// Owns every string in `plan`. **Made on the first update and never
    /// reset**, because a plan is at most a few dozen short steps and a step
    /// that is reworded a hundred times still costs a few kilobytes.
    plan_arena: ?std.heap.ArenaAllocator = null,

    const Out = union(enum) {
        stdout,
        buffer: struct { gpa: std.mem.Allocator, bytes: *std.ArrayList(u8) },
    };

    fn init(gpa: std.mem.Allocator, io: std.Io) Printer {
        return .{ .gpa = gpa, .io = io };
    }

    fn deinit(self: *Printer) void {
        if (self.plan_arena) |*one| one.deinit();
        self.plan_arena = null;
        self.plan = .{};
    }

    fn observer(self: *Printer) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    /// What the harness itself is doing, on its own line. See
    /// `chock_core.Loop.Observer.onNotice`: a session that waits out a rate
    /// limit in silence looks exactly like a session that has hung, and a user
    /// who cannot tell the two apart presses Ctrl-C on one that was about to
    /// carry on.
    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *Printer = @ptrCast(@alignCast(ptr));
        defer self.flush();
        // **Dim, and not a warning, although one thing on this channel would
        // earn a warning.** Two things arrive here: the harness saying it is
        // waiting out a rate limit, and the block of notices the loop builds
        // for the model. The second arrives most turns, and a colour that
        // fires most turns has stopped saying anything. One channel gets one
        // rank: see `src/tty.zig` on not painting by category.
        self.open(.dim);
        self.write("\nchock: ");
        self.write(text);
        self.write("\n");
        self.close(.dim);
    }

    /// **The reasoning is not shown and the answer is.** A model that thinks
    /// before it answers writes far more reasoning than answer, and a terminal
    /// that showed both would bury the answer in it. The reasoning is in the
    /// log either way, which is where a person who wants it goes. The silence
    /// this ends is the answer's own silence: text is what the model is
    /// telling the user.
    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *Printer = @ptrCast(@alignCast(ptr));
        defer self.flush();
        switch (piece) {
            .text => |text| {
                if (text.len == 0) return;
                self.write(text);
                self.streamed += 1;
            },
            .reasoning => {},
        }
    }

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        _ = id;
        const self: *Printer = @ptrCast(@alignCast(ptr));
        defer self.flush();
        switch (ev) {
            .message => |m| {
                // **A system role message is the harness talking to the
                // model**, for example the notice that a compaction is
                // coming. The user has to see that: a session that quietly
                // told the model something is a session the user cannot
                // explain afterwards.
                if (m.role == .system) {
                    self.open(.dim);
                    for (m.content) |part| {
                        if (part != .text or part.text.len == 0) continue;
                        self.write("\n");
                        self.write(part.text);
                    }
                    self.close(.dim);
                    return;
                }
                // The user's own message is not echoed: the user just typed
                // it. The tool role's message is the same result the
                // `tool.result` event already showed.
                if (m.role != .assistant) return;
                // The turn is over, so whatever was streamed belongs to it and
                // not to the next one.
                const streamed = self.streamed;
                self.streamed = 0;
                // **The newline closes what was written, so it needs
                // something to close.** A turn that only reasoned before it
                // called a tool shows nothing here, and an unconditional
                // newline after nothing is a blank line. Every model that
                // thinks first has such a turn, the `.tool_call` branch below
                // opens with a newline of its own, and a session with many
                // tool calls became mostly whitespace.
                var wrote_anything = streamed != 0;
                for (m.content) |part| switch (part) {
                    .text => |text| {
                        if (text.len == 0) continue;
                        // Already on the screen, piece by piece, since the
                        // moment the model produced it. See `streamed`.
                        if (streamed != 0) continue;
                        self.write(text);
                        wrote_anything = true;
                    },
                    .reasoning => {},
                    .tool_use, .tool_result, .unknown => {},
                };
                if (wrote_anything) self.write("\n");
            },
            .tool_call => |call| {
                // Dim. A person scrolling a long run is looking for the answer
                // and for what went wrong, and a call is neither.
                self.open(.dim);
                defer self.close(.dim);
                self.write("\n$ ");
                self.write(call.tool);
                self.write(" ");
                self.write(call.arguments);
                self.write("\n");
            },
            .tool_result => |result| {
                // **Chock's own sentence goes first, and above the result it
                // explains.** The result is written for the model and reads as
                // a message about the user rather than to them; this line is
                // the one written to the person. See
                // `chock_proto.event.ToolResult.note`, and `onNoticeFn` for
                // why Chock's own channel is dim and not a warning.
                if (result.note.len != 0) {
                    self.open(.dim);
                    self.write("chock: ");
                    self.write(result.note);
                    self.write("\n");
                    self.close(.dim);
                }
                // **Only a failed result is painted.** A result that worked is
                // ordinary output, and it gets the colour every ordinary line
                // gets, which is none.
                const rank: tty.Rank = if (result.is_error) .err else .plain;
                self.open(rank);
                defer self.close(rank);
                if (result.is_error) self.write("! ");
                const shown = result.output[0..@min(result.output.len, shown_result_bytes)];
                self.write(shown);
                if (shown.len != result.output.len) self.write("\n[...the whole result is in the log]");
                self.write("\n");
            },
            // **A compaction that happens in silence is the five minute
            // silence again.** The project owner watched a session sit with
            // no output and reasonably guessed it was compacting; it was not,
            // because nothing compacted at all then. Now that something does,
            // it says so, and it says the log kept everything.
            .compaction => |folded| {
                // **A fold the model had no part in is not the ordinary case**,
                // so it does not read as one. The reason decides the rank here
                // the same way it does for a session that ended. See
                // `chock_proto.event.Compaction.stand_in_reason`.
                const rank: tty.Rank = if (folded.stand_in_reason.len != 0) .warn else .dim;
                self.open(rank);
                defer self.close(rank);
                self.write("\nchock: the context was folded into a summary");
                if (folded.model_alias.len != 0) {
                    self.write(", written by ");
                    self.write(folded.model_alias);
                }
                if (folded.stand_in_reason.len != 0) {
                    self.write(", written by the harness, because ");
                    self.write(folded.stand_in_reason);
                }
                self.write(". Every turn is still in the session log.\n");
            },
            // **A background task that finished in silence would be a command
            // the user never saw run at all.** The agent is told the same fact
            // in the same moment, as a message, and the person watching has no
            // other way to learn a build ended.
            .task_complete => |done| {
                self.open(.dim);
                defer self.close(.dim);
                self.write("\nchock: the background task ");
                self.write(done.task_id);
                self.write(" finished, ");
                self.write(done.status.wireName());
                self.write(": ");
                self.write(done.command);
                self.write("\n");
            },
            .plan_update => |update| self.foldPlan(update),
            // **A promise the agent made about itself is written where the
            // person watching sees it**, and not only into the log. It is a
            // decision the agent took on its own, it holds for the rest of the
            // session, and nothing can lift it, so it is exactly the sort of
            // thing a person wants to read at the moment it happens rather than
            // in the morning.
            .policy_self => |update| {
                self.open(.dim);
                defer self.close(.dim);
                for (update.restrictions) |one| {
                    self.write("\nchock: the agent promised ");
                    self.write(one.action);
                    self.write(" at most ");
                    self.write(one.ceiling.wireName());
                    if (one.reason.len != 0) {
                        self.write(": ");
                        self.write(one.reason);
                    }
                    self.write("\n");
                }
            },
            .session_end => |ended| {
                // **The reason decides the rank.** A session that finished is
                // the ordinary case and reads as one. Every other reason is
                // something to act on: the agent gave up, ran out of money, was
                // refused, or crashed.
                const rank: tty.Rank = if (ended.reason == .finished) .dim else .warn;
                self.open(rank);
                defer self.close(rank);
                self.write("\nchock: session ended, ");
                self.write(ended.reason.wireName());
                if (ended.detail.len != 0) {
                    self.write(": ");
                    self.write(ended.detail);
                }
                self.write("\n");
            },
            else => {},
        }
    }

    /// Fold one `plan.update` in, and write the one row a person needs.
    ///
    /// **A list of N steps used to cost N rows every time any one of them
    /// moved.** One `update_plan` call really did write four rows saying what
    /// each step is now, and a task list has one current state, not one per
    /// event. `src/ui.zig`'s `Ui.foldPlan` settled the shape and this writes
    /// the same one: how much is done, and what is being worked on.
    ///
    /// **The running step is named and not only counted.** The common move is
    /// a step going from pending to in_progress, which moves no count at all,
    /// so a row with only counts on it would say nothing happened.
    ///
    /// **A step that was given up keeps a row of its own.** That is an event
    /// and not a state: only a transcript can say when a step was dropped and
    /// what else was going on. It fires on the move to `abandoned` and never
    /// on an update that repeats a status the step already had.
    ///
    /// **This summary is richer than the display's by one clause, and only
    /// when that clause has something to say.** The display keeps the standing
    /// state in the plan sidebar beside the transcript, where a given up step
    /// is a row a person can see for the rest of the session. `chock run` has
    /// no sidebar, so the same fact has to travel on the summary or be lost:
    /// `1 of 4 done` reads as three left when one of the four was abandoned.
    /// The count is written only while it is not zero, so an ordinary session
    /// reads exactly as the display reads.
    fn foldPlan(self: *Printer, update: chock_proto.event.PlanUpdate) void {
        // Which steps are newly given up has to be read before the fold. After
        // it, an update repeating a status it already had looks the same as one
        // that changed it.
        var gave_up: [max_said_steps]usize = undefined;
        var count: usize = 0;
        for (update.steps, 0..) |step, at| {
            if (!ui.isStatus(step.status, .abandoned)) continue;
            if (self.plan.find(step.id)) |had| {
                if (ui.isStatus(had.status, .abandoned)) continue;
            }
            if (count == gave_up.len) break;
            gave_up[count] = at;
            count += 1;
        }

        if (self.plan_arena == null) self.plan_arena = .init(self.gpa);
        // A plan that could not be folded is left as it stands. An observer
        // watches and never decides, so an allocator that has refused is not
        // this file's fault to report.
        self.plan.apply(self.plan_arena.?.allocator(), update) catch {};

        self.open(.dim);
        defer self.close(.dim);

        for (gave_up[0..count]) |at| {
            self.write("\nchock: plan step ");
            self.write(update.steps[at].id);
            self.write(" was given up");
            // An update that only moved a status carries no subject: the words
            // the step had are kept, and the fold is where they now are. See
            // `chock_proto.state.Plan.apply`.
            const said = self.subjectOf(update.steps[at]);
            if (said.len != 0) {
                self.write(": ");
                self.write(said);
            }
            self.write("\n");
        }

        const counts = self.plan.counts();
        var buffer: [32]u8 = undefined;
        self.write("\nchock: plan: ");
        self.write(std.fmt.bufPrint(&buffer, "{d}", .{counts.done}) catch "?");
        self.write(" of ");
        self.write(std.fmt.bufPrint(&buffer, "{d}", .{counts.total()}) catch "?");
        self.write(" done");
        if (counts.abandoned != 0) {
            self.write(", ");
            self.write(std.fmt.bufPrint(&buffer, "{d}", .{counts.abandoned}) catch "?");
            self.write(" given up");
        }
        if (self.stepInProgress()) |one| {
            self.write(", now on \"");
            self.write(one.subject);
            self.write("\"");
        }
        self.write("\n");
    }

    /// The most steps of one update that can each get a row of their own. An
    /// update is a whole task list, which `chock_core.tools` already bounds.
    const max_said_steps = 64;

    /// The words of one step of an update, taken from the fold when the update
    /// itself carried none.
    fn subjectOf(self: *const Printer, step: chock_proto.event.PlanStep) []const u8 {
        if (step.subject.len != 0) return step.subject;
        const held = self.plan.find(step.id) orelse return "";
        return held.subject;
    }

    /// The first step being worked on, or null when none is.
    fn stepInProgress(self: *const Printer) ?chock_proto.state.Plan.Step {
        for (self.plan.steps.items) |step| {
            if (ui.isStatus(step.status, .in_progress)) return step;
        }
        return null;
    }

    /// Start a run of text of this rank. Writes nothing at all when the
    /// painter is off, which is every pipe, every file, and every test that
    /// does not ask for colour.
    fn open(self: *Printer, rank: tty.Rank) void {
        self.write(self.paint.open(rank));
    }

    /// End it.
    fn close(self: *Printer, rank: tty.Rank) void {
        self.write(self.paint.close(rank));
    }

    /// A failed write is dropped on purpose. An observer watches and never
    /// decides: see `chock_core.Loop.Observer`. A terminal that went away,
    /// for example a pipe into `head`, must not end a session that is doing
    /// real work, and the log still holds every one of these bytes.
    ///
    /// **Through `src/tty.zig`'s standard output writer, and never straight to
    /// the descriptor.** That writer is holding bytes that have not left yet,
    /// so a write that went around it would arrive in front of them. One
    /// buffered standard output, or the order is not defined.
    fn write(self: *Printer, bytes: []const u8) void {
        switch (self.out) {
            .stdout => if (!tty.writeOut(bytes)) {
                // Nobody set the streams, which is a path that runs before
                // `main` wired them. Straight out is where these bytes always
                // went, and nothing is buffered to get ahead of.
                std.Io.File.stdout().writeStreamingAll(self.io, bytes) catch {};
            },
            // A test's own buffer. A failed append is dropped the same way a
            // failed write is, for the reason above.
            .buffer => |buffer| buffer.bytes.appendSlice(buffer.gpa, bytes) catch {},
        }
    }

    /// Send what standard output is holding, at the end of one observer call.
    ///
    /// **Two reasons, and each one alone would be enough.** The answer arrives
    /// piece by piece and a person watches it arrive, so holding pieces back
    /// until a buffer filled would turn a stream into a stutter. And
    /// `Loop.run` forks for every tool call: a child inherits the parent's
    /// unsent bytes, and although neither `exec` nor `std.process.exit` sends
    /// them, a buffer that is empty at every fork is one less thing to reason
    /// about.
    fn flush(self: *Printer) void {
        switch (self.out) {
            .stdout => tty.flushOut(),
            .buffer => {},
        }
    }
};

fn appendUserMessage(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    text: []const u8,
) !void {
    var locked = try storage.lock(io);
    defer locked.unlock(io) catch {};
    const content = [_]chock_proto.event.ContentPart{.{ .text = text }};
    _ = try locked.append(
        gpa,
        io,
        .{ .message = .{ .role = .user, .content = &content } },
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
    );
}

/// The message: the words on the command line, joined by a space, or, with
/// none, everything on standard input. **A pipe therefore works with no extra
/// flag**, which is the same default `chock login` uses for a credential.
fn readMessage(arena: std.mem.Allocator, io: std.Io, options: Options) StartError![]const u8 {
    if (options.message_words.len != 0) {
        return std.mem.join(arena, " ", options.message_words);
    }

    var buffer: [4096]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const text = reader.interface.allocRemaining(arena, .limited(max_stdin_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => {
            tty.print(
                .err,
                "chock run: the message on standard input is larger than {d} bytes.\n",
                .{max_stdin_bytes},
            );
            return error.Reported;
        },
        error.ReadFailed => {
            tty.print(.err, "chock run: standard input could not be read.\n", .{});
            return error.Reported;
        },
    };
    return std.mem.trim(u8, text, " \t\r\n");
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, options: Options) StartError![]const u8 {
    if (options.project) |given| {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        var dir = std.Io.Dir.cwd().openDir(io, given, .{}) catch |err| {
            tty.print(.err, "chock run: {s} could not be opened: {s}\n", .{ given, @errorName(err) });
            return error.Reported;
        };
        defer dir.close(io);
        const length = dir.realPath(io, &buffer) catch |err| {
            tty.print(.err, "chock run: {s} has no real path: {s}\n", .{ given, @errorName(err) });
            return error.Reported;
        };
        return arena.dupe(u8, buffer[0..length]);
    }
    return std.process.currentPathAlloc(io, arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            tty.print(.err, "chock run: the current directory could not be read: {s}\n", .{@errorName(err)});
            return error.Reported;
        },
    };
}

fn chooseSessionId(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *std.process.Environ.Map,
    project_root: []const u8,
    options: Options,
) StartError![session_paths.id_length]u8 {
    if (options.session) |given| {
        if (!session_paths.isValidId(given)) {
            tty.print(.err, "chock run: \"{s}\" is not a session identifier.\n", .{given});
            return error.Reported;
        }
        return given[0..session_paths.id_length].*;
    }
    if (options.continue_newest) {
        const newest = session_paths.newestId(arena, io, env, project_root) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                tty.print(.err, "chock run: the newest session could not be found: {s}\n", .{@errorName(err)});
                return error.Reported;
            },
        };
        return newest orelse {
            tty.print(.err, "chock run: this project has no session to continue.\n", .{});
            return error.Reported;
        };
    }
    return session_paths.newId(io);
}

/// Refuse an adoption that has nothing to take over, and say which of the four
/// reasons it is.
///
/// **A handover with nothing to hand over must be a refusal that names what is
/// wrong.** The process holding the log's exclusive lock is the owner of that
/// session, so an adoption is that lock changing hands, and each answer below
/// is a different way of asking for a lock that means nothing.
///
/// The reading is `sessions_cmd.readinessOf`, which `chock detach` and
/// `chock daemon` ask as well. **The words are this command's own**, because
/// what a person should do next differs by which command they typed. See that
/// function for why none of this is what stops two owners.
fn refuseAdoptWithNothingToAdopt(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
) StartError!void {
    switch (sessions_cmd.readinessOf(gpa, io, log_path, id)) {
        .ready => return,
        .no_such_session => tty.print(
            .err,
            "chock run: this project has no session {s} to adopt. `chock sessions` lists the " ++
                "sessions it does have.\n",
            .{id},
        ),
        .nothing_to_carry_on => tty.print(
            .err,
            "chock run: session {s} holds nothing to carry on from, so there is no conversation " ++
                "to adopt. Start it with a message instead.\n",
            .{id},
        ),
        .running => tty.print(
            .err,
            "chock run: session {s} is running now. The process that holds its log's lock owns " ++
                "it, and ownership is not taken from a session that is still using it.\n",
            .{id},
        ),
        // Fails closed, the same rule `chock sessions` keeps for a removal: an
        // absent answer is never a permissive answer.
        .unknown => tty.print(
            .err,
            "chock run: session {s} could not be read, or its lock could not be tested, so it " ++
                "was not adopted.\n",
            .{id},
        ),
    }
    return error.Reported;
}

/// What a person is told when the session lock was taken by somebody else
/// between the check and the session's own attempt. See
/// `refuseAdoptWithNothingToAdopt` for why a check cannot close that window and
/// why nothing is lost when it happens: the log is whole, and the session can be
/// adopted again.
const busy_detail = "another process took the session's log lock first, so it owns that session " ++
    "now. Nothing was lost: the log is whole, and `chock sessions` says who is running.";

/// What the prompt says about the project. One paragraph, and `prompt.Project`
/// drops it when both fields are empty.
///
/// This recognizes one project kind, by one file, and that is honest for a
/// prototype: naming a build command Chock guessed is worse than naming
/// none, because a model that runs a command that does not exist spends a
/// turn finding that out.
fn projectKind(io: std.Io, project_root: []const u8) chock_core.prompt.Project {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const build_zig = std.fmt.bufPrint(&buffer, "{s}/build.zig", .{project_root}) catch return .{};
    _ = std.Io.Dir.cwd().statFile(io, build_zig, .{}) catch return .{};
    return .{ .kind = "Zig", .build_command = "zig build test" };
}

const ParseError = error{ HelpWanted, BadArguments } || std.mem.Allocator.Error;

/// Every option that takes a value of its own. One list, read before a value
/// is taken off the command line: see `parseOptions`.
const value_options = [_][]const u8{
    "--provider",
    "--model",
    "--project",
    "--session",
    "--agent-kind",
    "--org-bundle",
    "--max-turns",
    "--export-dir",
    "--export-syslog",
    // The six a parent puts on a child's command line. Their names are read
    // from `chock_core.subagent.flag`, so the parent that writes one and the
    // child that reads it cannot spell it differently: see that file.
    subagent.flag.parent_session,
    subagent.flag.parent_kind,
    subagent.flag.spawn_reason,
    subagent.flag.scratchpad,
    subagent.flag.max_cost,
    subagent.flag.currency,
};

fn takesValue(argument: []const u8) bool {
    for (value_options) |name| {
        if (std.mem.eql(u8, argument, name)) return true;
    }
    return false;
}

fn parseOptions(arena: std.mem.Allocator, args: []const []const u8) ParseError!Options {
    var options = Options{};
    var words: std.ArrayList([]const u8) = .empty;
    // The spawn chain, one link per `--parent-kind`, in the order they arrive.
    // A list and not one string: **the whole chain is what binds a child**, and
    // the parent writes one pair per agent above it.
    var chain: std.ArrayList(chock_proto.event.SpawnLink) = .empty;

    var index: usize = 0;
    var only_words = false;
    while (index < args.len) : (index += 1) {
        const argument = args[index];

        if (only_words or argument.len == 0 or argument[0] != '-') {
            try words.append(arena, argument);
            continue;
        }
        if (std.mem.eql(u8, argument, "--")) {
            only_words = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--continue")) {
            options.continue_newest = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--adopt")) {
            options.adopt = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--allow-dirty")) {
            options.allow_dirty = true;
            continue;
        }
        if (std.mem.eql(u8, argument, "--no-notices")) {
            options.no_notices = true;
            continue;
        }

        // The name is checked before a value is taken, and not after. The
        // other way round, `chock run --nonsense` reads the next word as the
        // value of an option that does not exist, and then says "--nonsense
        // needs a value", which sends a user looking for the right value
        // instead of the right option.
        if (!takesValue(argument)) {
            // The fault is ranked and the usage text is not. Colouring a whole
            // help page red would make the one line that says what is wrong
            // harder to find, which is the fault this project is fixing.
            tty.print(.err, "chock run: there is no option named {s}.\n\n", .{argument});
            tty.print(.err, "{s}", .{usage_text});
            return error.BadArguments;
        }
        const value = value: {
            index += 1;
            if (index >= args.len) {
                tty.print(.err, "chock run: {s} needs a value.\n\n", .{argument});
                tty.print(.err, "{s}", .{usage_text});
                return error.BadArguments;
            }
            break :value args[index];
        };

        if (std.mem.eql(u8, argument, "--provider")) {
            options.provider = value;
        } else if (std.mem.eql(u8, argument, "--model")) {
            options.model = value;
        } else if (std.mem.eql(u8, argument, "--project")) {
            options.project = value;
        } else if (std.mem.eql(u8, argument, "--session")) {
            options.session = value;
        } else if (std.mem.eql(u8, argument, "--agent-kind")) {
            options.agent_kind = value;
        } else if (std.mem.eql(u8, argument, "--org-bundle")) {
            options.org_bundle = value;
        } else if (std.mem.eql(u8, argument, "--export-dir")) {
            options.export_dir = value;
        } else if (std.mem.eql(u8, argument, "--export-syslog")) {
            options.export_syslog = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.parent_session)) {
            options.parent_session = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.parent_kind)) {
            // One more agent above this one. **Appended and never replaced**: a
            // parser that kept the last one would leave a session three deep
            // running under a chain of one link.
            try chain.append(arena, .{ .agent_kind = value, .reason = "" });
        } else if (std.mem.eql(u8, argument, subagent.flag.spawn_reason)) {
            // The reason belongs to the link just named, which is how a pair is
            // put back together. `commandLine` writes the two in that order and
            // is the only thing that writes either.
            if (chain.items.len == 0) {
                tty.print(
                    .err,
                    "chock run: {s} names why one agent started another, so it comes after " ++
                        "the {s} it belongs to.\n",
                    .{ subagent.flag.spawn_reason, subagent.flag.parent_kind },
                );
                return error.BadArguments;
            }
            chain.items[chain.items.len - 1].reason = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.scratchpad)) {
            options.scratchpad = value;
        } else if (std.mem.eql(u8, argument, subagent.flag.max_cost)) {
            options.max_cost = std.fmt.parseFloat(f64, value) catch {
                tty.print(.err, "chock run: --max-cost takes a number, and \"{s}\" is not one.\n", .{value});
                return error.BadArguments;
            };
            if (!(options.max_cost.? > 0)) {
                tty.print(.err, "chock run: --max-cost has to be more than zero.\n", .{});
                return error.BadArguments;
            }
        } else if (std.mem.eql(u8, argument, subagent.flag.currency)) {
            options.currency = value;
        } else if (std.mem.eql(u8, argument, "--max-turns")) {
            options.max_turns = std.fmt.parseInt(usize, value, 10) catch {
                tty.print(.err, "chock run: --max-turns takes a number, and \"{s}\" is not one.\n", .{value});
                return error.BadArguments;
            };
            if (options.max_turns == 0) {
                tty.print(.err, "chock run: --max-turns 0 would run no turn at all.\n", .{});
                return error.BadArguments;
            }
        } else {
            // Unreachable in practice: `takesValue` above already refused
            // every name that is not one of these. This is here so adding a
            // name to `value_options` and forgetting the branch is a build
            // that still says something true, rather than one that silently
            // drops the option.
            tty.print(.err, "chock run: {s} is not handled yet.\n", .{argument});
            return error.BadArguments;
        }
    }

    if (options.session != null and options.continue_newest) {
        tty.print(.err, "chock run: --session and --continue name two different sessions.\n", .{});
        return error.BadArguments;
    }

    if (options.adopt) {
        // A session that does not exist yet has nothing to adopt, and a fresh
        // identifier is what `chooseSessionId` hands back when neither of these
        // is given. Without this check, `--adopt` on its own would make an empty
        // log and then refuse it for being empty, which sends a reader looking
        // at the wrong fault.
        if (options.session == null and !options.continue_newest) {
            tty.print(
                .err,
                "chock run: --adopt takes over a session that already exists, so it needs " ++
                    "--session <id> or --continue.\n",
                .{},
            );
            return error.BadArguments;
        }
        // **The whole point of the flag is that the conversation continues
        // where it stopped.** A message beside it is a person asking for two
        // different things at once, and guessing which one they meant would
        // either drop the message or start a turn nobody asked for.
        if (words.items.len != 0) {
            tty.print(
                .err,
                "chock run: --adopt carries on from what the session log already holds, so it " ++
                    "takes no message. Leave the message out, or run without --adopt to add one.\n",
                .{},
            );
            return error.BadArguments;
        }
    }

    options.message_words = words.items;
    options.parent_chain = chain.items;
    return options;
}

const testing = std.testing;

test "--adopt takes over a session that exists, and refuses every shape that is not that" {
    // **The replay half of a handover.** Three facts: it is off unless asked
    // for, it needs a session that already exists, and it takes no message,
    // because the conversation it carries on is the one in the log.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const id = "01JQ" ++ "A" ** 22;
    try testing.expect(!(try parseOptions(arena, &.{"a message"})).adopt);
    try testing.expect((try parseOptions(arena, &.{ "--adopt", "--session", id })).adopt);
    try testing.expect((try parseOptions(arena, &.{ "--adopt", "--continue" })).adopt);
    // And it really appends nothing: no words means `start` reads no standard
    // input and writes no message event.
    try testing.expectEqual(
        @as(usize, 0),
        (try parseOptions(arena, &.{ "--adopt", "--session", id })).message_words.len,
    );

    // **Each refusal is captured and read**, because the two are different
    // mistakes and a person has to be told which one they made. See
    // `tty.Capture`, and `test/proto/lock.zig` for why a test may not let a
    // line reach standard error.
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    // A fresh identifier is what `chooseSessionId` hands back with neither of
    // these, so `--adopt` alone would make an empty session and then refuse it
    // for being empty, which points a reader at the wrong fault.
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--adopt"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--session") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--continue") != null);

    // A message beside it is a person asking for two different things at once,
    // and the refusal says which of the two to drop.
    said.clear();
    try testing.expectError(
        error.BadArguments,
        parseOptions(arena, &.{ "--adopt", "--session", id, "and", "also", "this" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "takes no message") != null);
    try testing.expectEqualStrings("", said.out());
}

/// Write a log holding a `workspace.open` and, when `reason` says so, a
/// `session.end`. The shape a run that handed over leaves behind.
fn writeHandoverLog(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
    attempt: []const u8,
    base_commit: []const u8,
    reason: ?chock_proto.event.SessionEndReason,
) !void {
    const log = try chock_proto.log.Log.open(io, log_path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};
    // A fixed time and never a clock: this suite makes no assertion over one,
    // and nothing this test reads is a time.
    _ = try locked.append(gpa, io, .{ .session_start = .{
        .agent_kind = "main",
        .model_alias = "local",
        .parent_session = "",
    } }, 1);
    _ = try locked.append(gpa, io, .{ .workspace_open = .{
        .kind = .worktree,
        .attempt = attempt,
        .path = "/state/somewhere",
        .base_commit = base_commit,
    } }, 2);
    if (reason) |ended| {
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = ended, .detail = "" } }, 3);
    }
}

test "the next owner finds the handed over workspace in the log, and takes nothing else" {
    // **The workspace half of a live handover.** `start` mints a fresh attempt
    // identifier on every invocation and `headMoved` measures work against the
    // commit the checkout started at, so neither can be worked out by a second
    // process. Both are in the log, and this is what reads them back.
    //
    // Mutation check: return null for a `handed_over` session, and every
    // handover rebuilds from committed state, which throws away everything the
    // agent had not committed.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const dir = buffer[0..len];

    const id = "01JQ" ++ "A" ** 22;
    const attempt = "01JQ" ++ "B" ** 22;
    const base_commit = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";

    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id });
    try std.Io.Dir.createDirAbsolute(io, work, .default_dir);

    try writeHandoverLog(gpa, io, log_path, id, attempt, base_commit, .handed_over);

    // **The directory has to be there.** A person may have run
    // `chock workspace clear` between the two owners, and a run that then asked
    // `adopt` for a path that is gone would fail where it should start again
    // from committed state.
    try testing.expect(takenOver(gpa, io, arena, log_path, work) == null);

    const checkout = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, attempt });
    try std.Io.Dir.createDirAbsolute(io, checkout, .default_dir);

    const taken = takenOver(gpa, io, arena, log_path, work).?;
    // Spelled out, and not compared against a second read of the same log: what
    // is pinned is that these two values reach the next owner unchanged.
    try testing.expectEqualStrings(attempt, &taken.attempt);
    try testing.expectEqualStrings(base_commit, taken.base_commit);
}

test "a workspace opened after the handover belongs to the owner that came next" {
    // **The way this could have deleted live work.** A `state.Session` fold
    // never clears `end_reason`, and a resumed session writes no second
    // `session.start`, so once a session has handed over once the fold says
    // `handed_over` for ever, including while its next owner runs.
    //
    // A session hands over from A to the daemon's child B. B writes a
    // `workspace.open` of its own and works. A person runs `chock run
    // --continue`: with the reason alone, C would adopt the checkout B is
    // working in, and when B's turn ended, B's own teardown would run
    // `git worktree remove --force` on the directory C had just taken.
    //
    // The positions are what tell the two apart. Mutation check: drop the
    // `opened > ended_at` test and this stops holding, which is that.
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const dir = buffer[0..len];

    const id = "01JQ" ++ "A" ** 22;
    const first_attempt = "01JQ" ++ "B" ** 22;
    const second_attempt = "01JQ" ++ "C" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id });
    try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
    for ([_][]const u8{ first_attempt, second_attempt }) |one| {
        const checkout = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, one });
        try std.Io.Dir.createDirAbsolute(io, checkout, .default_dir);
    }

    // Owner A opens a workspace and hands the session over.
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        // A fixed time and never a clock: nothing this test reads is a time.
        _ = try locked.append(gpa, io, .{ .workspace_open = .{
            .kind = .worktree,
            .attempt = first_attempt,
            .path = "/state/a",
            .base_commit = "aaaa",
        } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{
            .reason = .handed_over,
            .detail = "",
        } }, 2);
    }

    // The next owner takes A's workspace, which is what it is for.
    const taken = takenOver(gpa, io, arena, log_path, work).?;
    try testing.expectEqualStrings(first_attempt, &taken.attempt);

    // Owner B starts, in the same workspace or in one of its own, and is
    // running now: its `workspace.open` is the newest event and there is no
    // ending after it.
    {
        const log = try chock_proto.log.Log.open(io, log_path, id);
        var backing = chock_proto.storage.JsonLines{ .log = log };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .workspace_open = .{
            .kind = .worktree,
            .attempt = second_attempt,
            .path = "/state/b",
            .base_commit = "bbbb",
        } }, 3);
    }

    // **And now nobody takes anything.** The stale `handed_over` is still the
    // newest ending, and a build that read the reason alone would hand B's live
    // checkout to a third process.
    try testing.expect(takenOver(gpa, io, arena, log_path, work) == null);
}

test "only a session that handed over gives its workspace away" {
    // A session that crashed also keeps its workspace, per `cleanupFor`, and
    // taking that one over is a separate decision with its own refusal in
    // `src/detach.zig`. A session still running has written no ending at all.
    //
    // Mutation check: drop the `end_reason` test in `takenOver` and every
    // `--continue` of a crashed session starts inside that session's leftovers,
    // which is a change nobody asked for and which no test here covers.
    const gpa = testing.allocator;
    const io = testing.io;

    const others = [_]?chock_proto.event.SessionEndReason{
        null,
        .finished,
        .errored,
        .canceled_by_user,
        .budget_reached,
    };
    // **What each reason answered, joined and compared once at the end.**
    // A per case `expect` says only that one of them failed, so this used to
    // carry a `std.debug.print` of the index beside it. Writing the whole table
    // instead names every reason and its answer in the failure itself, and it
    // puts nothing on standard error: see `test/proto/lock.zig`, which is what
    // makes that a rule rather than a preference.
    var answered: std.ArrayList(u8) = .empty;
    defer answered.deinit(gpa);
    var wanted: std.ArrayList(u8) = .empty;
    defer wanted.deinit(gpa);

    for (others) |reason| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(io, &buffer);
        const dir = buffer[0..len];

        const id = "01JQ" ++ "A" ** 22;
        const attempt = "01JQ" ++ "B" ** 22;
        const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
        const work = try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id });
        const checkout = try std.fmt.allocPrint(arena, "{s}/{s}", .{ work, attempt });
        try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
        try std.Io.Dir.createDirAbsolute(io, checkout, .default_dir);

        try writeHandoverLog(gpa, io, log_path, id, attempt, "a1b2c3", reason);
        const named: []const u8 = if (reason) |one| @tagName(one) else "no ending at all";
        try answered.print(gpa, "{s}: {s}\n", .{
            named,
            if (takenOver(gpa, io, arena, log_path, work) == null) "nothing adopted" else "adopted",
        });
        try wanted.print(gpa, "{s}: nothing adopted\n", .{named});
    }

    try testing.expectEqualStrings(wanted.items, answered.items);
}

test "a run that adopted a workspace never removes it, however it fails" {
    // **The worst thing this feature could do.** `Workspace.close` runs
    // `git worktree remove --force`, and an adopted checkout holds work another
    // owner left in it. A run that adopted one and then failed for its own
    // reasons, a bad provider or a lock it lost, must let go of it and never
    // delete it. `keep` is that: the same value released, and nothing on disk
    // touched.
    //
    // Driven against a real worktree, because what is pinned is what happens to
    // the files. Mutation check: call `close` for an adopted workspace and the
    // file the last owner wrote is gone.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const tmp_path = buffer[0..len];

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{tmp_path});
    const scratch = try std.fmt.allocPrint(arena, "{s}/scratch", .{tmp_path});
    try std.Io.Dir.createDirAbsolute(io, project, .default_dir);
    try std.Io.Dir.createDirAbsolute(io, scratch, .default_dir);

    var env = try std.testing.environ.createMap(arena);
    // The same ceiling every workspace test uses: this checkout is a git
    // repository and `tmpDir` sits underneath it, so without one `git` walks up
    // and finds the wrong repository.
    try env.put("GIT_CEILING_DIRECTORIES", tmp_path);
    try makeGitProject(arena, io, &env, project);

    const attempt = "01JQ" ++ "B" ** 22;
    var first = try chock_workspace.Workspace.open(arena, io, &env, project, scratch, attempt, null);
    const base_commit = try arena.dupe(u8, first.kind.worktree.base_commit);
    const written = try std.fmt.allocPrint(arena, "{s}/agent-wrote-this.txt", .{first.workPath()});
    {
        var handle = try std.Io.Dir.createFileAbsolute(io, written, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, "work nobody committed\n");
    }
    // A handover leaves it exactly here.
    first.keep(arena);

    var second = try chock_workspace.Workspace.adopt(
        arena,
        io,
        &env,
        project,
        scratch,
        attempt,
        base_commit,
        null,
    );
    // **The decision `start`'s own errdefer makes, and not a call this test
    // chose.** Mutation check: make `releaseOnFailure` answer `.remove` for an
    // adopted workspace, and the file the last owner wrote is gone.
    switch (releaseOnFailure(true)) {
        .keep => second.keep(arena),
        .remove => second.close(arena, io, &env, null) catch {},
        .hand_on => unreachable,
    }
    // And a workspace this process built is still removed, or every session a
    // person ever failed to start would stay on their disk.
    try testing.expectEqual(Cleanup.remove, releaseOnFailure(false));

    const stat = try std.Io.Dir.cwd().statFile(io, written, .{});
    try testing.expectEqual(@as(u64, "work nobody committed\n".len), stat.size);

    // And the checkout is still a live worktree, so a third owner can take it
    // in turn. A `close` here would have removed the registration as well as
    // the files.
    var third = try chock_workspace.Workspace.adopt(
        arena,
        io,
        &env,
        project,
        scratch,
        attempt,
        base_commit,
        null,
    );
    try testing.expectEqualStrings(base_commit, third.kind.worktree.base_commit);
    third.keep(arena);
}

test "a handover keeps the workspace and the scratchpad, and applies nothing" {
    // **The three teardown decisions of a live handover, in one place.** Each
    // one is a row of the table in `src/detach.zig`, and each one would be a
    // silent loss if it went the other way:
    //
    // * a removed workspace is every uncommitted change gone
    // * a removed scratchpad is every background command's output gone, and the
    //   log names those files by path
    // * an apply asks a person about half finished work, and takes the log lock
    //   this process has just let go of
    //
    // Mutation check: make `handedOver` answer false and all three flip.
    try testing.expect(handedOver(Exit.handed_over));
    try testing.expect(!handedOver(Exit.finished));
    try testing.expect(!handedOver(Exit.faulted));
    try testing.expect(!handedOver(Exit.refused));
    // A run whose session could not report an ending at all did not hand over.
    try testing.expect(!handedOver(error.Busy));

    // And the workspace stays, with a sentence of its own rather than the one
    // that tells a person their session went wrong.
    try testing.expectEqual(Cleanup.hand_on, cleanupFor(.handed_over, .nothing_to_apply));
    try testing.expectEqual(Cleanup.keep, cleanupFor(.faulted, .nothing_to_apply));
    try testing.expectEqual(Cleanup.remove, cleanupFor(.finished, .nothing_to_apply));

    // The exit code passes through untouched, because a handover is a statement
    // about the session and never about whether work landed.
    const nothing_shipped = ShippingReport{};
    try testing.expectEqual(
        Exit.handed_over,
        exitWithApply(.handed_over, .nothing_to_apply, &nothing_shipped),
    );
}

test "the words that are not options become the message, in the order they were given" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const options = try parseOptions(arena, &.{ "--model", "a-model", "add", "a", "test" });
    try testing.expectEqualStrings("a-model", options.model.?);
    try testing.expectEqual(@as(usize, 3), options.message_words.len);
    const joined = try std.mem.join(arena, " ", options.message_words);
    try testing.expectEqualStrings("add a test", joined);
}

test "no message on the command line leaves the words empty, which is what makes a pipe work" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const options = try parseOptions(arena, &.{ "--provider", "local" });
    try testing.expectEqual(@as(usize, 0), options.message_words.len);
    try testing.expectEqualStrings("local", options.provider.?);
}

test "a message that starts with a dash is a message after --, and an option otherwise" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const options = try parseOptions(arena, &.{ "--", "--not-an-option", "really" });
    try testing.expectEqual(@as(usize, 2), options.message_words.len);
    try testing.expectEqualStrings("--not-an-option", options.message_words[0]);

    // And without the separator the same word is refused, rather than
    // quietly becoming part of a prompt.
    //
    // **What the refusal says is captured and read.** A test that let it reach
    // the terminal would not be checking it, and it would put a
    // `failed command:` line in the build log of a suite that passed: see
    // `tty.Capture`, and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--not-an-option"}));
    // The word is named back, so a person can see which of several arguments
    // the parser objected to.
    try testing.expect(std.mem.indexOf(u8, said.err(), "--not-an-option") != null);
    try testing.expectEqualStrings("", said.out());
}

test "an unparsable command line fails, and never runs a session with a guessed value" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // **Every refusal is captured and names what it refused.** A parser that
    // said "bad arguments" for all five would pass an error only test, and a
    // person would have to guess which word was wrong. See `tty.Capture`, and
    // `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    // An option with no value must not swallow the next option, and must not
    // fall back to a default.
    const refusals = [_]struct { argv: []const []const u8, names: []const u8 }{
        .{ .argv = &.{"--model"}, .names = "--model" },
        .{ .argv = &.{ "--max-turns", "lots" }, .names = "lots" },
        .{ .argv = &.{ "--max-turns", "0" }, .names = "--max-turns 0" },
        .{ .argv = &.{"--nonsense"}, .names = "--nonsense" },
        // Two ways to name the session at once is a command line that means
        // two different things.
        .{
            .argv = &.{ "--continue", "--session", "01JQ" ++ "A" ** 22 },
            .names = "two different sessions",
        },
    };
    for (refusals) |one| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(arena, one.argv));
        try testing.expect(std.mem.indexOf(u8, said.err(), one.names) != null);
        try testing.expectEqualStrings("", said.out());
    }
}

test "--help is asked for on purpose, so it is not a usage failure" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    try testing.expectError(error.HelpWanted, parseOptions(arena_state.allocator(), &.{"--help"}));
}

test "the exit code comes from the last session end in the log, and a log with none is a fault" {
    // The log is the truth of a session, so the exit code is read back out of
    // it rather than out of whatever the code happened to return.
    const gpa = testing.allocator;
    const io = testing.io;

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01RUN");
        const storage = backing.storage();
        defer storage.close(io);
        // A log that stops with nothing saying why.
        var locked = try storage.lock(io);
        const content = [_]chock_proto.event.ContentPart{.{ .text = "hello" }};
        _ = try locked.append(gpa, io, .{ .message = .{ .role = .user, .content = &content } }, 1);
        try locked.unlock(io);
        try testing.expectEqual(Exit.faulted, try finalExit(gpa, io, storage));
    }

    {
        var backing = try chock_proto.storage.Memory.init(gpa, "01RUN");
        const storage = backing.storage();
        defer storage.close(io);
        var locked = try storage.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 1);
        try locked.unlock(io);
        try testing.expectEqual(Exit.finished, try finalExit(gpa, io, storage));
    }

    {
        // A session continued after an earlier one finished: the last end is
        // the one that decides. A reader that took the first would report
        // yesterday's answer for today's session.
        var backing = try chock_proto.storage.Memory.init(gpa, "01RUN");
        const storage = backing.storage();
        defer storage.close(io);
        var locked = try storage.lock(io);
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 1);
        _ = try locked.append(gpa, io, .{ .session_end = .{
            .reason = .canceled_by_user,
            .detail = "nobody answered",
        } }, 2);
        try locked.unlock(io);
        try testing.expectEqual(Exit.refused, try finalExit(gpa, io, storage));
    }
}

test "an option that does not exist is named as such, and never as one that needs a value" {
    // A parser that took the value first answers `chock run --nonsense` with
    // "--nonsense needs a value", which sends a user looking for the right
    // value instead of the right option. Measured by hand before this fix.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // **The words themselves are what this test is about**, so they are
    // captured and read rather than let through: see `tty.Capture`, and
    // `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--nonsense"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "no option named --nonsense") != null);
    // Mutation check for this whole test: take the value first and the line
    // below becomes "--nonsense needs a value", which is the message that sent
    // a user looking for the right value instead of the right option.
    try testing.expect(std.mem.indexOf(u8, said.err(), "needs a value") == null);

    // And it does not swallow the word after it either: with the value first,
    // `--nonsense add` parsed as an option with the value "add" and the
    // message never appeared at all.
    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{ "--nonsense", "add" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "no option named --nonsense") != null);
    said.clear();

    // Every name in the table still takes its value, so this refusal is not
    // simply refusing everything.
    //
    // **Every failure is collected and compared once**, rather than printed as
    // it happens. A `std.debug.print` used to name the first option that
    // failed; this names all of them, and it writes nothing to standard error
    // on a run that passes. See `test/proto/lock.zig`.
    var refused: std.ArrayList(u8) = .empty;
    defer refused.deinit(gpa);

    for (value_options) |name| {
        try testing.expect(takesValue(name));
        // `--spawn-reason` says why one named agent started another, so it is
        // read into the link the `--parent-kind` before it opened. On its own
        // it names a link that does not exist, which is its own refusal and is
        // pinned where the chain is: see the flags test above.
        const before: []const []const u8 = if (std.mem.eql(u8, name, subagent.flag.spawn_reason))
            &.{ subagent.flag.parent_kind, "main" }
        else
            &.{};
        const argv = try std.mem.concat(arena, []const u8, &.{ before, &.{ name, valueFor(name) } });
        _ = parseOptions(arena, argv) catch |err| {
            try refused.print(gpa, "{s} was refused with its own value: {t}\n", .{ name, err });
        };
    }

    // Empty, and a failure names every option that was refused rather than
    // only the first one.
    try testing.expectEqualStrings("", refused.items);
}

test "the flags a parent writes are the flags this parser reads" {
    // The parent builds a child's command line with
    // `chock_core.subagent.commandLine` and this is what reads one. A name
    // that matched in one place and not the other would be a child that ran
    // with no parent in its chain, no budget slice, and a scratchpad of its
    // own outside its parent's: three narrowings gone, in silence.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const prepared = chock_core.subagent.Prepared{
        .child_session = try arena.dupe(u8, "01JQ" ++ "A" ** 22),
        .log_path = try arena.dupe(u8, "/tmp/chock/child.jsonl"),
        .scratchpad_path = try arena.dupe(u8, "/tmp/chock/01PARENT/agents/01CHILD"),
    };
    const above = [_]chock_proto.event.SpawnLink{
        .{ .agent_kind = "main", .reason = "split the work" },
        .{ .agent_kind = "coder", .reason = "review the parser" },
    };
    const argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = "/nix/store/aaa/bin/chock",
        .project_root = "/home/ross/project",
        .parent_session = "01JQ" ++ "B" ** 22,
        .parent_chain = &above,
        .provider = "local",
        .model = "a-model",
    }, .{
        .agent_kind = "reviewer",
        .task = "read the parser",
        .reason = "review the parser",
        .budget = .{ .max_cost = 1.25, .currency = "USD" },
    }, prepared);

    // The program name and the subcommand come off, the way `src/main.zig`
    // takes them off before it calls this parser.
    const options = try parseOptions(arena, argv[2..]);

    try testing.expectEqualStrings("reviewer", options.agent_kind);
    try testing.expectEqualStrings("01JQ" ++ "B" ** 22, options.parent_session);
    try testing.expectEqualStrings("/tmp/chock/01PARENT/agents/01CHILD", options.scratchpad);
    try testing.expectEqual(@as(f64, 1.25), options.max_cost.?);
    try testing.expectEqualStrings("USD", options.currency);
    try testing.expectEqualStrings("/home/ross/project", options.project.?);
    try testing.expectEqualStrings("local", options.provider.?);
    try testing.expectEqualStrings("a-model", options.model.?);
    // The task is the message, and it is the whole of what the child reads.
    try testing.expectEqual(@as(usize, 1), options.message_words.len);
    try testing.expectEqualStrings("read the parser", options.message_words[0]);

    // And the chain this session runs under names **every** agent above it,
    // root first, which is what makes the policy an intersection over the whole
    // tree and not over the last two levels of it. A chain that came back one
    // link short was a real fault: see `spawnChain`.
    const chain = spawnChain(options);
    try testing.expectEqual(@as(usize, 2), chain.len);
    try testing.expectEqualStrings("main", chain[0].agent_kind);
    try testing.expectEqualStrings("split the work", chain[0].reason);
    try testing.expectEqualStrings("coder", chain[1].agent_kind);
    try testing.expectEqualStrings("review the parser", chain[1].reason);
    // So the depth this session reports is its real depth, which is what
    // `chock_policy.subagents.check` is given and what bounds the tree.
    try testing.expectEqual(@as(usize, 3), chain.len + 1);
    try testing.expectEqual(@as(usize, 0), spawnChain(.{}).len);

    // A reason with no kind before it names a link that does not exist, and a
    // parser that took it would put one agent's reason on another agent's link.
    //
    // **The refusal is captured and says which flag it belongs after**, because
    // the whole fault is an ordering one and a bare "bad arguments" would not
    // name it. See `tty.Capture`, and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadArguments,
        parseOptions(arena, &.{ subagent.flag.spawn_reason, "review the parser" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), subagent.flag.spawn_reason) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), subagent.flag.parent_kind) != null);
    try testing.expectEqualStrings("", said.out());
}

test "a budget slice narrows what chock.zon allows and can never widen it" {
    // Both controls hold. A parent divides what it has left, and the project's
    // own cap still binds every session of that project, so neither one can be
    // worked around by the other.
    const file_cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };

    // No slice at all: the project's cap, unchanged.
    try testing.expectEqual(@as(f64, 5.0), budgetFor(file_cap, .{}).?.max_cost);

    // A slice below the cap wins, because it is the narrower of the two.
    try testing.expectEqual(@as(f64, 1.25), budgetFor(file_cap, .{ .max_cost = 1.25 }).?.max_cost);

    // **A slice above the cap does not widen it.** A parent that asked for
    // more than the project allows gets the project's number.
    try testing.expectEqual(@as(f64, 5.0), budgetFor(file_cap, .{ .max_cost = 500.0 }).?.max_cost);

    // A project with no cap of its own still runs the child under its slice,
    // which is what bounds a tree whose project set no total.
    try testing.expectEqual(@as(f64, 1.25), budgetFor(null, .{ .max_cost = 1.25 }).?.max_cost);
    try testing.expectEqualStrings("USD", budgetFor(null, .{ .max_cost = 1.25 }).?.currency);

    // Two caps in two currencies cannot be compared, and inventing a rate
    // would be worse than not enforcing. The parent's own number is the answer,
    // because a parent that handed out a slice already decided the total.
    const in_yen = budgetFor(file_cap, .{ .max_cost = 900.0, .currency = "JPY" }).?;
    try testing.expectEqual(@as(f64, 900.0), in_yen.max_cost);
    try testing.expectEqualStrings("JPY", in_yen.currency);

    // And a session nobody gave a slice keeps whatever the file said, cap or
    // no cap.
    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetFor(null, .{}));
}

/// A value each option in `value_options` accepts, for the test above.
fn valueFor(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "--max-turns")) return "3";
    if (std.mem.eql(u8, name, subagent.flag.max_cost)) return "1.25";
    if (std.mem.eql(u8, name, "--session")) return "01JQ" ++ "A" ** 22;
    return "a-value";
}

test "the dirty tree warning names the count, the split, and the flag" {
    // The message a user acts on. Pinned whole: a count that says the wrong
    // number, or a flag named wrongly, sends somebody looking for files that
    // are not there. The numbers themselves come from git, and
    // `lib/chock-workspace/worktree.zig`'s own `countUncommitted` tests pin
    // that half.
    const gpa = testing.allocator;
    const text = try dirtyWarning(gpa, .{ .modified = 9, .untracked = 3 });
    defer gpa.free(text);
    try testing.expectEqualStrings(
        "chock run: 12 uncommitted files will not be visible to the agent\n" ++
            "           (9 modified, 3 untracked). Pass --allow-dirty to include them.\n",
        text,
    );
    // The flag is spelled the same way the parser reads it, so the message
    // cannot name an option that does not exist.
    const parsed = try parseOptions(gpa, &.{"--allow-dirty"});
    try testing.expect(parsed.allow_dirty);
    try testing.expect(std.mem.indexOf(u8, text, "--allow-dirty") != null);
}

test "a clean tree gets no warning at all, so the message stays worth reading" {
    // `handleUncommitted` returns before it ever builds a sentence when the
    // count is zero, and this is the check it returns on.
    const clean = chock_workspace.worktree.Uncommitted{};
    try testing.expect(!clean.any());
    try testing.expectEqual(@as(usize, 0), clean.total());

    // One untracked file is enough to make it worth saying.
    const dirty = chock_workspace.worktree.Uncommitted{ .untracked = 1 };
    try testing.expect(dirty.any());
}

test "--allow-dirty is off unless it is asked for, and it takes no value" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The default is the committed state. A flag that quietly turned itself
    // on would make every session non reproducible.
    const plain = try parseOptions(arena, &.{"fix the parser"});
    try testing.expect(!plain.allow_dirty);

    // It is a switch, not an option with a value: the word after it is part
    // of the message, not something it swallowed.
    const with_flag = try parseOptions(arena, &.{ "--allow-dirty", "fix", "the", "parser" });
    try testing.expect(with_flag.allow_dirty);
    try testing.expectEqual(@as(usize, 3), with_flag.message_words.len);
    try testing.expect(!takesValue("--allow-dirty"));
}

test "the ref a session's work lands on is the session's own, never a branch of the user" {
    // The worktree is detached so a session cannot move a branch of the user.
    // Moving one here at the end would undo that: the user's own working tree
    // would read as a large diff against a commit they never made.
    const gpa = testing.allocator;
    const ref = try applyRef(gpa, "01JQABCDEFGHJKMNPQRSTVWXYZ");
    defer gpa.free(ref);
    try testing.expectEqualStrings("refs/chock/01JQABCDEFGHJKMNPQRSTVWXYZ", ref);
    try testing.expect(std.mem.startsWith(u8, ref, "refs/chock/"));
    try testing.expect(!std.mem.startsWith(u8, ref, "refs/heads/"));
}

test "a session that finished but whose work was refused does not exit zero" {
    // A script that read 0 there would carry on as though the change was in
    // the repository. The work not landing is the thing the caller has to
    // act on.
    // **Every case here ships nothing**, which is every run of every
    // installation that requires no sink, so the answers below are the answers
    // this fold has always given.
    const quiet = ShippingReport{};
    try testing.expectEqual(Exit.refused, exitWithApply(.finished, .refused, &quiet));
    try testing.expectEqual(Exit.faulted, exitWithApply(.finished, .failed, &quiet));

    // A session that wrote files and never committed them did work that
    // Chock is about to throw away. A script that read 0 there would carry
    // on as though the project had been changed. Measured on the first real
    // run of the write tools: the agent edited a file, created another, and
    // exited 0 with the project untouched.
    try testing.expectEqual(Exit.faulted, exitWithApply(.finished, .uncommitted, &quiet));

    // A session that had nothing to carry back, or whose work landed, is a
    // session that did what was asked.
    try testing.expectEqual(Exit.finished, exitWithApply(.finished, .nothing_to_apply, &quiet));
    try testing.expectEqual(Exit.finished, exitWithApply(.finished, .landed, &quiet));

    // And the apply never hides the session's own outcome: a fault, a
    // budget, or the agent giving up is the first thing to act on, whatever
    // happened to the work afterwards.
    for ([_]Exit{ .faulted, .budget, .no_progress, .turn_limit, .refused }) |session_exit| {
        for ([_]Applied{ .nothing_to_apply, .landed, .refused, .failed, .uncommitted }) |applied| {
            try testing.expectEqual(session_exit, exitWithApply(session_exit, applied, &quiet));
        }
    }

    // **The audit fold is inside this one, and this is what says so.** A `run`
    // that folded the apply and forgot the record would pass every test of
    // `exitWithAudit` on its own, which is the shape of fault this project has
    // shipped three times.
    //
    // Mutation check: drop the `exitWithAudit` call from `exitWithApply` and
    // this fails, and nothing else in the file does.
    var lost = ShippingReport{};
    lost.add(.{ .name = "/var/audit/chock/01JQ.jsonl", .required = true, .health = .{
        .delivered = 2,
        .faults = 1,
        .first_fault = error.ConnectionRefused,
        .stalled_at = 96,
    } });
    try testing.expectEqual(Exit.audit_gap, exitWithApply(.finished, .landed, &lost));
    try testing.expectEqual(Exit.audit_gap, exitWithApply(.finished, .nothing_to_apply, &lost));
    // A session whose work was refused says that first: the apply is the thing
    // the person at the keyboard has to act on, and the record is the thing the
    // organisation acts on, so the nearer fault wins.
    try testing.expectEqual(Exit.refused, exitWithApply(.finished, .refused, &lost));
    try testing.expectEqual(Exit.faulted, exitWithApply(.faulted, .landed, &lost));
}

test "only a clean ending removes the workspace, and every way a session can go wrong keeps it" {
    // **The whole of the 2026-08-22 loss, as a decision.** A rate limit ended
    // that session and the worktree came down with 105 changed files in it.
    // Every one of these endings had the same cleanup before this existed.

    // The two clean endings. The commit is in the user's repository, or there
    // was never anything to carry back, so the workspace holds nothing that
    // is not somewhere else.
    try testing.expectEqual(Cleanup.remove, cleanupFor(.finished, .landed));
    try testing.expectEqual(Cleanup.remove, cleanupFor(.finished, .nothing_to_apply));

    // The measured one: the agent worked, never committed, and the workspace
    // is now the only copy of what it did.
    try testing.expectEqual(Cleanup.keep, cleanupFor(.finished, .uncommitted));
    // A refused or failed apply is the same fact from a different direction:
    // the repository is unchanged and the work is still in the workspace.
    try testing.expectEqual(Cleanup.keep, cleanupFor(.finished, .refused));
    try testing.expectEqual(Cleanup.keep, cleanupFor(.finished, .failed));

    // Every other way a session ends keeps it, whatever the apply said. A
    // budget that stopped a session, a Ctrl-C, an agent that gave up, and a
    // transport fault all leave work behind that nothing else holds.
    for ([_]Exit{ .faulted, .budget, .no_progress, .turn_limit, .refused, .usage }) |ended| {
        for ([_]Applied{ .nothing_to_apply, .landed, .refused, .failed, .uncommitted }) |applied| {
            try testing.expectEqual(Cleanup.keep, cleanupFor(ended, applied));
        }
    }

    // And a run whose session could not say how it ended at all is the least
    // safe case of the lot, so it keeps the workspace too.
    try testing.expectEqual(Cleanup.keep, cleanupFor(null, .landed));
}

test "the run keeps the workspace on an abnormal ending, with the agent's file still in it" {
    // **The decision and the act, wired together.** `cleanupFor` above says
    // which endings keep, and `Workspace.keep` says what keeping means. This
    // is the one that proves `chock run` joins them: a switch that called
    // `close` for both verdicts would pass every other test in this file and
    // would still delete the work.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &buffer);
    const tmp_path = buffer[0..len];

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{tmp_path});
    const scratch = try std.fmt.allocPrint(arena, "{s}/scratch", .{tmp_path});
    try std.Io.Dir.createDirAbsolute(io, project, .default_dir);
    try std.Io.Dir.createDirAbsolute(io, scratch, .default_dir);

    var env = try std.testing.environ.createMap(arena);
    // This project's own checkout is a git repository and `tmpDir` makes every
    // scratch directory underneath it, so without a ceiling `git` walks up and
    // finds the wrong repository. The same guard every workspace test uses.
    try env.put("GIT_CEILING_DIRECTORIES", tmp_path);
    try makeGitProject(arena, io, &env, project);

    // What the teardown wrote, captured rather than let through: see
    // `tty.Capture`, and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    for ([_]Cleanup{ .keep, .remove, .hand_on }) |verdict| {
        said.clear();
        var workspace = try chock_workspace.Workspace.open(
            arena,
            io,
            &env,
            project,
            scratch,
            @tagName(verdict),
            null,
        );
        const written = try std.fmt.allocPrint(
            arena,
            "{s}/agent-wrote-this.txt",
            .{workspace.workPath()},
        );
        {
            var handle = try std.Io.Dir.createFileAbsolute(io, written, .{});
            defer handle.close(io);
            try handle.writeStreamingAll(io, "work nobody committed\n");
        }

        // Copied before the teardown, because `keep` and `close` both free
        // every string the workspace owns: see `takeDownWorkspace`.
        const work_path = try arena.dupe(u8, workspace.workPath());
        takeDownWorkspace(&workspace, verdict, arena, io, &env, scratch);

        switch (verdict) {
            // The measured loss, prevented: the file is still where the agent
            // left it, not merely a directory that still exists.
            // **The same act for the same reason.** A handover leaves the
            // workspace for the process that is about to work in it, so the
            // file has to be there and have its bytes. Mutation check: make
            // `hand_on` remove, and a handover throws away everything the agent
            // had not committed, which is the loss the whole feature exists to
            // avoid.
            .keep, .hand_on => {
                const stat = try std.Io.Dir.cwd().statFile(io, written, .{});
                try testing.expectEqual(@as(u64, "work nobody committed\n".len), stat.size);
                // **A kept workspace says where the work is.** One nobody was
                // told about is a directory a person never goes back to, which
                // is the same loss as removing it. A handover says the same
                // thing behind `--verbose`, because the next owner is about to
                // work there and nobody has to go and look.
                if (verdict == .keep) {
                    try testing.expect(std.mem.indexOf(u8, said.err(), work_path) != null);
                }
            },
            // And the clean ending is unchanged, or every session a user ever
            // ran stays on their disk forever.
            .remove => {
                try testing.expectError(
                    error.FileNotFound,
                    std.Io.Dir.cwd().statFile(io, written, .{}),
                );
                // A clean ending is quiet: there is nothing for a person to do.
                try testing.expectEqualStrings("", said.err());
            },
        }
        try testing.expectEqualStrings("", said.out());
    }
}

/// A git repository with one commit in it, for the teardown test above.
fn makeGitProject(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project: []const u8,
) !void {
    const steps: []const []const []const u8 = &.{
        &.{"init"},
        &.{ "config", "user.email", "test@example.com" },
        &.{ "config", "user.name", "Test" },
    };
    for (steps) |argv| {
        var output = try chock_workspace.git.run(arena, io, env, project, argv, null);
        defer output.deinit(arena);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }

    const tracked = try std.fmt.allocPrint(arena, "{s}/tracked.txt", .{project});
    {
        var handle = try std.Io.Dir.createFileAbsolute(io, tracked, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, "hello\n");
    }

    const commits: []const []const []const u8 = &.{
        &.{ "add", "tracked.txt" },
        &.{ "commit", "-m", "first commit" },
    };
    for (commits) |argv| {
        var output = try chock_workspace.git.run(arena, io, env, project, argv, null);
        defer output.deinit(arena);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, output.term);
    }
}

/// A `ToolRunner` that runs nothing and counts what reached it. Only the git
/// shim tests below use it: what they pin is which calls get past
/// `GitToolRunner`, so the inner runner has to be one that says whether it was
/// called at all.
const CountingToolRunner = struct {
    calls: usize = 0,
    last_arguments: []const u8 = "",

    fn runner(self: *CountingToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatch };

    fn dispatch(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        _ = io;
        const self: *CountingToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_arguments = call.arguments;
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = try gpa.dupe(u8, "the real git ran"),
            .is_error = false,
            .truncated = false,
        };
    }
};

test "a git subcommand that has to reach another host is answered, and never reaches the real git" {
    // The measured session: `git fetch` reached the real git, the real git
    // forked `ssh`, and the model read `cannot run ssh: No such file or
    // directory`, then spent turns looking for a proxy. Nothing was breached,
    // and nothing about the sandbox changes here. What changes is that the
    // agent is told the truth in one turn.
    const gpa = testing.allocator;

    for ([_][]const u8{
        "{\"argv\":[\"git\",\"fetch\",\"origin\"]}",
        "{\"argv\":[\"git\",\"pull\"]}",
        "{\"argv\":[\"git\",\"push\",\"origin\",\"main\"]}",
        "{\"argv\":[\"git\",\"clone\",\"https://example.invalid/x.git\"]}",
        "{\"argv\":[\"git\",\"ls-remote\",\"origin\"]}",
        // An option before the subcommand is read the same way, so a fetch
        // does not get through by being spelled with one.
        "{\"argv\":[\"git\",\"-C\",\"sub\",\"fetch\"]}",
    }) |arguments| {
        var inner = CountingToolRunner{};
        var shim = GitToolRunner{ .inner = inner.runner() };

        const result = try shim.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = "run_command",
            .arguments = arguments,
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        // Answered here, so the real git never forked ssh at all.
        try testing.expectEqual(@as(usize, 0), inner.calls);
        try testing.expect(result.is_error);
        try testing.expect(std.mem.indexOf(u8, result.output, "no network") != null);
        try testing.expect(std.mem.indexOf(u8, result.output, "no proxy") != null);
    }
}

test "every other command still reaches the runner behind the shim, git included" {
    // The other half, and the one that matters more: this runner sits in
    // front of every tool call a session makes. A shim that quietly refused
    // more than it says would break the session's own work, and `git commit`
    // in particular is how that work reaches the user at all: see
    // `GitToolRunner` and `applyWork`.
    const gpa = testing.allocator;

    for ([_][]const u8{
        "{\"argv\":[\"git\",\"status\",\"--short\"]}",
        "{\"argv\":[\"git\",\"log\",\"--oneline\"]}",
        "{\"argv\":[\"git\",\"add\",\"-A\"]}",
        "{\"argv\":[\"git\",\"commit\",\"-m\",\"the work\"]}",
        "{\"argv\":[\"git\",\"checkout\",\"-b\",\"topic\"]}",
        "{\"argv\":[\"zig\",\"build\",\"test\"]}",
        // A vector this runner cannot read is `run_command`'s own complaint to
        // make, not this one's: see `gitRefusal`.
        "{\"argv\":[]}",
        "not json at all",
    }) |arguments| {
        var inner = CountingToolRunner{};
        var shim = GitToolRunner{ .inner = inner.runner() };

        const result = try shim.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = "run_command",
            .arguments = arguments,
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqual(@as(usize, 1), inner.calls);
        try testing.expect(!result.is_error);
    }

    // And a tool that is not `run_command` is not read as a git command line
    // whatever its arguments hold.
    var inner = CountingToolRunner{};
    var shim = GitToolRunner{ .inner = inner.runner() };
    const result = try shim.runner().dispatch(gpa, testing.io, .{
        .call_id = "call1",
        .tool = "write_file",
        .arguments = "{\"path\":\"x\",\"content\":\"{\\\"argv\\\":[\\\"git\\\",\\\"fetch\\\"]}\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);
    try testing.expectEqual(@as(usize, 1), inner.calls);
}

// `lib/chock-core/lsp.zig` holds the ranking, the bound and the say-once rule,
// and its own tests pin all three. These pin the wiring: which calls the runner
// looks at, and that the tool result is untouched for every other one.
//
// No test here starts a language server. See `chock_core.lsp.Server`, which is
// the seam, and this file's own `DiagnosticToolRunner`.

/// A `ToolRunner` that answers with whatever a test put in it, so a test can
/// state a write that worked, a write that was refused, and what the tool's own
/// text was, without a sandbox anywhere.
const StubToolRunner = struct {
    output: []const u8 = "wrote src/main.zig, 12 bytes, file_hash 0123456789abcdef\n",
    is_error: bool = false,
    calls: usize = 0,

    fn runner(self: *StubToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        _ = io;
        const self: *StubToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = try gpa.dupe(u8, self.output),
            .is_error = self.is_error,
            .truncated = false,
        };
    }
};

/// A `chock_core.lsp.Server` that answers from a table and counts what reached
/// it. The same shape that library's own tests use, and for the same reason.
const StubServer = struct {
    diagnostic: chock_core.lsp.Diagnostic = .{
        .path = "src/main.zig",
        .line = 12,
        .column = 5,
        .severity = .err,
        .message = "expected type 'u8', found 'void'",
    },
    calls: usize = 0,

    fn server(self: *StubServer) chock_core.lsp.Server {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.lsp.Server.VTable{ .diagnose = diagnoseFn };

    fn diagnoseFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        ask: chock_core.lsp.Ask,
    ) std.mem.Allocator.Error!chock_core.lsp.Answer {
        _ = io;
        _ = ask;
        const self: *StubServer = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        const list = try arena.alloc(chock_core.lsp.Diagnostic, 1);
        list[0] = self.diagnostic;
        return .{ .reported = list };
    }
};

test "a write that worked carries what the language server said, on the same result" {
    // **The whole point of the timing**: the agent reads this on the turn it
    // made the edit, not several turns later with more work built on top of the
    // mistake. Mutation check: append the block anywhere but the write's own
    // result and this fails.
    const gpa = testing.allocator;

    for ([_][]const u8{ "write_file", "edit_file" }) |tool| {
        var inner = StubToolRunner{};
        var stub = StubServer{};
        var session = chock_core.lsp.Session{
            .program = "zls",
            .suffixes = &.{".zig"},
            .server = stub.server(),
        };
        var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

        const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = tool,
            .arguments = "{\"path\":\"src/main.zig\",\"content\":\"x\",\"old_string\":\"a\",\"new_string\":\"b\"}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        // The tool's own text is still there, whole and first. A runner that
        // replaced it would take away the `file_hash` the next `edit_file`
        // anchors on.
        try testing.expect(std.mem.startsWith(u8, result.output, "wrote src/main.zig"));
        try testing.expect(std.mem.indexOf(u8, result.output, "1 problem after this edit") != null);
        try testing.expect(std.mem.indexOf(u8, result.output, "src/main.zig:12:5: error:") != null);
        try testing.expectEqual(@as(usize, 1), stub.calls);
    }
}

test "a session with no language server hands back the tool result byte for byte" {
    // A harness that gets worse when a server is missing is worse than no
    // harness, and this is that rule at the one place a production session
    // meets it. **This is also what every session Chock runs today does**: see
    // `DiagnosticToolRunner`, which says plainly that nothing starts a server
    // yet.
    const gpa = testing.allocator;

    var inner = StubToolRunner{};
    var session = chock_core.lsp.Session{};
    var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

    const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
        .call_id = "call1",
        .tool = "write_file",
        .arguments = "{\"path\":\"src/main.zig\",\"content\":\"x\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try testing.expectEqualStrings(inner.output, result.output);
    try testing.expect(!result.is_error);
}

test "a refused write and a call that is not a write are both passed straight through" {
    // Two different reasons for the same silence, and both matter. A write that
    // was refused wrote nothing, so there is nothing new to say about the file
    // and the refusal it carries is the whole answer. A `grep` or a
    // `run_command` names no file at all: see
    // `chock_core.tools.Tool.writesAProjectFile`.
    const gpa = testing.allocator;

    // A write the tool refused.
    {
        var inner = StubToolRunner{
            .output = "old_string does not appear in src/main.zig, so nothing was written",
            .is_error = true,
        };
        var stub = StubServer{};
        var session = chock_core.lsp.Session{ .suffixes = &.{".zig"}, .server = stub.server() };
        var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

        const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = "edit_file",
            .arguments = "{\"path\":\"src/main.zig\",\"old_string\":\"a\",\"new_string\":\"b\"}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqualStrings(inner.output, result.output);
        try testing.expect(result.is_error);
        // The server was never asked, so a refused edit costs exactly what it
        // cost before this runner existed.
        try testing.expectEqual(@as(usize, 0), stub.calls);
    }

    // Every call that is not a write, including the ones that name a path.
    for ([_][]const u8{ "read_file", "grep", "glob", "list_directory", "run_command" }) |tool| {
        var inner = StubToolRunner{ .output = "the tool's own answer" };
        var stub = StubServer{};
        var session = chock_core.lsp.Session{ .suffixes = &.{".zig"}, .server = stub.server() };
        var diagnosing = DiagnosticToolRunner{ .inner = inner.runner(), .session = &session };

        const result = try diagnosing.runner().dispatch(gpa, testing.io, .{
            .call_id = "call1",
            .tool = tool,
            .arguments = "{\"path\":\"src/main.zig\",\"pattern\":\"x\",\"argv\":[\"zig\",\"build\"]}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try testing.expectEqualStrings("the tool's own answer", result.output);
        try testing.expectEqual(@as(usize, 0), stub.calls);
    }
}

/// Drive `Printer` over `events` and give back what a terminal would have
/// shown. Only the tests below use this. `testing.io` is enough: a `Printer`
/// with a buffer sink never touches a file.
fn printedFor(gpa: std.mem.Allocator, events: []const chock_proto.event.Event) ![]u8 {
    var steps: std.ArrayList(PrinterStep) = .empty;
    defer steps.deinit(gpa);
    for (events) |ev| try steps.append(gpa, .{ .event = ev });
    return printedForSteps(gpa, steps.items);
}

/// One thing `chock_core.Loop` tells an observer. The two arrive interleaved
/// in a real session: pieces while a turn is running, events as it appends
/// them. See `chock_core.Loop.Observer`.
const PrinterStep = union(enum) {
    event: chock_proto.event.Event,
    piece: chock_core.Loop.Piece,
};

/// Drive `Printer` over `steps` and give back what a terminal would have
/// shown.
fn printedForSteps(gpa: std.mem.Allocator, steps: []const PrinterStep) ![]u8 {
    return printedForStepsPainted(gpa, steps, .off);
}

/// The same, with the painter stated. A test that wants to read escape
/// sequences passes `.colour`, and one that wants the plain bytes passes
/// `.off`, which is what a pipe and a file get.
fn printedForStepsPainted(
    gpa: std.mem.Allocator,
    steps: []const PrinterStep,
    paint: tty.Painter,
) ![]u8 {
    var shown: std.ArrayList(u8) = .empty;
    errdefer shown.deinit(gpa);
    var printer = Printer.init(gpa, testing.io);
    defer printer.deinit();
    printer.out = .{ .buffer = .{ .gpa = gpa, .bytes = &shown } };
    printer.paint = paint;
    const watcher = printer.observer();
    for (steps, 0..) |step, index| switch (step) {
        .event => |ev| watcher.onEvent(index, ev),
        .piece => |piece| watcher.onPiece(piece),
    };
    return shown.toOwnedSlice(gpa);
}

/// Count the lines in `text`. A trailing newline closes the last line and does
/// not open another.
fn lineCount(text: []const u8) usize {
    if (text.len == 0) return 0;
    var seen = std.mem.count(u8, text, "\n");
    if (text[text.len - 1] != '\n') seen += 1;
    return seen;
}

test "a quiet start says less than a verbose one and still names every instruction file" {
    // The rule the whole triage rests on: nothing is deleted, it moves. A quiet
    // run says which files went into the prompt, because those are untrusted
    // input and a path is what somebody opens. The layer and the byte count are
    // behind `--verbose`. Mutation check: turn the `tty.detail` calls in
    // `reportInstructions` back into ordinary prints and the count comparison
    // fails.
    const gpa = testing.allocator;
    const loaded = chock_core.instructions.Loaded{ .files = &.{
        .{ .layer = .operator, .path = "/home/a/.config/chock/AGENTS.md", .bytes = 900 },
        .{ .layer = .project, .path = "AGENTS.md", .bytes = 4096 },
    } };

    // These lines are diagnostics, so they go to standard error, and that is
    // the stream this reads.
    var quiet: std.Io.Writer.Allocating = .init(gpa);
    defer quiet.deinit();
    var loud: std.Io.Writer.Allocating = .init(gpa);
    defer loud.deinit();

    defer tty.configure(.{});
    defer tty.useStreams(testing.io, null, null);

    tty.configure(.{ .verbose = false });
    tty.useStreams(testing.io, null, &quiet.writer);
    reportInstructions(loaded);

    tty.configure(.{ .verbose = true });
    tty.useStreams(testing.io, null, &loud.writer);
    reportInstructions(loaded);

    try testing.expect(lineCount(quiet.written()) < lineCount(loud.written()));
    try testing.expectEqual(@as(usize, 1), lineCount(quiet.written()));

    // Every path is still on screen without the flag. That is the half of the
    // rule that says a line was moved and not deleted.
    for (loaded.files) |file| {
        try testing.expect(std.mem.indexOf(u8, quiet.written(), file.path) != null);
    }
    // And the sizes are only in the loud one.
    try testing.expect(std.mem.indexOf(u8, quiet.written(), "4096 bytes") == null);
    try testing.expect(std.mem.indexOf(u8, loud.written(), "4096 bytes") != null);
}

test "a display opens on the conversation the log already holds" {
    // **A session that was taken up used to open on an empty transcript.** So a
    // resume looked exactly like a fresh start, which is most of why `/resume`
    // read as broken. `ui.Ui.replay` is the display's half of the answer and
    // this function is the caller's half.
    //
    // **A real `ui.Ui` on no terminal at all**, because what is under test is
    // the wiring between a log and a display, and a stand-in for either would
    // prove neither.
    //
    // Mutation check: hand the events to nothing, or hand only the ones
    // `foldEvent` already draws, and the person's own words go missing.
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var backing = try chock_proto.storage.Memory.init(gpa, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    defer backing.deinit();
    const store = backing.storage();

    var locked = try store.lock(io);
    _ = try locked.append(gpa, io, .{ .message = .{
        .role = .user,
        .content = &.{.{ .text = "fix the parser" }},
    } }, 0);
    _ = try locked.append(gpa, io, .{ .message = .{
        .role = .assistant,
        .content = &.{.{ .text = "the parser is where it fails" }},
    } }, 0);
    try locked.unlock(io);

    var frames: std.Io.Writer.Allocating = .init(gpa);
    defer frames.deinit();
    var said: std.Io.Writer.Allocating = .init(gpa);
    defer said.deinit();
    defer tty.useStreams(io, null, null);
    tty.useStreams(io, &frames.writer, &said.writer);
    defer tty.configure(.{});
    tty.configure(.{});

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    // `/dev/null` takes no raw mode and answers no capability query, so the
    // whole path runs with no terminal anywhere.
    const device = try std.Io.Dir.openFileAbsolute(io, "/dev/null", .{});
    defer device.close(io);

    const screen = try ui.Ui.start(gpa, io, &env, .{ .terminal = .{
        .in = device,
        .out = device,
        .size = .{ .cols = 80, .rows = 24, .xpixel = 640, .ypixel = 384 },
    } });
    defer screen.deinit();

    replayInto(gpa, io, store, screen);

    var said_by_person = false;
    var said_by_model = false;
    for (screen.lines.items) |line| {
        if (std.mem.eql(u8, line.text, "fix the parser")) said_by_person = true;
        if (std.mem.eql(u8, line.text, "the parser is where it fails")) said_by_model = true;
    }
    try testing.expect(said_by_person);
    try testing.expect(said_by_model);

    // **A log that read cleanly says nothing at all.** A warning from this
    // function reaches the display's own transcript, because the display is up
    // by the time it runs, so an empty transcript is what says no line was
    // written. See `src/ui.zig`'s `Diagnostics`.
    try testing.expectEqualStrings("", screen.transcript.items);
}

/// This file's own source, so a test can say that a call exists and where it
/// sits among its neighbours.
///
/// **A structural check, and it says so plainly.** What it stands in for is an
/// end to end run of bare `chock` on a session that was taken up, and this
/// suite cannot start one: a display needs a real terminal on three
/// descriptors, `chock run` never opens one, and `test/cli` has no pseudo
/// terminal to lend. The fault it does catch is the one no green unit test can
/// see, which is a mechanism that works and that nothing calls.
const own_source = @embedFile("run.zig");

/// Where one call sits in this file, or an error naming the call that is gone.
///
/// **Each pattern opens with a real newline and the indent of the block**, so
/// it matches the call itself and never the same words inside a comment or
/// inside this test. The bytes of a pattern written here hold a backslash and
/// an `n`, and not the newline the pattern is looking for, so this file cannot
/// match itself either.
fn callAt(pattern: []const u8) error{CallIsGone}!usize {
    return std.mem.indexOf(u8, own_source, pattern) orelse error.CallIsGone;
}

test "the display is told what the session is, then filled from the log, then asked for a message" {
    // **Getting the order wrong shows an empty header behind a full
    // transcript**, and leaving the middle one out shows a session that was
    // taken up as a fresh one, which is most of why `/resume` read as broken.
    //
    // Mutation check: delete the `replayInto` call and this fails with
    // `CallIsGone`; move it above `one.describe` and the first comparison
    // fails.
    const described = try callAt("\n        one.describe(.{");
    const replayed = try callAt("\n        replayInto(gpa, io, started.storage, one);");
    const primed = try callAt("\n        if (options.display.?.first_message.len != 0) one.prime(");

    try testing.expect(described < replayed);
    try testing.expect(replayed < primed);
}

test "no startup line carries an escape sequence when the stream is not a terminal" {
    // The property a `chock run > log.txt 2>&1` needs, taken over the startup
    // reporter rather than over the painter on its own.
    const gpa = testing.allocator;
    var shown: std.Io.Writer.Allocating = .init(gpa);
    defer shown.deinit();

    defer tty.configure(.{});
    defer tty.useStreams(testing.io, null, null);
    // A terminal on the command line and a pipe on the stream: the pipe is what
    // decides, so this comes out clean.
    tty.configure(.{ .verbose = true, .stderr_is_tty = false, .term = "xterm-256color" });
    tty.useStreams(testing.io, null, &shown.writer);

    reportInstructions(.{
        .files = &.{.{ .layer = .project, .path = "AGENTS.md", .bytes = 4096 }},
        .subtrees_left_out = 3,
    });

    try testing.expect(shown.written().len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, shown.written(), 0x1b) == null);
}

test "a printer that is not writing to a terminal emits no escape sequence at all" {
    // The property a pipe and a file need. Every kind of event this printer
    // knows goes through it, so a branch that painted unconditionally would be
    // caught wherever it was. Mutation check: give `Printer.open` the body of
    // `tty.Painter.colour.open` and this fails.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "the answer" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .event = .{ .message = .{ .role = .system, .content = &content } } },
        .{ .event = .{ .tool_call = .{ .call_id = "1", .tool = "read_file", .arguments = "{}" } } },
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "no such file", .is_error = true, .truncated = false } } },
        .{ .event = .{ .compaction = .{
            .summary = "what happened",
            .from_id = 1,
            .through_id = 2,
            .kept_ranges = &.{},
            .model_alias = "small",
        } } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
        .{ .event = .{ .session_end = .{ .reason = .errored, .detail = "the provider hung up" } } },
    });
    defer gpa.free(shown);

    try testing.expect(shown.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, shown, 0x1b) == null);
}

test "a printer writing to a terminal paints a failed tool result and leaves the answer alone" {
    // Colour is rank. The model's own words are the program's answer and carry
    // no rank Chock can know, so they stay plain even with colour on. What is
    // painted is the line a person is scanning for.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "the answer" }};

    const failed = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "no such file", .is_error = true, .truncated = false } } },
    }, .colour);
    defer gpa.free(failed);
    try testing.expectEqualStrings("\x1b[31m! no such file\n\x1b[0m", failed);

    // A result that worked is ordinary output, and it gets what an ordinary
    // line gets.
    const worked = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "ok", .is_error = false, .truncated = false } } },
    }, .colour);
    defer gpa.free(worked);
    try testing.expectEqualStrings("ok\n", worked);

    // And the answer itself.
    const answer = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
    }, .colour);
    defer gpa.free(answer);
    try testing.expectEqualStrings("the answer\n", answer);
}

test "a result's note is written above the result, in Chock's own voice" {
    // **A tool result has two readers, and `chock run` shows both.** The
    // result is written for the model: a refused fetch tells the agent that
    // the policy file is the user's to write and not its own, which is what
    // stops it retrying or looking for a way round. A person reading that same
    // paragraph is reading a message about themselves in the third person, and
    // the project owner did exactly that on 2026-08-25.
    //
    // So the note goes first, under Chock's own `chock: ` prefix, which is the
    // same shape `onNoticeFn` uses and which the model can never produce: only
    // `Printer` writes at column 0. See
    // `chock_proto.event.ToolResult.note`.
    //
    // Mutation check: write the note after the output and the order assertion
    // fails; drop it and the first assertion does.
    const gpa = testing.allocator;
    const shown = try printedForSteps(gpa, &.{
        .{ .event = .{ .tool_result = .{
            .call_id = "1",
            .output = "nothing was read: which you cannot write and the user can.",
            .is_error = true,
            .truncated = false,
            .note = "add a rule to chock.zon to read ziglang.org.",
        } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "chock: add a rule to chock.zon to read ziglang.org.\n" ++
            "! nothing was read: which you cannot write and the user can.\n",
        shown,
    );

    // An ordinary result gains no line of Chock's. A sentence under every
    // result is a sentence nobody reads.
    const plain = try printedForSteps(gpa, &.{
        .{ .event = .{ .tool_result = .{ .call_id = "1", .output = "ok", .is_error = false, .truncated = false } } },
    });
    defer gpa.free(plain);
    try testing.expectEqualStrings("ok\n", plain);
}

test "a session that finished and one that did not are painted differently" {
    // The one line at the end that a script and a person both read. A run that
    // ended badly has to look different from one that did not, or the colour
    // has told the reader nothing.
    const gpa = testing.allocator;

    const clean = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .session_end = .{ .reason = .finished, .detail = "" } } },
    }, .colour);
    defer gpa.free(clean);

    const bad = try printedForStepsPainted(gpa, &.{
        .{ .event = .{ .session_end = .{ .reason = .budget_reached, .detail = "" } } },
    }, .colour);
    defer gpa.free(bad);

    try testing.expect(std.mem.startsWith(u8, clean, tty.Painter.colour.open(.dim)));
    try testing.expect(std.mem.startsWith(u8, bad, tty.Painter.colour.open(.warn)));
    try testing.expect(!std.mem.eql(u8, clean[0..4], bad[0..4]));
}

test "the answer is on the screen before the turn ends, and the event that closes the turn does not print it again" {
    // The measured silence: a session ran 5.3 minutes over about 57 model
    // calls and printed nothing while any of them was in flight, because the
    // `message` event is the end of a turn and there was nothing before it.
    // Now the pieces are printed as they arrive, so what is left for the event
    // is the newline that closes the line, and nothing else. A printer that
    // printed both would show every answer twice.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "Hello world" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .piece = .{ .text = "Hello " } },
        .{ .piece = .{ .text = "world" } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("Hello world\n", shown);
}

test "what was streamed belongs to its own turn, and the next turn starts from nothing" {
    // The counter has to be cleared by the event that closes a turn.
    // Otherwise the second turn's `message` event, which streamed nothing of
    // its own in this arrangement, would still be read as already printed and
    // would show nothing at all.
    const gpa = testing.allocator;
    const first = [_]chock_proto.event.ContentPart{.{ .text = "first" }};
    const second = [_]chock_proto.event.ContentPart{.{ .text = "second" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .piece = .{ .text = "first" } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &first } } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &second } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("first\nsecond\n", shown);
}

test "the model's reasoning is not printed as it arrives, so the answer is not buried in it" {
    // A model that thinks before it answers writes far more reasoning than
    // answer. The reasoning is in the log, which is where a person who wants
    // it looks. See `Printer.onPieceFn`.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "42" }};
    const shown = try printedForSteps(gpa, &.{
        .{ .piece = .{ .reasoning = "counting on my fingers" } },
        .{ .piece = .{ .text = "42" } },
        .{ .event = .{ .message = .{ .role = .assistant, .content = &content } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("42\n", shown);
}

test "a turn that only reasoned prints nothing at all, and not a blank line" {
    // Measured against claude-sonnet-5, which opens every turn with a
    // thinking block. The reasoning is not shown, so the turn had nothing to
    // print, and the newline that closed it had nothing to close. One blank
    // line per turn, and the tool call after it opens with a newline of its
    // own, so a session with many tool calls was mostly whitespace.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{
        .{ .reasoning = .{ .text = "weighing the approach", .signature = "SIG==" } },
        .{ .tool_use = .{ .call_id = "toolu_1", .tool = "list_directory", .arguments = "{}" } },
    };
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .assistant, .content = &content } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("", shown);
}

test "a turn that said something keeps the newline that closes it" {
    // The other half: the newline is not simply gone. A turn with words in it
    // still ends its own line, so the next thing printed starts on a fresh
    // one.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{
        .{ .reasoning = .{ .text = "weighing the approach", .signature = "SIG==" } },
        .{ .text = "I will list the files." },
    };
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .assistant, .content = &content } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings("I will list the files.\n", shown);
}

test "a reasoning only turn ahead of a tool call leaves one blank line and not two" {
    // The whole shape, end to end, because the count is the fault: this is
    // what a tool heavy session actually prints. The one blank line here is
    // the `.tool_call` branch's own leading newline, which separates the
    // command from whatever came before it. The turn that only reasoned adds
    // nothing to it.
    const gpa = testing.allocator;
    const thinking = [_]chock_proto.event.ContentPart{
        .{ .reasoning = .{ .text = "weighing the approach", .signature = "SIG==" } },
    };
    const answer = [_]chock_proto.event.ContentPart{.{ .text = "There are 4 entries." }};
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .assistant, .content = &thinking } },
        .{ .tool_call = .{ .call_id = "toolu_1", .tool = "list_directory", .arguments = "{\"path\":\".\"}" } },
        .{ .tool_result = .{
            .call_id = "toolu_1",
            .output = "README.md",
            .is_error = false,
            .truncated = false,
        } },
        .{ .message = .{ .role = .assistant, .content = &answer } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        \\
        \\$ list_directory {"path":"."}
        \\README.md
        \\There are 4 entries.
        \\
    , shown);
}

test "a user's own message is still not echoed, whatever the newline rule does" {
    // The user just typed it, and the tool role's message is the same result
    // the tool.result event already showed. Both branches return before the
    // newline question is reached, so a change to that question must not
    // start echoing either one.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{.{ .text = "list the files" }};
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .user, .content = &content } },
    });
    defer gpa.free(shown);
    try testing.expectEqualStrings("", shown);
}

test "a compaction says so on the terminal, and says the log kept everything" {
    // **A compaction in silence is the five minute silence again.** The
    // project owner once watched a session sit with no output and reasonably
    // guessed it was compacting. It was not, because nothing compacted at
    // all. Now that something does, the user hears it.
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .compaction = .{
            .summary = "the parser work is half done",
            .from_id = 12,
            .through_id = 900,
            .kept_ranges = &.{},
            .model_alias = "local",
        } },
    });
    defer gpa.free(shown);

    try testing.expect(std.mem.indexOf(u8, shown, "folded into a summary") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "local") != null);
    try testing.expect(std.mem.indexOf(u8, shown, "still in the session log") != null);
    // The summary itself is not printed. It is the model's context, not a
    // report to the user, and it is in the log for anyone who wants it.
    try testing.expect(std.mem.indexOf(u8, shown, "the parser work") == null);
}

test "what the harness tells the model reaches the user too" {
    // A session that quietly told the model something is a session the user
    // cannot explain afterwards. The notice before a compaction is the first
    // of these, and it arrives as a `system` role message, which the printer
    // used to drop with the user's own echo.
    const gpa = testing.allocator;
    const content = [_]chock_proto.event.ContentPart{
        .{ .text = "[chock] Your context holds 40000 tokens of the 65536 this model can take" },
    };
    const shown = try printedFor(gpa, &.{
        .{ .message = .{ .role = .system, .content = &content } },
    });
    defer gpa.free(shown);

    try testing.expect(std.mem.indexOf(u8, shown, "40000 tokens") != null);
}

test "a whole plan update is one row, and it names the step being worked on" {
    // **The owner's own complaint.** One `update_plan` call wrote one row per
    // step, so a list of four steps cost four rows every time any one of them
    // moved, and a task list has one current state rather than one per event.
    // `src/ui.zig` settled the shape and this writes the same one.
    //
    // Mutation check: put the per step loop back and this reads four rows
    // rather than one.
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .done },
            .{ .id = "s2", .subject = "write the command", .status = .in_progress },
            .{ .id = "s3", .subject = "measure it on Darwin", .status = .pending, .blocked_by = "s2" },
            .{ .id = "s4", .subject = "write the tests", .status = .pending },
        } } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "\nchock: plan: 1 of 4 done, now on \"write the command\"\n",
        shown,
    );
}

test "a step starting work moves no count and is still reported by name" {
    // **Why the row names the step and does not only count.** Pending to
    // in_progress is the commonest move a task list makes, and it moves no
    // count at all, so a row carrying only counts would repeat the row before
    // it and read as nothing having happened.
    //
    // The second update carries no subject, which is what
    // `chock_proto.state.Plan.apply` reads as "keep the words this step
    // already has". The words come off the fold, so the row still has them.
    //
    // Mutation check: drop the `now on` clause and the two rows are the same
    // bytes, which the comparison below refuses.
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .pending },
            .{ .id = "s2", .subject = "write the command", .status = .pending },
        } } },
        .{ .plan_update = .{ .steps = &.{.{ .id = "s2", .subject = "", .status = .in_progress }} } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "\nchock: plan: 0 of 2 done\n" ++
            "\nchock: plan: 0 of 2 done, now on \"write the command\"\n",
        shown,
    );
}

test "a step given up keeps a row of its own, once, and rides the summary after" {
    // **A state and an event are not the same thing.** `src/ui.zig` keeps the
    // standing state in the plan sidebar, where a step that was dropped is a
    // row a person can see for the rest of the session. `chock run` has no
    // sidebar, so the same fact travels two ways: a row at the moment it
    // happens, which is the only place the time of it can be read, and a count
    // on every summary after, because `1 of 3 done` reads as two left when one
    // of the three was given up.
    //
    // Mutation check: fire the row off the status rather than off the move and
    // the repeated update writes "was given up" a second time.
    //
    // Mutation check: drop the `given up` clause from the summary and the last
    // comparison fails.
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .plan_update = .{ .steps = &.{
            .{ .id = "s1", .subject = "read the fold", .status = .done },
            .{ .id = "s2", .subject = "write the command", .status = .pending },
            .{ .id = "s3", .subject = "measure it on Darwin", .status = .pending },
        } } },
        .{ .plan_update = .{ .steps = &.{.{ .id = "s3", .subject = "", .status = .abandoned }} } },
        .{ .plan_update = .{ .steps = &.{.{ .id = "s3", .subject = "", .status = .abandoned }} } },
    });
    defer gpa.free(shown);

    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, shown, "was given up"));
    // The words are the fold's, because the update that dropped the step
    // carried none of its own.
    try testing.expect(std.mem.indexOf(
        u8,
        shown,
        "chock: plan step s3 was given up: measure it on Darwin\n",
    ) != null);
    try testing.expect(std.mem.endsWith(u8, shown, "\nchock: plan: 1 of 3 done, 1 given up\n"));
}

test "a promise the agent makes is printed as it is made, with the reason it gave" {
    // The promise holds for the rest of the session and nothing lifts it, so
    // the person watching learns about it at the moment it happens rather than
    // by reading the log afterwards. The record is surfaced rather than buried,
    // and this is the earliest place it can be.
    const gpa = testing.allocator;
    const shown = try printedFor(gpa, &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "net.fetch",
            .ceiling = .deny,
            .reason = "this task reads local files only",
        }} } },
    });
    defer gpa.free(shown);

    try testing.expectEqualStrings(
        "\nchock: the agent promised net.fetch at most deny: this task reads local files only\n",
        shown,
    );

    // A promise from a newer Chock keeps its own spelling here too, because
    // the printer holds no list of ceilings of its own.
    const newer = try printedFor(gpa, &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "git.*",
            .ceiling = .{ .unknown = "ask_two_people" },
            .reason = "",
        }} } },
    });
    defer gpa.free(newer);
    try testing.expectEqualStrings("\nchock: the agent promised git.* at most ask_two_people\n", newer);
}

/// A `ToolRunner` that runs nothing and reports what the mount set and the
/// `PATH` looked like when it was called.
///
/// **This is the only way to prove the fact that matters**: that a store path
/// adopted between two tool calls is in the set the second one is built from.
/// A test that read `ProvisionToolRunner`'s own fields would prove that the
/// runner wrote them down, which is a different and much weaker statement.
const RecordingToolRunner = struct {
    context: *const chock_core.tools.Context,
    tool_env: *const std.process.Environ.Map,
    calls: usize = 0,
    last_store_paths: []const []const u8 = &.{},
    last_path: []const u8 = "",

    fn runner(self: *RecordingToolRunner) chock_core.Loop.ToolRunner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.ToolRunner.VTable{ .dispatch = dispatchFn };

    fn dispatchFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: chock_proto.event.ToolCall,
    ) chock_core.Loop.DispatchError!chock_proto.event.ToolResult {
        _ = io;
        const self: *RecordingToolRunner = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_store_paths = self.context.store_paths;
        self.last_path = self.tool_env.get("PATH") orelse "";
        return .{
            .call_id = try gpa.dupe(u8, call.call_id),
            .output = try gpa.dupe(u8, "ran"),
            .is_error = false,
            .truncated = false,
        };
    }
};

test "a program taken into the toolchain is mounted by the next tool call, and not by the one before" {
    // The question this whole feature turns on: can a store path become
    // visible to a sandbox while the session is live? It can, and the reason
    // is that there is no long lived sandbox. `Registry.dispatchWith` builds a
    // `sandbox.Config` from `Context.store_paths` for **every** call, so the
    // set is read once per call and never cached. This pins that, from the
    // side that reads it.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    try tool_env.put("PATH", "/nix/store/aaa-coreutils/bin");

    var context = chock_core.tools.Context{ .store_paths = &.{"/nix/store/aaa-coreutils"} };
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .tool_env = &tool_env,
        .context = &context,
    };
    try provisioning.start(context.store_paths);
    const runner = provisioning.runner();

    const call = chock_proto.event.ToolCall{
        .call_id = "c1",
        .tool = "run_command",
        .arguments = "{\"argv\":[\"rg\"]}",
    };

    // Before: one store path, and the dev shell's own PATH.
    const before = try runner.dispatch(gpa, std.testing.io, call);
    gpa.free(before.call_id);
    gpa.free(before.output);
    try std.testing.expectEqual(@as(usize, 1), recorder.last_store_paths.len);
    try std.testing.expectEqualStrings("/nix/store/aaa-coreutils/bin", recorder.last_path);

    const store_paths = [_][]const u8{
        "/nix/store/bbb-ripgrep",
        "/nix/store/ccc-pcre2",
    };
    const bin_dirs = [_][]const u8{"/nix/store/bbb-ripgrep/bin"};
    try provisioning.adopt("ripgrep", .{
        .program = "ripgrep",
        .installable = "nixpkgs#ripgrep",
        .bin_dirs = &bin_dirs,
        .store_paths = &store_paths,
    });

    // After: the whole closure is mounted, the dev shell's own paths are
    // still there, and the provisioned `bin` is ahead of them on the PATH so
    // the program the agent just asked for is the one that is found.
    const after = try runner.dispatch(gpa, std.testing.io, call);
    gpa.free(after.call_id);
    gpa.free(after.output);
    try std.testing.expectEqual(@as(usize, 3), recorder.last_store_paths.len);
    try std.testing.expectEqualStrings("/nix/store/aaa-coreutils", recorder.last_store_paths[0]);
    try std.testing.expectEqualStrings("/nix/store/ccc-pcre2", recorder.last_store_paths[2]);
    try std.testing.expectEqualStrings(
        "/nix/store/bbb-ripgrep/bin:/nix/store/aaa-coreutils/bin",
        recorder.last_path,
    );

    // And the pass through is really a pass through: both calls reached the
    // runner below, so nothing about this wrapper swallows ordinary work.
    try std.testing.expectEqual(@as(usize, 2), recorder.calls);
}

test "a session that cannot provision refuses the call and names no package manager as a way out" {
    // The model is not offered `provide_tool` in this case, so this is a call
    // that came out of nowhere. It still has to be answered with something
    // the model can act on, and the one thing that is true is: use what is
    // here, and do not reach for apt.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();

    var context = chock_core.tools.Context{};
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .tool_env = &tool_env,
        .context = &context,
    };

    const result = try provisioning.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "c1",
        .tool = "provide_tool",
        .arguments = "{\"program\":\"ripgrep\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "cannot add one") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "apt") != null);
    // And nothing was run below: a call this runner answers never reaches the
    // sandbox, so no `nix` was spawned to find out that there is no `nix`.
    try std.testing.expectEqual(@as(usize, 0), recorder.calls);
}

test "asking twice for the same program builds nothing the second time" {
    // A model that forgets it already asked would otherwise pay for a second
    // resolution, which on a cache miss is minutes. The answer says the
    // program is there, and it is not an error: the request is satisfied.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();
    try tool_env.put("PATH", "/nix/store/aaa/bin");

    var context = chock_core.tools.Context{};
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    // `settings` names a `nix` that is not there. The point is that this test
    // never reaches it: a repeat is answered before anything is spawned.
    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = .{
            .nix_program = "/nowhere/nix",
            .nix_store_program = null,
            .registry = "nixpkgs",
            .root_dir = null,
        },
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .tool_env = &tool_env,
        .context = &context,
    };
    try provisioning.adopt("ripgrep", .{
        .program = "ripgrep",
        .installable = "nixpkgs#ripgrep",
        .bin_dirs = &.{},
        .store_paths = &.{},
    });

    const result = try provisioning.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "c1",
        .tool = "provide_tool",
        .arguments = "{\"program\":\"ripgrep\"}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(!result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "already in this session") != null);
}

test "the policy key is the broker's own nix.build, and a project that said nothing cannot provision" {
    // Provisioning runs `nix build` on the host, outside the sandbox, with the
    // daemon, so it is measured against the action the broker already has for
    // exactly that. A key spelled again here would silently stop matching a
    // rule the user wrote.
    try std.testing.expectEqualStrings("nix.build", provision_action);

    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A project with no `chock.zon` gets the empty table, where every key
    // answers `ask`. `ask` cannot be answered mid session, because `Loop.run`
    // holds the log lock for the whole session, so the honest reading is that
    // this project does not provision. **The safe direction, and the same one
    // `applyWork` already takes.**
    const empty = try chock_policy.table.Table.parse(arena, ".{}", null);
    defer chock_policy.table.Table.destroy(arena, empty);
    try std.testing.expectEqual(
        chock_policy.table.Decision.ask,
        try provisionDecision(arena, empty, &.{}, "main", "a-model"),
    );

    // A project that said yes, in the file that is kept beyond the agent's
    // reach.
    const allowed = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "nix.build", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, allowed);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        try provisionDecision(arena, allowed, &.{}, "main", "a-model"),
    );

    // And a subagent holds no more than its parent, whatever the file says
    // about the child alone. The decision is the intersection over the chain,
    // so a `reviewer` allowed on its own still cannot provision under a `main`
    // that is denied.
    const child_only = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .agent_kind = "reviewer", .action = "nix.build", .decision = .allow },
        \\    .{ .agent_kind = "main", .action = "nix.build", .decision = .deny },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, child_only);
    const chain = [_]chock_proto.event.SpawnLink{.{ .agent_kind = "main", .reason = "review it" }};
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        try provisionDecision(arena, child_only, &chain, "reviewer", "a-model"),
    );
}

test "a promise the session made reaches the end of session approval, out of the log" {
    // The ratchet, along the route `applyWork` takes. An agent that promised
    // not to apply its work made that promise turns ago, in a `state.Session`
    // that no longer exists: `Loop.run` has ended by the time this decision is
    // made. So the promise has to come back out of the file, and this drives
    // the whole of that: `foldSession`, the conversion in
    // `chock_core.self_policy`, and `Broker.request`, which is what applies it.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A project that allows the apply outright, so the promise is the only
    // thing that can refuse it.
    const allows_the_apply = try chock_policy.table.Table.parse(arena,
        \\.{ .policy = .{ .rules = .{
        \\    .{ .action = "workspace.apply", .decision = .allow },
        \\} } }
    , null);
    defer chock_policy.table.Table.destroy(arena, allows_the_apply);

    // A session whose agent bound itself part way through, written the way
    // `Loop.runRestrictSelf` writes it.
    var backing = try chock_proto.storage.Memory.init(gpa, "01PROMISE");
    const storage = backing.storage();
    defer storage.close(io);
    {
        var writing = try storage.lock(io);
        _ = try writing.append(gpa, io, .{ .policy_self = .{ .restrictions = &.{.{
            .action = "workspace.apply",
            .ceiling = .deny,
            .reason = "the user asked me to read this project and change nothing",
        }} } }, 1);
        _ = try writing.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 2);
        try writing.unlock(io);
    }

    // What `applyWork` does: fold the log that is left, and carry the promises
    // into the request.
    var session = chock_proto.state.Session.init(gpa);
    defer session.deinit();
    foldSession(gpa, io, storage, &session);
    try std.testing.expectEqual(@as(usize, 1), session.self_policy.restrictions.items.len);

    const promised = try chock_core.self_policy.restrictionsFrom(
        arena,
        session.self_policy.restrictions.items,
    );

    var locked = try storage.lock(io);
    defer locked.unlock(io) catch {};
    const broker = chock_broker.Broker{
        .policy = allows_the_apply,
        .waiter = chock_broker.Broker.SystemWaiter.waiter(),
    };
    const ask = chock_broker.Broker.Request{
        .action = "workspace.apply",
        .summary = "move 3 objects and the ref refs/chock/01PROMISE",
        .detail = "a1b2c3 the change\n",
        .reason = "the session made a commit",
        .agent_kind = "main",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "",
        .timeout_ms = 0,
        .self_policy = promised,
    };

    // The promise decides, and nobody is asked. A refusal here is the agent's
    // own word holding after the agent is gone.
    const outcome = try broker.request(gpa, io, storage, &locked, ask, null);
    try std.testing.expectEqual(chock_broker.Broker.Outcome.denied_by_policy, outcome);
    try std.testing.expect(!outcome.permits());

    // The same request from a session that promised nothing is allowed, so the
    // line above is about the promise and not about the table or the request.
    var without = ask;
    without.self_policy = &.{};
    try std.testing.expectEqual(
        chock_broker.Broker.Outcome.allowed_by_policy,
        try broker.request(gpa, io, storage, &locked, without, null),
    );
}

test "a promise a parent made binds its subagents, out of the parent's own log" {
    // **A promise a parent made has to reach its children, or it is worth
    // nothing**: an agent that promises not to apply its work and then starts a
    // subagent to apply it has kept the letter of the promise and none of it. A
    // child holds no more than its parent, and this is that rule applied to the
    // half of the policy the parent wrote itself.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buffer[0..try tmp.dir.realPath(io, &dir_buffer)];

    // Three sessions: a grandparent that promised, a parent that promised
    // something else, and the child this decision is about.
    const grandparent = "01JQ" ++ "A" ** 22;
    const parent = "01JQ" ++ "B" ** 22;

    const Writer = struct {
        fn write(
            allocator: std.mem.Allocator,
            inner_io: std.Io,
            at: []const u8,
            id: []const u8,
            parent_id: []const u8,
            events: []const chock_proto.event.Event,
        ) !void {
            const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}.jsonl", .{ at, id }, 0);
            defer allocator.free(path);
            const log = try chock_proto.log.Log.open(inner_io, path, id);
            var backing = chock_proto.storage.JsonLines{ .log = log };
            const store = backing.storage();
            defer store.close(inner_io);
            var locked = try store.lock(inner_io);
            _ = try locked.append(allocator, inner_io, .{ .session_start = .{
                .agent_kind = "main",
                .model_alias = "main",
                .parent_session = parent_id,
            } }, 1);
            for (events, 2..) |one, time| {
                _ = try locked.append(allocator, inner_io, one, @intCast(time));
            }
            try locked.unlock(inner_io);
        }
    };

    try Writer.write(gpa, io, dir, grandparent, "", &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "workspace.apply",
            .ceiling = .deny,
            .reason = "the user asked for a read only review",
        }} } },
    });
    try Writer.write(gpa, io, dir, parent, grandparent, &.{
        .{ .policy_self = .{ .restrictions = &.{.{
            .action = "net.fetch",
            .ceiling = .ask,
            .reason = "no network without a person",
        }} } },
    });

    // The child promised one thing of its own, and inherits both of theirs.
    var child = chock_proto.state.Session.init(gpa);
    defer child.deinit();
    try child.apply(.{ .id = 1, .session = "01CHILD", .time_ms = 1, .event = .{ .policy_self = .{
        .restrictions = &.{.{
            .action = "git.push",
            .ceiling = .deny,
            .reason = "nothing leaves this machine",
        }},
    } } });

    const promised = try promisesFor(gpa, arena, io, dir, parent, &child);
    try std.testing.expectEqual(@as(usize, 3), promised.len);

    // The grandparent's promise reaches the child, which is the escalation
    // this closes: a promise that stopped at one level is a promise one spawn
    // undoes.
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "workspace.apply"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.ask,
        chock_policy.ratchet.ceilingFor(promised, "net.fetch"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "git.push"),
    );
    // And an act nobody in the chain promised anything about is untouched, so
    // the three above are about the promises and not about a walk that denies
    // everything it finds.
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(promised, "nix.build"),
    );

    // A root session reads nothing above it and keeps its own promise, which
    // is every session a person starts.
    const alone = try promisesFor(gpa, arena, io, dir, "", &child);
    try std.testing.expectEqual(@as(usize, 1), alone.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(alone, "workspace.apply"),
    );

    // **A walk that stopped short says so.** A promise that was not read is a
    // permission this session may hold and should not, so silence there would
    // be the worst kind. Captured rather than let through: see `tty.Capture`,
    // and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    // A parent whose log is not there stops the walk rather than ending the
    // session, and the promises read up to that point still hold. The child's
    // own promise is one of them.
    const gone = "01JQ" ++ "Z" ** 22;
    const missing = try promisesFor(gpa, arena, io, dir, gone, &child);
    try std.testing.expectEqual(@as(usize, 1), missing.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(missing, "git.push"),
    );
    try std.testing.expect(std.mem.indexOf(u8, said.err(), gone) != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "may not be applied") != null);

    // A parent identifier that is not an identifier at all is refused before
    // any path is built from it, and it is refused as that rather than as a
    // session that is simply missing.
    said.clear();
    const bad = try promisesFor(gpa, arena, io, dir, "../../etc", &child);
    try std.testing.expectEqual(@as(usize, 1), bad.len);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "not a session identifier") != null);
    try std.testing.expectEqualStrings("", said.out());
}

/// The agent `test/core/tree.zig` builds a real tree out of. Read here as a
/// build time constant for the same reason it is read there: Zig 0.16's test
/// runner panics on an argv it does not recognize, so the path cannot come in
/// as an argument.
///
/// **This module exists in the test build and not in the binary.** Nothing but
/// the test below names it, and a container level declaration is analysed only
/// where it is used, so `chock` itself still compiles with no such module. See
/// `build.zig`, which says why the two modules are apart.
const tree_child_path = @import("tree_child_path").tree_child_path;

test "a promise a grandparent made binds a grandchild of a tree that really ran" {
    // The test above builds three logs by hand. **This one builds them by
    // running three processes**, which is the difference that matters: the
    // identifiers are the ones an agent really chose, the links are the ones a
    // real `session.start` really wrote, and the logs sit where a real session
    // directory puts them. A walk that worked against a fixture and not against
    // a tree would pass there and fail here.
    //
    // What is still not a real grandchild's own doing is the walk itself: it
    // runs in this process, because `promisesFor` is program code and the agents
    // of the tree are a test helper. Everything it reads was written by the
    // tree.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_dir = dir_buffer[0..try tmp.dir.realPath(io, &dir_buffer)];
    try tmp.dir.createDir(io, "project", .default_dir);
    try tmp.dir.createDir(io, "sessions", .default_dir);

    const project = try std.fmt.allocPrint(arena, "{s}/project", .{root_dir});
    const dir = try std.fmt.allocPrint(arena, "{s}/sessions", .{root_dir});

    // Three agents, each promising something of its own, each one starting the
    // next. The root is at the top of the tree, so nobody is above it.
    const root_session = "01JQ" ++ "A" ** 22;
    try runTreeAgent(arena, io, project, dir, root_session,
        \\promise workspace.apply deny the user asked for a read only review
        \\spawn coder
        \\> promise net.fetch ask no network without a person
        \\> spawn worker
        \\> > promise git.push deny nothing leaves this machine
        \\> > say I read the parser
    );

    // Down the tree the way a person reading the logs would: each level's own
    // `session.spawn` names the level below it.
    var top = chock_proto.state.Session.init(gpa);
    defer top.deinit();
    try std.testing.expect(foldSessionById(gpa, io, dir, root_session, &top));
    try std.testing.expectEqual(@as(usize, 1), top.children.items.len);

    var middle = chock_proto.state.Session.init(gpa);
    defer middle.deinit();
    const middle_id = try arena.dupe(u8, top.children.items[0].session);
    try std.testing.expect(foldSessionById(gpa, io, dir, middle_id, &middle));
    try std.testing.expectEqual(@as(usize, 1), middle.children.items.len);

    var bottom = chock_proto.state.Session.init(gpa);
    defer bottom.deinit();
    const bottom_id = try arena.dupe(u8, middle.children.items[0].session);
    try std.testing.expect(foldSessionById(gpa, io, dir, bottom_id, &bottom));
    // The identifiers a real agent chose are ones this walk will build a path
    // from. An agent that chose a name of another shape would stop the walk at
    // its own level, and nothing else here would say so.
    try std.testing.expect(session_paths.isValidId(middle_id));
    try std.testing.expect(session_paths.isValidId(bottom_id));
    try std.testing.expectEqualStrings(middle_id, bottom.parent_session);

    // **The whole point.** The grandchild's own decision is bound by all three
    // promises, and the one at the top of the tree is two links away.
    const promised = try promisesFor(gpa, arena, io, dir, bottom.parent_session, &bottom);
    try std.testing.expectEqual(@as(usize, 3), promised.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "workspace.apply"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.ask,
        chock_policy.ratchet.ceilingFor(promised, "net.fetch"),
    );
    try std.testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.ratchet.ceilingFor(promised, "git.push"),
    );
    // An act nobody in the tree promised anything about is untouched, so the
    // three above are about the promises and not about a walk that denies
    // whatever it finds.
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(promised, "nix.build"),
    );

    // **And the promise really did have to travel.** The middle agent's own
    // session holds two of the three and not the grandparent's, and the
    // grandchild's own log holds one. So the answer above came off the logs
    // above it and not out of its own.
    const at_the_middle = try promisesFor(gpa, arena, io, dir, middle.parent_session, &middle);
    try std.testing.expectEqual(@as(usize, 2), at_the_middle.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(at_the_middle, "git.push"),
    );
    const alone = try promisesFor(gpa, arena, io, dir, "", &bottom);
    try std.testing.expectEqual(@as(usize, 1), alone.len);
    try std.testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.ratchet.ceilingFor(alone, "workspace.apply"),
    );
}

/// Start one agent of a real tree and wait for the whole tree below it. The
/// argument vector is the real one `commandLine` builds, and the agent below it
/// builds its own with the same function.
fn runTreeAgent(
    arena: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    dir: []const u8,
    session: []const u8,
    task: []const u8,
) !void {
    const prepared = chock_core.subagent.Prepared{
        .child_session = try arena.dupe(u8, session),
        .log_path = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ dir, session }),
        .scratchpad_path = try arena.dupe(u8, ""),
    };
    const argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = tree_child_path,
        .project_root = project,
        .parent_session = "",
    }, .{
        .agent_kind = "main",
        .task = task,
        .reason = chock_core.subagent.reasonFor(task),
    }, prepared);

    var env = try std.testing.environ.createMap(arena);
    defer env.deinit();
    try env.put("CHOCK_TEST_SESSION_DIR", dir);

    var child = try std.process.spawn(io, .{
        .argv = argv,
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    _ = child.wait(io) catch {};
}

test "a review that this session cannot pay for or start is refused, never skipped" {
    // A review is a whole subagent, so it is measured against the same two
    // limits every other agent is, and **a review that cannot run must not
    // become an allow**: `reviewFn` turns each of the answers below into
    // `error.ReviewNotRun`, and the broker turns that into
    // `review_unavailable`, which does not permit.
    const cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };
    const limits = chock_policy.subagents.Limits{ .max_depth = 3, .max_width = 2 };
    const fresh = chock_proto.state.Spend{ .amount = 1.0, .currency = "USD", .turns = 3 };
    const first = chock_policy.subagents.Standing{ .depth = 1, .width = 0 };

    // The ordinary case: a reviewer may be started, and it gets what is left
    // of the cap. Without this line every check below would pass against a
    // function that refused everything.
    {
        const bounds = reviewBounds(limits, first, cap, fresh, &.{});
        try std.testing.expectEqual(@as(?chock_policy.subagents.Refusal, null), bounds.refused_by_limits);
        try std.testing.expect(!bounds.nothing_left);
        try std.testing.expectEqual(@as(f64, 4.0), bounds.budget.?.max_cost);
        try std.testing.expectEqualStrings("USD", bounds.budget.?.currency);
    }

    // A session that has spent its whole cap. The two nulls are different
    // facts, and this is the one that must refuse.
    {
        const gone = chock_proto.state.Spend{ .amount = 5.5, .currency = "USD", .turns = 9 };
        const bounds = reviewBounds(limits, first, cap, gone, &.{});
        try std.testing.expectEqual(@as(?chock_cost.budget.Budget, null), bounds.budget);
        try std.testing.expect(bounds.nothing_left);
    }

    // A session that spent little and promised all of it to children. Measured
    // against spending alone, this one would hand the same money out twice.
    {
        const promised = [_]chock_proto.state.Child{
            .{ .session = "01A", .agent_kind = "worker", .reason = "one", .budget_max_cost = 4.0, .budget_currency = "USD" },
        };
        const bounds = reviewBounds(limits, first, cap, fresh, &promised);
        try std.testing.expectEqual(@as(?chock_cost.budget.Budget, null), bounds.budget);
        try std.testing.expect(bounds.nothing_left);
    }

    // Depth: a session already at the bottom of the tree starts no reviewer.
    // Without this a tree would grow one level per approval, because every
    // reviewer's own end of session apply would ask for one too.
    {
        const deep = chock_policy.subagents.Standing{ .depth = 3, .width = 0 };
        const bounds = reviewBounds(limits, deep, cap, fresh, &.{});
        try std.testing.expectEqual(chock_policy.subagents.Refusal.depth, bounds.refused_by_limits.?);
    }

    // Width, and the setting that turns subagents off entirely. A project that
    // wrote `max_width = 0` gets no reviewer, which is the right reading of a
    // project that said it wants no subagents.
    {
        const none_allowed = chock_policy.subagents.Limits{ .max_depth = 6, .max_width = 0 };
        const bounds = reviewBounds(none_allowed, first, cap, fresh, &.{});
        try std.testing.expectEqual(chock_policy.subagents.Refusal.width, bounds.refused_by_limits.?);
    }

    // A session with no cap at all gives the reviewer no cap, and that is not
    // the same as having nothing left: the reviewer runs. The honest reading
    // of a project that set no budget, and the same answer the session itself
    // already runs under.
    {
        const bounds = reviewBounds(limits, first, null, fresh, &.{});
        try std.testing.expectEqual(@as(?chock_cost.budget.Budget, null), bounds.budget);
        try std.testing.expect(!bounds.nothing_left);
        try std.testing.expectEqual(@as(?chock_policy.subagents.Refusal, null), bounds.refused_by_limits);
    }
}

test "the reviewer this run wires in is the kind the policy table names, and it gets no scratchpad" {
    // Two facts about the wiring, both of which a comment alone would let
    // decay. The kind is what selects the reviewer's own row of `chock.zon`,
    // so a name spelled twice is a rule that quietly stops matching. And the
    // scratchpad is the leak: `chock_core.scratchpad` lets a parent read a
    // child's, and the parent of a reviewer is the agent being reviewed.
    // The real child, built the way both callers build it. Nothing here is
    // dereferenced: `reviewChild` stores what it is given and this test never
    // starts anything.
    var child = reviewChild(std.testing.allocator, .empty, undefined, undefined, .{});
    var spawner = ReviewSpawner{
        .child = child.spawner(),
        .budget = null,
        .nothing_left = false,
        .refused_by_limits = null,
    };
    try std.testing.expectEqualStrings(
        chock_broker.review.default_kind,
        spawner.reviewer().kind,
    );
    try std.testing.expect(child.no_scratchpad);
}

/// A child that answers without starting anything, so a test can run the whole
/// of `ReviewSpawner.reviewFn`. The real one is `SubagentSpawner`, which needs
/// a session directory, a credential and a process.
const FakeReviewChild = struct {
    prepared: usize = 0,
    ran: usize = 0,
    outcome: chock_proto.event.AgentOutcome = .finished,
    answer: []const u8 = "{\"verdict\":\"approve\",\"why\":\"the diff is the fix the task asked for\"}",

    fn spawner(self: *FakeReviewChild) chock_core.subagent.Spawner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
    ) chock_core.subagent.Error!chock_core.subagent.Prepared {
        _ = io;
        _ = request;
        const self: *FakeReviewChild = @ptrCast(@alignCast(ptr));
        self.prepared += 1;
        return .{
            .child_session = try allocator.dupe(u8, "01REVIEWCHILD"),
            .log_path = try allocator.dupe(u8, "/tmp/chock/01REVIEWCHILD/log.jsonl"),
            .scratchpad_path = try allocator.dupe(u8, ""),
        };
    }

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: chock_core.subagent.Request,
        prepared: chock_core.subagent.Prepared,
    ) chock_core.subagent.Error!chock_core.subagent.Report {
        _ = io;
        _ = request;
        _ = prepared;
        const self: *FakeReviewChild = @ptrCast(@alignCast(ptr));
        self.ran += 1;
        return .{ .outcome = self.outcome, .result = try allocator.dupe(u8, self.answer) };
    }
};

/// The case every reviewer test below is put.
const a_case = chock_broker.review.Case{
    .action = "workspace.apply",
    .summary = "move 3 objects and one ref",
    .detail = "a1b2c3 fix the parser\n",
    .reason = "the session made a commit",
    .chain = &.{ "main", "coder" },
    .decision = .agent_review,
};

test "a reviewer is a child in its parent's log, so the width bound can see it" {
    // The fault this closes: a reviewer was a real process that nothing
    // counted, so a session could pass its own width bound with nothing
    // noticing. The link existed from the child's side, because the reviewer's
    // own `session.start` names its parent, but the parent's own log said
    // nothing, and the width is folded from the parent's log.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01PARENT");
    const storage = backing.storage();
    defer storage.close(io);

    var locked = try storage.lock(io);

    var child = FakeReviewChild{};
    var spawner = ReviewSpawner{
        .child = child.spawner(),
        .budget = .{ .max_cost = 4.0, .currency = "USD" },
        .nothing_left = false,
        .refused_by_limits = null,
        .locked = &locked,
    };

    const report = try spawner.reviewer().review(gpa, io, a_case);
    defer chock_broker.review.freeReport(gpa, report);
    // The review really happened, so what follows is about a reviewer that
    // ran and not about one that was refused before it started.
    try std.testing.expectEqual(@as(usize, 1), child.ran);
    try std.testing.expectEqual(chock_broker.review.Verdict.approved, report.verdict);

    try locked.unlock(io);

    var session = chock_proto.state.Session.init(gpa);
    defer session.deinit();
    var spawn_events: usize = 0;
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
        if (parsed.value.event == .session_spawn) spawn_events += 1;
    }

    // One event, and it is the one the fold counts. The kind is the reviewer's
    // own, so a person reading the log in the morning sees which child this
    // was, and the slice it was given is there too, so a parent that resumes
    // does not hand the same money out twice.
    try std.testing.expectEqual(@as(usize, 1), spawn_events);
    try std.testing.expectEqual(@as(usize, 1), session.children.items.len);
    try std.testing.expectEqualStrings(
        chock_broker.review.default_kind,
        session.children.items[0].agent_kind,
    );
    try std.testing.expectEqualStrings("01REVIEWCHILD", session.children.items[0].session);
    try std.testing.expectEqual(@as(f64, 4.0), session.children.items[0].budget_max_cost);

    // **And the count is what the limit reads.** A project that allows one
    // child has none left after this reviewer, which is the whole point: the
    // fold `reviewBounds` measures is the fold the event above changed.
    const one_child = chock_policy.subagents.Limits{ .max_depth = 6, .max_width = 1 };
    const standing = chock_policy.subagents.Standing{
        .depth = 1,
        .width = session.children.items.len,
    };
    const after = reviewBounds(one_child, standing, null, session.spend, session.children.items);
    try std.testing.expectEqual(chock_policy.subagents.Refusal.width, after.refused_by_limits.?);

    // Against the standing this session had before the reviewer, the same
    // limit allows one. Without this line the check above would pass against a
    // bound that refused everything.
    const before = reviewBounds(one_child, .{ .depth = 1, .width = 0 }, null, session.spend, &.{});
    try std.testing.expectEqual(@as(?chock_policy.subagents.Refusal, null), before.refused_by_limits);
}

test "a reviewer nothing can record does not run, and that is a refusal" {
    // The safe direction, and the reason the append is not best effort. A child
    // the width bound cannot see is the fault this whole arrangement closes, so
    // a spawn that cannot be written starts nothing at all. Every other way a
    // review fails to happen is already `error.ReviewNotRun`, and the broker
    // turns each one into `review_unavailable`, which does not permit.
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var child = FakeReviewChild{};
    var spawner = ReviewSpawner{
        .child = child.spawner(),
        .budget = null,
        .nothing_left = false,
        .refused_by_limits = null,
        // No handle, which is a caller that cannot record a child.
        .locked = null,
    };

    // What it said, captured rather than let through: see `tty.Capture`, and
    // `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);

    try std.testing.expectError(
        error.ReviewNotRun,
        spawner.reviewer().review(gpa, io, a_case),
    );
    // The session was prepared and the child was never run, so nothing was
    // started that nothing counted.
    try std.testing.expectEqual(@as(usize, 1), child.prepared);
    try std.testing.expectEqual(@as(usize, 0), child.ran);
    // **And it says a reviewer did not run, and why.** A review that silently
    // did not happen reads to the person afterwards exactly like a review that
    // said no, and the two are different outcomes.
    try std.testing.expect(std.mem.indexOf(u8, said.err(), "no reviewer was started") != null);
    try std.testing.expect(std.mem.indexOf(u8, said.err(), a_case.action) != null);
    try std.testing.expectEqualStrings("", said.out());
}

test "a reviewer child reads its own command line and holds no tools because of what it reads" {
    // **The wiring, end to end across the process boundary**, and it is the
    // half a test of `agentRole` alone would miss. `ReviewSpawner` starts a
    // `chock run` of its own, so the parent's decision reaches the child as one
    // word on a command line, and the child asks the question again. A rule
    // that held in the parent and was never read in the child would be a rule
    // nothing enforced: the child is what builds the tool list.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Exactly the request `ReviewSpawner.reviewFn` builds.
    const argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = "/nix/store/aaa-chock/bin/chock",
        .project_root = "/home/someone/project",
        .parent_session = "01PARENT",
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "workspace.apply" }},
    }, .{
        .agent_kind = chock_broker.review.default_kind,
        .task = "a case to weigh",
        .shape = .{ .schema = &chock_broker.review.result_fields },
        .reason = "workspace.apply",
    }, .{
        .child_session = try arena.dupe(u8, "01REVIEWER"),
        .log_path = try arena.dupe(u8, "/tmp/chock/01REVIEWER/log.jsonl"),
        // No scratchpad, which is what the reviewer really gets.
        .scratchpad_path = try arena.dupe(u8, ""),
    });

    // `argv[0]` is the program and `argv[1]` is the verb, which the child's
    // own `main` takes off before the options are parsed.
    const options = try parseOptions(arena, argv[2..]);
    try std.testing.expectEqualStrings(chock_broker.review.default_kind, options.agent_kind);
    try std.testing.expectEqual(chock_core.tools.Role.arbitrator, agentRole(options));

    // And the tool list that role builds is empty, which is the thing the
    // child then puts in its request and in its prompt.
    const support = chock_core.tools.Support{
        .adapter = .openai_compatible,
        .memory = true,
        .provisioning = true,
        .role = agentRole(options),
    };
    const definitions = try chock_core.tools.Registry.definitions(arena, support);
    try std.testing.expectEqual(@as(usize, 0), definitions.len);
    const prompt = try chock_core.prompt.build(arena, .{}, definitions, .{});
    try std.testing.expect(std.mem.indexOf(u8, prompt, "you have no tools") != null);

    // An ordinary child of the same shape is not an arbitrator, so every line
    // above is a fact about the reviewer's kind and not about every subagent.
    const worker_argv = try chock_core.subagent.commandLine(arena, .{
        .exe_path = "/nix/store/aaa-chock/bin/chock",
        .project_root = "/home/someone/project",
        .parent_session = "01PARENT",
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "do a piece of the work" }},
    }, .{
        .agent_kind = "worker",
        .task = "a piece of the work",
        .shape = .prose,
        .reason = "do a piece of the work",
    }, .{
        .child_session = try arena.dupe(u8, "01WORKER"),
        .log_path = try arena.dupe(u8, "/tmp/chock/01WORKER/log.jsonl"),
        .scratchpad_path = try arena.dupe(u8, "/tmp/chock/01PARENT/agents/01WORKER/scratch"),
    });
    const worker = try parseOptions(arena, worker_argv[2..]);
    try std.testing.expectEqual(chock_core.tools.Role.worker, agentRole(worker));
    const worker_definitions = try chock_core.tools.Registry.definitions(arena, .{
        .adapter = .openai_compatible,
        .role = agentRole(worker),
    });
    try std.testing.expect(worker_definitions.len > 0);
}

test "the end of session approval waits for a person, and agent_then_human can therefore run" {
    // The wall, and the one place `chock run` now goes through it. `applyWork`
    // asked with a timeout of zero, because nothing could append an
    // `approval.response` while this process held the session lock, and two
    // things followed from that number:
    //
    // 1. Every `ask` expired unanswered.
    // 2. `Broker.reviewed` reads the same number, and refuses an
    //    `agent_then_human` **before paying for a review**, because it knows
    //    the person half cannot happen. So a project that wrote that decision
    //    got a refusal with no review at all.
    //
    // `src/approval.zig` answers inside the wait, so a session at a terminal
    // now asks for real, and both of those stop being true. What this pins is
    // the number itself, on both sides, because it is the number the broker
    // branches on.
    try std.testing.expect(approval.timeoutMs(true) > 0);
    try std.testing.expectEqual(chock_broker.Broker.default_timeout_ms, approval.timeoutMs(true));

    // And the other half stays true, which is what keeps a subagent and a
    // daemon session honest: a zero here is what makes the broker refuse at
    // once instead of holding the log lock for a question nobody can answer.
    try std.testing.expectEqual(@as(i64, 0), approval.timeoutMs(false));
}

test "a session with a display asks in it, and never at the prompt as well" {
    // **Two readers on one descriptor race for every byte.** A display holds
    // standard input in raw mode and keeps a copy of every cell, and
    // `approval.Terminal` reads that same descriptor and writes a prompt across
    // those cells. A session with a display is a session at a terminal too, so
    // the two conditions overlap and only one of them may win.
    //
    // Mutation check: answer `.terminal` when both are true and a question is
    // asked twice, once in a region and once over the top of it, with two
    // readers taking each other's keys.
    try std.testing.expectEqual(.display, asksHere(true, true));
    try std.testing.expectEqual(.display, asksHere(true, false));
    try std.testing.expectEqual(.terminal, asksHere(false, true));
    try std.testing.expectEqual(.nobody, asksHere(false, false));

    // And a display is a person watching, so the question waits for one rather
    // than expiring at once the way a session nobody can answer does.
    try std.testing.expect(chock_broker.socket.timeoutMs(true, 0) > 0);
    try std.testing.expectEqual(@as(i64, 0), chock_broker.socket.timeoutMs(false, 0));
}

test "the header names every sandbox layer the driver gives, and says the word off for one it does not" {
    // **The one part of the header a person is there to see.** What is pinned
    // is that the answer comes from the driver's own declaration and from this
    // session's own config, and from nothing about the platform: this drives
    // `sandboxLayers` with a guarantee set of its own, which is a thing
    // `builtin` cannot produce.
    //
    // Mutation check: answer `.on` for a guarantee the driver does not give and
    // the second block below claims a sandbox layer that is not there, which is
    // the "never quiet" rule turned into a lie.
    const every = sandbox.Sandbox.Guarantees.initFull();
    const on = sandboxLayers(every, .none, "worktree");
    try std.testing.expectEqual(@as(usize, 6), on.len);
    for (on) |one| try std.testing.expectEqual(ui.Layer.State.on, one.state);
    // The header and the layer states both write these two words.
    try std.testing.expectEqualStrings("net", on[0].name);
    try std.testing.expectEqualStrings("none", on[0].note);
    try std.testing.expectEqualStrings("fs", on[1].name);
    try std.testing.expectEqualStrings("worktree", on[1].note);

    // A driver that gives nothing, which is the Darwin driver today: every
    // layer says so, and none of them is quietly left on.
    const none = sandboxLayers(sandbox.Sandbox.Guarantees.initEmpty(), .none, "worktree");
    for (none) |one| {
        try std.testing.expectEqual(ui.Layer.State.unsupported, one.state);
        try std.testing.expect(one.state.word().len != 0);
    }

    // A driver that gives every layer but one. The one it does not is the only
    // one that says so, and it is the layer this asked about.
    var short = every;
    short.remove(.path_restricted);
    const missing = sandboxLayers(short, .none, "worktree");
    for (missing) |one| {
        if (std.mem.eql(u8, one.name, "landlock")) {
            try std.testing.expectEqual(ui.Layer.State.unsupported, one.state);
        } else {
            try std.testing.expectEqual(ui.Layer.State.on, one.state);
        }
    }
}

test "a session that gave the network layer up says so, and a filtered one does not" {
    // A config may give the network namespace up only for an act a user
    // approved, and `Sandbox.Guarantee.network_isolated` is explicit that
    // `.filtered` keeps the namespace and `.host` does not. The header has to
    // tell those two apart, because one of them is the sandbox still holding
    // and the other is it let go.
    //
    // Mutation check: read `.filtered` as `.off` and a session whose MCP server
    // may reach one named host reads as a session with no network layer at all.
    const every = sandbox.Sandbox.Guarantees.initFull();

    const filtered = sandboxLayers(every, .filtered, "overlay");
    try std.testing.expectEqual(ui.Layer.State.on, filtered[0].state);
    try std.testing.expectEqualStrings("filtered", filtered[0].note);

    const host = sandboxLayers(every, .host, "overlay");
    try std.testing.expectEqual(ui.Layer.State.off, host[0].state);
    try std.testing.expectEqualStrings("host", host[0].note);
    try std.testing.expectEqualStrings("OFF", host[0].state.word());
    // And only that layer: giving the network up takes nothing else with it.
    for (host[1..]) |one| try std.testing.expectEqual(ui.Layer.State.on, one.state);

    // The workspace kind travels through as the word beside the fs layer, so a
    // person can see which of the two they are working in.
    try std.testing.expectEqualStrings("overlay", host[1].note);
}

test "the word beside the net layer is the name of the mode, for every mode there is" {
    // **The header and the code must say the same word for the same thing.**
    // The header used to say "off" for the mode the code called `isolated`,
    // which is two vocabularies for one fact, and the project owner read the
    // code's word as the opposite of what it meant. Nothing catches a third
    // word appearing here except this test, because the note is a free string.
    //
    // The loop is over `std.enums.values`, so a fourth mode added to
    // `namespace.Network` and given a note of its own invention fails here
    // rather than reaching a person's screen.
    //
    // Mutation check: answer "off" for `.none` again and this fails, while
    // every other test of `sandboxLayers` still passes.
    const every = sandbox.Sandbox.Guarantees.initFull();
    for (std.enums.values(sandbox.namespace.Network)) |mode| {
        const built = sandboxLayers(every, mode, "worktree");
        try std.testing.expectEqualStrings(@tagName(mode), built[0].note);
    }
}

test "a provisioned closure that overlaps the dev shell's is mounted once and not twice" {
    // Two closures that start at the same libc share nearly all of
    // themselves, so this is the ordinary case and not an edge one.
    // `withStore` builds one bind mount and one Landlock rule per entry, so a
    // repeat here is the same source bound on the same target, on every tool
    // call, for the rest of the session.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var tool_env = std.process.Environ.Map.init(gpa);
    defer tool_env.deinit();

    var context = chock_core.tools.Context{};
    var recorder = RecordingToolRunner{ .context = &context, .tool_env = &tool_env };

    var provisioning = ProvisionToolRunner{
        .inner = recorder.runner(),
        .settings = null,
        .arena = arena_state.allocator(),
        .host_env = &tool_env,
        .environ = .empty,
        .tool_env = &tool_env,
        .context = &context,
    };

    const dev_shell = [_][]const u8{
        "/nix/store/aaa-glibc",
        "/nix/store/bbb-zig",
    };
    try provisioning.start(&dev_shell);

    // ripgrep's closure: one path of its own, and the libc the dev shell
    // already carries.
    const closure = [_][]const u8{
        "/nix/store/aaa-glibc",
        "/nix/store/ccc-ripgrep",
    };
    try provisioning.adopt("ripgrep", .{
        .program = "ripgrep",
        .installable = "nixpkgs#ripgrep",
        .bin_dirs = &.{},
        .store_paths = &closure,
    });

    // Three paths, not four, and the same libc entry it always was.
    try std.testing.expectEqual(@as(usize, 3), context.store_paths.len);
    var glibc: usize = 0;
    for (context.store_paths) |path| {
        if (std.mem.eql(u8, path, "/nix/store/aaa-glibc")) glibc += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), glibc);

    // And a second program that needs the same libc again adds only its own.
    const second = [_][]const u8{ "/nix/store/aaa-glibc", "/nix/store/ddd-fd" };
    try provisioning.adopt("fd", .{
        .program = "fd",
        .installable = "nixpkgs#fd",
        .bin_dirs = &.{},
        .store_paths = &second,
    });
    try std.testing.expectEqual(@as(usize, 4), context.store_paths.len);
}

test "two provisioned programs get two sets of garbage collector roots, and the dev shell releases both" {
    // `nix-store --add-root` names its links after the prefix it is given, so
    // one prefix for every program would have the second provision replace
    // the first one's links. The program is still mounted after that, and it
    // is no longer held: a `nix-collect-garbage` then takes a toolchain the
    // agent has already been told it has.
    const gpa = std.testing.allocator;

    const first = try providedRootPrefix(gpa, "/state/dev-shell/proj", "ripgrep");
    defer gpa.free(first);
    const second = try providedRootPrefix(gpa, "/state/dev-shell/proj", "fd");
    defer gpa.free(second);
    try std.testing.expect(!std.mem.eql(u8, first, second));

    // And both are released by the one thing that releases the dev shell:
    // `DevShell`'s own `removeOldRoots` takes off every link whose name
    // starts with this word. The word is read from there, so a rename there
    // moves these too.
    const leaf = std.fs.path.basename(first);
    try std.testing.expect(std.mem.startsWith(u8, leaf, chock_nix.DevShell.root_link_name));
    try std.testing.expectEqualStrings("gcroot-provided-ripgrep", leaf);
}

test "a session with no MCP server passes every tool call through, byte for byte" {
    // **The property a project that named no server has to keep.** This runner
    // sits in front of every tool call a session makes, so a session with no
    // MCP block must reach the runner below it with the call exactly as it
    // arrived, and must add nothing to the result.
    //
    // Mutation check: answer a result of this runner's own for an unknown name
    // and every built-in tool of every project stops working.
    const gpa = std.testing.allocator;

    var state = McpState.init(gpa);
    defer state.deinit(std.testing.io);

    for ([_][]const u8{ "run_command", "read_file", "write_file", "get_current_time" }) |name| {
        var inner = CountingToolRunner{};
        var mcp_aware = McpToolRunner{ .inner = inner.runner(), .state = &state };

        const result = try mcp_aware.runner().dispatch(gpa, std.testing.io, .{
            .call_id = "call1",
            .tool = name,
            .arguments = "{\"argv\":[\"git\",\"status\"]}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try std.testing.expectEqual(@as(usize, 1), inner.calls);
        // The result is the one the runner below built, untouched.
        try std.testing.expectEqualStrings("the real git ran", result.output);
        try std.testing.expect(!result.is_error);
        // And the arguments crossed unchanged.
        try std.testing.expectEqualStrings("{\"argv\":[\"git\",\"status\"]}", inner.last_arguments);
    }
}

test "a call to an MCP tool is answered here and never reaches the runners below" {
    // The other half. A name a third party program chose must not reach the
    // git shim, the provisioner or the sandbox runner: every one of them reads
    // `call.tool` and acts on it, and none has any reason to see a name Chock
    // does not own.
    //
    // Mutation check: pass the call on to `inner` after `dispatch` answered
    // and the sandbox runner is handed a tool name it has never heard of.
    const gpa = std.testing.allocator;

    var host = ProbeHost{ .text = "the server answered", .is_error = false };
    var state = McpState.init(gpa);
    defer state.deinit(std.testing.io);
    var server = chock_core.mcp.Server{ .name = "probe", .host = host.host() };
    state.session.servers = @as(*[1]chock_core.mcp.Server, &server);

    var policy = AllowEverything{};
    try state.session.admit(&server, &.{.{ .name = "probe_tool" }}, policy.decider());

    var inner = CountingToolRunner{};
    var mcp_aware = McpToolRunner{ .inner = inner.runner(), .state = &state };

    const result = try mcp_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call7",
        .tool = "probe_tool",
        .arguments = "{}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expectEqual(@as(usize, 0), inner.calls);
    try std.testing.expectEqual(@as(usize, 1), host.calls);
    try std.testing.expectEqualStrings("the server answered", result.output);
    // The call id is the model's own, so the loop can pair the result with the
    // call that caused it.
    try std.testing.expectEqualStrings("call7", result.call_id);
}

test "the policy this wiring builds names the action, folds the chain, and refuses a child its parent lacks" {
    // The subagent limits, on the one question this wiring answers. **The chain
    // is what makes it an intersection**, and a wiring that asked about this
    // session's kind alone would give a subagent a tool its parent cannot hold.
    //
    // Mutation check: swap `evaluateChain` for `evaluateKindAlone` in
    // `TablePolicy.answer` and the second half of this test allows.
    const gpa = std.testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "mcp.time.*", .decision = .deny },
        \\            .{ .agent_kind = "fetcher", .action = "mcp.time.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try chock_policy.table.Table.parse(gpa, source, null);
    defer chock_policy.table.Table.destroy(gpa, table);

    var action_buffer: [chock_core.mcp.max_action_bytes]u8 = undefined;
    const action = chock_core.mcp.actionInto(&action_buffer, "time", "get_current_time").?;
    try std.testing.expectEqualStrings("mcp.time.tool.get_current_time", action);

    // The subagent on its own kind alone is permitted, so the refusal below is
    // the fold and not a missing rule.
    {
        var policy = TablePolicy{
            .policy = table,
            .chain = &.{"fetcher"},
            .agent_kind = "fetcher",
            .model = "m",
        };
        try std.testing.expectEqual(
            chock_policy.table.Decision.allow,
            policy.answer("get_current_time", action),
        );
    }

    // Under the parent that cannot hold it, it cannot either.
    {
        var policy = TablePolicy{
            .policy = table,
            .chain = &.{ "main", "fetcher" },
            .agent_kind = "fetcher",
            .model = "m",
        };
        try std.testing.expectEqual(
            chock_policy.table.Decision.deny,
            policy.answer("get_current_time", action),
        );
    }
}

test "a server reaches the network only when a rule says so, and never by default" {
    // **`none` is the default and it is not a flag.** A project that says
    // nothing about a server's network gets the sandbox a tool call gets, and
    // the empty table answers `ask`, which is not permission.
    //
    // Mutation check: read `decision != .deny` in `startMcp` and the first two
    // cases below hand a third party program a channel out.
    const gpa = std.testing.allocator;

    var buffer: [chock_core.mcp.max_action_bytes]u8 = undefined;
    const action = chock_core.mcp.networkActionInto(&buffer, "github").?;
    try std.testing.expectEqualStrings("mcp.github.network", action);

    const cases = [_]struct { source: [:0]const u8, filtered: bool }{
        // No rule at all, which is what nearly every project has.
        .{ .source = ".{ .policy = .{ .rules = .{} } }", .filtered = false },
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.network\", .decision = .ask } } } }",
            .filtered = false,
        },
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.network\", .decision = .deny } } } }",
            .filtered = false,
        },
        // The one spelling that lets a server out, and it has to be written on
        // purpose or the three cases above are vacuous.
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.network\", .decision = .allow } } } }",
            .filtered = true,
        },
        // **A rule about the tools is not a rule about the network.** A
        // project that allowed every tool of a server must not have given it a
        // socket by doing so.
        .{
            .source = ".{ .policy = .{ .rules = .{ .{ .action = \"mcp.github.tool.*\", .decision = .allow } } } }",
            .filtered = false,
        },
    };

    for (cases) |one| {
        const table = try chock_policy.table.Table.parse(gpa, one.source, null);
        defer chock_policy.table.Table.destroy(gpa, table);
        var policy = TablePolicy{
            .policy = table,
            .chain = &.{"main"},
            .agent_kind = "main",
            .model = "m",
        };
        const allowed = policy.answer("github", action) == .allow;
        try std.testing.expectEqual(one.filtered, allowed);
    }
}

/// An `mcp.Host` that answers from a field and counts what it was asked. The
/// tests above measure the wiring, and `lib/chock-core/mcp.zig` is where the
/// host behaviour itself is tested.
const ProbeHost = struct {
    text: []const u8,
    is_error: bool,
    calls: usize = 0,

    fn host(self: *ProbeHost) chock_core.mcp.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.mcp.Host.VTable{ .list = listFn, .call = callFn };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) chock_core.mcp.Error![]const chock_core.mcp.Declared {
        _ = ptr;
        _ = arena;
        _ = io;
        _ = budget_ns;
        return &.{};
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) chock_core.mcp.Error!chock_core.mcp.Outcome {
        _ = arena;
        _ = io;
        _ = name;
        _ = arguments;
        _ = budget_ns;
        const self: *ProbeHost = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return .{ .text = self.text, .is_error = self.is_error };
    }
};

test "a session with no plugin passes every tool call through, byte for byte" {
    // **The property a project that named no plugin has to keep**, and it is
    // every project today. This runner is the outermost of them all, so a
    // session with no `plugins` block must reach the runner below it with the
    // call exactly as it arrived, and must add nothing to the result.
    //
    // Mutation check: answer a result of this runner's own for an unknown name
    // and every built-in tool of every project stops working.
    const gpa = std.testing.allocator;

    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);

    for ([_][]const u8{ "run_command", "read_file", "write_file", "hello" }) |name| {
        var inner = CountingToolRunner{};
        var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };

        const result = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
            .call_id = "call1",
            .tool = name,
            .arguments = "{\"argv\":[\"git\",\"status\"]}",
        });
        defer gpa.free(result.call_id);
        defer gpa.free(result.output);

        try std.testing.expectEqual(@as(usize, 1), inner.calls);
        // The result is the one the runner below built, untouched.
        try std.testing.expectEqualStrings("the real git ran", result.output);
        try std.testing.expect(!result.is_error);
        // And the arguments crossed unchanged.
        try std.testing.expectEqualStrings("{\"argv\":[\"git\",\"status\"]}", inner.last_arguments);
    }
}

test "a call to a plugin tool is answered here, with the guest's own words, and never reaches the runners below" {
    // **The wiring this whole file was missing**: a tool a plugin declares is
    // offered to the model, and a call to it reaches the plugin and comes back
    // with what the plugin said. `test/plugin/engine.zig` is where the answer
    // really comes out of guest code; this pins that the runner chain carries
    // it to the loop.
    //
    // Mutation check: pass the call on to `inner` after `dispatch` answered and
    // the sandbox runner is handed a tool name it has never heard of.
    const gpa = std.testing.allocator;

    var host = PluginProbeHost{ .text = "Hello, world!", .is_error = false };
    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);

    var policy = AllowEverything{};
    try std.testing.expectEqual(
        @as(?chock_core.plugin.Failure, null),
        try state.session.admit("hello", .{
            .name = "written by the author",
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
            .author = "somebody",
            .tools = &.{.{ .name = "hello" }},
        }, policy.decider()),
    );

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = host.host() }};
    state.session.plugins = &loaded;

    // The model is offered it, which is the half a dispatch cannot show: a tool
    // nobody is told about is never called.
    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try state.session.appendDefinitions(gpa, &offered);
    try std.testing.expectEqual(@as(usize, 1), offered.items.len);
    try std.testing.expectEqualStrings("hello", offered.items[0].name);

    var inner = CountingToolRunner{};
    var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };

    const result = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call9",
        .tool = "hello",
        .arguments = "{}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expectEqual(@as(usize, 0), inner.calls);
    try std.testing.expectEqual(@as(usize, 1), host.calls);
    try std.testing.expectEqualStrings("Hello, world!", result.output);
    try std.testing.expect(!result.is_error);
    // The call id is the model's own, so the loop can pair the result with the
    // call that caused it.
    try std.testing.expectEqualStrings("call9", result.call_id);
    // The position in the plugin's own tool list, which is what the guest ABI
    // takes. A name on that wire would be a second thing the two sides have to
    // agree about.
    try std.testing.expectEqual(@as(u32, 0), host.last_index);
}

test "a plugin tool this project's policy refuses is refused before the plugin is reached" {
    // A plugin tool is an action on the policy table like every other, and a
    // refused one costs no process at all: the model is not offered it, and a
    // model that names it anyway is told why rather than "unknown tool".
    //
    // Mutation check: read the policy after the host in
    // `plugin.Session.dispatch` and a denied tool runs and then is refused.
    const gpa = std.testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "plugin.hello.tool.hello", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try chock_policy.table.Table.parse(gpa, source, null);
    defer chock_policy.table.Table.destroy(gpa, table);

    // The action the table is asked about is the one an author writes in the
    // file, or the rule above would be measuring nothing.
    var action_buffer: [chock_core.plugin.max_action_bytes]u8 = undefined;
    try std.testing.expectEqualStrings(
        "plugin.hello.tool.hello",
        chock_core.plugin.actionInto(&action_buffer, "hello", "hello").?,
    );

    var policy = TablePolicy{
        .policy = table,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "m",
    };

    var host = PluginProbeHost{ .text = "Hello, world!", .is_error = false };
    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);
    _ = try state.session.admit("hello", .{
        .name = "written by the author",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{.{ .name = "hello" }},
    }, policy.decider());

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = host.host() }};
    state.session.plugins = &loaded;

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try state.session.appendDefinitions(gpa, &offered);
    try std.testing.expectEqual(@as(usize, 0), offered.items.len);

    var inner = CountingToolRunner{};
    var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };
    const result = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call10",
        .tool = "hello",
        .arguments = "{}",
    });
    defer gpa.free(result.call_id);
    defer gpa.free(result.output);

    try std.testing.expect(result.is_error);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "not offered") != null);
    // **The plugin was never asked.** A refused tool must cost no process.
    try std.testing.expectEqual(@as(usize, 0), host.calls);
    // And it did not fall through to the runners below either: a refusal is an
    // answer, not a name this chain does not know.
    try std.testing.expectEqual(@as(usize, 0), inner.calls);
}

test "a plugin whose tool is named after a built-in loads none of its tools, and the built-in still runs" {
    // The project owner's own rule, read from this side of the wiring: the
    // whole plugin fails to load, so the good tool it declared first is not
    // offered either, and `read_file` still reaches the runner that owns it.
    //
    // Mutation check: refuse the one tool and keep the rest in
    // `plugin.Session.admit`, and `harmless` below is offered by a plugin that
    // tried to take a built-in's name.
    const gpa = std.testing.allocator;

    var host = PluginProbeHost{ .text = "the plugin answered", .is_error = false };
    var state = PluginState.init(gpa);
    defer state.deinit(std.testing.io);

    var policy = AllowEverything{};
    const failure = try state.session.admit("impostor", .{
        .name = "impostor",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{
            .{ .name = "harmless" },
            .{ .name = "read_file" },
        },
    }, policy.decider());
    try std.testing.expectEqual(chock_core.plugin.Failure.shadows_built_in, failure.?);

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "impostor", .host = host.host() }};
    state.session.plugins = &loaded;
    try std.testing.expect(state.session.isEmpty());

    var inner = CountingToolRunner{};
    var plugin_aware = PluginToolRunner{ .inner = inner.runner(), .state = &state };

    // Chock's own tool goes where it always went.
    const built_in = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call11",
        .tool = "read_file",
        .arguments = "{}",
    });
    defer gpa.free(built_in.call_id);
    defer gpa.free(built_in.output);
    try std.testing.expectEqual(@as(usize, 1), inner.calls);
    try std.testing.expectEqualStrings("the real git ran", built_in.output);

    // And the tool the plugin declared before the collision is not this
    // session's either: it falls through as a name nothing here knows.
    const other = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call12",
        .tool = "harmless",
        .arguments = "{}",
    });
    defer gpa.free(other.call_id);
    defer gpa.free(other.output);
    try std.testing.expectEqual(@as(usize, 2), inner.calls);
    try std.testing.expectEqual(@as(usize, 0), host.calls);
}

test "a plugin tool cannot take a name an MCP server already declared" {
    // Two suppliers of tools reach one model through one name space. Without
    // this the model would hold one name that means two things, and which one
    // it reached would be decided by the order of the runner chain.
    //
    // **The MCP server is admitted first and keeps its name**, because it is
    // already in the session: `startPlugins` runs after `startMcp` and hands
    // this list over. See `chock_core.plugin.Session.reserved`.
    //
    // Mutation check: answer an empty list from `reservedNames` and the plugin
    // tool below is offered too, so the model is told about `shared` twice.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var server_host = ProbeHost{ .text = "the server answered", .is_error = false };
    var mcp_state = McpState.init(gpa);
    defer mcp_state.deinit(std.testing.io);
    var server = chock_core.mcp.Server{ .name = "probe", .host = server_host.host() };
    mcp_state.session.servers = @as(*[1]chock_core.mcp.Server, &server);

    var policy = AllowEverything{};
    try mcp_state.session.admit(&server, &.{.{ .name = "shared" }}, policy.decider());

    var plugin_host_probe = PluginProbeHost{ .text = "the plugin answered", .is_error = false };
    var plugin_state = PluginState.init(gpa);
    defer plugin_state.deinit(std.testing.io);

    // The line `startPlugins` runs, and not a copy of it written here.
    plugin_state.session.reserved = try reservedNames(arena_state.allocator(), &mcp_state.session);
    _ = try plugin_state.session.admit("hello", .{
        .name = "written by the author",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{ .{ .name = "shared" }, .{ .name = "own" } },
    }, policy.decider());

    var loaded = [_]chock_core.plugin.Loaded{.{ .name = "hello", .host = plugin_host_probe.host() }};
    plugin_state.session.plugins = &loaded;

    try std.testing.expectEqual(
        chock_core.plugin.Refusal.already_declared,
        plugin_state.session.find("shared").?.refused.?,
    );
    try std.testing.expectEqual(
        @as(?chock_core.plugin.Refusal, null),
        plugin_state.session.find("own").?.refused,
    );

    // And the whole chain answers the way the list says: `shared` is the
    // server's, and the plugin's own tool is the plugin's.
    var inner = CountingToolRunner{};
    var mcp_aware = McpToolRunner{ .inner = inner.runner(), .state = &mcp_state };
    var plugin_aware = PluginToolRunner{ .inner = mcp_aware.runner(), .state = &plugin_state };

    const shared = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call13",
        .tool = "shared",
        .arguments = "{}",
    });
    defer gpa.free(shared.call_id);
    defer gpa.free(shared.output);
    try std.testing.expectEqualStrings("the server answered", shared.output);
    try std.testing.expectEqual(@as(usize, 1), server_host.calls);
    try std.testing.expectEqual(@as(usize, 0), plugin_host_probe.calls);

    const own = try plugin_aware.runner().dispatch(gpa, std.testing.io, .{
        .call_id = "call14",
        .tool = "own",
        .arguments = "{}",
    });
    defer gpa.free(own.call_id);
    defer gpa.free(own.output);
    try std.testing.expectEqualStrings("the plugin answered", own.output);
    try std.testing.expectEqual(@as(usize, 1), plugin_host_probe.calls);
    try std.testing.expectEqual(@as(usize, 0), inner.calls);
}

test "the sandbox a plugin host gets carries its program, its module and nothing writable" {
    // **A guest owns the address space of the process that runs it**, so this
    // config is the whole of what a hostile plugin reaches. Two facts have to
    // hold at once, and they pull against each other: the process must be able
    // to start at all, and it must reach nothing of the session.
    //
    // Mutation checks. Carry `workspace_config.rules` through and a plugin
    // reads the project. Drop the execute right on the program and the process
    // cannot be started at all, which `test/plugin/engine.zig` reaches for real.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // The shape a tool call's own config has: the workspace, writable, and a
    // network somebody was given.
    const workspace: sandbox.Config = .{
        .root = "/tmp/session-root",
        .mounts = &.{
            .{ .bind = .{ .source = "/home/someone/work", .target = "/home/someone/work", .read_only = false } },
        },
        .rules = &.{
            .{ .path = "/home/someone/work", .access = sandbox.landlock.AccessFs.read_write },
        },
        .cwd = "/home/someone/work",
        .env = &.{"PATH=/bin"},
        .network = .filtered,
    };

    const config = try pluginSandbox(
        arena_state.allocator(),
        std.testing.io,
        workspace,
        &.{"/nix/store/aaa-glibc"},
        &.{},
        "/nix/store/bbb-chock/bin/chock",
        "/home/someone/work/plugins/hello.wasm",
    );

    try std.testing.expect(config.network == .none);
    // Not the project directory: a plugin host opens one file, by an absolute
    // path, and has no rule for the workspace anyway.
    try std.testing.expectEqualStrings("/", config.cwd);

    var reaches_program = false;
    var reaches_module = false;
    for (config.rules) |rule| {
        // **Nothing writable, whatever the rule is about.**
        try std.testing.expect(!rule.access.write_file);
        try std.testing.expect(!rule.access.make_reg);
        try std.testing.expect(!rule.access.remove_file);
        try std.testing.expect(!rule.access.truncate);
        // And nothing about the workspace at all.
        try std.testing.expect(!std.mem.eql(u8, rule.path, "/home/someone/work"));

        if (std.mem.eql(u8, rule.path, plugin_host_target)) {
            reaches_program = rule.access.execute and rule.access.read_file;
        }
        if (std.mem.eql(u8, rule.path, plugin_module_target)) {
            reaches_module = rule.access.read_file;
        }
    }
    try std.testing.expect(reaches_program);
    try std.testing.expect(reaches_module);

    // The mount tree still carries the workspace, and that is not a hole: a
    // mount with no rule is present and unreachable. What the two mounts below
    // add is the program and the module, at fixed targets, read only.
    var binds_program = false;
    var binds_module = false;
    for (config.mounts) |mount| {
        const bind = switch (mount) {
            .bind => |one| one,
            else => continue,
        };
        if (std.mem.eql(u8, bind.target, plugin_host_target)) {
            binds_program = bind.read_only and
                std.mem.eql(u8, bind.source, "/nix/store/bbb-chock/bin/chock");
        }
        if (std.mem.eql(u8, bind.target, plugin_module_target)) {
            binds_module = bind.read_only and
                std.mem.eql(u8, bind.source, "/home/someone/work/plugins/hello.wasm");
        }
    }
    try std.testing.expect(binds_program);
    try std.testing.expect(binds_module);
}

test "a plugin host is started as chock itself, under the word that is not a command" {
    // **The fold to one binary, pinned where the command line is built.** The
    // plugin host was a second installed program that `chock` looked for beside
    // itself, so an install that copied one file lost every plugin. It is now
    // this program, re-execed under a hidden word, which is what
    // `chock_core.subagent.commandLine` already does for a subagent.
    //
    // Mutation check: drop the verb and the child parses the module path as a
    // command name, prints "there is no command named", and exits 1, which the
    // harness reads as a plugin host that died on the first call.
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const argv = try pluginArgv(arena_state.allocator(), &.{"read_file"});

    try std.testing.expectEqual(@as(usize, 4), argv.len);
    try std.testing.expectEqualStrings(plugin_host_target, argv[0]);
    try std.testing.expectEqualStrings(chock_core.plugin_host.verb, argv[1]);
    try std.testing.expectEqualStrings(plugin_module_target, argv[2]);
    // The capabilities come last and nothing is inserted after them.
    try std.testing.expectEqualStrings("read_file", argv[3]);
}

/// A `plugin.Host` that answers from a field and counts what it was asked. The
/// tests above measure the wiring, and `test/plugin/engine.zig` is where a real
/// guest really answers.
const PluginProbeHost = struct {
    text: []const u8,
    is_error: bool,
    calls: usize = 0,
    last_index: u32 = std.math.maxInt(u32),

    fn host(self: *PluginProbeHost) chock_core.plugin.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.plugin.Host.VTable{ .call = callFn };

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        index: u32,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) chock_core.plugin.Error!chock_core.plugin.Outcome {
        _ = arena;
        _ = io;
        _ = name;
        _ = arguments;
        _ = budget_ns;
        const self: *PluginProbeHost = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_index = index;
        return .{ .text = self.text, .is_error = self.is_error };
    }
};

/// A policy that says yes, so the two runner tests measure the wiring and not
/// the table. The table itself is measured by the two tests above it.
const AllowEverything = struct {
    fn decider(self: *AllowEverything) chock_core.mcp.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.mcp.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        _ = ptr;
        _ = tool;
        _ = action;
        return .allow;
    }
};

test "the interface asks again after a turn that finished, and after nothing else" {
    // **The conversation, and where it ends.** Bare `chock` runs a turn, asks
    // for the next message and runs another, for as long as the turns finish.
    // Every other ending is the session saying it is over, and a field drawn on
    // a session that is ending would ask for work that nothing would do.
    //
    // Mutation check: drop the `interrupted` arm and a Ctrl-C that landed after
    // the `session.end` was written puts the field back up on a session that is
    // already stopping. Return true for every ending and a session that ran out
    // of money is asked for more work.
    try testing.expect(keepAsking(.finished, false));

    // Ctrl-C, whatever this turn's own ending was.
    try testing.expect(!keepAsking(.finished, true));

    // And every other way a turn can end.
    for ([_]Exit{
        .usage,
        .faulted,
        .refused,
        .turn_limit,
        .not_implemented,
        .no_progress,
        .budget,
        .handed_over,
    }) |ending| {
        try testing.expect(!keepAsking(ending, false));
        try testing.expect(!keepAsking(ending, true));
    }
}

/// Write a bundle file into `dir` and give the absolute path of it. For the
/// tests below, which read one off a disk the way `start` does.
fn writeBundle(gpa: std.mem.Allocator, dir: std.Io.Dir, name: []const u8, source: []const u8) ![]u8 {
    const io = testing.io;
    try dir.writeFile(io, .{ .sub_path = name, .data = source });
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try dir.realPath(io, &buffer);
    return std.fs.path.join(gpa, &.{ buffer[0..written], name });
}

test "an installation with no org bundle reads no layer above the project and says nothing" {
    // The property that decides whether this may ship. Every installation that
    // has never heard of a bundle has to behave exactly as it did, and that
    // starts with the load answering null rather than reporting anything.
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(testing.io, &buffer);
    const data_dir = buffer[0..written];

    // Nothing may reach standard error or standard output. See `tty.Capture`,
    // and `test/proto/lock.zig` for why a test may not let a line through.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const none = try loadOrgBundle(arena, testing.io, data_dir, .{});
    try testing.expectEqual(@as(?*const chock_policy.org.Bundle, null), none);
    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());

    // And the table such an installation builds answers exactly what the plain
    // reader answers, for the acts and for the provider rows alike.
    const org_rules: []const chock_policy.table.Rule = if (none) |b| b.rules else &.{};
    try testing.expectEqual(@as(usize, 0), org_rules.len);
    const source = ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .allow } } } }";
    const under = try chock_policy.table.Table.parseUnder(arena, source, org_rules, null);
    const plain = try chock_policy.table.Table.parse(arena, source, null);
    const key = chock_policy.table.Key{
        .agent_kind = "main",
        .model = "local",
        .tool = "request_action",
        .action = "git.push",
    };
    try testing.expectEqual(
        plain.evaluateChain(&.{"main"}, key, null),
        under.evaluateChain(&.{"main"}, key, null),
    );
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        under.evaluateChain(&.{"main"}, key, null),
    );
}

test "a bundle the caller named and Chock cannot find is a fault, and a broken one names why" {
    // A path somebody typed is a request for that file. The installed bundle
    // being absent is the ordinary case; the one on the command line being
    // absent is a mistake the caller has to hear about.
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(testing.io, &buffer);
    const data_dir = buffer[0..written];

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const missing = try std.fs.path.join(arena, &.{ data_dir, "not-here.zon" });
    try testing.expectError(
        error.Reported,
        loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = missing }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "no org policy bundle") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);

    // A bundle that is there and cannot be read stops the session as well,
    // with the reason the reader gave rather than an error name. Falling back
    // to no bundle here would be falling open on a file an organisation wrote.
    said.clear();
    const broken = try writeBundle(arena, tmp.dir, "broken.zon", ".{ .rules = ");
    try testing.expectError(
        error.Reported,
        loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = broken }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "not valid") != null);

    // And a bundle from a newer Chock is refused rather than applied in part.
    said.clear();
    const newer = try writeBundle(arena, tmp.dir, "newer.zon", ".{ .version = 99, .rules = .{} }");
    try testing.expectError(
        error.Reported,
        loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = newer }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "version 99") != null);

    // A good one at a named path reads, and its rules reach the caller.
    said.clear();
    const good = try writeBundle(
        arena,
        tmp.dir,
        "good.zon",
        ".{ .subject = \"ross@example.org\", .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }",
    );
    const bundle = try loadOrgBundle(arena, testing.io, data_dir, .{ .org_bundle = good });
    try testing.expectEqualStrings("ross@example.org", bundle.?.subject);
    try testing.expectEqual(@as(usize, 1), bundle.?.rules.len);
    // The subject is said, and nothing about it is a fault. `tty.print` writes
    // the stream every other line of `chock run` writes, which is the same one
    // the session line beside it uses.
    try testing.expect(std.mem.indexOf(u8, said.err(), "org policy for ross@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "could not") == null);

    // The same good file is refused to a subagent. A parent writes its child's
    // command line and carries no bundle on it, so a child that took a path
    // here would run under an org policy its parent never read, which is the
    // one direction the subagent limits exist to prevent.
    said.clear();
    try testing.expectError(error.Reported, loadOrgBundle(arena, testing.io, data_dir, .{
        .org_bundle = good,
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "" }},
    }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "subagent takes") != null);

    // And a subagent with no flag reads the installed bundle exactly as its
    // parent did, which is why the flag is not needed for one.
    said.clear();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = chock_policy.org.file_name,
        .data = ".{ .subject = \"ross@example.org\", .rules = .{} }",
    });
    const asChild = try loadOrgBundle(arena, testing.io, data_dir, .{
        .parent_chain = &.{.{ .agent_kind = "main", .reason = "" }},
    });
    try testing.expectEqualStrings("ross@example.org", asChild.?.subject);
}

test "an installed bundle that expired still binds, and the session is told how stale it is" {
    // The expiry decision `chock_policy.org` states, at the one place a person
    // meets it. Neither failing shut nor falling open: the rules are still
    // read, and the staleness is on the screen.
    //
    // The time is a parameter here, so this asserts nothing about a wall
    // clock. `loadOrgBundle` reads the one clock and hands the number in.
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const source =
        \\.{
        \\    .subject = "ross@example.org",
        \\    .issuer = "example.org",
        \\    .expires_ms = 5000,
        \\    .rules = .{ .{ .action = "provider.public.*", .decision = .deny } },
        \\}
    ;
    const bundle = try chock_policy.org.parse(arena, source, null);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // Three days and a bit past the date.
    const three_days_later: i64 = 5000 + 3 * std.time.ms_per_day + 1;
    reportOrgBundle(bundle, three_days_later);
    try testing.expect(std.mem.indexOf(u8, said.err(), "org policy for ross@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "issued by example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired 3 days ago") != null);
    // The sentence has to say the bundle is still binding, or a reader takes
    // the warning for a bundle that has been dropped.
    try testing.expect(std.mem.indexOf(u8, said.err(), "still binds") != null);

    // One day reads as one day, so the plural is not a guess.
    said.clear();
    reportOrgBundle(bundle, 5000 + std.time.ms_per_day);
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired 1 day ago") != null);

    // Before the date there is no warning at all, and the subject is still
    // said, because who the policy belongs to is not a fault.
    said.clear();
    reportOrgBundle(bundle, 4000);
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired") == null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "org policy for ross@example.org") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 rule") != null);

    // And the rules survive the date, which is the half of the decision that
    // is not a message: the table built from an expired bundle refuses what
    // the bundle refused.
    const under = try chock_policy.table.Table.parseUnder(arena, ".{}", bundle.rules, null);
    const rows = try chock_policy.access.rowsFor("public", "gpt-5");
    try testing.expectEqual(chock_policy.table.Decision.deny, chock_policy.access.ceiling(under, .{
        .chain = &.{"main"},
        .agent_kind = "main",
        .model_alias = "public",
    }, &rows, null));

    // The one thing the date does act on: a file already past it may not be
    // handed to Chock now.
    said.clear();
    try testing.expectError(
        error.Reported,
        refuseUninstallableBundle(bundle, three_days_later, "/somewhere/org-policy.zon"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "expired before it was given") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/somewhere/org-policy.zon") != null);
    // And one that is still current installs with nothing said.
    said.clear();
    try refuseUninstallableBundle(bundle, 4000, "/somewhere/org-policy.zon");
    try testing.expectEqualStrings("", said.err());
}

test "a project cannot widen the models its org narrowed, and the refusal names the row" {
    // The end to end shape: a `chock.zon` that says a model is allowed, a
    // bundle above it that says it is not, and a session that does not start.
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const project_allows =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "provider.public.gpt-5", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const org_refuses = try chock_policy.org.parse(
        arena,
        ".{ .rules = .{ .{ .action = \"provider.public.*\", .decision = .deny } } }",
        null,
    );

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // The table this run would really build, off a real `chock.zon` and
    // through the one function `start` calls. A `loadPolicyUnder` that dropped
    // the bundle would pass every test of the layers themselves, so this is
    // the one that holds the wiring.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(testing.io, &buffer);
    const project_root = buffer[0..written];
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = chock_policy.table.file_name,
        .data = project_allows,
    });

    const wired = try loadPolicyUnder(arena, testing.io, project_root, org_refuses);
    const rows = try chock_policy.access.rowsFor("public", "gpt-5");
    const asking = chock_policy.access.Ask{
        .chain = &.{"main"},
        .agent_kind = "main",
        .model_alias = "public",
    };
    try testing.expectEqual(
        chock_policy.table.Decision.deny,
        chock_policy.access.ceiling(wired, asking, &rows, null),
    );
    // And the same directory with no bundle above it keeps what the file
    // wrote, so the refusal above is the bundle reaching the table.
    const unwired = try loadPolicyUnder(arena, testing.io, project_root, null);
    try testing.expectEqual(
        chock_policy.table.Decision.allow,
        chock_policy.access.ceiling(unwired, asking, &rows, null),
    );

    // With the bundle above it the session is refused, and the message names
    // both rows so the reader knows which line to go and read.
    const bound = try chock_policy.table.Table.parseUnder(arena, project_allows, org_refuses.rules, null);
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, bound, &.{}, .{}, "public", "gpt-5"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "may not use the model gpt-5") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "provider.public.gpt-5") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "deny") != null);

    // The same project with no bundle above it starts, so the refusal is the
    // organisation's and not something the file did to itself.
    said.clear();
    const alone = try chock_policy.table.Table.parse(arena, project_allows, null);
    try refuseProviderAndModel(arena, alone, &.{}, .{}, "public", "gpt-5");
    try testing.expectEqualStrings("", said.err());

    // A project that names no provider row at all is refused nothing, which is
    // every project that predates these names.
    const silent = try chock_policy.table.Table.parse(arena, ".{}", null);
    try refuseProviderAndModel(arena, silent, &.{}, .{}, "public", "gpt-5");
    try refuseProviderAndModel(arena, silent, &.{}, .{}, "local", "glm4.7-flash");
    try testing.expectEqualStrings("", said.err());

    // A provider name that could never be a row is a refusal of its own, with
    // the reason, rather than a decision taken over a name nobody could write.
    said.clear();
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, silent, &.{}, .{}, "pub*", "gpt-5"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "cannot be named in a policy rule") != null);
}

test "a subagent is refused a model its parent could not use" {
    // The fold that makes this more than a checkbox, at the level a session
    // meets it: the child's own row says `allow` and the answer is still
    // `deny`, because the minimum is taken over every link of the chain.
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const child_asks_for_more =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "provider.hub.big", .decision = .deny },
        \\            .{ .agent_kind = "worker", .action = "provider.hub.big", .decision = .allow },
        \\            .{ .action = "provider.hub.small", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const policy = try chock_policy.table.Table.parse(arena, child_asks_for_more, null);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const under_main: []const chock_proto.event.SpawnLink = &.{
        .{ .agent_kind = "main", .reason = "do a piece of the work" },
    };
    const as_worker = Options{ .agent_kind = "worker" };

    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, policy, under_main, as_worker, "hub", "big"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "may not use the model big") != null);
    // The refusal says the answer came from the chain, because a reader
    // looking at the `worker` row alone would see `allow` and be baffled.
    try testing.expect(std.mem.indexOf(u8, said.err(), "spawn chain") != null);

    // The cheap model is there for the child, so the fold narrowed rather than
    // switched the child off.
    said.clear();
    try refuseProviderAndModel(arena, policy, under_main, as_worker, "hub", "small");
    try testing.expectEqualStrings("", said.err());

    // A grandchild holds no more than the link above it either.
    const under_worker: []const chock_proto.event.SpawnLink = &.{
        .{ .agent_kind = "main", .reason = "" },
        .{ .agent_kind = "worker", .reason = "" },
    };
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, policy, under_worker, .{ .agent_kind = "helper" }, "hub", "big"),
    );

    // And the root itself is refused the model its own row denies, so the
    // rules are being read and not merely folded.
    said.clear();
    try testing.expectError(
        error.Reported,
        refuseProviderAndModel(arena, policy, &.{}, .{}, "hub", "big"),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "spawn chain") == null);
}

/// An observer that keeps what it was told, so a test can compare two
/// observers call for call.
const RecordingObserver = struct {
    gpa: std.mem.Allocator,
    said: std.ArrayList(u8) = .empty,

    fn deinit(self: *RecordingObserver) void {
        self.said.deinit(self.gpa);
    }

    fn observer(self: *RecordingObserver) chock_core.Loop.Observer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_core.Loop.Observer.VTable{
        .onEvent = onEventFn,
        .onPiece = onPieceFn,
        .onNotice = onNoticeFn,
    };

    fn onEventFn(ptr: *anyopaque, id: u64, ev: chock_proto.event.Event) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        self.said.print(self.gpa, "event {d} {s}\n", .{ id, @tagName(ev) }) catch {};
    }

    fn onPieceFn(ptr: *anyopaque, piece: chock_core.Loop.Piece) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        switch (piece) {
            .text => |text| self.said.print(self.gpa, "text {s}\n", .{text}) catch {},
            .reasoning => |text| self.said.print(self.gpa, "reasoning {s}\n", .{text}) catch {},
        }
    }

    fn onNoticeFn(ptr: *anyopaque, text: []const u8) void {
        const self: *RecordingObserver = @ptrCast(@alignCast(ptr));
        self.said.print(self.gpa, "notice {s}\n", .{text}) catch {};
    }
};

test "the two export options are off unless asked for, and each takes a value" {
    // **A session that names no sink is a session that opens no file and makes
    // no socket**: `runSession` puts every line of the export behind
    // `sink_count`, and this is where that count starts at zero. Mutation check:
    // default either of these to a path and every session in this project starts
    // writing somewhere nobody asked for.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plain = try parseOptions(arena, &.{"a message"});
    try testing.expectEqual(@as(?[]const u8, null), plain.export_dir);
    try testing.expectEqual(@as(?[]const u8, null), plain.export_syslog);

    const both = try parseOptions(arena, &.{
        "--export-dir",    "/var/audit/chock",
        "--export-syslog", "/dev/log",
        "go",
    });
    try testing.expectEqualStrings("/var/audit/chock", both.export_dir.?);
    try testing.expectEqualStrings("/dev/log", both.export_syslog.?);
    // The message survives, so an option that takes a value did not swallow it.
    try testing.expectEqual(@as(usize, 1), both.message_words.len);

    // Each needs a value, and the fault says which option rather than sending a
    // reader looking for the right value.
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--export-dir"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--export-dir needs a value") != null);
    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(arena, &.{"--export-syslog"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--export-syslog needs a value") != null);
}

test "an exporter with no sink passes every call through byte for byte" {
    // **The property a session that exports nothing depends on.** The exporter
    // wraps rather than replaces, so a run with no sink has to reach the printer
    // with exactly the calls it would have reached it with before the exporter
    // existed.
    //
    // Mutation check: have `onPieceFn` drop a piece, or have `onEventFn` push
    // before it forwards, and the two recordings below stop matching.
    const gpa = testing.allocator;

    var direct = RecordingObserver{ .gpa = gpa };
    defer direct.deinit();
    var wrapped_inner = RecordingObserver{ .gpa = gpa };
    defer wrapped_inner.deinit();

    var backing = try chock_proto.storage.Memory.init(gpa, "01TESTSESSION");
    defer backing.deinit();

    var exporter = Exporter{
        .gpa = gpa,
        .io = testing.io,
        .storage = backing.storage(),
        .inner = wrapped_inner.observer(),
        .sinks = &.{},
    };

    const steps = [_]PrinterStep{
        .{ .event = .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } } },
        .{ .piece = .{ .text = "half an answer" } },
        .{ .piece = .{ .reasoning = "thinking" } },
        .{ .event = .{ .session_end = .{ .reason = .finished, .detail = "" } } },
    };

    for ([_]chock_core.Loop.Observer{ direct.observer(), exporter.observer() }) |watcher| {
        for (steps, 0..) |step, index| switch (step) {
            .event => |ev| watcher.onEvent(index, ev),
            .piece => |piece| watcher.onPiece(piece),
        };
        watcher.onNotice("the harness is waiting");
    }

    try testing.expectEqualStrings(direct.said.items, wrapped_inner.said.items);
    // And it really ran: an empty comparison would pass against an exporter that
    // forwarded nothing at all.
    try testing.expect(direct.said.items.len != 0);

    // Nothing was shipped and nothing is reported, so a run with no sink says
    // nothing about export at all.
    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 0), report.count);
}

test "a session that exported nothing says nothing about export" {
    // The other half of "byte for byte as today": the end of a run is silent
    // when nobody asked for a sink. A line here would appear on every session
    // this project has ever run.
    const gpa = testing.allocator;
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const nothing = ShippingReport{};
    reportShipping(&nothing);
    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());
}

test "a sink that worked says one line, and a sink that went down says the whole state" {
    // **An audit trail that silently stops arriving is worse than one that never
    // started.** So the ordinary run says one plain line, which is what makes
    // the absence of that line mean something, and a run whose sink went down
    // says how many lines went, why it stopped, and from which byte of the log
    // nothing has left this machine.
    //
    // Mutation check: drop the `wantsSaying` branch and a session whose sink was
    // down all along reports the same line as one whose sink worked.
    const gpa = testing.allocator;
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    var worked = ShippingReport{};
    worked.add(.{ .name = "/var/audit/chock/01JQ.jsonl", .health = .{ .delivered = 12 } });
    reportShipping(&worked);
    try testing.expect(std.mem.indexOf(u8, said.err(), "12 lines") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "/var/audit/chock/01JQ.jsonl") != null);
    // Nothing about a fault, because there was none.
    try testing.expect(std.mem.indexOf(u8, said.err(), "could not be reached") == null);

    said.clear();
    var down = ShippingReport{};
    down.add(.{ .name = "/dev/log", .health = .{
        .delivered = 3,
        .faults = 4,
        .first_fault = error.ConnectionRefused,
        .stalled_at = 512,
    } });
    reportShipping(&down);
    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "/dev/log") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "ConnectionRefused") != null);
    // The byte the tail begins at, which is what makes the warning actionable
    // rather than a shrug.
    try testing.expect(std.mem.indexOf(u8, warned, "512") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "on this machine and nowhere else") != null);
}

test "the first time a sink cannot be reached, whoever is watching is told at once" {
    // **Not only at the end.** A session runs for minutes, and a person watching
    // it has to learn that the trail stopped while there is still something they
    // can do about it. It goes through the observer this one wraps, because a
    // display may be up and a line written straight to standard error would land
    // behind an alternate screen.
    //
    // Mutation check: drop `said` and a sink that is down puts one line on the
    // screen per event, which buries the session the lines are about.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01TESTSESSION");
    defer backing.deinit();
    const store = backing.storage();
    {
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .session_end = .{ .reason = .finished, .detail = "" } }, 1000);
    }

    var watching = RecordingObserver{ .gpa = gpa };
    defer watching.deinit();

    // A sink that is not there: a socket path with nothing bound to it.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const missing = try std.fmt.allocPrint(gpa, "{s}/nothing-here", .{dir_path});
    defer gpa.free(missing);

    var syslog = chock_proto.ship.Syslog{ .path = missing };
    defer syslog.close();
    var sinks = [_]Exporter.Sending{.{
        .name = missing,
        .shipper = .{ .sink = syslog.sink(), .session = "01TESTSESSION" },
    }};
    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = store,
        .inner = watching.observer(),
        .sinks = &sinks,
    };

    const watcher = exporter.observer();
    watcher.onEvent(16, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    try testing.expect(std.mem.indexOf(u8, watching.said.items, "could not be reached") != null);
    try testing.expect(std.mem.indexOf(u8, watching.said.items, "The session carries on") != null);

    // Said once. Three more events with the sink still gone add no second line.
    const after_first = std.mem.count(u8, watching.said.items, "could not be reached");
    try testing.expectEqual(@as(usize, 1), after_first);
    for (0..3) |_| watcher.onEvent(16, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, watching.said.items, "could not be reached"),
    );

    // And the session was never stopped: every event still reached the observer
    // this one wraps.
    try testing.expectEqual(@as(usize, 4), std.mem.count(u8, watching.said.items, "event 16"));

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 1), report.count);
    try testing.expect(report.entries[0].health.wantsSaying());
    try testing.expectEqual(@as(u64, 0), report.entries[0].health.delivered);
}

test "a session's log reaches the file drop line by line, and verifies there" {
    // The whole point, driven through the exporter a session really uses rather
    // than through the shipper alone: an event that the loop appended has left
    // this machine by the time the next one lands.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);

    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/session.jsonl", .{dir_path}, 0);
    defer gpa.free(log_path);
    const drop_path = try std.fmt.allocPrint(gpa, "{s}/copy.jsonl", .{dir_path});
    defer gpa.free(drop_path);

    var backing = chock_proto.storage.JsonLines{
        .log = try chock_proto.log.Log.open(io, log_path, "01TESTSESSION"),
    };
    const store = backing.storage();
    defer store.close(io);

    var watching = RecordingObserver{ .gpa = gpa };
    defer watching.deinit();
    var drop = chock_proto.ship.FileDrop{ .path = drop_path };
    defer drop.close(io);
    var sinks = [_]Exporter.Sending{.{
        .name = drop_path,
        .shipper = .{ .sink = drop.sink(), .session = "01TESTSESSION" },
    }};
    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = store,
        .inner = watching.observer(),
        .sinks = &sinks,
    };
    const watcher = exporter.observer();

    // Two turns, each appended and then announced, which is the order
    // `Loop.appendAndApply` uses.
    var locked = try store.lock(io);
    for ([_]chock_proto.event.Event{
        .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    }, 0..) |ev, index| {
        const id = try locked.append(gpa, io, ev, @intCast(1000 + index));
        watcher.onEvent(id, ev);
        // Each event has left the machine before the next one is written, which
        // is the whole argument for shipping live rather than at the end.
        const so_far = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
        defer gpa.free(so_far);
        try testing.expect(std.mem.count(u8, so_far, "\n") == index + 2);
    }
    try locked.unlock(io);

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 1), report.count);
    try testing.expect(!report.entries[0].health.wantsSaying());

    // The copy is the log, so the far end verifies it with the code that wrote
    // it. Read after `finish`, which is what flushes.
    const original = try std.Io.Dir.cwd().readFileAlloc(io, log_path, gpa, .limited(1 << 20));
    defer gpa.free(original);
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, drop_path, gpa, .limited(1 << 20));
    defer gpa.free(copy);
    try testing.expectEqualStrings(original, copy);
}

test "the two export options really build the two sinks, and neither builds none" {
    // **The wiring, and not only the pieces.** Three mechanisms in this project
    // have shipped with green tests and no real caller, and no test of a shipper
    // or a sink on its own could catch a fourth.
    //
    // Mutation check: drop either branch of `Sinks.open` and the count below
    // falls to one; drop both and every session exports nothing however it was
    // asked.
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const wanted = try std.fmt.allocPrint(arena, "{s}/audit", .{dir_path});
    const id = "01JQ" ++ "A" ** 22;

    // Neither option and no bundle: no path is built, and no sink either.
    // **This is what makes a session that asked for no sink the session it was
    // before export existed.**
    {
        try testing.expectEqual(
            @as(usize, 0),
            (try auditSinks(arena, io, .{}, null, id)).len,
        );
        var none = Sinks{};
        defer none.close(io);
        none.open(.{}, &.{}, id);
        try testing.expectEqual(@as(usize, 0), none.count);
        try testing.expect(!none.anyRequired());
    }

    const from_flags = try auditSinks(arena, io, .{ .export_dir = wanted }, null, id);
    const drop_path = from_flags[0].path;
    // One file per session, named after it, so a collector knows which session a
    // file holds without opening it.
    try testing.expect(std.mem.startsWith(u8, drop_path, wanted));
    try testing.expect(std.mem.endsWith(u8, drop_path, "/" ++ id ++ ".jsonl"));
    // Nobody required it, so it is optional and nothing about it is loud.
    try testing.expect(!from_flags[0].required);
    // The directory was made rather than required, so an operator naming one
    // that does not exist yet still gets a session.
    var made = try std.Io.Dir.cwd().openDir(io, wanted, .{});
    made.close(io);

    // Both: one file drop, one syslog socket.
    var both = Sinks{};
    defer both.close(io);
    both.open(
        .{},
        &.{
            .{ .kind = .directory, .path = drop_path },
            .{ .kind = .syslog, .path = "/dev/log" },
        },
        id,
    );
    try testing.expectEqual(@as(usize, 2), both.count);

    const named = both.slice();
    try testing.expectEqualStrings(drop_path, named[0].name);
    try testing.expectEqualStrings(id, named[0].shipper.session);
    try testing.expectEqualStrings("/dev/log", named[1].name);
    try testing.expectEqualStrings(id, named[1].shipper.session);
    // A fresh session took up nobody's log, so a forgetful sink is not told that
    // it may hold some of this twice.
    try testing.expect(!named[0].shipper.continued);
    try testing.expect(!named[1].shipper.continued);

    // And a run that carried one on is. Each of the three ways of saying so
    // counts, because each one takes up a log another run already wrote.
    for ([_]Options{
        .{ .export_syslog = "/dev/log", .adopt = true },
        .{ .export_syslog = "/dev/log", .continue_newest = true },
        .{ .export_syslog = "/dev/log", .session = id },
    }) |carried_on| {
        var again = Sinks{};
        defer again.close(io);
        again.open(carried_on, try auditSinks(arena, io, carried_on, null, id), id);
        try testing.expectEqual(@as(usize, 1), again.count);
        try testing.expect(again.slice()[0].shipper.continued);
    }

    // **The names a `ShippingReport` keeps outlive the sinks.** A real run
    // crashed here: the path was allocated on the session's own path and freed
    // by `Sinks.close`, and phase 3 then read it. Nothing here owns a string, so
    // closing every sink leaves each name exactly as it was.
    var report: ShippingReport = .{};
    for (named) |one| report.add(.{ .name = one.name, .health = one.shipper.health });
    both.close(io);
    try testing.expectEqualStrings(drop_path, report.entries[0].name);
    try testing.expectEqualStrings("/dev/log", report.entries[1].name);
}

test "a project cannot drop a sink its installation required, and can add one of its own" {
    // **The ratchet, in the shape a sink can take it.** An organisation says
    // where every session sends its log; a project may add a place of its own,
    // because more of the record reaching more places narrows nothing, and it
    // may not take one away. Removal is not something a command line can
    // express, which is stronger than a check somebody has to remember.
    //
    // Mutation check: drop the org loop in `auditSinks` and the required sink
    // is gone whenever a developer names one of their own, which is the whole
    // control evaporating on the machines that use export at all. Drop the two
    // option branches and a project can no longer add one.
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const id = "01JQ" ++ "A" ** 22;

    const required_dir = try std.fmt.allocPrint(arena, "{s}/org-audit", .{dir_path});
    const own_dir = try std.fmt.allocPrint(arena, "{s}/my-audit", .{dir_path});
    const source = try std.fmt.allocPrintSentinel(
        arena,
        ".{{ .subject = \"ross@example.org\", .rules = .{{}}, .sinks = .{{ " ++
            ".{{ .kind = .directory, .path = \"{s}\" }}, " ++
            ".{{ .kind = .syslog, .path = \"/dev/log\" }} }} }}",
        .{required_dir},
        0,
    );
    const bundle = try chock_policy.org.parse(arena, source, null);

    // The developer names neither option. **The trail still leaves the
    // machine**, which is the difference between a control and an option and
    // the whole reason this field exists.
    {
        const only_required = try auditSinks(arena, io, .{}, bundle, id);
        try testing.expectEqual(@as(usize, 2), only_required.len);
        try testing.expect(only_required[0].required);
        try testing.expect(only_required[1].required);
        try testing.expect(std.mem.startsWith(u8, only_required[0].path, required_dir));
        try testing.expectEqualStrings("/dev/log", only_required[1].path);
    }

    // The developer names one of their own. Both are used: a project adds and
    // never replaces, and the required ones come first because nobody typed
    // them.
    const both = try auditSinks(arena, io, .{ .export_dir = own_dir }, bundle, id);
    try testing.expectEqual(@as(usize, 3), both.len);
    try testing.expect(both[0].required and both[1].required);
    try testing.expect(!both[2].required);
    try testing.expect(std.mem.startsWith(u8, both[2].path, own_dir));
    // And the required directory is still in the list, which is the assertion
    // the mutation above breaks.
    try testing.expect(std.mem.startsWith(u8, both[0].path, required_dir));

    // A sink both of them named is opened once, and it stays required. Two
    // `FileDrop`s over one file would write the same bytes at the same offsets
    // from two counts and leave a copy that verifies as broken, and a
    // duplicate on a command line must not be able to demote a sink either.
    //
    // Mutation check: drop `addPlannedSink`'s loop and this reads 3 rather
    // than 2, with two drops aimed at one file.
    const same = try auditSinks(
        arena,
        io,
        .{ .export_dir = required_dir, .export_syslog = "/dev/log" },
        bundle,
        id,
    );
    try testing.expectEqual(@as(usize, 2), same.len);
    try testing.expect(same[0].required);
    try testing.expect(same[1].required);

    // And every planned sink really becomes a shipper, which is the wiring no
    // test of `auditSinks` alone would catch.
    var sinks = Sinks{};
    defer sinks.close(io);
    sinks.open(.{}, both, id);
    try testing.expectEqual(@as(usize, 3), sinks.count);
    try testing.expect(sinks.anyRequired());
    try testing.expectEqual(@as(usize, 2), sinks.drop_count);
    try testing.expectEqual(@as(usize, 1), sinks.syslog_count);
    // **Each drop has a transport of its own.** One `FileDrop` shared by two
    // required directories would send the second one's lines to the first.
    for (sinks.slice(), both) |sending, planned| {
        try testing.expectEqualStrings(planned.path, sending.name);
        try testing.expectEqual(planned.required, sending.required);
    }
    try testing.expect(sinks.drops[0].sink().ptr != sinks.drops[1].sink().ptr);
}

test "an installation with no bundle plans exactly the sinks the command line named" {
    // **Byte for byte as today.** Every installation that has never seen a
    // bundle has to reach the same sinks, in the same order, with nothing
    // required, and has to skip the start-time probe entirely so that not one
    // extra byte moves at a different moment.
    //
    // Mutation check: default `PlannedSink.required` to true and the probe
    // below runs on every session in the world, and every optional sink starts
    // reporting an exit code an organisation never asked for.
    const gpa = testing.allocator;
    const io = testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const id = "01JQ" ++ "A" ** 22;
    const wanted = try std.fmt.allocPrint(arena, "{s}/audit", .{dir_path});

    const planned = try auditSinks(
        arena,
        io,
        .{ .export_dir = wanted, .export_syslog = "/dev/log" },
        null,
        id,
    );
    try testing.expectEqual(@as(usize, 2), planned.len);
    try testing.expectEqual(chock_policy.org.RequiredSink.Kind.directory, planned[0].kind);
    try testing.expectEqualStrings(
        try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ wanted, id }),
        planned[0].path,
    );
    try testing.expectEqual(chock_policy.org.RequiredSink.Kind.syslog, planned[1].kind);
    try testing.expectEqualStrings("/dev/log", planned[1].path);
    // Nothing is required, so nothing probes and nothing reaches the exit code.
    try testing.expect(!planned[0].required);
    try testing.expect(!planned[1].required);

    var sinks = Sinks{};
    defer sinks.close(io);
    sinks.open(.{}, planned, id);
    try testing.expect(!sinks.anyRequired());

    // A bundle that requires no sink is the same as no bundle at all, which is
    // what every bundle written before this field is.
    const older = try chock_policy.org.parse(arena, ".{ .subject = \"ross\", .rules = .{} }", null);
    var under_older = Sinks{};
    defer under_older.close(io);
    under_older.open(.{}, try auditSinks(arena, io, .{}, older, id), id);
    try testing.expectEqual(@as(usize, 0), under_older.count);
    try testing.expect(!under_older.anyRequired());

    // And the exit code of such a run is untouched, however badly its own
    // optional sink went. A `--export-dir` on a full disk is that person's own
    // business and must not turn their run red.
    var optional_gap = ShippingReport{};
    optional_gap.add(.{ .name = "/tmp/audit", .health = .{
        .faults = 3,
        .first_fault = error.NoSpaceLeft,
        .stalled_at = 88,
    } });
    try testing.expect(!optional_gap.requiredGap());
    try testing.expectEqual(Exit.finished, exitWithAudit(.finished, &optional_gap));
}

test "a required sink that cannot be reached is said at the start, and leaves the exit code" {
    // **The decision `chock_policy.org` writes out, measured.** A session must
    // not fail because an audit sink is down, so this one runs; and a required
    // sink is not an optional one, so it says so before the first turn, it says
    // who required it, and the gap it left is in the exit status.
    //
    // Mutation check: make an unreachable required sink return an error out of
    // `probe` and the session cannot start, which is the answer that turns an
    // organisation's control into an outage. Drop the `required` branch of
    // `sayFault` and the line names a path nobody typed with no way to find out
    // who did.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_path = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);

    const log_path = try std.fmt.allocPrintSentinel(gpa, "{s}/session.jsonl", .{dir_path}, 0);
    defer gpa.free(log_path);
    var backing = chock_proto.storage.JsonLines{
        .log = try chock_proto.log.Log.open(io, log_path, "01TESTSESSION"),
    };
    const store = backing.storage();
    defer store.close(io);

    // A directory that cannot be made, because a file of that name is in the
    // way. This is the shape of a real collector directory on a machine that
    // was set up wrong, and nothing here needs a network.
    try tmp.dir.writeFile(io, .{ .sub_path = "blocked", .data = "not a directory" });
    const unreachable_path = try std.fmt.allocPrint(gpa, "{s}/blocked/audit/s.jsonl", .{dir_path});
    defer gpa.free(unreachable_path);

    var watching = RecordingObserver{ .gpa = gpa };
    defer watching.deinit();
    var drop = chock_proto.ship.FileDrop{ .path = unreachable_path };
    defer drop.close(io);
    var sending = [_]Exporter.Sending{.{
        .name = unreachable_path,
        .required = true,
        .shipper = .{ .sink = drop.sink(), .session = "01TESTSESSION" },
    }};
    var exporter = Exporter{
        .gpa = gpa,
        .io = io,
        .storage = store,
        .inner = watching.observer(),
        .sinks = &sending,
    };

    // **Before the first turn, and it returns nothing at all.** There is no
    // path out of `probe` that stops a session.
    exporter.probe();
    const at_start = watching.said.items;
    try testing.expect(std.mem.indexOf(u8, at_start, unreachable_path) != null);
    // Who required it, because nobody at this keyboard did, and a reader told
    // only a path goes looking through a command line that does not hold it.
    try testing.expect(std.mem.indexOf(u8, at_start, "org policy requires") != null);
    // And that the session carries on, or the line reads as a session that has
    // already stopped.
    try testing.expect(std.mem.indexOf(u8, at_start, "carries on") != null);

    // The session runs. The log gains its events and none of them leave.
    {
        var locked = try store.lock(io);
        defer locked.unlock(io) catch {};
        _ = try locked.append(gpa, io, .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } }, 1000);
        _ = try locked.append(gpa, io, .{
            .session_end = .{ .reason = .finished, .detail = "" },
        }, 2000);
    }
    exporter.observer().onEvent(1, .{ .session_end = .{ .reason = .finished, .detail = "" } });

    var report: ShippingReport = .{};
    exporter.finish(&report);
    try testing.expectEqual(@as(usize, 1), report.count);
    try testing.expectEqual(@as(u64, 0), report.entries[0].health.delivered);
    try testing.expect(report.entries[0].required);
    try testing.expect(report.entries[0].gap());

    // **The teeth.** The session finished and did what it was asked to do, and
    // the run says the record did not get out.
    try testing.expect(report.requiredGap());
    try testing.expectEqual(Exit.audit_gap, exitWithAudit(.finished, &report));

    // The end of the run says it where a person reads, with the exit code in
    // the sentence so the number is not a riddle.
    var said: tty.Capture = undefined;
    said.start(io, gpa);
    defer said.stop(io);
    reportShipping(&report);
    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "org policy requires") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "on this machine and nowhere else") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "exit 9") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "must not fail") != null);
}

test "a required sink that came back leaves no gap, and a broken session keeps its own code" {
    // **How narrow `Exit.audit_gap` is, which is what stops it being the
    // refuse-to-start answer wearing a different hat.** The log on disk is the
    // queue, so a sink that was down for a minute is given every line it
    // missed, and a run like that ends exactly as it would have.
    //
    // Mutation check: read `faults` instead of `stalled_at` in `Entry.gap` and
    // the first case below turns red, which is every daemon restart in an
    // organisation failing somebody's build.
    var recovered = ShippingReport{};
    recovered.add(.{ .name = "/var/audit/chock/01JQ.jsonl", .required = true, .health = .{
        .delivered = 40,
        .faults = 6,
        .first_fault = error.ConnectionRefused,
        .stalled_at = null,
        .recovered = true,
    } });
    try testing.expect(!recovered.entries[0].gap());
    try testing.expect(!recovered.requiredGap());
    try testing.expectEqual(Exit.finished, exitWithAudit(.finished, &recovered));

    // A line the sink was there for and would not carry is a gap, because a
    // second attempt would send the same bytes to the same sink for ever. That
    // hole is as permanent as a tail that never left.
    var refused = ShippingReport{};
    refused.add(.{ .name = "/dev/log", .required = true, .health = .{
        .delivered = 39,
        .refused = 1,
        .first_refusal = "the line is larger than one syslog datagram",
    } });
    try testing.expect(refused.requiredGap());
    try testing.expectEqual(Exit.audit_gap, exitWithAudit(.finished, &refused));

    // **It never raises anything**, the same rule `exitWithApply` keeps. A
    // session that faulted or was refused reports that, because a broken
    // session is the first thing to act on and a script reading `audit_gap`
    // there would look at the wrong problem.
    for ([_]Exit{ .faulted, .refused, .budget, .no_progress, .turn_limit, .handed_over }) |ended| {
        try testing.expectEqual(ended, exitWithAudit(ended, &refused));
    }

    // And a run that required nothing is never touched, which is every run of
    // every installation with no bundle.
    const nothing = ShippingReport{};
    try testing.expect(!nothing.requiredGap());
    try testing.expectEqual(Exit.finished, exitWithAudit(.finished, &nothing));
}

test "a required sink that worked says so, and names the installation rather than a flag" {
    // The ordinary day. A required sink that is doing its job still says one
    // plain line, which is what makes the absence of that line mean something,
    // and it says who required it so a reader does not go looking for a flag.
    //
    // Mutation check: drop the required half of `reportShipping` and a sink
    // nobody typed is reported as though somebody had.
    const gpa = testing.allocator;
    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    var worked = ShippingReport{};
    worked.add(.{
        .name = "/var/audit/chock/01JQ.jsonl",
        .required = true,
        .health = .{ .delivered = 12 },
    });
    reportShipping(&worked);
    try testing.expect(std.mem.indexOf(u8, said.err(), "12 lines") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "this installation requires") != null);
    // Nothing about an exit code, because there is no gap to explain.
    try testing.expect(std.mem.indexOf(u8, said.err(), "exit 9") == null);
}

test "this session's own credential is what the redactor is given" {
    // **The wiring, which is the whole point.** `chock_core.redact.Policy`
    // defaults inert, so nothing redacts anything until a caller fills it in,
    // and this project has shipped mechanisms with no caller before. The line
    // that matters is `Loop.Deps.redact = started.redact`, and this is the
    // function behind `started.redact`.
    //
    // Mutation check: return `.{}` from `redactionFor` and this fails, while
    // every other test in this file still passes.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const token = "sk-not-a-real-key-0123456789";
    const policy = try redactionFor(arena, "hub", token, &.{});

    try testing.expectEqual(@as(usize, 1), policy.secrets.len);
    try testing.expectEqualStrings(token, policy.secrets[0].value);
    // The source and not a guess, so an agent reading a marker can tell a
    // credential Chock holds from a pattern that fired.
    try testing.expectEqual(chock_core.redact.Source.credential, policy.secrets[0].source);
    // And it really would change a request.
    try testing.expect(!policy.isEmpty());
    try testing.expectEqual(@as(usize, 0), policy.tooShort());
    // The heuristics stay off, which is `redact.zig`'s own default and its own
    // argument: they have false positives and a caller must choose them.
    try testing.expect(!policy.heuristics);

    // An ordinary credential says nothing at all. A line on every run is a line
    // nobody reads.
    try testing.expectEqualStrings("", said.err());
    try testing.expectEqualStrings("", said.out());
}

test "a credential nobody could match is skipped and said out loud, and an absent one is silent" {
    // `redact.min_secret_bytes` exists for this: a short value appears inside
    // ordinary words, inside hashes and inside base64, so matching it would fill
    // every request with markers and teach an agent to distrust every marker it
    // sees. Skipping is right and silence about skipping is not.
    //
    // Mutation check: drop the `tooShort` branch and a person with a four
    // character credential believes it is protected when it is not.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const short = "abc";
    const policy = try redactionFor(arena, "hub", short, &.{});
    try testing.expectEqual(@as(usize, 1), policy.tooShort());
    // Skipped means skipped: the policy changes no request at all, so nothing
    // is half protected.
    try testing.expect(policy.isEmpty());

    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "hub") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "not kept out") != null);
    // **And it never prints the value.** A diagnostic carrying the credential
    // would put it in the very place this exists to keep it out of.
    try testing.expect(std.mem.indexOf(u8, warned, short) == null);

    // **An empty token is not a short credential.** An instance that needs no
    // credential at all, which is every local provider somebody runs without
    // auth, has nothing to protect and nothing to say about it.
    said.clear();
    const none = try redactionFor(arena, "local", "", &.{});
    try testing.expectEqual(@as(usize, 0), none.secrets.len);
    try testing.expectEqual(@as(usize, 0), none.tooShort());
    try testing.expect(none.isEmpty());
    try testing.expectEqualStrings("", said.err());
}

test "no line this file writes about redaction can hold a credential" {
    // The rule stated as a property rather than as one assertion about one
    // sentence: whatever `redactionFor` says, and for whatever token, the token
    // is not in it.
    //
    // **Every token below is a run of letters no English word holds**, and that
    // is not fussiness: a one character token of `q` is inside the word
    // "request", so a test using it would fail on a sentence that leaks nothing.
    // The property is about the credential appearing, not about a letter.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    for ([_][]const u8{ "Zqx", "ZqxJv", "ZqxJvWk42", "Zqx" ** 70 }) |token| {
        said.clear();
        const others = [_]chock_auth.config.Instance{.{
            .name = "second",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            .credential = .{ .token = token },
            .context_tokens = null,
            .capabilities = .{},
        }};
        _ = try redactionFor(arena, "hub", token, &others);
        try testing.expect(std.mem.indexOf(u8, said.err(), token) == null);
        try testing.expect(std.mem.indexOf(u8, said.out(), token) == null);
    }
}

test "every credential the configuration holds is in the set, and not only the one in use" {
    // A machine set up for a comparison run holds two live provider
    // credentials, and only one of them is the one this session sends with.
    // The other is just as real, and a tool result can echo it just as easily.
    //
    // Mutation check: drop the loop over `instances` in `redactionFor` and the
    // second credential below is missing from the set, so it would reach the
    // log whole.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const in_use = "sk-in-use-00000000000000";
    const idle = "sk-idle-1111111111111111";

    const instances = [_]chock_auth.config.Instance{
        .{
            .name = "hub",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            // The same session, reached through the store rather than the
            // file, so this entry is a duplicate and must not be counted twice.
            .credential = .{ .token = in_use },
            .context_tokens = null,
            .capabilities = .{},
        },
        .{
            .name = "spare",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            .credential = .{ .token = idle },
            .context_tokens = null,
            .capabilities = .{},
        },
        .{
            .name = "by-path",
            .kind = .anthropic,
            .base_url = "https://example.invalid",
            // A path and not a value. There is nothing here to add.
            .credential = .{ .token_file = "/run/secrets/spare" },
            .context_tokens = null,
            .capabilities = .{},
        },
        .{
            .name = "local",
            .kind = .openai_compat,
            .base_url = "http://127.0.0.1:5000/v1",
            .credential = .absent,
            .context_tokens = null,
            .capabilities = .{},
        },
    };

    const policy = try redactionFor(arena, "hub", in_use, &instances);
    try testing.expectEqual(@as(usize, 2), policy.secrets.len);

    var saw_in_use = false;
    var saw_idle = false;
    for (policy.secrets) |secret| {
        try testing.expectEqual(chock_core.redact.Source.credential, secret.source);
        if (std.mem.eql(u8, secret.value, in_use)) saw_in_use = true;
        if (std.mem.eql(u8, secret.value, idle)) saw_idle = true;
    }
    try testing.expect(saw_in_use);
    try testing.expect(saw_idle);

    // Two ordinary credentials say nothing at all.
    try testing.expectEqualStrings("", said.err());
}

test "a short credential on another provider is named, and the good one still works" {
    // The short value rule holds over the whole set and not over the first
    // entry alone. A value nobody can match safely is skipped, and the person
    // who wrote it is told which provider it belongs to.
    //
    // Mutation check: warn on `policy.tooShort() != 0` with one line that names
    // `instance_name` and the line names the wrong provider.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const good = "sk-in-use-00000000000000";
    const tiny = "abc";

    const instances = [_]chock_auth.config.Instance{.{
        .name = "spare",
        .kind = .anthropic,
        .base_url = "https://example.invalid",
        .credential = .{ .token = tiny },
        .context_tokens = null,
        .capabilities = .{},
    }};

    const policy = try redactionFor(arena, "hub", good, &instances);
    try testing.expectEqual(@as(usize, 1), policy.tooShort());
    // The one that can be matched still is, so a short value on one provider
    // does not turn the whole policy off.
    try testing.expect(!policy.isEmpty());

    const warned = said.err();
    try testing.expect(std.mem.indexOf(u8, warned, "spare") != null);
    try testing.expect(std.mem.indexOf(u8, warned, "not kept out of this session's log") != null);
    // The provider that is fine is not named, because nothing is wrong with it.
    try testing.expect(std.mem.indexOf(u8, warned, "hub") == null);
    try testing.expect(std.mem.indexOf(u8, warned, good) == null);
}

test "the broker is given the same values, without the ones nobody can match" {
    // **The broker is a second writer into the one log**, and the loop's own
    // funnel cannot reach it: `chock-broker` imports no `chock-core`. So the
    // values travel, and `chock_broker.Broker.redaction` is what takes them.
    //
    // Mutation check: return `&.{}` from `brokerRedaction` and the count below
    // fails. Drop the `min_secret_bytes` test there and the short value reaches
    // a set that would fill every approval record with markers.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var said: tty.Capture = undefined;
    said.start(testing.io, gpa);
    defer said.stop(testing.io);

    const good = "sk-in-use-00000000000000";
    const tiny = "abc";

    const instances = [_]chock_auth.config.Instance{.{
        .name = "spare",
        .kind = .anthropic,
        .base_url = "https://example.invalid",
        .credential = .{ .token = tiny },
        .context_tokens = null,
        .capabilities = .{},
    }};

    const policy = try redactionFor(arena, "hub", good, &instances);
    const values = try brokerRedaction(arena, policy);

    // The one that can be matched, and only it. The short one was already said
    // out loud by `redactionFor`, by the name of the provider it belongs to, so
    // dropping it here is silent on purpose and not silent about nothing.
    try testing.expectEqual(@as(usize, 1), values.len);
    try testing.expect(std.mem.eql(u8, values[0], good));
    for (values) |value| try testing.expect(!std.mem.eql(u8, value, tiny));
    try testing.expect(std.mem.indexOf(u8, said.err(), "spare") != null);

    // A session that resolved no credential hands the broker nothing, and a
    // broker with nothing replaces nothing and copies nothing.
    const empty = try brokerRedaction(arena, .{});
    try testing.expectEqual(@as(usize, 0), empty.len);
}
