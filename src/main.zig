//! The `chock` program: the command line, and nothing else. Every subcommand
//! below is wiring over libraries that are already built and already tested.
//!
//! ## The one constraint that decides how this file is written
//!
//! **`Registry.dispatch` calls `Sandbox.spawn`, which calls `fork`, and
//! `fork` carries only the calling thread into the child.** A caller holding
//! a lock on another thread gives a child that deadlocks. So `chock run`
//! stays single threaded on the tool path, and the `std.Io` it hands to
//! `Loop.run` is built with a failing allocator, which is an `Io` that cannot
//! start a thread at all. See `src/run.zig`, which explains the three phases
//! that follow from it, and `test/core/tools_probe.zig`, which is where that
//! shape came from.
//!
//! `chock daemon` runs a child process per session and never calls `Loop.run`
//! itself, so it may use threads freely: see `src/daemon.zig`.
//!
//! ## One binary, and one word that is not a command
//!
//! **`zig-out/bin` holds `chock` and nothing else.** Chock links no libc and
//! Zig cross compiles it, so an install is one file, and a helper program
//! found by a path is exactly what a one file install cannot survive. So this
//! program starts a copy of itself where it used to start another program:
//! `chock run --parent-session ...` for a subagent, and `chock __plugin-host`
//! for the process one plugin runs inside. See `plugin_host_verb`, and
//! `test/plugin/one_binary.zig`, which fails the day a second artifact is
//! installed.
//!
//! ## Exit codes carry meaning
//!
//! A script reads them, so they come from the `session.end` reason the log
//! already records and not from wherever the code happened to return. See
//! `Exit`.
//!
//! **A subcommand that did nothing never exits 0.** That is the fault which
//! made the Darwin cross compile check hollow for weeks: a step that reports
//! success for work it did not do is worse than no step at all.

const std = @import("std");
const builtin = @import("builtin");
const chock_broker = @import("chock-broker");
const chock_core = @import("chock-core");
const chock_proto = @import("chock-proto");

const plugin_host_cmd = @import("plugin-host.zig");
const run_cmd = @import("run.zig");
const login_cmd = @import("login.zig");
const daemon_cmd = @import("daemon.zig");
const serve_cmd = @import("serve.zig");
const detach_cmd = @import("detach.zig");
const memory_cmd = @import("memory.zig");
const cache_cmd = @import("cache.zig");
const workspace_cmd = @import("workspace.zig");
const usage_cmd = @import("usage.zig");
const plan_cmd = @import("plan.zig");
const sessions_cmd = @import("sessions.zig");
const approve_cmd = @import("approve.zig");
const doctor_cmd = @import("doctor.zig");
const askpass_cmd = @import("askpass.zig");
const tty = @import("tty.zig");
const ui = @import("ui.zig");

pub const session = @import("session.zig");

/// What the standard library is told about this program.
///
/// **One field, and it changes where no message goes.** `src/ui.zig` needs to
/// read one line a dependency writes, the line lattice writes when a compositor
/// keymap does not load, because that line is the only report of a keyboard a
/// person could not type on. `ui.logMessage` reads it and passes every message
/// on to `std.log.defaultLog`, so what a run prints is what it printed before.
/// See `ui.keymap_watch`.
pub const std_options: std.Options = .{ .logFn = ui.logMessage };

/// The version of this build, exactly as `build.zig.zon` spells it, unless
/// the build was given `-Dversion`.
///
/// **The number is never written in this file.** `build.zig` is the one place
/// that can read the manifest, because `@import` of a manifest works from the
/// root of its own package alone, and it hands the string over as a build
/// option. So there is one place to edit, and a release artefact carries the
/// same string its file name is built from. The test at the end of this file
/// reads the manifest itself and fails the day the two stop agreeing.
pub const version = @import("chock-version").text;

/// The whole line `chock --version` prints.
pub const version_line = versionLine(version);

/// The line for one version string. The number passes through as it is,
/// because `-Dversion` and `.github/workflows/ci.yml` can both hand over a
/// string that is not legal semantic versioning, and reading it is not this
/// function's job.
fn versionLine(comptime text: []const u8) []const u8 {
    return "chock " ++ text;
}

/// What the process exits with. A script reads these, so each one names a
/// different fact and none of them is a catch all.
pub const Exit = enum(u8) {
    /// The session finished: the model answered with no tool call left to
    /// run.
    finished = 0,
    /// The command line could not be understood, or the session could not be
    /// started at all. Nothing ran.
    usage = 1,
    /// The session started and ended with a fault.
    faulted = 2,
    /// The session was refused or canceled. **A refusal is not a crash and must
    /// not look like one**: an approval nobody answers is a refusal, and a
    /// script that treats that as a crash will retry something a person already
    /// said no to.
    refused = 3,
    /// The caller asked for a turn limit with `--max-turns` and the session
    /// reached it with no final answer. Off by default: see
    /// `chock_core.Loop.Deps.max_turns`.
    turn_limit = 4,
    /// The subcommand was understood and is not built yet.
    not_implemented = 5,
    /// The session stopped because it had stopped making progress: the same
    /// tool, with the same arguments, over and over. See
    /// `chock_core.Loop.no_progress_repeats`. **The agent gave up**, which is
    /// a different fact from a crash and from running out of money, and a
    /// script acts on all three differently.
    no_progress = 6,
    /// The session reached the budget in `chock.zon` and stopped rather than
    /// spending past it. **The agent ran out of money.** Not `refused`: a
    /// person refusing one act and a cap stopping the whole session are two
    /// different things to act on.
    budget = 7,
    /// Another process asked for this session and this one let go of it. **The
    /// work is not over and it is not this process's any more**, which is a
    /// third thing, different from finishing and from being canceled.
    ///
    /// Not zero, and this is the whole reason it is a code of its own: a script
    /// that read zero would carry on as though the task were done, and the task
    /// is still being worked on by somebody else. Not `refused` either, because
    /// nobody said no to anything. See `chock detach`.
    handed_over = 8,
    /// The session did its work, and a sink this installation's org policy
    /// bundle **requires** still held none of the tail of the log when the
    /// session ended. Part of the record is on this machine and nowhere else.
    ///
    /// **The one part of a required sink an organisation can act on without a
    /// person choosing to tell it.** `chock_policy.org` carries the whole
    /// argument: a session must not fail because an audit sink is down, so this
    /// is a status and never a refusal to run, and it is deliberately narrow. A
    /// sink that went down and came back leaves no gap at all, because the log
    /// on disk is the queue and the shipper backfills every line it missed, and
    /// a run like that exits `finished`. Only a gap that is still open at the
    /// end reaches this code.
    ///
    /// **Only over a required sink.** A sink somebody asked for on the command
    /// line is that person's own business, and a `--export-dir` on a full disk
    /// must not turn every developer's run red.
    ///
    /// Not `faulted`: the session did what it was asked to do, and a script
    /// that retried it would run the work twice. What is wrong is the record.
    audit_gap = 9,
    /// The model backend was reached and answered a turn with nothing at all:
    /// no text, no tool call, no content of any kind. **The session produced no
    /// answer**, so a script must never read this as work that was done. See
    /// `chock_proto.event.SessionEndReason.empty_response` for the measured
    /// session this comes from.
    ///
    /// Not `faulted`: nothing broke, and a script that treats a fault as a
    /// reason to stop should treat this as a reason to ask again. Not
    /// `no_progress` either: the agent did not give up on a task, it never said
    /// anything about one.
    empty_response = 10,
    /// The model backend refused the request. It answered with `stop_reason`
    /// `refusal` and said why in the same message, which the session log
    /// carries. **Nothing broke and nobody was asked**, so this is neither
    /// `faulted` nor `refused`: `refused` is a person, or an approval nobody
    /// answered, saying no to one act, and this is the provider saying no to
    /// the request itself.
    ///
    /// Not `empty_response`, which is the code it is nearest to and the one
    /// with the opposite advice: a turn that carried nothing is worth asking
    /// again, and a refusal asked again is refused again. A script that reads
    /// this code must change the request or stop, and Chock itself does
    /// neither on its own. See
    /// `chock_proto.event.SessionEndReason.refused_by_model`.
    model_refused = 11,

    pub fn code(self: Exit) u8 {
        return @intFromEnum(self);
    }
};

/// The exit code for a session that ended with `reason`.
///
/// **The reason alone decides, and no code is read out of a message.** This
/// function once matched a prefix of the sentence `Loop.run` wrote for the
/// turn limit, because `event.SessionEndReason` had no member for it. A
/// reword in that file would then have turned every turn limit into an
/// ordinary fault here, silently. Every reason a session can end with is now
/// a member of its own, so there is nothing left to guess and no `detail`
/// parameter to guess it from.
pub fn exitFor(reason: chock_proto.event.SessionEndReason) Exit {
    return switch (reason) {
        .finished => .finished,
        .canceled_by_user => .refused,
        // Reaching a cap is not a fault: the user wrote the number and Chock
        // kept to it.
        .budget_reached => .budget,
        .no_progress => .no_progress,
        .turn_limit => .turn_limit,
        .errored => .faulted,
        // **Never `finished`, and never `refused`.** A handover is a session
        // that carries on somewhere else: nothing finished and nobody said no.
        // See `Exit.handed_over`.
        .handed_over => .handed_over,
        // **Never `finished`**, which is exactly what this was before it had a
        // member: a turn that carried nothing ended the session `finished` and
        // exited 0. See `Exit.empty_response`.
        .empty_response => .empty_response,
        // **Never `refused`, which is a person saying no, and never
        // `errored`, because a refusal is an answer and not a fault.** See
        // `Exit.model_refused`.
        .refused_by_model => .model_refused,
        // A reason a newer Chock wrote and this one does not know. Never
        // `finished`: an absent answer is never a permissive answer, which is
        // the same rule a policy keeps.
        .unknown => .faulted,
    };
}

/// The usage text, built from `commands` itself rather than typed out a
/// second time, so a command can never be listed and absent, or present and
/// unlisted. A command this build does not implement says so here too.
/// Print the usage text on `stream`.
///
/// **Standard output when a person asked for it, standard error when they got
/// it because the command line was wrong.** A person who types `chock --help |
/// less` wants the text in the pipe, and a script that reads standard output
/// must not be handed a help page as if it were an answer.
///
/// **Public because bare `chock` prints it too.** That command is the interface
/// now, and this is what it falls back to when there is no display to draw: see
/// `src/ui.zig`.
pub fn printUsage(stream: tty.Stream) void {
    // **The version is on the first line a person reads.** A bug report is
    // pasted out of the page somebody already had open far more often than
    // out of a second command they had to know to run.
    //
    // **The task form is on this page, because this page is where a person
    // who got it wrong is sent.** `chock fix the parser` is the first thing
    // somebody types, and a first word is a command name, so it is refused.
    // A page that listed the commands alone taught nothing at the one moment
    // it was read. See `namesNoCommand` for why the rule stays as it is.
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
        // Wide enough for the longest name in `commands`. A name that
        // overflows this pushes its own summary out of the column and makes
        // the whole list read as ragged.
        tty.say(stream, .plain, "  {s: <9}  {s}{s}\n", .{
            entry.name,
            entry.summary,
            if (entry.run == null) "  (not implemented yet)" else "",
        });
    }
    tty.say(stream, .plain, "\nEvery command also takes:\n\n{s}", .{tty.options_text});
    tty.say(stream, .plain, "\nRun `chock <command> --help` for what one command takes.\n", .{});
}

/// Decide colour and verbosity for the whole process, and give back the
/// arguments with the two options that decided them removed.
///
/// **Done once, here, before any subcommand runs.** A colour flag that only
/// `chock run` understood would be the beginning of two conventions: see
/// `src/tty.zig`.
///
/// **Both streams are asked, and neither answers for the other.** `chock run >
/// answer.txt` in a terminal has a file on one and a terminal on the other.
///
/// The `Io` comes from `std.process.Init`, which is where the program's own
/// standard output and standard error come from too. Asking whether a stream is
/// a terminal starts no thread, so it does not break the single threaded rule
/// this file's own top comment states.
fn setUpOutput(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    args: []const []const u8,
) !?[]const []const u8 {
    const taken = tty.takeGlobalFlags(arena, args) catch |err| switch (err) {
        // Already reported by `takeGlobalFlags`, which names the value it was
        // given and the three it accepts.
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

/// What every subcommand's own entry point looks like. One shape for all of
/// them, so the table below can hold them side by side. `exe_path` is
/// `argv[0]`: only `chock daemon` needs it, to start a child of itself for
/// each session, and the rest ignore it.
pub const Run = *const fn (
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8;

/// One subcommand. **`run` is null for one this build understands and does not
/// implement**, and then `why` says what it is waiting on and `landed` says how
/// to check that the sentence is still true.
///
/// A subcommand Chock will answer to later and a word Chock has never heard
/// of are different facts, and a user acts on them differently. Keeping both
/// in one table is what stops the two lists drifting: a command that was
/// implemented and left in a separate "not built" list would answer "not
/// implemented yet" forever, and nothing would catch it.
pub const Command = struct {
    name: []const u8,
    summary: []const u8,
    run: ?Run = null,
    why: []const u8 = "",
    /// **What makes `why` checkable rather than prose.** Answers whether the
    /// thing `why` says is missing has since been built. Required for a
    /// command with no `run`, and null for one that has it.
    ///
    /// A `why` on its own is a sentence asserting a fact about the world, and
    /// no test can compare a sentence against the world. `chock usage` said
    /// "the cost record is not built yet" for a whole milestone after the cost
    /// record landed, while the test below, which pins this table's internal
    /// consistency, passed the entire time. So the reason names a declaration
    /// instead: the comptime block under `commands` fails the build on the day
    /// that declaration appears, which is the day somebody should be reminded
    /// that this command is waiting on nothing.
    ///
    /// **It catches the spelling it names and nothing else.** A feature that
    /// lands under a different name goes unnoticed here, so the sweep stays:
    /// when a milestone lands, grep for anything that says it is waiting on
    /// that milestone.
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
};

// **Every reason a command gives for not being built is checked here, and a
// reason that has expired fails the build.** See `Command.landed` for the
// fault this exists for: a `why` is prose, prose cannot be tested against the
// world, and `chock usage` answered "not implemented yet" for a milestone
// after the thing it named was finished.
//
// A comptime block and not a test, so it is not something a person can build
// the program without.
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

/// How much of standard output is held before a system call sends it.
///
/// A table is many small writes, and one write per row would be one system
/// call per row. Nothing here needs the number to be exact: it is a trade
/// between system calls and memory, and a row longer than this is written
/// straight through rather than split.
const stdout_buffer_size = 8 * 1024;

/// The one word this program answers to that is not a command.
///
/// `chock __plugin-host <module path> [capability ...]` makes this process the
/// host one plugin runs inside, and `src/plugin-host.zig` is what it then
/// runs. The word itself, and the whole argument for a hidden verb rather than
/// a second installed program, is `chock_core.plugin_host.verb`.
///
/// **Not in `commands`, and that is the decision.** `commands` is the list a
/// person reads: `printUsage` prints it and `chock <word>` answers out of it.
/// This is not that. It is one process of Chock starting another, so keeping
/// it out leaves the table's own rule, that every command is either built or
/// says why it is not, a rule about commands. **No third state is needed**: a
/// hidden entry in the table would have wanted one, because it is built and
/// must not be listed, and every reader of that table would then have to hold
/// two ideas rather than one.
///
/// The two lists cannot drift apart, which is the fault this file warns about
/// everywhere else: the comptime block below refuses to build a table that
/// names this word, so a command can never shadow the verb and the verb can
/// never shadow a command.
const plugin_host_verb = chock_core.plugin_host.verb;

// **A command of this name would be unreachable**, because `main` answers the
// verb before it reaches the table at all. A comptime block and not a test, so
// nobody can build a `chock` with a command they cannot run.
comptime {
    for (commands) |entry| {
        if (std.mem.eql(u8, entry.name, plugin_host_verb)) @compileError("chock " ++
            entry.name ++ " is both a command in the table and the hidden plugin host verb, " ++
            "so the command could never run. Rename the command.");
    }
}

// **The name a link selects must be a command in the table.** `main` reads the
// program's own name and runs `askpass` when it matches, which is the only way
// `GIT_ASKPASS` can reach it: see the branch itself. If that name and the
// command's own ever drift apart, the link would run one thing and `chock
// askpass` another, and only one of them would be documented. A comptime
// block, so the two cannot drift at all.
comptime {
    var found = false;
    for (commands) |entry| {
        if (std.mem.eql(u8, entry.name, chock_broker.askpass.link_name)) found = true;
    }
    if (!found) @compileError("the askpass link is named " ++ chock_broker.askpass.link_name ++
        ", and no command in the table has that name, so the link would reach nothing.");
}

/// The words this file answers itself instead of passing to a subcommand.
///
/// **Two of them open with a dash and are still not options**, which is the
/// whole reason this list exists: `namesNoCommand` has to let them through to
/// the dispatch below.
const own_words = [_][]const u8{ "--help", "-h", "help", "--version", "version" };

/// Whether a first argument names no command, and so is an option on bare
/// `chock`.
///
/// **An option is not a command name.** So `chock --allow-dirty` is bare
/// `chock` with an option, and the whole line goes to the parser `chock run`
/// already uses.
///
/// **This is deliberately not a list of the options `run` takes.** Naming them
/// here would put the same list in two files, and the next option added to
/// `run` would be reported as a missing command until somebody remembered to
/// add it here as well. That already happened once, to `--verbose`, and then
/// again to `--allow-dirty` when the fix named two options instead of all of
/// them. An unknown option now gets `run`'s own error, which says which option
/// it was and prints the usage that lists the real ones.
///
/// `chock --verbose run` still means `run`: only the first argument is read, so
/// a line whose options come before a command reaches the table untouched.
fn namesNoCommand(first: []const u8) bool {
    if (first.len == 0 or first[0] != '-') return false;
    for (own_words) |one| {
        if (std.mem.eql(u8, first, one)) return false;
    }
    return true;
}

pub fn main(init: std.process.Init) !u8 {
    // One arena for the command line, the configuration, and every path
    // built from them. All of it is bounded by the size of the command line
    // and the configuration file, and all of it lives as long as the process
    // does, so an arena is both correct and the cheapest thing to reason
    // about.
    const arena = init.arena.allocator();

    // A general purpose allocator for the session itself, which allocates and
    // frees on every turn and would grow an arena without bound over fifty of
    // them.
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = switch (builtin.mode) {
        .Debug, .ReleaseSafe => debug_allocator.allocator(),
        .ReleaseFast, .ReleaseSmall => std.heap.smp_allocator,
    };

    const args = try init.minimal.args.toSlice(arena);

    // **The hidden verb is answered before anything else in this file runs**,
    // and the order is not tidiness. A plugin host process writes the wire on
    // its own standard output, so the buffered writer below must never exist
    // on this path: two writers on one descriptor is a corrupt reply. And the
    // rest of `args` is a plugin's capability list, which is the only input a
    // host process trusts, so `setUpOutput` must not rewrite it looking for
    // `--color` and `--verbose`. See `plugin_host_verb`.
    if (args.len >= 2 and std.mem.eql(u8, args[1], plugin_host_verb)) {
        return plugin_host_cmd.main(arena, gpa, init.io, args[2..]);
    }

    // **The two streams, and the only place in the program that opens them.**
    //
    // Standard output is buffered, and the `defer` below is what sends it. That
    // `defer` runs on every path this function can take, because no subcommand
    // calls `std.process.exit` and none of them panics: each returns an exit
    // code, refusals included. See `src/tty.zig`.
    //
    // **Standard error has a zero length buffer on purpose.**
    // `std.Io.Writer.flush` is a no-op on a writer with no buffer, so a
    // diagnostic has already left by the time the call returns and nothing can
    // lose it.
    var stdout_buffer: [stdout_buffer_size]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &stdout_buffer);
    var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
    tty.useStreams(init.io, &stdout.interface, &stderr.interface);
    defer tty.flushOut();

    // **The name this program was invoked as can select one command, and one
    // only.** `git` and `ssh` run a password helper as one executable path
    // with the prompt as its one argument, and neither puts a shell in the
    // way, so `GIT_ASKPASS` has no room for a subcommand: measured, and
    // `lib/chock-broker/askpass.zig` records what git answered. A link named
    // `askpass` is what closes that, and this is where the name is read. It is
    // the multi-call trick a coreutils install already uses.
    //
    // **Not a second dispatch table.** The name has to match a command that is
    // already in `commands`, and the comptime block below says so, so this can
    // never become a way to reach something the table does not list.
    if (std.mem.eql(u8, std.fs.path.basename(args[0]), chock_broker.askpass.link_name)) {
        return askpass_cmd.main(arena, gpa, init.minimal.environ, args[0], args[1..]);
    }

    if (args.len < 2 or namesNoCommand(args[1])) {
        // **Bare `chock` is the interface**, and an option is not a command
        // name, so a line that opens with one is bare `chock` with options on
        // it. The whole line then goes to the very parser `chock run` uses: see
        // `namesNoCommand` for why that is one list and not two.
        //
        // `setUpOutput` first, because the interface reads `tty.stdoutIsTty`
        // and the painter, and neither is decided until this has run.
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
        // Asked for, so it is the answer, and `chock --help | less` gets it.
        printUsage(.out);
        // Asking for help and getting it is the one thing this program does
        // that succeeds without doing any work.
        return Exit.finished.code();
    }

    if (std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "version")) {
        // A version is read by a script far more often than by a person.
        tty.out(.plain, "{s}\n", .{version_line});
        return Exit.finished.code();
    }

    for (commands) |entry| {
        if (!std.mem.eql(u8, command, entry.name)) continue;
        if (entry.run) |go| return go(arena, gpa, init.minimal.environ, args[0], rest);
        // Never 0. A command that did nothing must not report success: that
        // is the fault which made the Darwin cross compile check hollow for
        // weeks.
        tty.print(.err, "chock {s}: not implemented yet, because {s}\n", .{ entry.name, entry.why });
        return Exit.not_implemented.code();
    }

    // **The line that refuses the word also says how to ask for the task**,
    // because a person reads this line at the exact moment they are wrong,
    // and the page under it is the page they already had. This line used to
    // say that "hi" is no command and stop there, which sends a person to
    // look for a subcommand they never wanted.
    //
    // **Offered, and never done for them.** A bare word stays an error: a
    // `chock rnu` that quietly asked an agent about "rnu" would spend money
    // on a typo. See `namesNoCommand`.
    //
    // Every word is repeated, with `--` in front, and the quotes a person
    // used are not put back. They are not needed: `chock run` joins the words
    // after `--` with one space, so `chock "fix the parser"` and `chock -- fix
    // the parser` ask for the same thing.
    tty.print(.err, "chock: there is no command named \"{s}\"\n", .{command});
    tty.print(.err, "chock: to run it as a task instead, write `chock -- {s}`\n\n", .{
        try std.mem.join(arena, " ", args[1..]),
    });
    printUsage(.err);
    return Exit.usage.code();
}

const testing = std.testing;

test "the version this program reports is the one in build.zig.zon" {
    // **The manifest is read here, off the disk, and the build option is not
    // trusted to say what is in it.** A test that compared the option against
    // itself would pass on the day somebody wrote a number into `build.zig`
    // by hand, which is the fault this test exists for. The path comes from
    // `build.zig`, which is the only thing that knows where the manifest is,
    // and it reaches this test binary alone: see the module for it there.
    const manifest_path = @import("manifest_path").manifest_path;

    const text = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        manifest_path,
        testing.allocator,
        .limited(64 * 1024),
    );
    defer testing.allocator.free(text);

    // `.minimum_zig_version` does not match this, because the character
    // before `version` there is an underscore and not a dot.
    const opener = ".version = \"";
    const after_key = std.mem.indexOf(u8, text, opener) orelse return error.ManifestHasNoVersion;
    const value = text[after_key + opener.len ..];
    const closer = std.mem.indexOfScalar(u8, value, '"') orelse return error.ManifestHasNoVersion;

    try testing.expectEqualStrings(value[0..closer], version);

    // And the line a person pastes into a bug report is that number and
    // nothing else. `indexOf` would pass on a line that buried it.
    try testing.expectEqualStrings("chock " ++ version, version_line);
}

test "the version line carries whatever number it is given" {
    // The shape `.github/workflows/ci.yml` builds for a commit with no tag
    // reaches the line unchanged. It is not a legal semver pre-release
    // identifier when the hash is digits alone, and that stops nothing.
    try testing.expectEqualStrings("chock 0.1.0", versionLine("0.1.0"));
    try testing.expectEqualStrings("chock 1.0.0-rc.1", versionLine("1.0.0-rc.1"));
    try testing.expectEqualStrings("chock 0.0.0-0123456", versionLine("0.0.0-0123456"));
}

test "the exit code for a refused session says refused, and never says fault" {
    // An approval nobody answers is a refusal, and a refusal is not a crash. A
    // script that reads the same code for both will retry something a person
    // already said no to.
    try testing.expectEqual(Exit.refused, exitFor(.canceled_by_user));
    try testing.expect(exitFor(.canceled_by_user) != .faulted);
    try testing.expect(exitFor(.canceled_by_user) != .finished);
}

test "each session end reason gets its own exit code, and none of them is zero except finished" {
    try testing.expectEqual(Exit.finished, exitFor(.finished));
    try testing.expectEqual(Exit.faulted, exitFor(.errored));
    try testing.expectEqual(Exit.faulted, exitFor(.{ .unknown = "some-newer-reason" }));

    // Every reason that is not `finished` gives a non zero code, so a script
    // that only checks for zero still learns that something went wrong.
    const not_finished = [_]chock_proto.event.SessionEndReason{
        .canceled_by_user,
        .errored,
        .budget_reached,
        .no_progress,
        .turn_limit,
        // A session that changed hands is not one that finished. A script that
        // read zero here would report a task done that another process is
        // still working on.
        .handed_over,
        // A turn the provider answered with nothing. A script that read zero
        // here would report an answer nobody was given.
        .empty_response,
        // A turn the provider refused. A script that read zero here would
        // report work that was never done, on a request that was declined.
        .refused_by_model,
        .{ .unknown = "some-newer-reason" },
    };
    for (not_finished) |reason| {
        try testing.expect(exitFor(reason).code() != 0);
    }
}

test "a model backend refusal is neither a fault nor a person saying no" {
    // Three facts a script acts on differently: the provider declined the
    // request, something broke, and a person refused one act. Before this,
    // a refusal ended the session `finished` and exited 0. See
    // `chock_proto.event.SessionEndReason.refused_by_model`.
    const declined = exitFor(.refused_by_model);
    try testing.expectEqual(Exit.model_refused, declined);
    try testing.expect(declined != Exit.faulted);
    try testing.expect(declined != Exit.refused);
    try testing.expect(declined != Exit.finished);
    // Nearest neighbour, opposite advice: asking again is reasonable after an
    // empty turn and gets the same answer after a refusal.
    try testing.expect(declined != Exit.empty_response);
    try testing.expect(declined.code() != 0);
}

test "the agent giving up, running out of money, and crashing are three different exit codes" {
    // The whole point of giving each reason a member: a script can tell them
    // apart. Before this, the turn limit was an `errored` end told apart by a
    // sentence prefix, and a budget shared a code with a user's refusal.
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
    // `exitFor` switches over `SessionEndReason` with no `else`, so a member
    // added to the event type fails the build here rather than falling into
    // whichever branch an `else` happened to name. This test names the
    // members that exist today, so adding one is a change somebody makes on
    // purpose in two places.
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
    try testing.expectEqual(@as(usize, 12), count);
}

test {
    testing.refAllDecls(@This());
}

test "every command is either built or says why it is not, and never both" {
    // One table drives the dispatch, the usage text, and this test. A command
    // that was implemented and left behind in a separate "not built" list
    // would answer "not implemented yet" forever, and nothing would catch it.
    //
    // **This test alone was not enough**, and that is worth stating where the
    // next reader will see it. It pins the table's internal consistency, and
    // `chock usage` passed it for a whole milestone while telling every user
    // that the cost record was not built, because by then it was. The `why` was
    // prose about the world, and this test cannot see the world. What catches
    // that is `Command.landed` and the comptime block beside `commands`.
    for (commands) |entry| {
        try testing.expect(entry.name.len != 0);
        try testing.expect(entry.summary.len != 0);
        if (entry.run == null) {
            try testing.expect(entry.why.len != 0);
            // A reason with nothing to check it against is the shape that
            // went stale. The comptime block refuses to build one; this says
            // the same thing where a reader of the tests will find it.
            try testing.expect(entry.landed != null);
            try testing.expect(!entry.landed.?());
        } else {
            try testing.expectEqualStrings("", entry.why);
            try testing.expect(entry.landed == null);
        }
    }
}

test "a command that is not built exits non zero, so a script never reads success for work nobody did" {
    // The fault that made the Darwin cross compile check hollow for weeks.
    try testing.expect(Exit.not_implemented.code() != 0);

    // **Every command in the table is now built**, and `chock askpass` was the
    // last one. This line used to assert the opposite, and its own comment
    // said that whoever built the last one had to decide on purpose whether
    // the branch stays. The decision is that it stays: `Command.run` is still
    // optional, the dispatch below still answers `not_implemented` for a null
    // one, and the comptime block under `commands` still refuses a command
    // that is not built and names nothing to check its reason against. So the
    // next command that lands before its work does gets the same treatment
    // this one got, and nothing here has to be rebuilt to give it.
    for (commands) |entry| {
        if (entry.run != null) continue;
        // Not built, so it must still say why, and the reason must still be
        // checkable. The comptime block is what fails the build when the
        // reason expires; this is the half a test can read.
        try testing.expect(entry.why.len != 0);
        try testing.expect(entry.landed != null);
    }
}

/// How many single character insertions, deletions and substitutions turn `a`
/// into `b`. **A test helper and nothing else**, so it is written for being
/// read rather than for speed: the whole matrix, over words of at most a few
/// characters.
fn editDistance(a: []const u8, b: []const u8) usize {
    // One row of the matrix, kept as the row above while the next is built.
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
    // The test below is only worth what this is worth, so this is measured
    // rather than assumed.
    try testing.expectEqual(@as(usize, 0), editDistance("run", "run"));
    // A substitution.
    try testing.expectEqual(@as(usize, 1), editDistance("run", "ruv"));
    // A deletion, then an insertion.
    try testing.expectEqual(@as(usize, 1), editDistance("run", "ru"));
    try testing.expectEqual(@as(usize, 1), editDistance("run", "rung"));
    try testing.expectEqual(@as(usize, 3), editDistance("", "run"));
    // Two substitutions and an insertion: `pl` stays, `an` becomes `ug`, and
    // `i` goes in before the `n`.
    try testing.expectEqual(@as(usize, 3), editDistance("plan", "plugin"));
}

test "a person cannot reach the plugin host verb by mistyping a word chock answers to" {
    // **The verb is reachable and it is not discoverable**, and this is the
    // half that says nobody arrives there by accident. A plugin host process
    // takes its capability list off argv and serves a wire on standard output,
    // so a person who meant `chock plan` and got one would see a program that
    // reads nothing and answers nothing.
    //
    // Distance and not a prefix rule, because a prefix rule pins the spelling
    // of the guard rather than the property. Mutation check: rename the verb
    // to `plann`, or to `plan`, and this fails; the comptime block beside
    // `commands` catches only the exact collision.
    for (commands) |entry| {
        try testing.expect(editDistance(entry.name, plugin_host_verb) >= 3);
    }
    for (own_words) |word| {
        try testing.expect(editDistance(word, plugin_host_verb) >= 3);
    }
}

test "the plugin host verb is in no command table and in no usage text" {
    // The other half: a word this program answers to and never offers. It is
    // absent from the table, so `printUsage` cannot list it, and `printUsage`
    // builds its text from that table alone.
    //
    // Mutation check: add an entry named `plugin_host_verb` to `commands` and
    // this fails, as does the comptime block beside the table.
    for (commands) |entry| {
        try testing.expect(!std.mem.eql(u8, entry.name, plugin_host_verb));
    }
    for (own_words) |word| {
        try testing.expect(!std.mem.eql(u8, word, plugin_host_verb));
    }
}

test "the command table names each command exactly once" {
    // Two entries of one name would make the second one unreachable, and the
    // usage text would list a command that can never run.
    for (commands, 0..) |entry, index| {
        for (commands[index + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, entry.name, other.name));
        }
    }
}

test "the three commands this milestone builds are all in the table and all built" {
    // This milestone's own scope, pinned by name. This is what catches a
    // subcommand quietly losing its entry point in a refactor.
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
    // **The split is the shape.** `chock daemon` owns sessions and `chock
    // serve` is a client of it, so that in a hosted world the daemon can be
    // somewhere else and the frontend can sit in front of it. A `chock daemon
    // --web` would have made the two one process, and unpicking that later is
    // the work this split exists to avoid.
    //
    // Mutation check: fold `serve` into `daemon` as an option and this fails.
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
            // Its own entry point in its own file. The two share the control
            // protocol and nothing else.
            try testing.expect(entry.run.? == serve_cmd.main);
            try testing.expect(entry.run.? != daemon_cmd.main);
        }
    }
    try testing.expect(found_daemon);
    try testing.expect(found_serve);
}

test "chock usage is built and says nothing about waiting on anything" {
    // The command that answered "not implemented yet, because the cost record
    // is not built yet" for a whole milestone after the cost record landed.
    // Pinned by name so that losing its entry point is a failure here rather
    // than a sentence a user reads.
    for (commands) |entry| {
        if (!std.mem.eql(u8, entry.name, "usage")) continue;
        try testing.expect(entry.run != null);
        try testing.expectEqualStrings("", entry.why);
        return;
    }
    return error.TestUnexpectedResult;
}

test "an option is not a command name, and this file's own two words still are" {
    // **The rule, and it names no option.** Every option `chock run` takes must
    // work on bare `chock` without being listed here: a second list is how
    // `--verbose` broke, and then `--allow-dirty` broke again when the fix
    // named two options rather than the shape. See `namesNoCommand`.
    //
    // Mutation check: list options by name instead and every option this test
    // does not mention is answered with "there is no command named".
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
        // Not an option `run` takes. It is still not a command name, so it goes
        // to `run`'s parser, which refuses it and says which option it was.
        "--no-such-option",
        "-x",
    }) |first| try testing.expect(namesNoCommand(first));

    // A command is a command.
    for ([_][]const u8{ "run", "sessions", "usage", "plan", "nonesuch", "" }) |first| {
        try testing.expect(!namesNoCommand(first));
    }

    // And the two words this file answers itself open with a dash and are not
    // options. Mutation check: drop the `own_words` loop and `chock --help`
    // opens an interface instead of printing the help.
    for (own_words) |one| try testing.expect(!namesNoCommand(one));
}
