//! `chock sessions`: what this project's sessions were, which of them is
//! running right now, and how to be rid of one.
//!
//! ```
//! chock sessions                        # every session, oldest first
//! chock sessions verify [<session>]
//! chock sessions remove <session>
//! chock sessions prune --older-than <days>
//! ```
//!
//! ## The listing needs no index
//!
//! A session identifier starts with the millisecond it was made, in an alphabet
//! that sorts in the same order as the number, so a directory listing is
//! already oldest first. See `session.zig`'s own `newId`, which says exactly
//! that and gives it as the reason a ULID was chosen over a random UUID. So
//! this command keeps no separate index of sessions, and there is no second
//! record that can disagree with the directory.
//!
//! The same identifier is where the start time comes from, through
//! `session.startedMs`. **Not the file's modification time**, which a copy, a
//! restore, or an append moves, and which says when the log was last written
//! rather than when the session began.
//!
//! ## Which sessions are running comes from the lock, never from a timestamp
//!
//! **A stale directory is the case a timestamp gets wrong and the lock gets
//! right.** A session that was killed leaves a log whose last write was a
//! moment ago and whose process is gone. Any rule over a modification time
//! either calls that session live, and refuses to remove a directory nothing
//! will ever touch again, or calls a session that is quietly thinking dead, and
//! offers to delete a running agent's only record. The lock has neither failure:
//! the kernel drops it when the last descriptor closes, which a killed process
//! does on the way out.
//!
//! ## Removing a session destroys the only account of what an agent did
//!
//! This is why `remove` asks first and `chock cache clear` does not. A
//! toolchain cache is rebuilt by the next build. A kept workspace is announced
//! by `chock workspace` with "take what you want out of them" before anybody
//! clears it. A log is neither: it is the record, nothing else holds a copy,
//! and there is no step that makes it again.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_core = @import("chock-core");
const chock_pcsc = @import("chock-pcsc");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const approval = @import("approval.zig");
const session_paths = @import("session.zig");
const usage_cmd = @import("usage.zig");
const workspace_cmd = @import("workspace.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const chain = chock_proto.chain;
const event = chock_proto.event;
const state = chock_proto.state;
const seal = chock_pcsc.seal;
const sidecar = chock_pcsc.sidecar;

/// What a session log is called: the session identifier, then this. The same
/// name `src/usage.zig` and `src/plan.zig` read, from the layout `session.zig`
/// builds.
const log_suffix = ".jsonl";
/// What a session's workspace scratch is called. The same name
/// `src/workspace.zig` reads.
const work_suffix = ".work";
/// What a session's sandbox root is called.
const root_suffix = ".root";

/// How long the removal question waits for an answer. Long enough to read what
/// is about to go, and short enough that a command nobody is watching ends
/// rather than sitting on a terminal all night. The same reasoning
/// `src/approval.zig`'s own `timeoutMs` gives for its five minutes.
pub const answer_timeout_ms: u64 = 5 * 60 * 1000;

/// A day, in milliseconds. What `--older-than` counts in.
pub const day_ms: u64 = 24 * 60 * 60 * 1000;

const usage_text =
    \\Usage: chock sessions [list|verify [<session>]|seal [<session>]|
    \\                       export [<session>] --to <dir>|remove <session>|prune] [options]
    \\
    \\With no subcommand, says what every session of this project was, oldest first,
    \\and which of them is running now, marked with a * at the start of the row. A
    \\session is running when its log's lock is held, which is the same fact that
    \\decides who owns the session.
    \\
    \\To read one session rather than the list: chock usage show <session> says what
    \\it cost, and chock plan show <session> says what task list it kept.
    \\
    \\verify reads the hash chain each log carries: every event holds the hash of the
    \\line before it, so an event changed after the fact is found and named. A hash
    \\chain is not a signature. Whoever can rewrite the whole file can write a chain
    \\that agrees with it. What it finds is an edit in the middle. verify also reads
    \\the seal beside each log and says which of the three levels made it, or says
    \\there is none. A log with no seal is never reported as passing.
    \\
    \\seal signs the head of a log's chain and writes the signature into a file beside
    \\it, which is what a rewrite of the whole log cannot forge. It changes no log and
    \\takes no log's lock, and it refuses a session that is running now, because that
    \\log's head moves with the next event.
    \\
    \\seal signs with a card key when a card will give one, and with this installation's
    \\software key when no card is there or when Enter is pressed at the PIN prompt. It
    \\writes nothing and ends with a fault when somebody answered the PIN question and
    \\the card did not sign, because that person asked for a card seal and did not get
    \\one. Pass --require-card to refuse every software seal, whatever the reason.
    \\
    \\export copies a log, byte for byte, into a directory a collector reads, and then
    \\verifies the copy. A log that never leaves this machine can still be rewritten
    \\here; one that has left cannot. `chock run --export-dir` does the same thing
    \\line by line as a session runs, which is what an installation should use.
    \\
    \\A session log is the only record of what an agent did, so removing one asks
    \\first. It takes the session's workspace and sandbox root with it.
    \\
    \\An organisation can require this project's logs to be kept, with a rule for
    \\session.remove or session.prune in the org policy bundle. Such a rule refuses a
    \\removal before anything is asked, and --yes does not answer it.
    \\
    \\Options:
    \\  --project <dir>      The project. Defaults to the current directory.
    \\  --to <dir>           For export: where the copies go. Made if it is not there.
    \\  --older-than <days>  For prune: remove sessions that started before this.
    \\  --require-card       For seal: sign on a card or write nothing. Refuses every
    \\                       software seal, including the one a machine with no reader
    \\                       would otherwise write.
    \\  --yes                Do not ask. Only for a caller that has already decided.
    \\  --org-bundle <path>  Read this org policy bundle instead of the one this
    \\                       installation holds.
    \\
++ tty.options_text;

const Options = struct {
    project: ?[]const u8 = null,
    action: Action = .list,
    session: []const u8 = "",
    older_than_days: ?u32 = null,
    yes: bool = false,
    /// The org policy bundle to read instead of the one in the data directory.
    /// **The same option `chock run` takes**, and it means the same thing: read
    /// this file. It is here so an installation can be checked against a bundle
    /// before it is put in place.
    org_bundle: ?[]const u8 = null,
    /// Where `export` writes its copies. Null for every other action.
    to: ?[]const u8 = null,
    /// Whether `seal` may fall back to the software key at all.
    ///
    /// **A card seal or nothing.** A person sealing a public release wants a
    /// command that cannot quietly give them a level 3 artefact, and the honest
    /// fallback the rest of this mechanism is built around is exactly what they
    /// do not want on that run. Off by default, because a machine with no reader
    /// is the ordinary case and a software seal there is recorded and honest.
    require_card: bool = false,
};

/// **`verify` is not a seventh command shape.** There is one shape for the six
/// commands that fold a log, and reading a log's chain is another reading of a
/// log, so it lives inside the command that already lists them.
///
/// **`export` is spelled with `@""` because it is a keyword in Zig**, and the
/// word a person types is what matters: `std.meta.stringToEnum` matches the
/// field's own name either way, and `@tagName` gives back `export`.
const Action = enum {
    list,
    verify,
    /// Sign the head of a log's chain. **A reading of a log and a write beside
    /// it, and never a write into it**: see `lib/chock-pcsc/sidecar.zig`.
    seal,
    @"export",
    remove,
    prune,

    /// Whether this action takes a session name at all. **`verify`, `seal` and
    /// `export` take an optional one**, because doing nothing is the harmless
    /// answer for each: with a name they work on one log, without a name on
    /// every log of the project. `remove` needs one and the rest take none.
    fn takesSession(self: Action) bool {
        return switch (self) {
            .verify, .seal, .@"export", .remove => true,
            .list, .prune => false,
        };
    }
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    // `.environ` is what `Threaded` resolves a bare `argv[0]` against, and the
    // remove path spawns a bare `git`. Left out, a Nix machine finds no `git`
    // at all: the same trap `src/workspace.zig` and `src/run.zig` document.
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
        tty.print(.err, "chock sessions: the session directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    if (options.action == .list) return listSessions(arena, io, dir, project_root);

    // **Before the question about who is at the keyboard**, because neither of
    // these removes anything and a reading nobody asked for is still a reading
    // anybody may have. A script with no terminal can verify a log.
    if (options.action == .verify) {
        if (options.session.len != 0 and !session_paths.isValidId(options.session)) {
            tty.print(
                .err,
                "chock sessions verify: \"{s}\" is not a session identifier\n",
                .{options.session},
            );
            return Exit.usage.code();
        }
        return verifySessions(arena, io, dir, project_root, options.session);
    }

    if (options.action == .seal) {
        if (options.session.len != 0 and !session_paths.isValidId(options.session)) {
            tty.print(
                .err,
                "chock sessions seal: \"{s}\" is not a session identifier\n",
                .{options.session},
            );
            return Exit.usage.code();
        }
        return sealMain(arena, gpa, io, &env, dir, project_root, options.session, options.require_card);
    }

    if (options.action == .@"export") {
        if (options.session.len != 0 and !session_paths.isValidId(options.session)) {
            tty.print(
                .err,
                "chock sessions export: \"{s}\" is not a session identifier\n",
                .{options.session},
            );
            return Exit.usage.code();
        }
        return exportSessions(arena, io, dir, options.session, options.to.?);
    }

    // A name that is not a session identifier is answered before anything asks
    // who is here. **The refusal has to name the real fault**: "run this at a
    // terminal" for a name that could never be removed at a terminal either
    // sends a reader to fix the wrong thing, which is the confusing failure
    // this project pays a turn for every time.
    if (options.action == .remove and !session_paths.isValidId(options.session)) {
        tty.print(
            .err,
            "chock sessions remove: \"{s}\" is not a session identifier\n",
            .{options.session},
        );
        return Exit.usage.code();
    }

    // **Before the question, because this is not a question.** An organisation
    // that requires these logs to be kept has said so already, and asking a
    // person whether to do a thing that is refused would be a prompt whose only
    // honest answer is no. See `retentionRefusal`, and this file's own top
    // comment for why the rule lives in the org bundle.
    const org_rules = loadOrgRules(arena, io, &env, options.org_bundle) orelse
        return Exit.refused.code();
    const action = switch (options.action) {
        .remove => remove_action,
        .prune => prune_action,
        // All four are answered above, before anything asks who is here, and
        // not one of them takes anything away.
        .list, .verify, .seal, .@"export" => unreachable,
    };
    if (try retentionRefusal(arena, org_rules, action)) |why| {
        tty.print(.warn, "chock sessions {s}: {s}\n", .{ @tagName(options.action), why });
        return Exit.refused.code();
    }

    // A removal needs somebody to answer for it. `hasTerminal` reads what
    // standard input really is, which is why this decision is made here, in the
    // one function no test drives, and why the rule itself is `canAsk`.
    if (!canAsk(options.yes, approval.hasTerminal(io))) {
        tty.print(
            .warn,
            "chock sessions: removing a session destroys the only record of what it did, " ++
                "and there is nobody here to ask. Run this at a terminal, or pass --yes.\n",
            .{},
        );
        // The same rule one level up: a question nobody can answer is a
        // refusal, and a refusal is not a crash.
        return Exit.refused.code();
    }

    var stdin = approval.Stdin{};
    const console = stdin.console();

    return switch (options.action) {
        .list, .verify, .seal, .@"export" => unreachable,
        .remove => removeSession(
            arena,
            io,
            &env,
            console,
            !options.yes,
            dir,
            project_root,
            options.session,
        ),
        .prune => pruneSessions(
            arena,
            io,
            &env,
            console,
            !options.yes,
            dir,
            project_root,
            @intCast(@max(0, std.Io.Timestamp.now(io, .real).toMilliseconds())),
            options.older_than_days.?,
        ),
    };
}

/// Whether a removal may go ahead at all.
///
/// **Either there is a person to ask, or the caller has already decided.** A
/// script with no terminal that never said `--yes` gets neither a prompt it
/// cannot answer nor a silent deletion.
pub fn canAsk(assume_yes: bool, at_terminal: bool) bool {
    return assume_yes or at_terminal;
}

/// The action name an org policy bundle writes to keep a session log from being
/// removed one at a time.
pub const remove_action = "session.remove";

/// The action name an org policy bundle writes to keep a whole project's session
/// logs from being pruned.
///
/// **Its own name and not the same one `remove` reads.** An organisation that
/// wants a person to be able to be rid of one session by hand, and never to
/// sweep a directory clean, writes one rule and not the other. A single name
/// would make those two the same decision, and they are not.
pub const prune_action = "session.prune";

/// The agent kind a removal at a terminal is read under.
///
/// **A person is not an agent, and a policy key has four fields whatever asked.**
/// So this is the kind a session a person starts runs under, and a retention
/// rule is written with an `action` alone, which matches every kind. A bundle
/// that does name an `agent_kind` narrows its rule to that one spelling, which
/// is what naming a key field means everywhere else in the policy language.
pub const retention_kind = "main";

/// The name `table.Key.tool` carries for a retention question.
///
/// **No tool asks it**: the thing asking is this command. The same shape
/// `chock_policy.access.tool_name` already takes for a question a session asks
/// before any tool exists, and for the same reason: `table.Key` allows no empty
/// part, and a bundle that wants to write `.tool = "sessions"` on a rule can.
pub const retention_tool = "sessions";

/// The name `table.Key.model` carries for a retention question.
///
/// **No model is involved at all.** A person at a terminal is removing a record,
/// and nothing about whether it may go should turn on which model wrote it. A
/// name rather than an empty string, because `table.Key` allows no empty part,
/// so a rule that names any real model alias never answers a retention question,
/// which is the reading that is wanted.
pub const retention_model = "none";

/// Whether a removal may go ahead under `decision`.
///
/// A switch with no `else`, so a sixth `Decision` fails the build here rather
/// than falling into whichever branch an `else` happened to name.
pub fn retentionAllows(decision: chock_policy.table.Decision) bool {
    return switch (decision) {
        // Nothing named this action, or the organisation said it is allowed.
        // The removal goes on to the question this command already asks.
        .allow => true,
        // A person decides, and that is exactly what this command does next.
        // `--yes` is the caller taking that decision, which is what it means
        // everywhere else in Chock.
        .ask => true,
        .deny => false,
        // A reviewer agent answers first, and there is no agent at a `chock
        // sessions` prompt to answer. **An absent answer is never a permissive
        // answer**, the same rule a policy keeps, so this refuses rather than
        // falling through to the question.
        .agent_review, .agent_then_human => false,
    };
}

/// Why this installation's organisation does not allow `action`, or null when it
/// does. The message is for the person who ran the command.
///
/// **Read as a ceiling and never as a decision**, which is what makes an
/// installation with no bundle, and one whose bundle says nothing about
/// sessions, behave exactly as they did before this existed. See
/// `chock_policy.table.Table.ceilingChain` and `chock_policy.org`'s own top
/// comment for the two defaults and why they differ.
///
/// **A bundle this could not read refuses.** A retention rule nobody could read
/// must never be the same thing as a retention rule nobody wrote.
pub fn retentionRefusal(
    arena: std.mem.Allocator,
    org_rules: []const chock_policy.table.Rule,
    action: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    // An installation with no bundle pays nothing at all: no parse, no table,
    // no allocation.
    if (org_rules.len == 0) return null;

    // **An empty project file on purpose.** The question is what the
    // organisation allows, and a rule in a file inside the project could only
    // narrow the answer further, which is not the control this is. The bundle is
    // the whole of it, folded through the one function that already decides
    // which rule wins, so there is no second answer to that here.
    const table = chock_policy.table.Table.parseUnder(arena, ".{}", org_rules, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // `".{}"` is a literal of this file and holds no policy block, so every
        // other way `parseUnder` refuses a file is about bytes that are not
        // here. Refusing is still the safe direction.
        else => return "the organisation's policy could not be read, so nothing was removed",
    };

    const decision = table.ceilingChain(&.{retention_kind}, .{
        .agent_kind = retention_kind,
        .model = retention_model,
        .tool = retention_tool,
        .action = action,
    }, null);
    if (retentionAllows(decision)) return null;

    return try std.fmt.allocPrint(
        arena,
        "this installation's organisation requires session logs to be kept: its policy answers " ++
            "{s} for {s}. Nothing was removed, and --yes does not answer this. A session log is " ++
            "the only record of what an agent did, and the organisation that issued this " ++
            "installation's policy says it stays.",
        .{ @tagName(decision), action },
    );
}

/// The rules this installation's organisation gave it, or an empty list when it
/// was given none.
///
/// Null when a bundle is there and could not be read, which is already reported
/// by the time this returns. **Not the same as an empty list**: a bundle nobody
/// can read may be the very bundle that requires retention.
fn loadOrgRules(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    given: ?[]const u8,
) ?[]const chock_policy.table.Rule {
    const path = if (given) |named|
        named
    else path: {
        const data_dir = chock_auth.paths.dataDir(arena, env) catch |err| {
            tty.print(
                .err,
                "chock sessions: the data directory is unknown ({s}), so this cannot tell whether " ++
                    "an organisation requires these logs to be kept\n",
                .{@errorName(err)},
            );
            return null;
        };
        break :path std.fs.path.join(arena, &.{ data_dir, chock_policy.org.file_name }) catch return null;
    };

    var diag: ?chock_policy.org.Diagnostic = null;
    const bundle = chock_policy.org.load(arena, io, path, &diag) catch |err| switch (err) {
        // The ordinary installation has no bundle, and that is never a fault.
        error.NoBundleFile => {
            // A path the caller named and that is not there is a different fact:
            // they asked for that file.
            if (given == null) return &.{};
            tty.print(.err, "chock sessions: there is no org policy bundle at {s}\n", .{path});
            return null;
        },
        else => {
            if (diag) |*one| {
                tty.print(.err, "chock sessions: {f}\n", .{one});
            } else {
                tty.print(.err, "chock sessions: the org policy bundle could not be read: {s}\n", .{@errorName(err)});
            }
            return null;
        },
    };
    // **An expired bundle keeps binding, in full.** `chock_policy.org` decides
    // that once, for the whole program, and the reason is that a bundle can only
    // narrow: dropping an expired one can only widen, at the moment nobody can
    // be reached to say whether that is right. So nothing here reads the date.
    return bundle.rules;
}

/// Whether a session is running.
pub const Liveness = enum {
    /// Another process holds this log's lock, so it owns this session and the
    /// session is running.
    live,
    /// Nobody holds the lock. The session has ended, cleanly or otherwise.
    idle,
    /// The lock could not be tested at all. **Never read as `idle`**: an absent
    /// answer is never a permissive answer, which is the same rule a policy
    /// keeps, so nothing removes a session in this state.
    unknown,
};

/// Whether the session whose log is at `log_path` is running.
///
/// **The lock is tested by taking it and giving it straight back, and the probe
/// asks for a shared lock.** `flock(2)`, which is what `std.Io.File.tryLock`
/// reaches on every target Chock runs on, locks an open file description rather
/// than a path or a process, so the descriptor opened here contends with a real
/// session's own descriptor exactly as a second `chock run` would, and the
/// release below gives back only what this call took. **A live session's lock is
/// never touched**: the kernel holds it against that session's own descriptor,
/// and nothing here can reach it.
///
/// Shared and not exclusive for one measured reason: two people running
/// `chock sessions` at the same moment would each hold an exclusive probe
/// against the other, and each would report the other's probe as a live
/// session. Two shared probes do not contend, so the answer does not depend on
/// who else is looking. A held exclusive lock refuses a shared request just the
/// same, so a running session is still found.
///
/// The one window left is a session **taking** its lock during the moment a
/// probe holds one, which reaches `chock run` as `error.Busy`. It is two
/// syscalls wide, and the alternative, a rule over a timestamp, is wrong for
/// every session that was killed: see this file's own top comment.
///
/// The file is opened read only, so this works for a log the caller may not
/// write, and `flock` places a lock on a read only description happily where a
/// `fcntl` write lock would not.
pub fn livenessOf(io: std.Io, log_path: [:0]const u8) Liveness {
    var one = probe(io, log_path) orelse return .unknown;
    defer one.release(io);
    return if (one.acquired) .idle else .live;
}

/// The lock a probe asks for. **Shared, and the choice is load bearing**: see
/// `livenessOf` for why two probes must not contend, and the test that holds
/// two at once for what changing this to `.exclusive` breaks.
const probe_lock: std.Io.File.Lock = .shared;

/// One test of a log's lock, with the descriptor that made it still open.
///
/// Its own type, rather than the whole of `livenessOf` in one function, so that
/// a test can hold two probes at the same moment. That is the only way to pin
/// the reason `probe_lock` is shared, and a single probe cannot show it.
const Probe = struct {
    file: std.Io.File,
    /// False when somebody else already held the lock, which is a running
    /// session.
    acquired: bool,

    /// Give back exactly what this probe took, and nothing else. The close
    /// alone would do it, since the kernel drops a description's locks when its
    /// last descriptor goes, and the unlock is written out so the release does
    /// not depend on that.
    fn release(self: *Probe, io: std.Io) void {
        if (self.acquired) self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

/// Open `log_path` and test its lock. Null when the file could not be opened or
/// the lock could not be tested at all.
fn probe(io: std.Io, log_path: [:0]const u8) ?Probe {
    const flags: std.posix.O = .{ .ACCMODE = .RDONLY };
    const fd = std.posix.openatZ(std.posix.AT.FDCWD, log_path, flags, 0) catch return null;
    var file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    const acquired = file.tryLock(io, probe_lock) catch {
        file.close(io);
        return null;
    };
    return .{ .file = file, .acquired = acquired };
}

/// Whether a session can be taken over by another process, and what is wrong
/// when it cannot.
///
/// **One reading, three voices.** `chock detach`, `chock daemon`'s own `adopt`,
/// and `chock run --adopt` all ask this question and each says the answer in its
/// own words. A second copy of the reading is how two commands quietly start
/// disagreeing about which sessions may change hands.
pub const Readiness = enum {
    /// Nobody owns it and it holds a conversation. It can change hands.
    ready,
    /// There is no log at that path. A client named an identifier this machine
    /// never wrote, and **nothing may make one under it**: see `readinessOf`.
    no_such_session,
    /// The log is there and holds no event at all, so there is no conversation
    /// to carry on from.
    nothing_to_carry_on,
    /// Somebody holds the log's exclusive lock, so that process owns the
    /// session and is still using it.
    running,
    /// The log could not be read, or its lock could not be tested. **Never read
    /// as `ready`**: an absent answer is never a permissive answer.
    unknown,
};

/// Ask whether the session whose log is at `log_path` can change hands.
///
/// **This is not what stops two owners, and it must not be read as though it
/// were.** `flock(2)` is: the second process to ask for the exclusive lock is
/// refused by the kernel, and `chock_proto.log.Log.lock` turns that refusal into
/// `error.Busy` at once rather than blocking. What this buys is a sentence a
/// person can read, in place of that error arriving from inside a session that
/// has already built a workspace. A session that takes its own lock in the
/// window between this answer and the new owner's `lock` call still wins, and
/// the loser is told so.
///
/// **It opens the log through `Log.open` and never creates one.** `statFile`
/// runs first for exactly that reason: `Log.open` makes the file when it is
/// missing, so an identifier somebody mistyped would otherwise become a brand
/// new empty session that then reports itself adoptable.
///
/// The replay is what says whether there is a conversation, and not the file's
/// own size. A replay is what `chock_core.Loop.run` folds at its start, so this
/// asks the same question the new owner will ask; a size rule would be a second
/// reading that a grown header could make disagree with the first.
pub fn readinessOf(
    gpa: std.mem.Allocator,
    io: std.Io,
    log_path: [:0]const u8,
    id: []const u8,
) Readiness {
    std.debug.assert(session_paths.isValidId(id));

    _ = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch return .no_such_session;

    const opened = chock_proto.log.Log.open(io, log_path, id) catch return .unknown;
    var backing = chock_proto.storage.JsonLines{ .log = opened };
    const store = backing.storage();
    defer store.close(io);

    var replay = store.replay(gpa, io, 0) catch return .unknown;
    defer replay.deinit();
    const first = replay.next(io) catch return .unknown;
    if (first) |parsed| parsed.deinit() else return .nothing_to_carry_on;

    // Last, because it is the only answer that can change a moment later, and
    // reporting the oldest fault first is what makes the message useful.
    return switch (livenessOf(io, log_path)) {
        .idle => .ready,
        .live => .running,
        .unknown => .unknown,
    };
}

/// One session, folded from its own log.
pub const Session = struct {
    /// The session identifier, which is the log's own name without its suffix.
    id: []const u8,
    /// When the session started, from the timestamp the identifier carries.
    /// See `session.startedMs`.
    started_ms: u64,
    /// The first model a `usage` event named. Empty when no turn named one,
    /// which is what a session that never got a reply looks like.
    model: []const u8 = "",
    /// How many models this session used. `chock usage show <session>` is what
    /// breaks a session that used more than one down model by model.
    model_count: usize = 0,
    /// What the agent called this session, or empty for one it never named.
    ///
    /// **The last title wins.** A log cannot edit a title in place, so an agent
    /// that learns halfway through what the work really is writes a second
    /// `session.title` event, and this fold takes the later one. See
    /// `chock_proto.event.SessionTitle`.
    ///
    /// **Model written text, and never printed raw.** `titleText` is what turns
    /// one of these into bytes a terminal may see.
    title: []const u8 = "",
    /// The alias `session_start` named, which is what the caller asked for
    /// rather than what the provider answered with. Empty when the log holds no
    /// start event.
    model_alias: []const u8 = "",
    /// Why the session ended, from the last `session_end` event. Null when the
    /// log holds none, which is a session that is running now or one that was
    /// killed.
    end: ?event.SessionEndReason = null,
    spend: state.Spend = .{},
    live: Liveness = .unknown,
    /// **False when the log could not be opened or replayed at all**: a header
    /// no build of Chock wrote, or a file nothing can read. Such a session is
    /// still listed, with what its name alone says. A listing that dropped it
    /// would leave a directory on disk that no command admits to.
    readable: bool = true,
    /// False when the log could not be read all the way to its end: a torn tail
    /// from a crash mid write, or a line that would not decode. The numbers are
    /// then a floor and not a total.
    complete: bool = true,
    /// What the log's hash chain said, read in the same pass as everything
    /// else on this row.
    ///
    /// **This is what tells "somebody edited this" apart from "the power went
    /// out".** Both used to arrive here as `complete = false`, and a listing
    /// that says only "the log ends mid write" for a file somebody rewrote is
    /// a listing that hides the one fact worth acting on. See
    /// `lib/chock-proto/chain.zig` for the verdicts, and for an honest account
    /// of what a chain does not defeat.
    ///
    /// A session whose log could not be opened keeps the default,
    /// `unreadable`, which is never a pass.
    chain: chain.Report = .{},
    /// What the seal beside this log said, read in the same pass.
    ///
    /// **The default is `absent`, which is never a pass.** Every log written
    /// before there were seals, and every log nobody has sealed, carries this.
    /// A reader must not be able to take the quiet answer for a signature, so
    /// `verify` prints it on every row. See `lib/chock-pcsc/sidecar.zig`.
    seal: seal.Reading = .{},
    /// The digest of this log's header line and of its last line. The second is
    /// the head of the chain, which is what a seal signs.
    ///
    /// **Only meaningful when `readable`.** A log nothing could open keeps the
    /// filler below, which is not a digest of anything: it is 64 characters so
    /// that a caller which prints it cannot go out of bounds, and `readable` is
    /// what says whether to believe it.
    header_digest: chain.Digest = [_]u8{'?'} ** chain.digest_len,
    head_digest: chain.Digest = [_]u8{'?'} ** chain.digest_len,
    /// Whether the session's `.work` directory still holds anything.
    ///
    /// **Not whether the directory is there.** Almost every session leaves an
    /// empty `.work` behind, so a marker that reads existence alone is true on
    /// every row and tells a reader nothing. Measured on a real state
    /// directory: 27 directories, 3 workspaces. `removalPlan` keeps the wider
    /// question, because an empty directory is still a directory to delete.
    has_work: bool = false,
    /// Whether the session's `.root` directory still holds anything. Same rule
    /// as `has_work`.
    has_root: bool = false,
};

/// Whether `dir_path` is a directory with at least one entry in it.
///
/// **A missing directory and an empty one give the same answer**, because a
/// reader of the listing wants to know what is still held, and neither holds
/// anything. The two are told apart by `removalPlan`, which has to delete the
/// empty one.
fn holdsAnything(io: std.Io, dir_path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return false;
    defer dir.close(io);
    var it = dir.iterateAssumeFirstIteration();
    const first = it.next(io) catch return false;
    return first != null;
}

/// Where one session's log is, inside a project's session directory.
///
/// **Here because this file owns the suffix.** `fold` and `list` build the same
/// path from the same constant, and a caller that spelled `.jsonl` itself would
/// be a second copy of a name only this file should know.
pub fn logPathIn(
    allocator: std.mem.Allocator,
    dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error![:0]u8 {
    std.debug.assert(session_paths.isValidId(id));
    return std.fmt.allocPrintSentinel(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
}

/// Fold one session's log. Null when this project has no session of that
/// identifier.
///
/// **A log this cannot read answers a `Session` and not null.** That is the one
/// place this fold differs from `src/usage.zig`'s, and it is deliberate: a
/// command that manages sessions has to name the session whose log is broken,
/// because that is the session somebody wants to remove.
///
/// **The file is checked before the log is opened**, the same rule
/// `src/usage.zig` and `src/plan.zig` keep and for the same reason:
/// `chock_proto.log.Log.open` creates the file it is given when there is none,
/// so asking about a session that never existed would otherwise bring one into
/// being and then report on it.
pub fn fold(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!?Session {
    std.debug.assert(session_paths.isValidId(id));
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;

    const work = try std.fmt.allocPrint(allocator, "{s}/{s}" ++ work_suffix, .{ dir, id });
    const root = try std.fmt.allocPrint(allocator, "{s}/{s}" ++ root_suffix, .{ dir, id });

    var one = Session{
        .id = try allocator.dupe(u8, id),
        .started_ms = session_paths.startedMs(id),
        // Read before the log is opened, because opening it in this process
        // would make the answer "the lock is free" whatever anybody else holds.
        .live = livenessOf(io, path),
        .has_work = holdsAnything(io, work),
        .has_root = holdsAnything(io, root),
    };

    const log = chock_proto.log.Log.open(io, path, id) catch {
        one.readable = false;
        one.complete = false;
        return one;
    };
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    // The chain is read in this same pass, not in a second one. A listing over
    // a project with many sessions reads every log once, and verifying is a
    // hash of the bytes it is already walking.
    one.header_digest = store.headerDigest(io) catch {
        one.readable = false;
        one.complete = false;
        return one;
    };
    var reader = chain.Verifier.init(one.header_digest);

    var replay = store.replay(allocator, io, 0) catch {
        one.readable = false;
        one.complete = false;
        return one;
    };
    defer replay.deinit();

    var models: std.ArrayList([]const u8) = .empty;
    defer models.deinit(allocator);

    while (true) {
        // Read before the call. See `chock_proto.storage.Replay.at`: only the
        // value from beforehand names the line a failed or torn read stopped
        // on.
        const line_start = replay.at();
        const parsed = replay.next(io) catch {
            // A line that will not decode stops the fold here. Everything
            // before it is real, and `complete` is what stops a reader taking a
            // floor for a total.
            one.complete = false;
            one.chain = reader.finish(.undecodable, line_start);
            break;
        } orelse {
            // A torn tail is a crash mid write, not a clean end of log, and an
            // event may have gone with it.
            const torn = replay.truncated();
            if (torn) one.complete = false;
            one.chain = reader.finish(if (torn) .torn else .complete, line_start);
            break;
        };
        defer parsed.deinit();
        reader.take(parsed.value.id, replay.line(), parsed.value.prev);

        // Every string kept below is copied into `allocator` first: the
        // envelope it came from is released at the end of this loop body.
        switch (parsed.value.event) {
            .session_start => |start| {
                if (one.model_alias.len == 0 and start.model_alias.len != 0) {
                    one.model_alias = try allocator.dupe(u8, start.model_alias);
                }
            },
            // The last end wins. A session that ended, was resumed, and ended
            // again is at the reason it ended with last.
            .session_end => |ended| one.end = try dupeReason(allocator, ended.reason),
            // The last name wins, for the reason the last end does: a rename is
            // a second event, because the log cannot write over the first.
            .session_title => |named| one.title = try allocator.dupe(u8, named.title),
            .usage => |turn| {
                var counted = turn;
                if (counted.cost == .known) counted.cost = .{ .known = .{
                    .value = counted.cost.known.value,
                    .currency = try allocator.dupe(u8, counted.cost.known.currency),
                } };
                one.spend.add(counted);

                if (turn.model.len == 0) continue;
                if (!contains(models.items, turn.model)) {
                    const name = try allocator.dupe(u8, turn.model);
                    try models.append(allocator, name);
                    if (one.model.len == 0) one.model = name;
                }
            },
            else => {},
        }
    }

    one.model_count = models.items.len;
    // The head of the chain is the digest of the last whole line the reader
    // took, which is what `chain.Verifier` is already carrying: it is the value
    // the next event's `prev` would have to hold. A log with no event at all
    // leaves the header's own digest here, which is the same rule
    // `log.lastLineDigest` keeps.
    one.head_digest = reader.expected;
    one.seal = readSeal(allocator, io, path, one);
    return one;
}

/// Read the seal beside a log and check it against the log itself.
///
/// **Every value it is checked against comes from the pass just finished**, not
/// from the record: the header digest, the head, and the count of events. A
/// reader that took any of them out of the seal would be asking a record
/// whether it agrees with itself.
///
/// Needs no card, no daemon and no credential store. See `lib/chock-pcsc.zig`.
fn readSeal(
    allocator: std.mem.Allocator,
    io: std.Io,
    log_path: []const u8,
    one: Session,
) seal.Reading {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = sidecar.pathFor(&path_buffer, log_path) catch return .{ .verdict = .absent };

    // On the stack, and it may be: a `Reading` holds no pointer into either of
    // these, so neither has to outlive this call.
    var certs = seal.ReadBuffer{};
    const found = sidecar.read(allocator, io, path, &certs);
    return switch (found) {
        .absent => .{ .verdict = .absent },
        .malformed => .{ .verdict = .malformed },
        .seal => |written| seal.read(written, .{
            .session = one.id,
            .header = &one.header_digest,
            .head = &one.head_digest,
            .events = one.chain.events,
        }, .{
            // **No attestation root, so no seal is ever read as hardware
            // backed here.** Chock ships no vendor certificate authority, and
            // taking one on trust because a record carried it would make the
            // strongest of the three levels the easiest to claim. A seal that
            // claims an attestation therefore reads as `claim_unsupported`
            // until an installation says which root it trusts.
            .root = null,
            // Passed in and never read from a clock inside the library. Zero
            // because there is no root to measure a validity window against.
            .now_sec = 0,
        }),
    };
}

fn contains(names: []const []const u8, name: []const u8) bool {
    for (names) |seen| {
        if (std.mem.eql(u8, seen, name)) return true;
    }
    return false;
}

/// A reason whose own strings belong to `allocator`. Only `unknown` carries
/// one: every other member is a tag, and its `wireName` is a comptime string
/// that outlives any replay.
fn dupeReason(
    allocator: std.mem.Allocator,
    reason: event.SessionEndReason,
) std.mem.Allocator.Error!event.SessionEndReason {
    return switch (reason) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => reason,
    };
}

/// Every session of `dir`, oldest first. Caller owns the slice and everything
/// in it, which for a real caller is an arena.
///
/// **Oldest first with no index**, because a session identifier starts with its
/// own timestamp: see this file's own top comment and `session.zig`'s `newId`.
///
/// A session directory that cannot be read at all answers an empty list. A
/// project that never ran a session has no such directory, and that is an
/// ordinary state rather than a fault.
pub fn list(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
) std.mem.Allocator.Error![]Session {
    var handle = std.Io.Dir.openDirAbsolute(io, dir, .{ .iterate = true }) catch return &.{};
    defer handle.close(io);

    var found: std.ArrayList(Session) = .empty;
    var walker = handle.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, log_suffix)) continue;
        const stem = entry.name[0 .. entry.name.len - log_suffix.len];
        // A name this build did not write is never turned into a path: the same
        // rule `session.zig` keeps, and the reason `isValidId` exists.
        if (!session_paths.isValidId(stem)) continue;

        const one = try fold(allocator, io, dir, stem) orelse continue;
        try found.append(allocator, one);
    }

    const sessions = try found.toOwnedSlice(allocator);
    std.mem.sort(Session, sessions, {}, olderFirst);
    return sessions;
}

fn olderFirst(_: void, a: Session, b: Session) bool {
    return std.mem.order(u8, a.id, b.id) == .lt;
}

/// The longest string `timeText` writes, with room for a year past this one.
pub const time_text_bytes: usize = 32;

/// The first millisecond this refuses to print a date for. A `startedMs` past
/// this came out of an identifier no `newId` wrote, and walking a year at a
/// time to reach it would cost more than the answer is worth.
const year_10000_ms: u64 = 253402300800000;

/// When a session started, in UTC, as a person reads it.
///
/// **UTC and never the machine's own zone.** `src/clock.zig` states the split:
/// whether somebody is awake is a local question, and lining a session up with
/// a log is a UTC one. This is the second, and a listing whose times moved with
/// the reader's zone could not be compared against a log at all.
pub fn timeText(buffer: *[time_text_bytes]u8, started_ms: u64) []const u8 {
    if (started_ms >= year_10000_ms) return "a time no session was started at";

    const seconds = std.time.epoch.EpochSeconds{ .secs = started_ms / 1000 };
    const year_day = seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day = seconds.getDaySeconds();

    return std.fmt.bufPrint(buffer, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2} UTC", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u32, month_day.day_index) + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
    }) catch "a time no session was started at";
}

/// What every line of a title is written after.
///
/// **This is the boundary between the agent's words and Chock's**, and it is the
/// same defence `chock_core.ask.question_marker` puts in front of a question.
/// Every fact this command states itself starts at column zero or column two: a
/// session row starts with the running marker and then the identifier, and every
/// sentence about a project or a log starts with "chock sessions:". A title is
/// written by a model, so it goes on a line of its own, behind this, and no byte
/// the model chose can reach either of those columns. A title that read
/// `01M0TMATKB6M4H3GY35KYA68QR  2026-08-24 19:35 UTC  finished` cannot be made to
/// look like a row of the table it sits in.
pub const title_marker = "      | ";

/// The line the listing prints once, above the rows, when any session has a
/// title. **It says whose words the indented lines are**, which the gutter alone
/// cannot: a reader who did not know would take a title for a fact Chock states.
///
/// Printed only when there is something to explain, so a project whose sessions
/// have no titles reads exactly as it did before titles existed.
pub const title_legend = "The indented line under a session is the title the agent gave it, in " ++
    "the agent's own words.";

/// What is printed in place of a title that is not text at all.
pub const title_not_text = "(a title that is not text)";

/// One title, as a person reads it, or null for a session that has none. Caller
/// owns the result.
///
/// **A log is a file on disk, so nothing here trusts what is in it.**
/// `chock_core.Loop.titleRefusalText` already refuses a title that is not one
/// short line of plain text, so no log this build wrote holds one. That is not
/// the same as no log holding one: another build can write a log, and a person
/// with an editor can write anything at all. So this filters again.
///
/// Three things are done, and each one stops a different fault:
///
/// * **Every byte a terminal reads as an instruction becomes a question mark.**
///   A cursor move can repaint a row above it and a carriage return can write
///   over the gutter that says whose words these are. The same defence
///   `chock_core.ask.writeFiltered` gives a question, and it takes the line
///   break with it here, because a title is one line and a line break would put
///   the agent's own words at column zero.
/// * **Bytes that are not valid UTF-8 are not printed at all.** There is nothing
///   to read in them and a terminal makes its own mind up about what they are.
/// * **A title past the bound is cut on a character boundary and marked.** The
///   writer refuses a long one rather than cutting it, because it can ask the
///   model for a shorter one. A reader has no such option: the bytes are already
///   in the log.
///
/// **This is not the whole of the problem**, and it is the same honest limit
/// `chock_core.ask.writeFiltered` writes down: text can still mislead a reader
/// with the characters that reverse a line's direction, and with a word that
/// reads like another word.
pub fn titleText(
    allocator: std.mem.Allocator,
    raw: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    if (raw.len == 0) return null;
    if (!std.unicode.utf8ValidateSlice(raw)) return try allocator.dupe(u8, title_not_text);

    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(allocator);
    for (raw) |byte| {
        // Only ASCII control characters are checked byte by byte, which is safe
        // over UTF-8: every byte of a multi byte character is 0x80 or above, so
        // none of them can be mistaken for one.
        const drives_the_terminal = byte < 0x20 or byte == 0x7F;
        try kept.append(allocator, if (drives_the_terminal) '?' else byte);
    }

    const cut = chock_core.notices.cutToCharacter(kept.items, chock_core.Loop.max_title_bytes);
    if (cut.len == kept.items.len) return try allocator.dupe(u8, cut);
    return try std.fmt.allocPrint(allocator, "{s} (the rest of this title is not shown)", .{cut});
}

/// What state a session is in, in one word a person reads.
///
/// **The lock decides first.** A session whose lock is held is running,
/// whatever its log last said, because the lock is a fact about right now and
/// the log is a record of the past.
///
/// A session with no end event and no lock is the killed case: nothing wrote a
/// reason, and nothing ever will. It says so rather than guessing one.
pub fn stateText(one: Session) []const u8 {
    if (one.live == .live) return "running";
    if (one.end) |reason| return reason.wireName();
    if (one.live == .unknown) return "no end recorded, lock not tested";
    return "no end recorded";
}

/// What model a session ran on, as a person reads it. Caller owns the result.
///
/// **An alias is never printed as if it were a model.** `main` is the name of a
/// slot in `chock.zon`, and a reader who took it for a model name would be
/// reading a fact this command does not have.
pub fn modelText(
    allocator: std.mem.Allocator,
    one: Session,
) std.mem.Allocator.Error![]u8 {
    if (one.model.len != 0) {
        if (one.model_count > 1) {
            return std.fmt.allocPrint(
                allocator,
                "{s} and {d} more",
                .{ one.model, one.model_count - 1 },
            );
        }
        return allocator.dupe(u8, one.model);
    }
    if (one.model_alias.len != 0) {
        return std.fmt.allocPrint(allocator, "the {s} alias, unanswered", .{one.model_alias});
    }
    return allocator.dupe(u8, "no model recorded");
}

fn turnWord(count: u64) []const u8 {
    return if (count == 1) "turn" else "turns";
}

fn eventWord(count: u64) []const u8 {
    return if (count == 1) "event" else "events";
}

/// What a chain reading says, in full, as a person reads it. Caller owns the
/// result.
///
/// **"Somebody edited this" and "the power went out" never share a sentence.**
/// That is the whole reason they are separate verdicts: a reader does
/// different things about them. One is a crash to recover from and the other
/// is a person to find, so neither may be softened into the other's words.
///
/// **Nothing here calls an unchained log good.** A log from before the chain
/// existed can say nothing about whether it was edited, and a sentence that
/// left that out would read as a pass.
pub fn chainText(
    allocator: std.mem.Allocator,
    report: chain.Report,
) std.mem.Allocator.Error![]u8 {
    return switch (report.verdict) {
        // A log with no event in it is intact by default, and saying "the
        // chain holds over all 0 events" for one reads as a claim where there
        // is none. A session that never got past `chock run` starting leaves
        // exactly this, so it is a common row and not a corner.
        .intact => if (report.events == 0)
            allocator.dupe(u8, "this log holds no event at all, so there was nothing to check")
        else
            std.fmt.allocPrint(
                allocator,
                "the chain holds over all {d} {s}",
                .{ report.events, eventWord(report.events) },
            ),
        .partly_chained => std.fmt.allocPrint(
            allocator,
            "the chain holds over {d} of {d} events; the first {d} were written before the chain existed",
            .{ report.chained, report.events, report.events - report.chained },
        ),
        .unchained => if (report.events == 1)
            allocator.dupe(
                u8,
                "no chain at all: the one event in this log was written before the chain " ++
                    "existed, so nothing can say whether this log was edited",
            )
        else
            std.fmt.allocPrint(
                allocator,
                "no chain at all: all {d} events were written before the chain existed, " ++
                    "so nothing can say whether this log was edited",
                .{report.events},
            ),
        .broken => std.fmt.allocPrint(
            allocator,
            "this log was changed after it was written: event {d} carries the hash of bytes " ++
                "that are no longer in front of it, so the change is between event {d} and event {d}",
            .{ report.at, report.after, report.at },
        ),
        .torn => std.fmt.allocPrint(
            allocator,
            "the last line is unfinished, which is a crash or a power loss and not an edit; " ++
                "the chain holds over the {d} {s} before it, at byte {d}",
            .{ report.events, eventWord(report.events), report.at },
        ),
        .undecodable => std.fmt.allocPrint(
            allocator,
            "a whole line at byte {d} will not decode; the chain holds over the {d} {s} before it",
            .{ report.at, report.events, eventWord(report.events) },
        ),
        .unreadable => allocator.dupe(u8, "this log could not be read at all, so nothing was checked"),
    };
}

/// What one row says about the seal beside a log. Caller owns the result.
///
/// **Every reading gets a line, including `absent`.** A row that said nothing
/// for an unsealed log would let a reader take the quiet answer for a
/// signature, which is the one mistake this whole mechanism exists to stop.
///
/// **The level is a number out of three, the direction of the scale, and a
/// name.** A reader who has seen one of these rows can rank the next one
/// without learning a vocabulary, and the numbers are the wire values
/// `seal.Level` pins, so the row and the record cannot drift apart. See
/// `levelRank` for why the direction is written out.
pub fn sealText(
    allocator: std.mem.Allocator,
    reading: seal.Reading,
) std.mem.Allocator.Error![]u8 {
    return switch (reading.verdict) {
        .absent => allocator.dupe(
            u8,
            "no seal: nothing has signed this log, so a rewrite of the whole file is not defeated",
        ),
        .malformed => allocator.dupe(
            u8,
            "a seal that could not be read at all, so nothing was checked; read this log as unsealed",
        ),
        .signature_bad => allocator.dupe(
            u8,
            "the seal does not check out against the key it carries: somebody changed it, " ++
                "or that key never signed this",
        ),
        .head_mismatch => std.fmt.allocPrint(
            allocator,
            "the seal checks out and it is about a different log: the {s} does not match. " ++
                "A chain repaired by hand looks exactly like this",
            .{@tagName(reading.mismatched orelse .head)},
        ),
        // **The scheme is named as well as the level.** Two seals at the same
        // level can be made by different kinds of key, and a person looking at a
        // row has to be able to tell this installation's own elliptic curve key
        // from the RSA key on a card. It is derived from the key inside the
        // signed bytes, so it is worth exactly what the signature is.
        .signed_software, .signed_card, .signed_card_attested => std.fmt.allocPrint(
            allocator,
            "sealed with an {s} key, {s}: {s}",
            .{
                (reading.scheme orelse seal.Scheme.ecdsa_p256).text(),
                levelRank(reading.claimed),
                levelText(reading.claimed),
            },
        ),
        .claim_unsupported => std.fmt.allocPrint(
            allocator,
            "the seal claims a key made on a card and shows nothing that supports it ({s}); " ++
                "read this log as unsealed",
            .{@tagName(reading.attestation)},
        ),
    };
}

/// The level as a number, with the direction of the scale said out loud.
///
/// **"level 3 of 3" alone reads as the top of a scale**, the way three stars out
/// of three does, and level 3 is the weakest of the three. The number is the
/// wire value `seal.Level` pins and it cannot be turned round, so the words say
/// which end is which. A number a reader can rank the wrong way is worse than
/// no number, because the mistake it invites is to trust a software key more
/// than a card one.
///
/// **Each level names its own rank, and no line states the rule.** "level 3 of
/// 3, and level 1 is the strongest" made a reader hold two numbers and work out
/// which one their level was, and on a first pass it reads as a contradiction.
/// The word beside the number says the answer instead.
fn levelRank(level: ?seal.Level) []const u8 {
    return switch (level orelse .software) {
        .card_attested => "level 1 of 3, the strongest of the three",
        .card => "level 2 of 3, the middle of the three",
        .software => "level 3 of 3, the weakest of the three",
    };
}

/// What a recorded level is, in words. **Each one says what it proves and what
/// it does not**, because "a card key" alone reads as proof of hardware and
/// only an attestation is that.
fn levelText(level: ?seal.Level) []const u8 {
    return switch (level orelse .software) {
        .card_attested => "a card key, with an attestation saying it was made there and never left",
        .card => "a card key, with no attestation, so nothing here can check that claim",
        .software => "a software key, which proves one key signed and nothing about where it lives",
    };
}

/// The short note a listing row carries for a log whose chain says something,
/// or null for one that says nothing a row needs. Caller owns the result.
pub fn chainNote(
    allocator: std.mem.Allocator,
    report: chain.Report,
) std.mem.Allocator.Error!?[]u8 {
    return switch (report.verdict) {
        .broken => try std.fmt.allocPrint(
            allocator,
            "  (this log was edited: the chain breaks between event {d} and event {d})",
            .{ report.after, report.at },
        ),
        .torn => try allocator.dupe(u8, "  (the log ends mid write)"),
        .undecodable => try std.fmt.allocPrint(
            allocator,
            "  (a whole line at byte {d} will not decode)",
            .{report.at},
        ),
        // An intact chain, an old log with none, and a log nothing could open
        // all say nothing extra here. The last already has its own note, and
        // a marker on every old log would be a column that says nothing.
        .intact, .partly_chained, .unchained, .unreadable => null,
    };
}

fn listSessions(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    project_root: []const u8,
) !u8 {
    const sessions = try list(arena, io, dir);
    if (sessions.len == 0) {
        tty.print(.plain, "chock sessions: this project has no sessions ({s})\n", .{dir});
        return Exit.finished.code();
    }

    // **Both paths are `--verbose` lines.** A person who typed the command in a
    // directory knows which directory it was, and where the logs are kept
    // answers no question this command was asked. Two lines at the head of
    // every run of every command is the largest cost there is, because it is
    // paid on every invocation of everything.
    tty.detail("{s}\n{s}\n\n", .{ project_root, dir });

    // **Once, above the rows, and only when there is something to explain.** A
    // gutter keeps the agent's words off the columns Chock's own words start
    // at, and it cannot say whose words they are. This does. A project whose
    // sessions were never named prints nothing extra at all.
    for (sessions) |one| {
        if (one.title.len == 0) continue;
        tty.out(.plain, "{s}\n\n", .{title_legend});
        break;
    }

    var live_count: usize = 0;
    var with_work: usize = 0;
    var edited_count: usize = 0;
    for (sessions) |one| {
        if (one.live == .live) live_count += 1;
        if (one.has_work) with_work += 1;

        var time_buffer: [time_text_bytes]u8 = undefined;
        tty.out(.plain, "{s} {s}  {s}  {s: <20}  {d:>4} {s}  {s}  {s}", .{
            // A running session is marked where the eye lands first, because it
            // is the one fact on the line that changes what a reader may do.
            if (one.live == .live) "*" else " ",
            one.id,
            timeText(&time_buffer, one.started_ms),
            stateText(one),
            one.spend.turns,
            turnWord(one.spend.turns),
            try modelText(arena, one),
            try usage_cmd.costText(arena, one.spend),
        });
        if (one.has_work) tty.out(.plain, "  (holds a workspace)", .{});
        // **On the row, and therefore on standard output**, although both are
        // warnings. They are the end of a line that started on standard output,
        // and a line split across the two streams is a line neither of them
        // holds. Ranked with the standard output painter, so a terminal still
        // colours them and a pipe still gets clean bytes.
        if (!one.readable) tty.out(.warn, "  (this log could not be read)", .{});
        if (one.readable) {
            if (try chainNote(arena, one.chain)) |note| {
                // An edited log is ranked as an error and a crash as a warning,
                // because they are not the same thing to find in a listing.
                const rank: tty.Rank = if (one.chain.edited()) .err else .warn;
                if (one.chain.edited()) edited_count += 1;
                tty.out(rank, "{s}", .{note});
            }
        }
        tty.out(.plain, "\n", .{});

        // **On a line of its own, and after the row rather than inside it.** A
        // title is written by a model and the row is written by Chock, so the
        // two never share a line: see `title_marker`. It also keeps the columns
        // of the table straight, which a field of any length in the middle of a
        // row would not.
        if (try titleText(arena, one.title)) |named| {
            tty.out(.plain, title_marker ++ "{s}\n", .{named});
        }
    }

    tty.out(.plain, "\n{d} {s}", .{
        sessions.len,
        if (sessions.len == 1) "session" else "sessions",
    });
    if (live_count != 0) {
        tty.out(.plain, ", {d} running now", .{live_count});
    }
    if (with_work != 0) {
        tty.out(.plain, ", {d} still holding a workspace", .{with_work});
    }
    // **The four hints and the sentence about the lock live in `--help`.**
    // Each was worth reading once and none of them is worth reading on every
    // listing, and `chock sessions --help` is where a person goes to ask what
    // else this command does.
    tty.out(.plain, ".\n", .{});

    // **The listing ends non-zero when a log was edited.** A row a reader may
    // scroll past is not enough for the one fact on this screen that says
    // somebody changed the record, and a script that only reads the exit code
    // must not be told a project of edited logs is well.
    if (edited_count != 0) {
        tty.print(
            .err,
            "\nchock sessions: {d} of these logs {s} edited after {s} written. " ++
                "Read {s} with: chock sessions verify\n",
            .{
                edited_count,
                if (edited_count == 1) "was" else "were",
                if (edited_count == 1) "it was" else "they were",
                if (edited_count == 1) "it" else "them",
            },
        );
        return Exit.faulted.code();
    }
    return Exit.finished.code();
}

/// Say what a project's session logs' hash chains hold, either for one session
/// or for every one of them.
///
/// **Nothing here writes, locks, or removes.** A verification of a session
/// another process is running right now is still worth reading: it says the
/// chain held over everything on disk at the moment it looked, and the owner
/// goes on appending after that.
fn verifySessions(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    project_root: []const u8,
    id: []const u8,
) !u8 {
    const sessions = if (id.len == 0)
        try list(arena, io, dir)
    else one: {
        const one = try fold(arena, io, dir, id) orelse {
            tty.print(.err, "chock sessions verify: this project has no session {s} ({s})\n", .{ id, dir });
            return Exit.usage.code();
        };
        const only = try arena.alloc(Session, 1);
        only[0] = one;
        break :one only;
    };

    if (sessions.len == 0) {
        tty.print(.plain, "chock sessions verify: this project has no sessions ({s})\n", .{dir});
        return Exit.finished.code();
    }

    // A `--verbose` line, the same as in `listSessions`.
    tty.detail("{s}\n{s}\n\n", .{ project_root, dir });

    var damaged: usize = 0;
    var read_count: usize = 0;
    var sealed_count: usize = 0;
    for (sessions) |one| {
        if (!one.readable) {
            tty.out(.warn, "{s}  this log could not be read at all, so nothing was checked\n", .{one.id});
            continue;
        }
        read_count += 1;
        // Ranked by what the reading found, so a terminal paints the one line
        // that names a person differently from the ones that name a crash.
        const rank: tty.Rank = switch (one.chain.verdict) {
            .intact, .partly_chained => .plain,
            .unchained, .torn => .warn,
            .broken, .undecodable, .unreadable => .err,
        };
        tty.out(rank, "{s}  {s}\n", .{ one.id, try chainText(arena, one.chain) });

        // **A second line under every row, never a row that stays quiet.** See
        // `sealText`: silence about a seal is the one answer a reader could
        // mistake for a signature.
        if (one.seal.signed()) sealed_count += 1;
        const seal_rank: tty.Rank = switch (one.seal.verdict) {
            // A log nobody sealed is the ordinary state, so it is not painted
            // as a fault. It is still said out loud.
            .absent, .signed_software, .signed_card, .signed_card_attested => .plain,
            // A seal file that will not read is a crash mid write or a text
            // editor. **A warning and not an error**, for the reason a torn log
            // is one: neither is proof that anybody changed anything.
            .malformed => .warn,
            // A seal that was written and does not hold names a person, the
            // same as a broken chain does.
            .signature_bad, .head_mismatch, .claim_unsupported => .err,
        };
        var indent_buffer: [session_paths.id_length]u8 = @splat(' ');
        const indent = indent_buffer[0..@min(one.id.len, indent_buffer.len)];
        tty.out(seal_rank, "{s}  {s}\n", .{ indent, try sealText(arena, one.seal) });

        // **Counted once for the row, never once for each fault.** A log with a
        // broken chain and a broken seal is one log that did not check out, and
        // a count that reached "2 of 1 logs" would be a message a reader
        // stopped believing.
        if (rank == .err or seal_rank == .err) damaged += 1;
    }

    // **The caveat is printed every time a log had no signature over it**, and
    // not only when something is wrong. It belongs beside a clean answer most
    // of all: an `intact` line with nothing under it reads as proof, and it is
    // not proof.
    //
    // **A sealed log has earned different words**, because the rewrite that
    // sentence warns about is exactly what a seal defeats. One unsealed log in
    // the run is enough to bring the warning back: it is true of that log, and
    // a reader must not have to work out which line it applies to.
    if (read_count != 0 and sealed_count == read_count) {
        tty.out(.plain, "\n{s}\n", .{seal.defeats_a_rewrite});
    } else {
        tty.out(.plain, "\n{s}\n", .{chain.not_a_signature});
    }

    if (damaged == 0) return Exit.finished.code();
    tty.print(
        .err,
        "\nchock sessions verify: {d} of {d} {s} did not check out.\n",
        .{ damaged, sessions.len, if (sessions.len == 1) "log" else "logs" },
    );
    // Never zero. A log that was edited, or one holding a whole line nothing
    // can decode, is not a session anybody should archive or believe, and a
    // script that reads only the exit code must be told so.
    return Exit.faulted.code();
}

/// Which key signed this run, and why it was that one.
///
/// **The reason travels with the signer.** A command that held the signer and
/// worked the reason out again later would be free to print a sentence about a
/// machine it never measured, which is the fault the line at the end of this
/// command used to have.
const Choice = struct {
    signer: seal.Signer,
    /// **What the caller really got**, and never what it wanted.
    level: seal.Level,
    /// What reaching for a card key found on this run. `.ready` only when a
    /// card is what signed.
    card: chock_pcsc.attempt.Outcome,
    /// The reader the card was found in. Empty when no card signed.
    reader: []const u8 = "",
    /// The transport's own sentence about `card`, or empty when it has none to
    /// give. It carries the socket path and the two protocol versions that an
    /// outcome alone cannot.
    detail: []const u8 = "",
    /// How many bytes the refused PIN had, and null when no length was measured.
    /// **A count and never the value.** It goes to
    /// `chock_pcsc.attempt.Outcome.sentenceWith`, which puts it in the sentence
    /// for the two outcomes a length caused and drops it for every other one.
    pin_bytes: ?usize = null,
    /// What the card said about its own counter, read without spending a try.
    /// Null when no counter was read.
    tries: ?chock_pcsc.piv.Tries = null,
    /// Whether the caller said a card seal or nothing. See `sealRefusal`.
    require_card: bool = false,

    /// The facts `sealRefusal` decides on. **A view and never a copy**, so the
    /// decision `sealMain` makes before it chooses a key and the one
    /// `sealSessions` makes before it writes cannot come apart.
    fn fallback(self: Choice) Fallback {
        return .{
            .found = self.card,
            .require_card = self.require_card,
            .tries = self.tries,
            .pin_bytes = self.pin_bytes,
            .detail = self.detail,
        };
    }
};

/// Sign the head of a log's chain and write the seal beside it, for one session
/// or for every session of the project.
///
/// **This writes nothing into a log and takes no log's lock.** A seal is a file
/// beside the log: `lib/chock-pcsc/sidecar.zig` says why it cannot be a line
/// inside one.
///
/// **A running session is refused rather than sealed.** Its head moves with the
/// next event, so a seal written now would read as `head_mismatch` a second
/// later, and a seal that goes stale by design teaches a reader to ignore the
/// one answer that names a person.
///
/// **It reaches for no card and no store.** Everything about which key signed
/// arrives in `choice`, from `sealMain`, which is what lets a test on a machine
/// with no reader drive every level this prints.
fn sealSessions(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    project_root: []const u8,
    id: []const u8,
    choice: Choice,
) !u8 {
    // **Checked here as well as in `sealMain`, and on purpose.** `sealMain`
    // decides before it chooses a key, so no key is made for a run that will
    // write nothing. This decides before the first write, so no caller can reach
    // the write without passing the same rule. One function answers both, so the
    // two cannot come apart.
    if (try sealRefusal(arena, choice.fallback())) |why| {
        tty.print(.err, "{s}", .{why});
        return Exit.faulted.code();
    }

    const signer = choice.signer;
    const level = choice.level;
    const sessions = if (id.len == 0)
        try list(arena, io, dir)
    else one: {
        const one = try fold(arena, io, dir, id) orelse {
            tty.print(.err, "chock sessions seal: this project has no session {s} ({s})\n", .{ id, dir });
            return Exit.usage.code();
        };
        const only = try arena.alloc(Session, 1);
        only[0] = one;
        break :one only;
    };

    if (sessions.len == 0) {
        tty.print(.plain, "chock sessions seal: this project has no sessions ({s})\n", .{dir});
        return Exit.finished.code();
    }

    tty.detail("{s}\n{s}\n\n", .{ project_root, dir });

    var refused: usize = 0;
    for (sessions, 0..) |one, index| {
        if (!one.readable) {
            tty.out(.warn, "{s}  this log could not be read at all, so there is nothing to sign\n", .{one.id});
            refused += 1;
            continue;
        }
        if (one.live == .live) {
            tty.out(
                .warn,
                "{s}  this session is running now, so its head moves with the next event; not sealed\n",
                .{one.id},
            );
            refused += 1;
            continue;
        }

        // **`level` is what the caller really got, and never what it wanted.**
        // The whole mechanism is built so that a fallback is recorded: see
        // `lib/chock-pcsc/seal.zig`. The signer and the level arrive together
        // for that reason, from the one place that chose them.
        // The key and the signature live here, because a seal borrows both and
        // this frame outlives the record written from it.
        var held = seal.Held{};
        const written = seal.sign(.{
            .session = one.id,
            .header = one.header_digest,
            .head = one.head_digest,
            .events = one.chain.events,
            .level = level,
        }, signer, &held) catch |err| {
            refused += 1;
            // **The sentence, when the signer has one.** A card ends every
            // signature it will not make with the one error the seal format
            // has, so the error name alone told a person nothing about a PIN
            // they mistyped or a line the terminal would not read. See
            // `seal.Signer.reason`.
            const why = signer.reason() orelse {
                tty.print(.err, "{s}  this log could not be signed: {s}\n", .{ one.id, @errorName(err) });
                continue;
            };
            tty.print(.err, "{s}  this log was not sealed: {s}\n", .{ one.id, why });
            // **A refusal is final for the run.** A slot whose PIN policy is
            // `always` is asked before every signature, so going on to the next
            // log would put the same question up again, and three wrong answers
            // block the card. The signer refuses the rest by itself, and this
            // says so rather than printing the same sentence on every row left.
            const left = sessions.len - (index + 1);
            if (left != 0) tty.print(
                .err,
                "chock sessions seal: {d} more {s} not asked about, because a refusal ends the run.\n",
                .{ left, if (left == 1) "log was" else "logs were" },
            );
            refused += left;
            break;
        };

        var record_buffer = seal.Buffer{};
        const record = seal.toRecord(written, &record_buffer) catch |err| {
            tty.print(.err, "{s}  this seal could not be written: {s}\n", .{ one.id, @errorName(err) });
            refused += 1;
            continue;
        };

        const log_path = try logPathIn(arena, dir, one.id);
        var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = sidecar.pathFor(&path_buffer, log_path) catch {
            tty.print(.err, "{s}  the path for this seal is too long to write\n", .{one.id});
            refused += 1;
            continue;
        };
        sidecar.write(arena, io, path, record) catch |err| {
            tty.print(.err, "{s}  the seal could not be written: {s}\n", .{ one.id, @errorName(err) });
            refused += 1;
            continue;
        };

        // **The level number is on the row and what it proves is not.** One
        // run signs every log with one key, so `levelText` was the same
        // sentence on every row: twenty three logs got twenty three copies of
        // it. The line below says it once, for the whole run, and the number
        // here is what a reader ranks a row by.
        tty.out(.plain, "{s}  sealed over {d} {s}, {s}\n", .{
            one.id,
            one.chain.events,
            eventWord(one.chain.events),
            levelRank(level),
        });
    }

    // **Said on every run, and not only when somebody asks.** A person who
    // never reads this line would otherwise take a seal for a card, which is
    // the silent downgrade the recorded level exists to stop. It is the one
    // place the run says what its key proves, so it is never shortened.
    //
    // "Read them back with: chock sessions verify" was here as well. That is a
    // hint and not an answer, so it moved to `chock sessions --help`, which
    // already says what verify reads.
    tty.out(.plain, "\n{s}\n", .{try signedWithText(arena, choice, sessions.len - refused)});

    if (refused == 0) return Exit.finished.code();
    tty.print(
        .err,
        "\nchock sessions seal: {d} of {d} {s} not sealed.\n",
        .{ refused, sessions.len, if (sessions.len == 1) "log was" else "logs were" },
    );
    return Exit.faulted.code();
}

/// The line that says which key signed this run, and what that proves. Caller
/// owns the result.
///
/// **It carries `levelText` because the rows no longer do.** One run signs with
/// one key, so the rows say the level number and this line, once, says what a
/// key of that level is worth. Shortening it to "sealed" would overstate the
/// guarantee, which is the one thing this whole mechanism exists to stop.
///
/// **Every word of it is derived from what this run measured.** The sentence
/// for a fallback is the one `chock_pcsc.attempt.Outcome` holds for the step
/// that stopped, and the sentence for a card names the reader the card was
/// found in. Nothing here states a property of the build.
///
/// That is not a style point. The line this replaced said "this build links no
/// PC/SC library", which was true when it was written and false one task later,
/// and no test could catch it because it was a constant. A sentence chosen by a
/// measurement goes stale only when the measurement does.
///
/// **The reason is first and the outcome is second.** The line used to name the
/// key it fell back to and then say why, so a person read a result they could
/// not yet account for and had to carry it to the end of the sentence. `sealed`
/// is how many seals were written, because "Every seal above" names a set a
/// reader looks for and cannot find when there is one of them.
fn signedWithText(
    allocator: std.mem.Allocator,
    choice: Choice,
    sealed: usize,
) std.mem.Allocator.Error![]u8 {
    const subject = if (sealed == 1) "The seal above" else "Every seal above";

    if (choice.card == .ready) {
        // A daemon that named a reader longer than the field that holds it
        // leaves this empty. **The reader is dropped rather than cut short**: a
        // name half printed is a name that points at the wrong machine.
        if (choice.reader.len == 0) return std.fmt.allocPrint(
            allocator,
            "{s} was signed on a card in a reader on this machine, " ++
                "PIV slot {X:0>2}, and that is {s}: {s}.",
            .{
                subject,
                @intFromEnum(chock_pcsc.attempt.seal_slot),
                levelRank(choice.level),
                levelText(choice.level),
            },
        );
        return std.fmt.allocPrint(
            allocator,
            "{s} was signed on the card in reader \"{s}\", PIV slot {X:0>2}, " ++
                "and that is {s}: {s}.",
            .{
                subject,
                choice.reader,
                @intFromEnum(chock_pcsc.attempt.seal_slot),
                levelRank(choice.level),
                levelText(choice.level),
            },
        );
    }

    // The number of bytes that were typed belongs to the two outcomes a length
    // refused, and `sentenceWith` drops it for every other one. The buffer is
    // borrowed for as long as the sentence is read, which is until the line
    // below is built.
    var room: [chock_pcsc.attempt.max_sentence_len]u8 = undefined;
    const why = choice.card.sentenceWith(choice.pin_bytes, &room);

    if (choice.detail.len == 0) return std.fmt.allocPrint(
        allocator,
        "No card key signed on this run, because {s}. " ++
            "{s} was signed with this installation's software key, and that is {s}: {s}.",
        .{ why, subject, levelRank(choice.level), levelText(choice.level) },
    );

    // The transport has a sentence of its own for four of the outcomes, and it
    // carries the socket path or the two protocol version numbers that no
    // outcome can. A person acts on those and cannot act on "no daemon".
    return std.fmt.allocPrint(
        allocator,
        "No card key signed on this run, because {s}: {s}. " ++
            "{s} was signed with this installation's software key, and that is {s}: {s}.",
        .{
            why,
            choice.detail,
            subject,
            levelRank(choice.level),
            levelText(choice.level),
        },
    );
}

/// Find the best key this machine will give and seal what was asked for.
///
/// **The card is asked for first, on every run.** A fallback that was never a
/// fallback is a claim about hardware nobody measured: the whole reason
/// `seal.Level` records which key signed is that the weaker one must be
/// visible, and it is only honest if the stronger one was really tried.
///
/// **The one place that joins the three libraries**, and the only part of the
/// seal path that names a platform driver, a credential store or a reader.
/// `sealSessions` and `signingKey` are both below it and neither reaches for
/// one, which is what lets a test on any host drive them.
fn sealMain(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    dir: []const u8,
    project_root: []const u8,
    id: []const u8,
    require_card: bool,
) !u8 {
    const data_dir = chock_auth.paths.dataDir(arena, env) catch |err| {
        tty.print(.err, "chock sessions seal: the data directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };
    var driver = chock_auth.store.Driver{ .data_dir = data_dir };

    // **It must not move**, because the attempt below points at it and the
    // signer points at the attempt.
    var transport = chock_pcsc.default(io);
    defer transport.deinit();
    // The card's answers land here, and the signer keeps it, so it outlives
    // every call below.
    var scratch: [chock_pcsc.piv.max_object_len]u8 = undefined;
    var attempt = chock_pcsc.attempt.Attempt.init(transport.pcsc(), &scratch);
    defer attempt.deinit();

    // **A person at a terminal is the ordinary case for a card seal.** A stock
    // signature slot asks for the PIN before it will use its key, so a run that
    // asked nobody fell back to software every time and said nobody could be
    // asked, which was false whenever somebody had typed the command.
    //
    // `at_terminal` is read here, once, and the asker answers `nobody` before it
    // writes a byte when it is false: see `TerminalPin.askFn`.
    var asking = TerminalPin{ .io = io, .at_terminal = approval.hasTerminal(io) };
    attempt.asker = asking.asker();
    const found = attempt.open();

    // **What the card said about its own slot**, for a person working out why a
    // run asks for the PIN as often as it does. A slot whose policy is `always`
    // wants one before every signature, so sealing twenty logs asks twenty
    // times, and that is the card's rule and not this program's.
    if (attempt.metadata) |slot| tty.detail(
        "PIV slot {X:0>2}: {s}, PIN policy {s}, touch policy {s}\n",
        .{
            @intFromEnum(chock_pcsc.attempt.seal_slot),
            slot.algorithm.text(),
            @tagName(slot.pin_policy),
            @tagName(slot.touch_policy),
        },
    );

    if (attempt.signer()) |card_signer| return sealSessions(arena, io, dir, project_root, id, .{
        .signer = card_signer,
        .level = attempt.level().?,
        .card = found,
        .reader = attempt.reader(),
    });

    // **A fallback nobody chose is not a fallback.** Everything below this point
    // writes a level 3 seal, and there are two runs that must not get one: the
    // one where somebody answered the PIN question and the card did not sign,
    // and the one where the caller said a card or nothing. Both leave the log
    // unsealed, so running the command again is a clean try rather than a second
    // seal beside a first.
    const measured = Fallback{
        .found = found,
        .require_card = require_card,
        .tries = attempt.tries,
        // The count of bytes the card path measured, so the line says the number
        // a person typed rather than a rule they must measure themselves
        // against. Null on every run a length did not stop.
        .pin_bytes = attempt.pin_bytes,
        .detail = transportDetail(arena, &transport, found),
    };
    if (try sealRefusal(arena, measured)) |why| {
        tty.print(.err, "{s}", .{why});
        return Exit.faulted.code();
    }

    var key = signingKey(gpa, io, data_dir, driver.secrets()) orelse return Exit.faulted.code();
    return sealSessions(arena, io, dir, project_root, id, .{
        .signer = key.signer(),
        .level = .software,
        .card = found,
        .detail = measured.detail,
        .pin_bytes = measured.pin_bytes,
        .tries = measured.tries,
        .require_card = require_card,
    });
}

/// Everything a run measured about the card before it decided whether it may
/// write a software seal. **Facts only**, so `sealRefusal` states no property of
/// the build and a test can drive every one of them on a machine with no reader.
const Fallback = struct {
    /// What reaching for a card key found.
    found: chock_pcsc.attempt.Outcome,
    /// Whether the caller said a card seal or nothing.
    require_card: bool,
    /// What the card said about its own counter, read without spending a try.
    tries: ?chock_pcsc.piv.Tries = null,
    /// How many bytes the refused PIN had. **A count and never the value.**
    pin_bytes: ?usize = null,
    /// The transport's own sentence, or empty when it has none.
    detail: []const u8 = "",
};

/// Why this run will write no seal at all, or null when it may write a software
/// one. Caller owns the result.
///
/// **A fallback nobody chose is not a fallback, and this is the line that says
/// so.** The whole seal mechanism is built to fall back and record it, and that
/// is right for a machine with no reader: nothing was tried and nothing failed.
/// It was wrong for one run in particular. Somebody asked for a card seal, gave
/// a PIN, the PIN was refused, and the command wrote a weaker artefact and
/// reported success. A person scripting a release would never see that the card
/// was not used, which is the silent downgrade `seal.Level` exists to stop, one
/// level up.
///
/// Three groups, and `attempt.Outcome.pinAttemptFailed` is where the split is
/// written out in full:
///
/// 1. **Nothing was tried.** No reader, no card, nobody at a keyboard. A
///    software seal, and the run worked.
/// 2. **Somebody pressed Enter.** The prompt offers that as the way to sign with
///    the software key, so it is a person choosing. A software seal, and the run
///    worked.
/// 3. **Somebody answered and no card key signed.** No seal at all, and the run
///    faulted.
///
/// **Nothing is written for the third group, on purpose.** The alternative is to
/// write the software seal and fault anyway, which leaves a file the next run
/// has to deal with and a record that reads like a choice nobody made. With no
/// file, running the command again is a clean try.
///
/// `--require-card` refuses the first two groups as well, for the one case that
/// needs it: a person sealing a public release wants a command that cannot
/// quietly give them a level 3 artefact, whatever is or is not in the reader.
fn sealRefusal(
    allocator: std.mem.Allocator,
    fallback: Fallback,
) std.mem.Allocator.Error!?[]u8 {
    // A card signed. There is no fallback to refuse.
    if (fallback.found == .ready) return null;

    var room: [chock_pcsc.attempt.max_sentence_len]u8 = undefined;
    const why = fallback.found.sentenceWith(fallback.pin_bytes, &room);

    if (fallback.found.pinAttemptFailed()) {
        // The count of tries left, when the card named one. **Read without
        // spending a try**, and it is the number that decides whether somebody
        // types again at all.
        var left_room: [64]u8 = undefined;
        const left = switch (fallback.tries orelse chock_pcsc.piv.Tries.unknown) {
            .left => |count| std.fmt.bufPrint(
                &left_room,
                "The card has {d} {s} left. ",
                .{ count, if (count == 1) "try" else "tries" },
            ) catch "",
            .blocked, .verified, .unknown => "",
        };
        return try std.fmt.allocPrint(
            allocator,
            "chock sessions seal: the PIN question was answered and no card key signed, " ++
                "so nothing was sealed.\n" ++
                "{s}.\n" ++
                "{s}Nothing here tries again, because a card blocks after the last try.\n" ++
                "Run the command again for another try, or press Enter at the prompt to sign " ++
                "with this installation's software key instead.\n",
            .{ why, left },
        );
    }

    if (!fallback.require_card) return null;

    // The transport's own sentence carries the socket path and the two protocol
    // versions that no outcome can, and a person acts on those.
    if (fallback.detail.len == 0) return try std.fmt.allocPrint(
        allocator,
        "chock sessions seal: --require-card was given and no card key signed, " ++
            "so nothing was sealed.\n" ++
            "{s}.\n" ++
            "Put the card in a reader and run the command again, or leave --require-card out " ++
            "to sign with this installation's software key.\n",
        .{why},
    );
    return try std.fmt.allocPrint(
        allocator,
        "chock sessions seal: --require-card was given and no card key signed, " ++
            "so nothing was sealed.\n" ++
            "{s}: {s}.\n" ++
            "Put the card in a reader and run the command again, or leave --require-card out " ++
            "to sign with this installation's software key.\n",
        .{ why, fallback.detail },
    );
}

/// The PIN prompt for a person at the terminal that typed the command.
///
/// **Nobody to ask is a refusal, and it is decided before a byte is written.**
/// A subagent, a session `chock daemon` started and a piped run all have nobody
/// at a keyboard, and a prompt drawn where nothing can answer it is a hang. The
/// same rule `lib/chock-core/ask.zig` keeps, read the same way round.
///
/// **The count of tries left is said before anything is typed.** A PIV card
/// blocks after three wrong PINs and then needs the PUK, so a person deciding
/// whether to try has to know how many are left. Reading the count spends none.
///
/// **This holds no PIN.** The value goes from the keyboard into the buffer
/// `chock-pcsc` handed over and from there into one `VERIFY` command. Nothing
/// here keeps it, prints it, or writes it anywhere: `lib/chock-pcsc/pin.zig`
/// states the whole rule, and the comptime block at the end of this file fails
/// the build if this structure grows a field one could sit in.
const TerminalPin = struct {
    io: std.Io,
    /// Whether somebody is at a keyboard. Read once, by the caller, before this
    /// is built.
    at_terminal: bool,
    /// How many times a person was asked. **For the guard that there is no
    /// retry**, and for the message that says how many prompts a run took.
    asked: usize = 0,

    fn asker(self: *TerminalPin) chock_pcsc.pin.Asker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_pcsc.pin.Asker.VTable{ .ask = askFn };

    fn askFn(
        ptr: *anyopaque,
        question: chock_pcsc.pin.Question,
        out: *chock_pcsc.pin.Buffer,
    ) chock_pcsc.pin.Answer {
        const self: *TerminalPin = @ptrCast(@alignCast(ptr));
        // Before a byte is written. A prompt on a pipe is a hang.
        if (!self.at_terminal) return .nobody;
        self.asked += 1;

        sayTries(question);

        var text: [96]u8 = undefined;
        const asked = std.fmt.bufPrint(
            &text,
            "PIN for the card in PIV slot {X:0>2}: ",
            .{@intFromEnum(question.slot)},
        ) catch "PIN for the card: ";

        const typed = tty.readSecret(self.io, asked, out[0..]) catch |err|
            return answerFor(err);
        return .{ .pin = typed };
    }
};

/// What a failed read of the terminal says about the person at it.
///
/// **A function and not five lines inside `askFn`**, for the reason
/// `tty.secretTermios` is one: a test binary has no terminal to fail at, and
/// this is the part that must be right. `src/tty.zig` says the same about the
/// settings it hands over.
///
/// **The answer follows what happened, and nothing here rounds to a decline.**
/// A decline is a person who chose to give nothing, and each one of these is
/// something else. Telling somebody who typed a long line that they gave
/// nothing is the same fault as telling somebody who gave nothing that they
/// typed something wrong, which this project made once already.
///
/// None of these reaches a card, so the choice costs no try and is about
/// honesty alone.
fn answerFor(err: tty.SecretError) chock_pcsc.pin.Answer {
    return switch (err) {
        // The one refusal in the set. The prompt offers Enter as the way to
        // sign with the software key, so a person who presses it did what they
        // were told.
        error.Empty => .declined,
        // Standard input was a terminal when the caller measured it and is not
        // one now, so there is nobody at a keyboard to give a PIN.
        error.NotATerminal => .nobody,
        // **Its own answer.** A terminal that would not hide the typing, and a
        // line that could not be read at all, both leave this with nothing to
        // say about what anybody typed.
        error.EchoStuck, error.Unreadable => .unreadable,
        // Something was typed, and it was too long to be a PIN. See
        // `chock_pcsc.pin.Answer.too_long`.
        error.TooLong => .too_long,
    };
}

/// Say how many tries the card has left, before anybody types.
///
/// **The number comes from the card and never from a count kept here.** A try
/// spent by any other program on this machine counts against the same counter,
/// so a number this process worked out itself would be wrong exactly when it
/// mattered.
fn sayTries(question: chock_pcsc.pin.Question) void {
    if (question.reader.len != 0) {
        tty.print(.plain, "\nA card in reader \"{s}\" wants its PIN before it will sign.\n", .{question.reader});
    } else {
        tty.print(.plain, "\nA card in a reader on this machine wants its PIN before it will sign.\n", .{});
    }

    switch (question.tries) {
        .left => |left| tty.print(
            if (left <= 1) .err else .warn,
            "It has {d} {s} left. After the last one the card blocks and only the PUK unblocks it. " ++
                "Nothing here tries again: press Enter to sign with the software key instead.\n",
            .{ left, if (left == 1) "try" else "tries" },
        ),
        .blocked => tty.print(.err, "It has no tries left and needs the PUK.\n", .{}),
        .verified => tty.print(.plain, "It has already taken the PIN on this connection.\n", .{}),
        .unknown => tty.print(
            .warn,
            "It did not say how many tries are left. A PIV card blocks after three wrong ones. " ++
                "Nothing here tries again: press Enter to sign with the software key instead.\n",
            .{},
        ),
    }
}

/// The transport driver's own sentence about why it gave no card, or empty.
///
/// **Only for an outcome the transport is about.** A card with an empty slot
/// left no failure on the driver, and printing the last one there would name a
/// fault that is not the one that happened.
fn transportDetail(
    arena: std.mem.Allocator,
    transport: *chock_pcsc.Driver,
    found: chock_pcsc.attempt.Outcome,
) []const u8 {
    if (comptime !@hasDecl(chock_pcsc.platform, "Failure")) {
        // A driver that opens nothing states no failure. The outcome's own
        // sentence is the whole answer on that platform.
        return "";
    } else {
        if (!found.fromTransport()) return "";
        const failure = transport.failure orelse return "";
        // An allocation that failed leaves the outcome's own sentence, which is
        // the part a person needs most.
        return std.fmt.allocPrint(arena, "{f}", .{failure}) catch "";
    }
}

/// The software key this installation signs with, made on the first run and
/// kept in `secrets` after that. Null when it could not be had, and the reason
/// has already been printed.
///
/// **The key is made here and kept by `chock-auth`, and neither library knows
/// about the other.** `chock-pcsc` must never need a credential store, because
/// a verifier has none; `chock-auth` must never need `chock-pcsc`, because
/// `chock login` runs before any of this exists. This function is where the two
/// meet, which is what `lib/chock-auth/signing.zig` says in full.
///
/// **`secrets` is passed in and never built here.** The driver is the Keychain
/// on macOS, and a Keychain on a machine reached over ssh with no desktop
/// session refuses every write, so a test that built the real driver would fail
/// on one host and pass on another. See `lib/chock-auth/store.zig`.
fn signingKey(
    gpa: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    secrets: chock_auth.store.Secrets,
) ?chock_pcsc.software.Key {
    var diag: ?chock_auth.store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    if (chock_auth.signing.load(gpa, io, secrets, &diag) catch |err| {
        reportKeyFault(err, diag);
        return null;
    }) |secret| {
        return chock_pcsc.software.Key.fromSecret(secret) catch {
            // A stored value of the right width that is not a scalar on the
            // curve. A store somebody edited, and never a reason to make a new
            // key: a new key would orphan every seal the old one wrote, and it
            // would do it quietly.
            tty.print(
                .err,
                "chock sessions seal: the stored signing key is not a key on the curve. " ++
                    "Nothing was signed, and nothing was replaced.\n",
                .{},
            );
            return null;
        };
    }

    // The first run on this machine. **The key is made here and not in
    // `chock-auth`**, because only the curve knows which 32 bytes are a scalar
    // on it: see `lib/chock-auth/signing.zig`.
    const made = chock_pcsc.software.Key.generate(io);
    chock_auth.store.ensureDir(io, data_dir, &diag) catch |err| {
        reportKeyFault(err, diag);
        return null;
    };
    chock_auth.signing.save(gpa, io, secrets, made.toSecret(), &diag) catch |err| {
        reportKeyFault(err, diag);
        return null;
    };
    tty.print(
        .plain,
        "chock sessions seal: made this installation's signing key and kept it in the credential store.\n",
        .{},
    );
    return made;
}

fn reportKeyFault(err: anyerror, diag: ?chock_auth.store.Diagnostic) void {
    if (diag) |d| {
        tty.print(.err, "chock sessions seal: the signing key could not be reached: {f}\n", .{&d});
    } else {
        tty.print(
            .err,
            "chock sessions seal: the signing key could not be reached: {s}\n",
            .{@errorName(err)},
        );
    }
}

/// What one session's export came to.
pub const Exported = struct {
    id: []const u8,
    /// Where the copy was written.
    path: []const u8,
    /// How many lines of the log reached it, the header line included.
    lines: u64,
    /// What a verification of the copy found, whole. **The copy and not the
    /// original**: a reading of the original would say nothing about whether the
    /// copy is what a reader at the far end will find.
    ///
    /// The whole report and not the verdict alone, so a copy that did not check
    /// out names the two events the change sits between, exactly as `chock
    /// sessions verify` does.
    report: chain.Report = .{},
    /// Why the copy is not the whole log, when it is not.
    fault: ?anyerror = null,
};

/// Copy the log of session `id` into `dir`, byte for byte, and verify the copy.
///
/// **Nothing here writes to a log, locks one, or removes one.** A copy is a
/// reading. The log's owner is whichever process holds its exclusive lock, and
/// this is never that: a session running right now can be exported, and what
/// lands is everything on disk at the moment this looked.
///
/// The copy is byte for byte the log, header line and all, which is what lets
/// `chock_proto.storage.verify` read it at the far end with the very code that
/// wrote it. See `lib/chock-proto/ship.zig`.
pub fn exportSession(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    to: []const u8,
    id: []const u8,
) !Exported {
    const log_path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    const copy_path = try std.fmt.allocPrint(allocator, "{s}/{s}" ++ log_suffix, .{ to, id });

    var backing = chock_proto.storage.JsonLines{
        .log = chock_proto.log.Log.open(io, log_path, id) catch |err| {
            return Exported{ .id = id, .path = copy_path, .lines = 0, .fault = err };
        },
    };
    const store = backing.storage();
    defer store.close(io);

    var drop = chock_proto.ship.FileDrop{ .path = copy_path };
    defer drop.close(io);
    var shipper = chock_proto.ship.Shipper{ .sink = drop.sink(), .session = id };
    shipper.finish(allocator, io, store);

    var exported = Exported{
        .id = id,
        .path = copy_path,
        .lines = shipper.health.delivered,
        .fault = shipper.health.first_fault,
    };

    var arrived = chock_proto.storage.JsonLines{
        .log = chock_proto.log.Log.open(io, try std.fmt.allocPrintSentinel(
            allocator,
            "{s}",
            .{copy_path},
            0,
        ), id) catch |err| {
            if (exported.fault == null) exported.fault = err;
            return exported;
        },
    };
    const arrived_store = arrived.storage();
    defer arrived_store.close(io);

    const report = chock_proto.storage.verify(arrived_store, allocator, io) catch |err| {
        if (exported.fault == null) exported.fault = err;
        return exported;
    };
    exported.report = report;
    return exported;
}

/// Copy one session's log, or every session's, into `to`, and say what each copy
/// verifies as.
fn exportSessions(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    to: []const u8,
) !u8 {
    // Made rather than required, the same choice `chock run --export-dir` makes:
    // an operator naming a directory a collector will watch should not have to
    // make it first.
    std.Io.Dir.cwd().createDirPath(io, to) catch |err| {
        tty.print(.err, "chock sessions export: {s} could not be made: {s}\n", .{ to, @errorName(err) });
        return Exit.usage.code();
    };

    const sessions = if (id.len == 0) try list(arena, io, dir) else one: {
        const folded = try fold(arena, io, dir, id) orelse {
            tty.print(.err, "chock sessions export: this project has no session {s} ({s})\n", .{ id, dir });
            return Exit.usage.code();
        };
        const only = try arena.alloc(Session, 1);
        only[0] = folded;
        break :one only;
    };

    if (sessions.len == 0) {
        tty.print(.plain, "chock sessions export: this project has no sessions ({s})\n", .{dir});
        return Exit.usage.code();
    }

    var faulted: usize = 0;
    for (sessions) |one| {
        const done = try exportSession(arena, io, dir, to, one.id);
        if (done.fault != null or done.report.verdict == .broken or done.report.verdict == .undecodable) {
            faulted += 1;
            tty.print(.err, "{s}  {s}  {s}\n", .{
                done.id,
                if (done.fault) |err| @errorName(err) else "the copy did not check out",
                try chainText(arena, done.report),
            });
            continue;
        }
        tty.out(.plain, "{s}  {d} lines  {s}\n", .{ done.id, done.lines, done.path });
    }

    // **Said on every run, a clean one most of all.** A list of copies with
    // nothing under it reads as proof, and it is not proof.
    tty.out(.plain, "\n{s}\n", .{chain.not_a_signature});
    tty.out(
        .plain,
        "A copy proves only that the bytes which arrived hold a chain that agrees with itself.\n" ++
            "What it adds is that they are no longer only here: a rewrite of the log on this\n" ++
            "machine now disagrees with a copy this machine cannot reach.\n",
        .{},
    );

    if (faulted == 0) return Exit.finished.code();
    tty.print(
        .err,
        "\nchock sessions export: {d} of {d} {s} did not copy cleanly.\n",
        .{ faulted, sessions.len, if (sessions.len == 1) "log" else "logs" },
    );
    return Exit.faulted.code();
}

/// Everything one removal would take. Built before anything is deleted, so the
/// person answering the question sees the whole of it.
pub const Removal = struct {
    id: []const u8,
    log_path: []const u8,
    log_bytes: u64 = 0,
    work_path: []const u8,
    work: chock_core.cache.Size = .{},
    has_work: bool = false,
    root_path: []const u8,
    root: chock_core.cache.Size = .{},
    has_root: bool = false,

    /// Every byte this removal would take.
    pub fn totalBytes(self: Removal) u64 {
        return self.log_bytes + self.work.bytes + self.root.bytes;
    }
};

/// What removing the session `id` of `dir` would take. Null when this project
/// has no session of that identifier.
///
/// **Measured whole, never up to a bound**: this is what a person reads to
/// decide, and a number that stopped counting early would answer a different
/// question. The same rule `src/workspace.zig` keeps for its own listing.
pub fn planRemoval(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!?Removal {
    std.debug.assert(session_paths.isValidId(id));

    const log_path = try std.fmt.allocPrint(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id });
    const stat = std.Io.Dir.cwd().statFile(io, log_path, .{}) catch return null;

    var plan = Removal{
        .id = try allocator.dupe(u8, id),
        .log_path = log_path,
        .log_bytes = stat.size,
        .work_path = try std.fmt.allocPrint(allocator, "{s}/{s}" ++ work_suffix, .{ dir, id }),
        .root_path = try std.fmt.allocPrint(allocator, "{s}/{s}" ++ root_suffix, .{ dir, id }),
    };

    plan.has_work = chock_core.cache.exists(io, plan.work_path);
    if (plan.has_work) {
        plan.work = chock_core.cache.measure(allocator, io, plan.work_path, std.math.maxInt(u64));
    }
    plan.has_root = chock_core.cache.exists(io, plan.root_path);
    if (plan.has_root) {
        plan.root = chock_core.cache.measure(allocator, io, plan.root_path, std.math.maxInt(u64));
    }
    return plan;
}

/// The question, as a person reads it. Caller owns the result.
///
/// Its own function, over a folded session and a plan and nothing else, so a
/// test reads exactly what a person would and no test needs a terminal. The
/// same shape `src/approval.zig`'s own `promptText` has.
pub fn removalText(
    allocator: std.mem.Allocator,
    one: Session,
    plan: Removal,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    var time_buffer: [time_text_bytes]u8 = undefined;
    try text.print(allocator, "\nchock sessions: this would remove one session and everything it owns.\n\n", .{});
    try text.print(allocator, "  session  {s}\n", .{one.id});
    try text.print(allocator, "  started  {s}\n", .{timeText(&time_buffer, one.started_ms)});
    try text.print(allocator, "  state    {s}\n", .{stateText(one)});
    try text.print(allocator, "  model    {s}\n", .{try modelText(allocator, one)});
    try text.print(allocator, "  {d} {s}, {s}\n", .{
        one.spend.turns,
        turnWord(one.spend.turns),
        try usage_cmd.costText(allocator, one.spend),
    });

    try text.print(allocator, "\n  the log             {s}  {d} bytes\n", .{ plan.log_path, plan.log_bytes });
    if (plan.has_work) {
        try text.print(allocator, "  its workspace       {s}  {d} bytes in {d} files\n", .{
            plan.work_path,
            plan.work.bytes,
            plan.work.files,
        });
    }
    if (plan.has_root) {
        try text.print(allocator, "  its sandbox root    {s}  {d} bytes in {d} files\n", .{
            plan.root_path,
            plan.root.bytes,
            plan.root.files,
        });
    }

    // The sentence the whole prompt exists for. The log is the record of a
    // session, and nothing else holds a copy of it.
    try text.appendSlice(
        allocator,
        "\nThe log is the only record of what this agent did. Nothing else holds a copy,\n" ++
            "and no step makes it again.\n",
    );
    if (plan.has_work) {
        try text.appendSlice(
            allocator,
            "The workspace goes too. Take what you want out of it first.\n",
        );
    }
    try text.appendSlice(allocator, "\nRemove it? [y/N] ");
    return text.toOwnedSlice(allocator);
}

pub const RemoveError = error{
    /// The workspace could not be removed, so the log was kept: it is the only
    /// thing left that explains the directory still on disk.
    WorkspaceKept,
    /// The sandbox root could not be removed, so the log was kept, for the same
    /// reason.
    SandboxRootKept,
    /// Everything else went and the log did not.
    LogKept,
};

/// Take the session `plan` names.
///
/// **The log is deleted last, and only once everything it explains has gone.**
/// A removal that fails part way through then leaves the record of the session
/// that owned the leftover directory, so a person can still find out what it
/// was. The other order leaves a directory nothing on the machine can explain,
/// which is the state this whole command exists to prevent.
pub fn remove(io: std.Io, plan: Removal) RemoveError!void {
    if (plan.has_work) {
        std.Io.Dir.cwd().deleteTree(io, plan.work_path) catch return error.WorkspaceKept;
    }
    if (plan.has_root) {
        std.Io.Dir.cwd().deleteTree(io, plan.root_path) catch return error.SandboxRootKept;
    }
    std.Io.Dir.cwd().deleteTree(io, plan.log_path) catch return error.LogKept;
}

/// Ask `question` and answer whether a plain yes came back.
///
/// **Anything that is not a yes is a no**, which is `src/approval.zig`'s own
/// `saysYes` rule and the reason this calls it rather than reading the answer
/// itself. Nobody there, nothing typed, and a word this does not know are all
/// refusals.
pub fn agreed(io: std.Io, console: approval.Console, question: []const u8) bool {
    // Filtered, the same way an approval is: the paths below come out of a
    // directory a person can name, and a terminal escape in one would otherwise
    // repaint the question it is being asked about.
    approval.writeFiltered(console, io, question);

    var line: [approval.max_answer_bytes]u8 = undefined;
    var filled: usize = 0;
    while (filled < line.len) {
        switch (console.read(io, line[filled..], answer_timeout_ms)) {
            .bytes => |count| {
                // A read that delivered nothing cannot deliver a newline
                // either, and looping on it would hang the command on a console
                // that answers `bytes` forever. The real `Stdin` says `ended`
                // instead, so this only guards a console that does not.
                if (count == 0) return false;
                const before = filled;
                filled += count;
                const at = std.mem.indexOfScalar(u8, line[before..filled], '\n') orelse continue;
                return approval.saysYes(line[0 .. before + at]);
            },
            // Nothing typed inside the budget, an input that ended, or a stop.
            // None of the three is permission.
            .idle, .ended, .canceled => return false,
        }
    }
    // More was typed than any answer this reads. Never a yes: see `saysYes`.
    return false;
}

fn removeSession(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    console: approval.Console,
    ask: bool,
    dir: []const u8,
    project_root: []const u8,
    id: []const u8,
) !u8 {
    if (!session_paths.isValidId(id)) {
        tty.print(.err, "chock sessions remove: \"{s}\" is not a session identifier\n", .{id});
        return Exit.usage.code();
    }

    const one = try fold(arena, io, dir, id) orelse {
        tty.print(.err, "chock sessions remove: this project has no session {s} ({s})\n", .{ id, dir });
        // Never `finished`: a command that did nothing must not report success.
        // See `src/main.zig`'s own top comment.
        return Exit.usage.code();
    };

    if (one.live != .idle) {
        printLiveRefusal(one);
        return Exit.usage.code();
    }

    const plan = try planRemoval(arena, io, dir, id) orelse {
        tty.print(.err, "chock sessions remove: this project has no session {s} ({s})\n", .{ id, dir });
        return Exit.usage.code();
    };

    if (ask) {
        const question = try removalText(arena, one, plan);
        if (!agreed(io, console, question)) {
            tty.print(.warn, "\nchock sessions: nothing was removed.\n", .{});
            return Exit.refused.code();
        }
    }

    return finishRemoval(arena, io, env, project_root, &.{plan});
}

/// Why a live session is not removable, said in full.
fn printLiveRefusal(one: Session) void {
    switch (one.live) {
        .live => tty.print(
            .warn,
            "chock sessions remove: {s} is running now, so it was not removed. Its log's " ++
                "lock is held, which is what says a process still owns this session.\n",
            .{one.id},
        ),
        .unknown => tty.print(
            .warn,
            "chock sessions remove: {s} was not removed, because its log's lock could not be " ++
                "tested and so this cannot tell whether it is running.\n",
            .{one.id},
        ),
        .idle => unreachable,
    }
}

/// Remove every plan, then drop the project's record of the worktrees that went
/// with them, and report. The second half is `src/workspace.zig`'s own
/// `pruneWorktrees`, called rather than written out again: a worktree is
/// registered in the project's `.git`, so deleting the directory alone leaves
/// the project believing a worktree exists that does not.
fn finishRemoval(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project_root: []const u8,
    plans: []const Removal,
) !u8 {
    var removed: usize = 0;
    var went: u64 = 0;
    var took_a_workspace = false;
    for (plans) |plan| {
        if (plan.has_work) took_a_workspace = true;
        remove(io, plan) catch |err| {
            tty.print(
                .warn,
                "chock sessions: {s} was not fully removed: {s}. The log is still there, " ++
                    "so what is left on disk can still be explained.\n",
                .{ plan.id, @errorName(err) },
            );
            continue;
        };
        removed += 1;
        went += plan.totalBytes();
    }

    if (took_a_workspace) workspace_cmd.pruneWorktrees(arena, io, env, project_root);

    tty.print(.plain, "chock sessions: removed {d} of {d} {s}, {d} bytes\n", .{
        removed,
        plans.len,
        if (plans.len == 1) "session" else "sessions",
        went,
    });
    // A removal that removed nothing it was asked to remove did not do the job,
    // and must not report that it did.
    if (removed == 0) return Exit.usage.code();
    return Exit.finished.code();
}

/// Which of `sessions` a prune of `older_than_days` would take, oldest first.
/// Caller owns the slice; the sessions in it are borrowed.
///
/// **A session that is running is never in the answer, and neither is one whose
/// lock could not be tested.** An absent answer is never a permissive answer,
/// the same rule a policy keeps.
///
/// `now_ms` is given rather than read, so no test here depends on a clock and
/// the whole rule is data. The same discipline `src/clock.zig` keeps.
pub fn prunable(
    allocator: std.mem.Allocator,
    sessions: []const Session,
    now_ms: u64,
    older_than_days: u32,
) std.mem.Allocator.Error![]Session {
    const window = @as(u64, older_than_days) * day_ms;
    var found: std.ArrayList(Session) = .empty;
    for (sessions) |one| {
        if (one.live != .idle) continue;
        // A session started in the future, which a clock that went backwards
        // can produce, is not old. `+|` saturates rather than wrapping into a
        // small number that would read as old.
        if (one.started_ms +| window > now_ms) continue;
        try found.append(allocator, one);
    }
    return found.toOwnedSlice(allocator);
}

fn pruneSessions(
    arena: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    console: approval.Console,
    ask: bool,
    dir: []const u8,
    project_root: []const u8,
    now_ms: u64,
    older_than_days: u32,
) !u8 {
    const sessions = try list(arena, io, dir);
    const going = try prunable(arena, sessions, now_ms, older_than_days);

    if (going.len == 0) {
        tty.print(
            .warn,
            "chock sessions prune: no session of this project is more than {d} days old " ++
                "and not running ({s})\n",
            .{ older_than_days, dir },
        );
        return Exit.usage.code();
    }

    // **Everything that would go is on screen before anything goes**, whether
    // or not there is a question after it. A prune that named a count and not
    // the sessions would be a command nobody could check.
    tty.out(.plain, "chock sessions prune: this would remove {d} of {d} {s}, all of them\n", .{
        going.len,
        sessions.len,
        if (sessions.len == 1) "session" else "sessions",
    });
    tty.out(.plain, "more than {d} days old and none of them running.\n\n", .{older_than_days});

    var plans: std.ArrayList(Removal) = .empty;
    var total: u64 = 0;
    for (going) |one| {
        const plan = try planRemoval(arena, io, dir, one.id) orelse continue;
        total += plan.totalBytes();
        try plans.append(arena, plan);

        var time_buffer: [time_text_bytes]u8 = undefined;
        tty.out(.plain, "  {s}  {s}  {s}  {d} bytes{s}\n", .{
            one.id,
            timeText(&time_buffer, one.started_ms),
            stateText(one),
            plan.totalBytes(),
            if (plan.has_work) "  (holds a workspace)" else "",
        });
    }

    tty.out(
        .plain,
        "\n{d} bytes in all. Every log listed above is the only record of what that agent did.\n",
        .{total},
    );

    if (ask) {
        if (!agreed(io, console, "\nRemove them all? [y/N] ")) {
            tty.print(.warn, "\nchock sessions: nothing was removed.\n", .{});
            return Exit.refused.code();
        }
    }

    return finishRemoval(arena, io, env, project_root, plans.items);
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
        if (std.mem.eql(u8, argument, "--older-than")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.older_than_days = std.fmt.parseInt(u32, args[index], 10) catch return error.BadArguments;
            continue;
        }
        if (std.mem.eql(u8, argument, "--org-bundle")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.org_bundle = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--to")) {
            index += 1;
            if (index >= args.len) return error.BadArguments;
            options.to = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--require-card")) {
            options.require_card = true;
            continue;
        }
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
        if (options.session.len != 0) return error.BadArguments;
        options.session = argument;
    }

    // Each action takes exactly what it needs and nothing it does not. A
    // `remove` with no session, or a `prune` with no window, would otherwise
    // have to invent one, and inventing which sessions to delete is the one
    // thing this command must never do.
    if (options.action == .remove and options.session.len == 0) return error.BadArguments;
    if (!options.action.takesSession() and options.session.len != 0) return error.BadArguments;
    if (options.action == .prune and options.older_than_days == null) return error.BadArguments;
    if (options.action != .prune and options.older_than_days != null) return error.BadArguments;
    // **`export` needs somewhere to write, and no other action may name one.** A
    // copy with no destination would have to invent one, and inventing where an
    // audit trail lands is the one thing this command must never do.
    if (options.action == .@"export" and options.to == null) return error.BadArguments;
    if (options.action != .@"export" and options.to != null) return error.BadArguments;
    // **Only `seal` chooses a key**, so only `seal` can be told which one it may
    // use. Taking the flag anywhere else would let a `verify` read as though it
    // checked something it never looked at.
    if (options.action != .seal and options.require_card) return error.BadArguments;
    return options;
}

/// The project this command is about, as an absolute path. **The same call
/// `chock run`, `chock cache`, `chock memory`, `chock workspace`, `chock usage`
/// and `chock plan` make**, for the same reason: a session directory is keyed
/// by the project's real path, so a spelling this command resolved differently
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

/// A `Console` a test scripts. It never touches a terminal. The same shape
/// `src/approval.zig`'s own test console has, and for the same reason: a test
/// that read real standard input would wait for a person nobody is going to
/// send.
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

fn scratchDir(arena: std.mem.Allocator, tmp: *testing.TmpDir, leaf: []const u8) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ buffer[0..len], leaf });
}

/// A session directory holding one log per identifier, each carrying the events
/// it was given. The events go in by hand, so what comes out is checkable to
/// the token.
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

/// A `.work` directory holding one file, the way a session that kept its
/// workspace leaves one.
fn makeWorkspace(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8) ![]const u8 {
    const work = try std.fmt.allocPrint(arena, "{s}/{s}" ++ work_suffix, .{ dir, id });
    try std.Io.Dir.createDirAbsolute(io, work, .default_dir);
    const file = try std.fmt.allocPrint(arena, "{s}/agent-wrote-this.txt", .{work});
    var handle = try std.Io.Dir.createFileAbsolute(io, file, .{});
    defer handle.close(io);
    try handle.writeStreamingAll(io, "1234567890");
    return file;
}

test "the command line names an action and exactly what that action needs" {
    try testing.expectEqual(Action.list, (try parseOptions(&.{})).action);
    try testing.expectEqual(Action.list, (try parseOptions(&.{"list"})).action);

    const removing = try parseOptions(&.{ "remove", "01JQ" ++ "A" ** 22 });
    try testing.expectEqual(Action.remove, removing.action);
    try testing.expectEqualStrings("01JQ" ++ "A" ** 22, removing.session);
    try testing.expect(!removing.yes);

    const pruning = try parseOptions(&.{ "prune", "--older-than", "30", "--yes" });
    try testing.expectEqual(Action.prune, pruning.action);
    try testing.expectEqual(@as(?u32, 30), pruning.older_than_days);
    try testing.expect(pruning.yes);

    const with_project = try parseOptions(&.{ "--project", "/somewhere", "remove", "01JQ" ++ "B" ** 22 });
    try testing.expectEqualStrings("/somewhere", with_project.project.?);
    try testing.expectEqualStrings("01JQ" ++ "B" ** 22, with_project.session);

    // An action that needs a session and did not get one, and one that got a
    // session it has no use for. Inventing which session a command meant is the
    // one thing a removal must never do.
    try testing.expectError(error.BadArguments, parseOptions(&.{"remove"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "list", "01JQ" ++ "A" ** 22 }));
    // A prune with no window would have to invent one.
    try testing.expectError(error.BadArguments, parseOptions(&.{"prune"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "prune", "--older-than", "not-a-number" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "list", "--older-than", "30" }));

    try testing.expectError(error.BadArguments, parseOptions(&.{"forget-everything"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "a session another process owns reads as live, and the probe leaves its lock alone" {
    // **The fact this whole command rests on.** The process holding the log's
    // lock is the owner of the session, so "is it running" is already answered
    // by the kernel and needs no heuristic.
    //
    // The lock is taken here on a second open file description. `flock(2)`
    // locks a description, not a process, and its own manual says a lock taken
    // through one descriptor may be denied to the same process through another,
    // so this contends for real. `test/proto/lock.zig` starts a second process
    // because the property it pins is specifically about two processes; the
    // property here is only that a held lock is seen, and the kernel does not
    // care who holds it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);

    // Nobody holds it yet.
    try testing.expectEqual(Liveness.idle, livenessOf(testing.io, path));

    var owner = try chock_proto.log.Log.open(testing.io, path, id);
    var held = try owner.lock(testing.io);

    // Held, so the session is running.
    try testing.expectEqual(Liveness.live, livenessOf(testing.io, path));

    // **And the probe did not take it away.** Three separate ways of asking,
    // because this is the failure the probe could cause and never report: a
    // second probe still sees it held, the owner can still append through the
    // handle it already has, and a fresh attempt to own the session is still
    // refused, which is the exact call `chock run` makes.
    //
    // The third is the one that would catch a lock that is per process rather
    // than per open file description. Under such a lock the open and close
    // inside `livenessOf` would drop the owner's hold silently, and every
    // reading below would flip to a session nobody owns.
    try testing.expectEqual(Liveness.live, livenessOf(testing.io, path));
    _ = try held.append(arena, testing.io, .{ .message = .{
        .role = .assistant,
        .content = &.{.{ .text = "still working" }},
    } }, 1);
    {
        var taker = try chock_proto.log.Log.open(testing.io, path, id);
        defer taker.close(testing.io);
        try testing.expectError(error.Busy, taker.lock(testing.io));
    }

    // Released, and the same probe now says so. Without this line the test
    // would pass against a `livenessOf` that always answered `live`.
    try held.unlock(testing.io);
    owner.close(testing.io);
    try testing.expectEqual(Liveness.idle, livenessOf(testing.io, path));

    // A log that is not there at all is not a live session, and it is not an
    // idle one either: nothing was tested.
    const missing = try std.fmt.allocPrintSentinel(arena, "{s}/never-made" ++ log_suffix, .{dir}, 0);
    try testing.expectEqual(Liveness.unknown, livenessOf(testing.io, missing));
}

test "two probes at the same moment never mistake each other for a running session" {
    // **Why the probe asks for a shared lock.** Two people running
    // `chock sessions` at once each open the same logs. With an exclusive
    // probe, whichever got there first would hold the other off, and the second
    // would report every session on the machine as running: an answer that
    // depends on who else is looking is not an answer.
    //
    // This is the one test that can see that choice, because it needs two
    // probes alive at the same moment. `livenessOf` releases before it returns,
    // so a test written over it alone would pass either way.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);

    var first = probe(testing.io, path).?;
    defer first.release(testing.io);
    try testing.expect(first.acquired);

    var second = probe(testing.io, path).?;
    defer second.release(testing.io);
    // The line an exclusive probe fails on.
    try testing.expect(second.acquired);

    // And with both of them held, a third reader still reads the session for
    // what it is: nobody owns it.
    try testing.expectEqual(Liveness.idle, livenessOf(testing.io, path));
}

test "a live session is never removable, and the refusal is not an exit of zero" {
    // The one rule the destructive half turns on. Removing a running agent's
    // log deletes the only record of work that is still being done, and the
    // process would go on writing into a file with no name.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    _ = try makeWorkspace(arena, testing.io, dir, id);

    const project = try scratchDir(arena, &tmp, "project");
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);
    var env = std.process.Environ.Map.init(arena);

    // A console scripted to say yes. It must never be reached: the refusal
    // comes before the question, so nothing can answer its way past a live
    // session.
    var fake = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer fake.deinit();

    var owner = try chock_proto.log.Log.open(testing.io, path, id);
    var held = try owner.lock(testing.io);

    // What the command wrote, captured rather than let through: a test that
    // let it reach the terminal would not be reading it, and it would put a
    // `failed command:` line in the build log of a suite that passed. See
    // `tty.Capture`, and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const code = try removeSession(arena, testing.io, &env, fake.console(), true, dir, project, id);
    try testing.expect(code != Exit.finished.code());
    // **And it says why, in the words that name the test for it.** "Not
    // removed" on its own reads as a fault; the held lock is what decides, and
    // a person who reads that knows to stop the session first.
    try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "running now") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "lock") != null);
    // A refusal is a diagnostic and never a row a pipe reads.
    try testing.expectEqualStrings("", said.out());
    said.clear();
    // Nobody was even asked, which is what makes this a refusal rather than a
    // question a script could answer wrongly.
    try testing.expectEqual(@as(usize, 0), fake.reads);

    // And the log is still there, byte for byte, along with its workspace.
    _ = try std.Io.Dir.cwd().statFile(testing.io, path, .{});
    const work = try std.fmt.allocPrint(arena, "{s}/{s}" ++ work_suffix, .{ dir, id });
    try testing.expect(chock_core.cache.exists(testing.io, work));

    // Once the owner lets go, the very same call removes it. Without this the
    // test would pass against a `removeSession` that refused everything.
    try held.unlock(testing.io);
    owner.close(testing.io);
    fake.reads = 0;
    try testing.expectEqual(
        Exit.finished.code(),
        try removeSession(arena, testing.io, &env, fake.console(), true, dir, project, id),
    );
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );
}

test "a session whose lock cannot be tested is not removable either" {
    // An absent answer is never a permissive answer, which is a policy's rule
    // and this file's rule for a lock.
    const unknown = Session{ .id = "01JQ" ++ "A" ** 22, .started_ms = 0, .live = .unknown };
    try testing.expectEqualStrings("no end recorded, lock not tested", stateText(unknown));

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // And a prune never takes one, however old it is.
    const going = try prunable(arena, &.{unknown}, std.math.maxInt(u32), 1);
    try testing.expectEqual(@as(usize, 0), going.len);
}

test "the listing is oldest first and needs no index of its own" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    // Written newest first, so a listing that reported the order the directory
    // handed them out would fail here on at least one filesystem.
    const newest = "01K3CW3600" ++ "C" ** 16;
    const middle = "01K2F2DKG0" ++ "B" ** 16;
    const oldest = "01JQAAAAAA" ++ "A" ** 16;
    try makeLog(arena, testing.io, dir, newest, &.{});
    try makeLog(arena, testing.io, dir, middle, &.{});
    try makeLog(arena, testing.io, dir, oldest, &.{});

    const sessions = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 3), sessions.len);
    try testing.expectEqualStrings(oldest, sessions[0].id);
    try testing.expectEqualStrings(middle, sessions[1].id);
    try testing.expectEqualStrings(newest, sessions[2].id);

    // The start time comes out of the identifier and rises with it, so no
    // separate record of when a session started has to be kept or trusted.
    try testing.expect(sessions[0].started_ms < sessions[1].started_ms);
    try testing.expect(sessions[1].started_ms < sessions[2].started_ms);

    var buffer: [time_text_bytes]u8 = undefined;
    try testing.expectEqualStrings("2025-08-12 12:00 UTC", timeText(&buffer, sessions[1].started_ms));

    // No file in this directory is an index, and nothing but the logs is read.
    try testing.expectEqual(@as(usize, 3), (try list(arena, testing.io, dir)).len);
}

test "a log this build cannot read is listed rather than dropped or fatal" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const good = "01JQ" ++ "A" ** 22;
    const broken = "01JQ" ++ "B" ** 22;
    try makeLog(arena, testing.io, dir, good, &.{
        .{ .usage = .{ .model = "qwen3", .cost = .free } },
    });
    {
        // A header no build of Chock wrote, which is what `Log.open` refuses.
        const path = try std.fmt.allocPrint(arena, "{s}/{s}" ++ log_suffix, .{ dir, broken });
        var handle = try std.Io.Dir.createFileAbsolute(testing.io, path, .{});
        defer handle.close(testing.io);
        try handle.writeStreamingAll(testing.io, "this is not a chock session log\n");
    }

    const sessions = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 2), sessions.len);
    try testing.expectEqualStrings(good, sessions[0].id);
    try testing.expect(sessions[0].readable);
    try testing.expectEqualStrings(broken, sessions[1].id);
    try testing.expect(!sessions[1].readable);
    try testing.expect(!sessions[1].complete);

    // And the whole command over that directory still succeeds, rather than
    // giving up on the one file it could not parse.
    //
    // **This is also the one place the stream split can be read in a unit
    // test.** The rows go to standard output so `chock sessions | grep` reads
    // them, and the note about the broken log goes to standard error. A
    // capture with one buffer could not tell those apart: see `tty.Capture`.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        Exit.finished.code(),
        try listSessions(arena, testing.io, dir, "/home/somebody/work/parser"),
    );

    // Both sessions are rows, and the broken one says on its own row that it
    // could not be read rather than being dropped.
    try testing.expect(std.mem.indexOf(u8, said.out(), good) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), broken) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "could not be read") != null);
    // **The project and the directory are not printed at all.** A person who
    // ran the command in a directory knows which one it was, and two path lines
    // at the head of every command is the largest cost in the whole program:
    // they are paid on every invocation of everything. They are `--verbose`
    // lines now, and `--verbose` is off here.
    try testing.expect(std.mem.indexOf(u8, said.out(), "/home/somebody/work/parser") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), dir) == null);
    // Nothing about a healthy listing is a warning.
    try testing.expectEqualStrings("", said.err());

    // And with `--verbose` both come back, on standard error with every other
    // `--verbose` line, so the rows a pipe reads are still only rows.
    said.clear();
    tty.configure(.{ .verbose = true });
    defer tty.configure(.{});
    _ = try listSessions(arena, testing.io, dir, "/home/somebody/work/parser");
    try testing.expect(std.mem.indexOf(u8, said.err(), "/home/somebody/work/parser") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), dir) != null);

    // The broken one is still removable, which is the reason it is listed.
    const plan = (try planRemoval(arena, testing.io, dir, broken)).?;
    try testing.expect(plan.log_bytes != 0);
}

test "a fold says when a session started, what it ran on, how it ended, and what it cost" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01K2F2DKG0" ++ "A" ** 16;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .usage = .{
            .input_tokens = 1000,
            .output_tokens = 100,
            .model = "claude-opus-5",
            .cost = .{ .known = .{ .value = 0.25, .currency = "USD" } },
        } },
        .{ .usage = .{ .model = "qwen3", .cost = .free } },
        .{ .session_end = .{ .reason = .budget_reached, .detail = "" } },
    });

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(@as(u64, 1755000000000), one.started_ms);
    try testing.expectEqualStrings("claude-opus-5", one.model);
    try testing.expectEqual(@as(usize, 2), one.model_count);
    try testing.expectEqualStrings("main", one.model_alias);
    try testing.expectEqual(@as(u64, 2), one.spend.turns);
    try testing.expectEqual(event.SessionEndReason.budget_reached, one.end.?);
    try testing.expect(one.readable and one.complete);

    // How it ended is the reason the log holds, not a guess, and it is not
    // "running" for a session nobody owns.
    try testing.expectEqualStrings("budget_reached", stateText(one));

    // The model column names a model and says there was another, so a session
    // that mixed models never reads as one that used a single model.
    try testing.expectEqualStrings("claude-opus-5 and 1 more", try modelText(arena, one));

    // And a session that got no reply has no model to name, so the alias is
    // said to be an alias rather than printed as if it were a model.
    const quiet = "01K2F2DKG0" ++ "B" ** 16;
    try makeLog(arena, testing.io, dir, quiet, &.{});
    const nothing = (try fold(arena, testing.io, dir, quiet)).?;
    try testing.expectEqualStrings("", nothing.model);
    try testing.expectEqualStrings("the main alias, unanswered", try modelText(arena, nothing));
    // Not "finished", and not a made up reason: nothing wrote one.
    try testing.expectEqualStrings("no end recorded", stateText(nothing));
}

test "a session's title is the last one the agent wrote, and a resumed session keeps it" {
    // **The fold is the only source of a title**, so this is what proves a
    // session that was resumed still has the name it was given before. It also
    // proves the supersede rule: the log cannot edit a title in place, so a
    // rename is a second event and the later one is the one a person reads.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    // Named, ended, resumed, renamed, ended again. Every one of those events is
    // between the two titles on purpose: nothing but a later title may change
    // the answer.
    const id = "01K2F2DKG0" ++ "T" ** 16;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .session_title = .{ .title = "read the parser tests" } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
        .{ .session_start = .{ .agent_kind = "coder", .model_alias = "main", .parent_session = "" } },
        .{ .usage = .{ .model = "qwen3", .cost = .free } },
        .{ .session_title = .{ .title = "port the parser to the new lexer" } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    });

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqualStrings("port the parser to the new lexer", one.title);
    // And the name the session went by first is still in the log, which is what
    // an append only record buys: nothing was written over.
    const bytes = try readLog(arena, testing.io, dir, id);
    try testing.expect(std.mem.indexOf(u8, bytes, "read the parser tests") != null);
    try testing.expect(std.mem.indexOf(u8, bytes, "\"session.title\"") != null);

    // A session nobody named has no title, and no row invents one for it.
    const nameless = "01K2F2DKG0" ++ "X" ** 16;
    try makeLog(arena, testing.io, dir, nameless, &.{});
    const quiet = (try fold(arena, testing.io, dir, nameless)).?;
    try testing.expectEqualStrings("", quiet.title);
    try testing.expectEqual(@as(?[]u8, null), try titleText(arena, quiet.title));

    // Mutation check: keep the first title instead of the last, by writing
    // `if (one.title.len == 0)` in front of the `.session_title` arm of `fold`,
    // and the first `expectEqualStrings` fails.
}

test "a hostile title cannot forge a row of the table or drive the terminal" {
    // A title is written by a model and printed in a list beside facts Chock
    // states itself, so the fault to stop is a title that reads as Chock's own
    // words, and a title that repaints the screen of whoever ran the command.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A forged row, a forged sentence of Chock's, an escape sequence that clears
    // the screen, and a carriage return that would write over the gutter.
    const nasty = "\x1b[2J\x1b[H\r01M0TMATKB6M4H3GY35KYA68QR  2026-08-24 19:35 UTC  finished" ++
        "\nchock sessions: 0 of these logs were edited\x07";
    const shown = (try titleText(arena, nasty)).?;

    // Not one byte a terminal reads as an instruction survives, and that
    // includes the line break: a title is one line, and a second line would put
    // the model's own words at column zero.
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, 0x1b));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, '\r'));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, 0x07));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, '\n'));
    // The letters those sequences carried are still readable, so a person can
    // see what the title tried to say.
    try testing.expect(std.mem.indexOf(u8, shown, "01M0TMATKB6M4H3GY35KYA68QR") != null);

    // And the whole of it is written after the gutter, so the forged row and the
    // forged sentence both sit indented, where no row and no sentence of Chock's
    // ever starts.
    const line = try std.fmt.allocPrint(arena, title_marker ++ "{s}\n", .{shown});
    try testing.expect(std.mem.startsWith(u8, line, title_marker));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, line, "\nchock sessions:"));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, line, "\n01M0TMATKB"));

    // Bytes that are not text are not printed at all: there is nothing to read
    // in them, and a terminal makes its own mind up about what they are.
    try testing.expectEqualStrings(title_not_text, (try titleText(arena, "\xff\xfe name")).?);

    // A title longer than the writer would ever have allowed is cut on a
    // character boundary and says it was cut, because a reader cannot ask for a
    // shorter one the way the writer can.
    const long = "e" ** (chock_core.Loop.max_title_bytes + 40);
    const trimmed = (try titleText(arena, long)).?;
    try testing.expect(trimmed.len < long.len);
    try testing.expect(std.mem.indexOf(u8, trimmed, "not shown") != null);
    // And a title exactly at the bound is printed whole, with nothing added.
    const exact = "e" ** chock_core.Loop.max_title_bytes;
    try testing.expectEqualStrings(exact, (try titleText(arena, exact)).?);

    // Mutation check: keep `byte` instead of the question mark in `titleText`,
    // and the four `indexOfScalar` lines fail. Cut at `max_title_bytes - 1`
    // instead, and the title exactly at the bound stops being printed whole.
}

test "the listing prints a title behind the gutter, and says whose words it is" {
    // The end of the road the agent's title travels: a person runs
    // `chock sessions` and reads it. This drives `listSessions` itself, so what
    // is pinned is the bytes that reach the terminal and not a helper.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01K2F2DKG0" ++ "V" ** 16;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .session_title = .{ .title = "wire the session title tool into the loop" } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    });

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(Exit.finished.code(), try listSessions(arena, testing.io, dir, "/project"));

    const text = said.out();
    // The title is there, on a line of its own, behind the gutter.
    try testing.expect(std.mem.indexOf(u8, text, "\n" ++ title_marker ++
        "wire the session title tool into the loop\n") != null);
    // And the reader is told once whose words the indented lines are.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, title_legend));
    // The row itself still carries what it always did, on its own line.
    try testing.expect(std.mem.indexOf(u8, text, id) != null);

    // A project whose sessions were never named prints nothing extra at all.
    const bare = try scratchDir(arena, &tmp, "bare");
    try makeLog(arena, testing.io, bare, "01K2F2DKG0" ++ "W" ** 16, &.{});
    said.clear();
    _ = try listSessions(arena, testing.io, bare, "/project");
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, said.out(), title_legend));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, said.out(), title_marker));

    // Mutation check: write two spaces in place of `title_marker`, and the
    // first `expect` fails. Print the legend without looking for a title first,
    // and the two lines about the project with no titles fail.
}

test "removing a session takes its workspace and its sandbox root, and takes the log last" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    const wrote = try makeWorkspace(arena, testing.io, dir, id);
    const root = try std.fmt.allocPrint(arena, "{s}/{s}" ++ root_suffix, .{ dir, id });
    try std.Io.Dir.createDirAbsolute(testing.io, root, .default_dir);

    const plan = (try planRemoval(arena, testing.io, dir, id)).?;
    try testing.expect(plan.has_work);
    try testing.expect(plan.has_root);
    try testing.expectEqual(@as(u64, 10), plan.work.bytes);
    try testing.expect(plan.log_bytes != 0);
    try testing.expect(plan.totalBytes() > plan.log_bytes);

    try remove(testing.io, plan);

    // Gone from the filesystem, all three, not merely absent from a listing.
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, wrote, .{}));
    try testing.expect(!chock_core.cache.exists(testing.io, plan.work_path));
    try testing.expect(!chock_core.cache.exists(testing.io, plan.root_path));
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{}),
    );
    try testing.expectEqual(@as(usize, 0), (try list(arena, testing.io, dir)).len);
}

test "a removal that cannot take the workspace keeps the log, so nothing is left unexplained" {
    // The order is the whole point. If the log went first and the workspace
    // then failed, the directory left behind would have no record anywhere of
    // which session made it or what that session was doing.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    var plan = (try planRemoval(arena, testing.io, dir, id)).?;

    // A workspace path that says it is there and is not. `deleteTree` on a
    // missing path succeeds, so the failure is forced with a path that cannot
    // be a directory at all: the log file with a name under it.
    plan.has_work = true;
    plan.work_path = try std.fmt.allocPrint(arena, "{s}/inside-a-file", .{plan.log_path});

    try testing.expectError(error.WorkspaceKept, remove(testing.io, plan));

    // The log is still there. That is the fact this test exists for.
    _ = try std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{});
    try testing.expectEqual(@as(usize, 1), (try list(arena, testing.io, dir)).len);
}

test "the question names what will go and says the log is the only copy, and only yes removes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01K2F2DKG0" ++ "A" ** 16;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .usage = .{ .model = "claude-opus-5", .cost = .free } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    });
    _ = try makeWorkspace(arena, testing.io, dir, id);

    const one = (try fold(arena, testing.io, dir, id)).?;
    const plan = (try planRemoval(arena, testing.io, dir, id)).?;
    const question = try removalText(arena, one, plan);

    try testing.expect(std.mem.indexOf(u8, question, id) != null);
    try testing.expect(std.mem.indexOf(u8, question, "2025-08-12 12:00 UTC") != null);
    try testing.expect(std.mem.indexOf(u8, question, "claude-opus-5") != null);
    try testing.expect(std.mem.indexOf(u8, question, plan.log_path) != null);
    try testing.expect(std.mem.indexOf(u8, question, plan.work_path) != null);
    try testing.expect(std.mem.indexOf(u8, question, "only record") != null);
    try testing.expect(std.mem.indexOf(u8, question, "Take what you want out of it") != null);
    try testing.expect(std.mem.endsWith(u8, question, "[y/N] "));

    const project = try scratchDir(arena, &tmp, "project");
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);
    var env = std.process.Environ.Map.init(arena);

    // What the command itself writes, apart from the question the console
    // carries. Captured rather than let through: see `tty.Capture`, and
    // `test/proto/lock.zig`.
    var wrote: tty.Capture = undefined;
    wrote.start(testing.io, testing.allocator);
    defer wrote.stop(testing.io);

    // Anything that is not a plain yes leaves everything where it is.
    const refusals = [_][]const u8{ "n\n", "\n", "sure\n", "yes please\n" };
    for (refusals) |said| {
        var no = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{said} };
        defer no.deinit();
        const code = try removeSession(arena, testing.io, &env, no.console(), true, dir, project, id);
        try testing.expectEqual(Exit.refused.code(), code);
        // The question really did reach the console, so the refusal is an
        // answer and not a path that never asked.
        try testing.expect(std.mem.indexOf(u8, no.shown.items, "only record") != null);
        _ = try std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{});
    }

    // Nobody at all is a refusal too.
    var nobody = FakeConsole{ .gpa = arena, .replies = &.{.ended} };
    defer nobody.deinit();
    try testing.expectEqual(
        Exit.refused.code(),
        try removeSession(arena, testing.io, &env, nobody.console(), true, dir, project, id),
    );
    _ = try std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{});

    // Every refusal above says so, and says nothing went, so a person is never
    // left wondering whether the answer was taken.
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "nothing was removed") != null);

    // And a plain yes does remove it. Without this the test would pass against
    // a `removeSession` that never removed anything.
    wrote.clear();
    var yes = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"Y\n"} };
    defer yes.deinit();
    try testing.expectEqual(
        Exit.finished.code(),
        try removeSession(arena, testing.io, &env, yes.console(), true, dir, project, id),
    );
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{}),
    );
    // And it says what went. A removal that reported nothing would leave the
    // person who answered yes with no record of what they agreed to.
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "removed 1 of 1") != null);
}

test "a removal with nobody to ask and no --yes never happens" {
    // The rule that keeps a script from deleting a record silently, and keeps a
    // command with no terminal from waiting on a prompt nobody can see.
    try testing.expect(!canAsk(false, false));
    try testing.expect(canAsk(false, true));
    try testing.expect(canAsk(true, false));
    try testing.expect(canAsk(true, true));

    // **A name that is not an identifier is settled before this rule is read.**
    // Measured before the order was fixed: piping `chock sessions remove nope`
    // answered "run this at a terminal", which is true, useless, and sends the
    // reader to fix a thing that was never the fault. The two answers are told
    // apart by which question is asked first, so the order is the fact this
    // pins, not the wording.
    try testing.expect(!session_paths.isValidId("nope"));
    try testing.expect(session_paths.isValidId("01M0" ++ "A" ** 22));
}

test "a prune shows every session it would take, takes none that is running, and none that is young" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const old = Session{ .id = "01JQ" ++ "A" ** 22, .started_ms = 1_000 * day_ms, .live = .idle };
    const young = Session{ .id = "01JQ" ++ "B" ** 22, .started_ms = 1_100 * day_ms, .live = .idle };
    const old_and_running = Session{ .id = "01JQ" ++ "C" ** 22, .started_ms = 900 * day_ms, .live = .live };
    const sessions = [_]Session{ old, young, old_and_running };

    // Now is day 1130, so `old` is 130 days back and `young` is 30.
    const now = 1_130 * day_ms;

    const over_ninety = try prunable(arena, &sessions, now, 90);
    try testing.expectEqual(@as(usize, 1), over_ninety.len);
    try testing.expectEqualStrings(old.id, over_ninety[0].id);

    // The running one is 230 days old and still never goes.
    const over_ten = try prunable(arena, &sessions, now, 10);
    try testing.expectEqual(@as(usize, 2), over_ten.len);
    for (over_ten) |one| try testing.expect(!std.mem.eql(u8, one.id, old_and_running.id));

    // Exactly at the window is old enough, and one millisecond short is not.
    // Without this pair the test would pass against an off by a whole day rule.
    const exactly = try prunable(arena, &.{old}, old.started_ms + 90 * day_ms, 90);
    try testing.expectEqual(@as(usize, 1), exactly.len);
    const one_short = try prunable(arena, &.{old}, old.started_ms + 90 * day_ms - 1, 90);
    try testing.expectEqual(@as(usize, 0), one_short.len);

    // A window nothing falls into takes nothing, rather than everything.
    const none = try prunable(arena, &sessions, now, 10_000);
    try testing.expectEqual(@as(usize, 0), none.len);

    // A session that says it started after now, which a clock that went
    // backwards gives, is not old. The saturating add is what stops that
    // reading as a very old session.
    const future = Session{ .id = "01JQ" ++ "D" ** 22, .started_ms = now + day_ms, .live = .idle };
    try testing.expectEqual(@as(usize, 0), (try prunable(arena, &.{future}, now, 0)).len);
}

test "a prune declined at the question removes nothing, and one accepted removes only what it listed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    // 2025-03-26 and 2025-08-12 by their own identifiers.
    const older = "01JQAAAAAA" ++ "A" ** 16;
    const newer = "01K2F2DKG0" ++ "B" ** 16;
    try makeLog(arena, testing.io, dir, older, &.{});
    try makeLog(arena, testing.io, dir, newer, &.{});

    const project = try scratchDir(arena, &tmp, "project");
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);
    var env = std.process.Environ.Map.init(arena);

    // A moment thirty days after the newer session started, so only the older
    // one is past a ninety day window.
    const now = session_paths.startedMs(newer) + 30 * day_ms;

    // What the command writes, apart from the question the console carries.
    // Captured rather than let through: see `tty.Capture`, and
    // `test/proto/lock.zig`.
    var wrote: tty.Capture = undefined;
    wrote.start(testing.io, testing.allocator);
    defer wrote.stop(testing.io);

    var no = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"n\n"} };
    defer no.deinit();
    try testing.expectEqual(
        Exit.refused.code(),
        try pruneSessions(arena, testing.io, &env, no.console(), true, dir, project, now, 90),
    );
    try testing.expectEqual(@as(usize, 2), (try list(arena, testing.io, dir)).len);
    // Everything it would have taken was on screen before it asked.
    try testing.expect(std.mem.indexOf(u8, no.shown.items, "[y/N]") != null);
    // **And the count it named was one of two, not all of them.** A prune that
    // said "this would remove 2 of 2" and then took one would be a question
    // answered about something else.
    try testing.expect(std.mem.indexOf(u8, wrote.out(), "1 of 2") != null);
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "nothing was removed") != null);
    wrote.clear();

    var yes = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer yes.deinit();
    try testing.expectEqual(
        Exit.finished.code(),
        try pruneSessions(arena, testing.io, &env, yes.console(), true, dir, project, now, 90),
    );

    // Only the old one went. A prune that took the lot would pass a test that
    // only counted what was removed.
    const left = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 1), left.len);
    try testing.expectEqualStrings(newer, left[0].id);

    // And a prune with nothing to take does not report success.
    wrote.clear();
    var never = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer never.deinit();
    try testing.expect((try pruneSessions(
        arena,
        testing.io,
        &env,
        never.console(),
        true,
        dir,
        project,
        now,
        90,
    )) != Exit.finished.code());
    // It says which directory it looked in and how old a session had to be, so
    // a person can see whether the window is what they meant. **A refusal, so
    // standard error**: the rows a listing puts on standard output are the ones
    // a pipe reads, and there are none here.
    try testing.expect(std.mem.indexOf(u8, wrote.err(), dir) != null);
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "90 days") != null);
    try testing.expectEqualStrings("", wrote.out());
    // Nobody was asked, so the console was never read for this one.
    try testing.expectEqual(@as(usize, 0), never.reads);
}

test "asking about a session this project never had removes nothing and creates no log" {
    // `Log.open` creates the file it is given, which is right for `chock run`
    // and wrong for a command that only reads: a question about a session that
    // never existed must not bring one into being and then offer to delete it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");
    try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);

    const project = try scratchDir(arena, &tmp, "project");
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);
    var env = std.process.Environ.Map.init(arena);

    const never = "01JQ" ++ "Z" ** 22;
    try testing.expectEqual(@as(?Session, null), try fold(arena, testing.io, dir, never));
    try testing.expectEqual(@as(?Removal, null), try planRemoval(arena, testing.io, dir, never));

    const path = try std.fmt.allocPrint(arena, "{s}/{s}" ++ log_suffix, .{ dir, never });
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );

    var fake = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer fake.deinit();

    var wrote: tty.Capture = undefined;
    wrote.start(testing.io, testing.allocator);
    defer wrote.stop(testing.io);

    // Neither a session that never ran nor a name that is not an identifier at
    // all reports success, and neither reaches a path.
    //
    // **And the two are refused in different words**, which is worth pinning:
    // one is a session this project does not have, and the other is a name that
    // could never be one. A person who typed a path needs to be told that, not
    // that their project is empty.
    try testing.expect((try removeSession(
        arena,
        testing.io,
        &env,
        fake.console(),
        true,
        dir,
        project,
        never,
    )) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, wrote.err(), never) != null);
    try testing.expect(std.mem.indexOf(u8, wrote.err(), dir) != null);

    wrote.clear();
    try testing.expect((try removeSession(
        arena,
        testing.io,
        &env,
        fake.console(),
        true,
        dir,
        project,
        "../../etc/passwd",
    )) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "not a session identifier") != null);
    try testing.expectEqualStrings("", wrote.out());

    // And nobody was asked either way: the refusal comes before the question,
    // so no answer can get past it.
    try testing.expectEqual(@as(usize, 0), fake.reads);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );
}

test "a project that never ran a session lists nothing rather than failing" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const missing = try scratchDir(arena, &tmp, "never-ran");

    var wrote: tty.Capture = undefined;
    wrote.start(testing.io, testing.allocator);
    defer wrote.stop(testing.io);

    try testing.expectEqual(@as(usize, 0), (try list(arena, testing.io, missing)).len);
    try testing.expectEqual(
        Exit.finished.code(),
        try listSessions(arena, testing.io, missing, "/home/somebody/work/parser"),
    );
    // **It names the directory it found nothing in.** A person who ran Chock in
    // the wrong project reads the same words as a person whose project is
    // genuinely new, unless the path is on the line.
    try testing.expect(std.mem.indexOf(u8, wrote.err(), missing) != null);
    // No rows, because there is nothing to list: a pipe reads an empty stream
    // rather than a sentence it would have to parse around.
    try testing.expectEqualStrings("", wrote.out());
}

test "only a session log is read, and a file that is not one is left alone" {
    // A session directory also holds a workspace and a sandbox root, and it can
    // hold a file no build of Chock wrote. None of those is a session, and
    // listing one would offer to remove a directory this command did not make.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    _ = try makeWorkspace(arena, testing.io, dir, id);
    {
        var handle = try std.Io.Dir.createFileAbsolute(
            testing.io,
            try std.fmt.allocPrint(arena, "{s}/notes.jsonl", .{dir}),
            .{},
        );
        handle.close(testing.io);
    }
    try std.Io.Dir.createDirAbsolute(
        testing.io,
        try std.fmt.allocPrint(arena, "{s}/not-a-session" ++ work_suffix, .{dir}),
        .default_dir,
    );

    const sessions = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 1), sessions.len);
    try testing.expectEqualStrings(id, sessions[0].id);
    try testing.expect(sessions[0].has_work);
}

test "an empty work directory is not a workspace, and removal still takes it" {
    // Measured on a real state directory before this test existed: 27 sessions,
    // 27 `.work` directories, and 3 workspaces. A marker that read existence
    // alone printed on all 27 rows, which told a reader nothing at all. The
    // wider question stays in `removalPlan`, because the empty directory is
    // still a directory somebody wants deleted.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const arena = fba.allocator();
    const dir = try scratchDir(arena, &tmp, "empty-work");

    const id = "01M0" ++ "B" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    const work = try std.fmt.allocPrint(arena, "{s}/{s}" ++ work_suffix, .{ dir, id });
    try std.Io.Dir.createDirAbsolute(testing.io, work, .default_dir);

    const sessions = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 1), sessions.len);
    try testing.expect(!sessions[0].has_work);

    // The same directory, from the other question's point of view.
    const plan = (try planRemoval(arena, testing.io, dir, id)).?;
    try testing.expect(plan.has_work);
}

test "every chain sentence reads as English at one event and at none" {
    // Read off a real state directory of 27 sessions on 2026-08-24: seven of
    // them held exactly one event and two held none at all, so a count of one
    // and a count of zero are the common rows here rather than corners. The
    // first draft of these sentences said "every one of the 1 event" and "the
    // chain holds over all 0 events" on those rows.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqualStrings(
        "this log holds no event at all, so there was nothing to check",
        try chainText(arena, .{ .verdict = .intact, .events = 0, .chained = 0 }),
    );
    try testing.expectEqualStrings(
        "the chain holds over all 1 event",
        try chainText(arena, .{ .verdict = .intact, .events = 1, .chained = 1 }),
    );
    try testing.expectEqualStrings(
        "the chain holds over all 2 events",
        try chainText(arena, .{ .verdict = .intact, .events = 2, .chained = 2 }),
    );

    const one_old = try chainText(arena, .{ .verdict = .unchained, .events = 1 });
    try testing.expect(std.mem.indexOf(u8, one_old, "the one event") != null);
    const many_old = try chainText(arena, .{ .verdict = .unchained, .events = 5 });
    try testing.expect(std.mem.indexOf(u8, many_old, "all 5 events") != null);

    // And no sentence in the set is empty, whatever the verdict, because a
    // blank row would read as a log with nothing wrong with it.
    for (std.enums.values(chain.Verdict)) |verdict| {
        const said = try chainText(arena, .{ .verdict = verdict, .events = 3, .chained = 2, .at = 90, .after = 40 });
        try testing.expect(said.len != 0);
    }
}

test "a time is printed in UTC, and a number that is not a time says so" {
    // A listing whose times moved with the reader's own zone could not be
    // lined up against a log: see `src/clock.zig` for the split between the two
    // questions.
    var buffer: [time_text_bytes]u8 = undefined;
    try testing.expectEqualStrings("1970-01-01 00:00 UTC", timeText(&buffer, 0));
    try testing.expectEqualStrings("2025-08-12 12:00 UTC", timeText(&buffer, 1755000000000));
    try testing.expectEqualStrings("2025-08-24 01:46 UTC", timeText(&buffer, 1756000000000));

    // A `startedMs` this far out came from an identifier no `newId` wrote, and
    // walking a year at a time to reach it would cost more than the answer.
    const far = timeText(&buffer, std.math.maxInt(u50));
    try testing.expect(std.mem.indexOf(u8, far, "no session was started") != null);
}

/// Read a session's whole log file.
fn readLog(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8) ![]u8 {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    return std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4 * 1024 * 1024));
}

fn writeLog(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8, bytes: []const u8) !void {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

/// Change one run of bytes in a session's log for another of the same length,
/// leaving every offset after it where it was. **The same length on purpose**:
/// an edit that moved the following lines would be found by the offsets alone,
/// and nothing but the chain can see this one.
fn editLog(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    find: []const u8,
    replacement: []const u8,
) !void {
    std.debug.assert(find.len == replacement.len);
    const bytes = try readLog(arena, io, dir, id);
    const at = std.mem.indexOf(u8, bytes, find).?;
    @memcpy(bytes[at..][0..replacement.len], replacement);
    try writeLog(arena, io, dir, id, bytes);
}

/// Put a fragment with no closing newline on the end of a session's log, the
/// shape a write that reached the kernel and never finished leaves behind.
/// Gives back the byte offset the fragment starts at.
fn tearLog(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8) !u64 {
    const bytes = try readLog(arena, io, dir, id);
    const at = bytes.len;
    const torn = try std.fmt.allocPrint(arena, "{s}{{\"id\":0,\"sessi", .{bytes});
    try writeLog(arena, io, dir, id, torn);
    return at;
}

/// Rewrite a log the way somebody with a text editor and four lines of shell
/// would: change one event, then compute every `prev` after it again so the
/// chain agrees with the new text.
///
/// **This is the attack a hash chain cannot defeat**, stated by
/// `lib/chock-proto/chain.zig` in its own first lines, and the reason a seal
/// exists. A repair leaves the chain reporting `intact`.
///
/// The digests are patched **inside the lines**, and each line is hashed after
/// its own patch, so changing one event really does move every digest after it
/// and the head with them. A model that kept the digests beside the lines
/// would let an edit leave the head alone and would prove nothing.
fn repairLog(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    find: []const u8,
    replacement: []const u8,
) !void {
    std.debug.assert(find.len == replacement.len);
    const bytes = try readLog(arena, io, dir, id);
    const at = std.mem.indexOf(u8, bytes, find).?;
    @memcpy(bytes[at..][0..replacement.len], replacement);

    const marker = "\"prev\":\"";
    var start: usize = 0;
    var previous: ?chain.Digest = null;
    while (std.mem.indexOfScalarPos(u8, bytes, start, '\n')) |end| {
        if (previous) |digest| {
            if (std.mem.indexOf(u8, bytes[start..end], marker)) |found| {
                @memcpy(bytes[start + found + marker.len ..][0..chain.digest_len], &digest);
            }
        }
        // Hashed after its own patch, which is what makes the change travel.
        previous = chain.of(bytes[start..end]);
        start = end + 1;
    }
    try writeLog(arena, io, dir, id, bytes);
}

/// The key every seal in these tests is signed with.
///
/// **Fixed, and made here rather than fetched from a store.** `signingKey` is
/// the only part of this command that touches a credential driver, and on
/// macOS that driver is the Keychain, which refuses every write on a machine
/// reached over ssh with no desktop session. A test that went through it would
/// pass on one host and fail on another, which is a test about the host and not
/// about the seal.
const test_seal_seed = [_]u8{0x5e} ** 32;

/// Seal one session, or every session of `dir` when `id` is empty.
///
/// **The card outcome is `no_reader` and not a pretend success.** These tests
/// run on build machines with no reader, and a helper that claimed a card
/// would put words in the output that no test here measured.
fn sealForTest(arena: std.mem.Allocator, dir: []const u8, id: []const u8) !u8 {
    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    // `key` lives for the whole call below, which is all the signer needs.
    return sealSessions(arena, testing.io, dir, "/home/somebody/work/parser", id, .{
        .signer = key.signer(),
        .level = .software,
        .card = .no_reader,
    });
}

/// A `Secrets` driver that holds one name and one value in memory. Neither a
/// file nor a Keychain, which is why `store.Secrets` is a vtable.
const MemorySecrets = struct {
    gpa: std.mem.Allocator,
    name: []const u8 = "",
    value: []const u8 = "",

    fn secrets(self: *MemorySecrets) chock_auth.store.Secrets {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = chock_auth.store.Secrets.VTable{ .get = getFn, .put = putFn };

    fn deinit(self: *MemorySecrets) void {
        self.gpa.free(self.name);
        self.gpa.free(self.value);
        self.* = undefined;
    }

    fn getFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?chock_auth.store.Diagnostic,
    ) chock_auth.store.Error!?[]u8 {
        _ = io;
        _ = diag;
        const self: *MemorySecrets = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, self.name, name)) return null;
        return try gpa.dupe(u8, self.value);
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?chock_auth.store.Diagnostic,
    ) chock_auth.store.Error!void {
        _ = io;
        _ = diag;
        const self: *MemorySecrets = @ptrCast(@alignCast(ptr));
        self.gpa.free(self.name);
        self.gpa.free(self.value);
        self.name = try gpa.dupe(u8, name);
        self.value = try gpa.dupe(u8, value);
    }
};

/// The seal file beside a session's log, as bytes a test can read or rewrite.
fn sealPathIn(arena: std.mem.Allocator, dir: []const u8, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}" ++ log_suffix ++ sidecar.suffix, .{ dir, id });
}

/// A log of `count` message events, each carrying text a test can find and
/// change.
fn makeCountedLog(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    count: usize,
) !void {
    const events = try arena.alloc(event.Event, count);
    for (events, 0..) |*one, i| {
        const text = try std.fmt.allocPrint(arena, "event number {d}", .{i});
        const content = try arena.alloc(event.ContentPart, 1);
        content[0] = .{ .text = text };
        one.* = .{ .message = .{ .role = .user, .content = content } };
    }
    try makeLog(arena, io, dir, id, events);
}

test "a fold reads the chain in the same pass, and a log written honestly is intact" {
    // The baseline. Without it, every test below would pass against a fold
    // that reported every log as broken.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 3);

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(chain.Verdict.intact, one.chain.verdict);
    // The three messages and the session.start event `makeLog` writes first.
    try testing.expectEqual(@as(u64, 4), one.chain.events);
    try testing.expectEqual(@as(u64, 4), one.chain.chained);
    try testing.expect(!one.chain.edited());
    try testing.expect(one.complete);

    // And nothing on the row says anything, because there is nothing to say.
    try testing.expectEqual(@as(?[]u8, null), try chainNote(arena, one.chain));
}

test "an edited log and a torn log are two different rows, and the listing does not exit zero" {
    // **The fact this whole change exists for, at the place a person reads
    // it.** Before the chain, both of these logs reached the listing as "the
    // log ends mid write", and the file somebody rewrote got the milder words
    // of the two.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const edited_id = "01JQ" ++ "A" ** 22;
    const torn_id = "01JQ" ++ "B" ** 22;
    const clean_id = "01JQ" ++ "C" ** 22;
    try makeCountedLog(arena, testing.io, dir, edited_id, 4);
    try makeCountedLog(arena, testing.io, dir, torn_id, 4);
    try makeCountedLog(arena, testing.io, dir, clean_id, 4);

    try editLog(arena, testing.io, dir, edited_id, "event number 1", "event number 8");
    const fragment_at = try tearLog(arena, testing.io, dir, torn_id);

    const edited = (try fold(arena, testing.io, dir, edited_id)).?;
    try testing.expectEqual(chain.Verdict.broken, edited.chain.verdict);
    try testing.expect(edited.chain.edited());

    const torn = (try fold(arena, testing.io, dir, torn_id)).?;
    try testing.expectEqual(chain.Verdict.torn, torn.chain.verdict);
    // **Not an edit.** A crash must never be reported as a person.
    try testing.expect(!torn.chain.edited());
    try testing.expectEqual(fragment_at, torn.chain.at);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // **Never zero**, because a row a reader scrolls past is not enough for
    // this, and a script that reads only the code must be told.
    const code = try listSessions(arena, testing.io, dir, "/home/somebody/work/parser");
    try testing.expect(code != Exit.finished.code());

    // The two rows carry two different sentences, and the edited one names
    // where. Both are on standard output, because each is the end of a row
    // that started there.
    try testing.expect(std.mem.indexOf(u8, said.out(), "this log was edited") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "the log ends mid write") != null);
    // And the clean log has neither sentence to its name: three rows, one of
    // each note, so a note is not simply printed on every row.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said.out(), "this log was edited"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, said.out(), "the log ends mid write"));
    try testing.expect(std.mem.indexOf(u8, said.out(), clean_id) != null);
}

test "verify names the two events an edit sits between, and never exits zero" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 4);
    try editLog(arena, testing.io, dir, id, "event number 2", "event number 7");

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(chain.Verdict.broken, one.chain.verdict);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(code != Exit.finished.code());

    // The sentence a person acts on: it says the log was changed, and it says
    // between which two events, so somebody can go and read them.
    try testing.expect(std.mem.indexOf(u8, said.out(), "changed after it was written") != null);
    var at_buffer: [32]u8 = undefined;
    const at_text = try std.fmt.bufPrint(&at_buffer, "{d}", .{one.chain.at});
    try testing.expect(std.mem.indexOf(u8, said.out(), at_text) != null);
    var after_buffer: [32]u8 = undefined;
    const after_text = try std.fmt.bufPrint(&after_buffer, "{d}", .{one.chain.after});
    try testing.expect(std.mem.indexOf(u8, said.out(), after_text) != null);

    // And the count of what did not check out is a diagnostic, not a row.
    try testing.expect(std.mem.indexOf(u8, said.err(), "did not check out") != null);
}

test "verify says a chain is not a signature, on a clean run as well as a bad one" {
    // **The caveat belongs beside a clean answer most of all.** An "intact"
    // line with nothing under it reads as proof that nothing was ever changed,
    // and it is not proof: whoever can rewrite the whole file can write a
    // chain that agrees with it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        Exit.finished.code(),
        try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "the chain holds over all 3 events") != null);
    // The same words the module that holds the mechanism argues for, so the
    // two cannot drift apart.
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
    // A clean run says nothing on standard error at all.
    try testing.expectEqualStrings("", said.err());
    said.clear();

    // And the same sentence is there when the answer is bad, so nobody reads
    // its absence as a stronger claim.
    try editLog(arena, testing.io, dir, id, "event number 0", "event number 5");
    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
}

test "a log this command sealed verifies with only the key in the seal, and the row names the level" {
    // The whole point, end to end: `seal` signs the head of a real log and
    // `verify` reads it back with nothing but the record and the log's own
    // digests. No card, no daemon, and the credential store holds only the
    // secret, which the verifier never asks for.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 3);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // **Before**, so this test cannot pass against a `verify` that prints the
    // sealed words on every run: an unsealed log says it has no seal, and it
    // says a chain is not a signature.
    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.out(), "no seal") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), seal.defeats_a_rewrite) == null);
    said.clear();

    try testing.expectEqual(
        Exit.finished.code(),
        try sealForTest(arena, dir, id),
    );
    // The seal is a file beside the log and nothing was written into the log.
    const before = try readLog(arena, testing.io, dir, id);
    try testing.expect(std.mem.indexOf(u8, before, "chock_seal") == null);
    _ = try std.Io.Dir.cwd().statFile(testing.io, try sealPathIn(arena, dir, id), .{});
    said.clear();

    // **After**: the level is named, and the sentence a chain alone has to
    // print is gone, because a seal is exactly what it disclaims.
    try testing.expectEqual(
        Exit.finished.code(),
        try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "level 3 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "a software key") != null);
    // The kind of key as well as the level, so an elliptic curve software seal
    // and an RSA card seal are told apart by reading the row.
    try testing.expect(std.mem.indexOf(u8, said.out(), "ECDSA P-256") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), seal.defeats_a_rewrite) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) == null);
    try testing.expectEqualStrings("", said.err());

    // And the fold agrees with the words: the reading is a signature that
    // checks out, at the level the record carries.
    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.signed_software, one.seal.verdict);
    try testing.expect(one.seal.signed());
    try testing.expect(!one.seal.hardwareProved());
}

test "a log whose chain was repaired by hand passes the chain and fails the seal" {
    // The four lines of shell that defeat a hash chain, done here in full: one
    // event changed and every `prev` after it computed again. The chain reports
    // that it holds. The seal is what catches it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 3);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);
    _ = try sealForTest(arena, dir, id);
    said.clear();

    try repairLog(arena, testing.io, dir, id, "event number 1", "event number 9");

    const one = (try fold(arena, testing.io, dir, id)).?;
    // **The chain is happy.** This is the fact the seal exists to answer, and
    // a repair that broke the chain would make the rest of this test vacuous.
    try testing.expectEqual(chain.Verdict.intact, one.chain.verdict);
    try testing.expect(!one.chain.edited());
    // The seal is over the head that was signed, and the head has moved.
    try testing.expectEqual(seal.Verdict.head_mismatch, one.seal.verdict);
    try testing.expectEqual(@as(?seal.Field, .head), one.seal.mismatched);
    try testing.expect(!one.seal.signed());

    // And the command says so, and never exits zero over it.
    const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.out(), "the chain holds over all 4 events") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "about a different log") != null);
    // The warning about a rewrite is back, because this log is not sealed any
    // more in any sense a reader can use.
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of 1 log did not check out") != null);
    said.clear();

    // And a log with both faults at once is still one log that did not check
    // out. A count that reached "2 of 1 logs" would be a message a reader stops
    // believing.
    try editLog(arena, testing.io, dir, id, "event number 0", "event number 8");
    const both = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(chain.Verdict.broken, both.chain.verdict);
    try testing.expectEqual(seal.Verdict.head_mismatch, both.seal.verdict);
    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of 1 log did not check out") != null);
}

test "an absent seal is printed as absent and never as a pass, and deleting one is visible" {
    // A sidecar can be deleted by anybody, which is the cost of it being a
    // file. The cost is paid openly: the row says there is no seal, so nobody
    // can read the quiet answer as a signature.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

    // A log nobody sealed. `absent` is the default and it is not a pass: it is
    // also not a failure of the command, because most logs carry no seal.
    const unsealed = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.absent, unsealed.seal.verdict);
    try testing.expect(!unsealed.seal.signed());
    try testing.expectEqual(@as(?seal.Level, null), unsealed.seal.claimed);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        Exit.finished.code(),
        try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "no seal") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "sealed, level") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), seal.defeats_a_rewrite) == null);
    said.clear();

    // Now seal it, delete the sidecar, and read it again. The log goes back to
    // "no seal", and never to "sealed and holding".
    _ = try sealForTest(arena, dir, id);
    try testing.expectEqual(
        seal.Verdict.signed_software,
        (try fold(arena, testing.io, dir, id)).?.seal.verdict,
    );

    try std.Io.Dir.cwd().deleteFile(testing.io, try sealPathIn(arena, dir, id));
    const gone = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.absent, gone.seal.verdict);
    try testing.expect(!gone.seal.signed());
    said.clear();

    try testing.expectEqual(
        Exit.finished.code(),
        try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "no seal") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
}

test "the line that says which key signed is built from what the run measured" {
    // The fault this replaced: a fixed sentence saying "this build links no
    // PC/SC library", which was true when it was written and false one task
    // later, and which no test could catch because it was a constant.
    //
    // Each outcome below is a different machine, and each has to produce a
    // different line. A command that held one sentence would print the same
    // words for all of them.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    const cases = [_]struct { outcome: chock_pcsc.attempt.Outcome, words: []const u8 }{
        .{ .outcome = .no_reader, .words = "no reader is attached" },
        .{ .outcome = .no_card, .words = "holds no card" },
        .{ .outcome = .no_key, .words = "it says its signature slot holds no key" },
        // The distinction that cost this project a wrong conclusion. A card
        // that was only asked about a certificate must not be reported as a
        // card with no key.
        .{ .outcome = .no_certificate, .words = "holds no certificate" },
        .{ .outcome = .key_unsupported, .words = "cannot sign with" },
        .{ .outcome = .pin_required, .words = "nobody to ask" },
        .{ .outcome = .pin_declined, .words = "none was given" },
        // A person who typed a long line, and a terminal that gave nothing
        // back, are two more machines, and neither of them is the one above.
        .{ .outcome = .pin_too_long, .words = "bytes were typed" },
        .{ .outcome = .pin_unreadable, .words = "could not be read" },
        // The three shapes a PIN is refused for. Each one is a person who did a
        // different thing, so each one is its own machine here.
        .{ .outcome = .pin_too_short, .words = "the six a PIV PIN is at least" },
        .{ .outcome = .pin_too_long_for_card, .words = "more than one PIN" },
        .{ .outcome = .pin_holds_pad, .words = "byte FF" },
        .{ .outcome = .pin_wrong, .words = "one try is gone" },
        .{ .outcome = .pin_blocked, .words = "PUK" },
        .{ .outcome = .no_daemon, .words = "no PC/SC daemon answered" },
    };
    for (cases) |one| {
        const line = try signedWithText(arena, .{
            .signer = key.signer(),
            .level = .software,
            .card = one.outcome,
        }, 4);
        try testing.expect(std.mem.indexOf(u8, line, one.words) != null);
        try testing.expect(std.mem.indexOf(u8, line, "software key") != null);
        // No line states a property of the build. That is the whole fault.
        try testing.expect(std.mem.indexOf(u8, line, "links no PC/SC") == null);
        // **The reason comes before the result.** A person who reads which key
        // signed before they read why has to carry the result to the end of the
        // line to account for it.
        const why = std.mem.indexOf(u8, line, one.words).?;
        const what = std.mem.indexOf(u8, line, "software key").?;
        try testing.expect(why < what);
    }

    // The transport's own sentence is carried through when there is one, so a
    // person gets the socket path and not only "no daemon".
    const detailed = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .software,
        .card = .no_daemon,
        .detail = "there is no pcscd socket at /run/pcscd/pcscd.comm",
    }, 4);
    try testing.expect(std.mem.indexOf(u8, detailed, "/run/pcscd/pcscd.comm") != null);

    // And a card that signed names the reader it was found in, so "a card"
    // never has to be taken on trust.
    const carded = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .card,
        .card = .ready,
        .reader = "Yubico YubiKey OTP+FIDO+CCID 00 00",
    }, 4);
    try testing.expect(std.mem.indexOf(u8, carded, "Yubico YubiKey OTP+FIDO+CCID 00 00") != null);
    try testing.expect(std.mem.indexOf(u8, carded, "9C") != null);
    try testing.expect(std.mem.indexOf(u8, carded, "software key") == null);

    // A card whose reader name did not fit the field still names the slot, and
    // never prints an empty pair of quotation marks where a name belongs.
    const nameless = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .card,
        .card = .ready,
    }, 4);
    try testing.expect(std.mem.indexOf(u8, nameless, "9C") != null);
    try testing.expect(std.mem.indexOf(u8, nameless, "\"\"") == null);
}

test "the line says the number of bytes that were typed, and only where a length refused them" {
    // **What the owner met.** Two runs against their own card, a correct prompt
    // saying 3 tries left, and a line that named three possible causes and
    // settled none of them. Their PIN really is longer than eight bytes, which
    // on a YubiKey usually means a real PIN of another application on the same
    // key. The number is what tells them that at once.
    //
    // Mutation check: drop `.pin_bytes` from the `Choice` that `sealMain` builds
    // and the first check here fails on the number.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    const counted = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .software,
        .card = .pin_too_long_for_card,
        .pin_bytes = 12,
    }, 1);
    try testing.expect(std.mem.indexOf(u8, counted, "because 12 bytes were typed") != null);
    try testing.expect(std.mem.indexOf(u8, counted, "six to eight bytes") != null);
    // And the two facts a person cannot work out for themselves.
    try testing.expect(std.mem.indexOf(u8, counted, "Bytes are not characters") != null);
    try testing.expect(std.mem.indexOf(u8, counted, "more than one PIN") != null);

    // A run that measured no count says the rule and no number, rather than a
    // number it did not measure.
    const uncounted = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .software,
        .card = .pin_too_long_for_card,
    }, 1);
    try testing.expect(std.mem.indexOf(u8, uncounted, "because more bytes were typed") != null);
    try testing.expect(std.mem.indexOf(u8, uncounted, "six to eight bytes") == null);

    // **No number beside a refusal a length did not cause.** The pad byte is
    // refused whatever the length is, so a count printed here would read as the
    // cause.
    const padded = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .software,
        .card = .pin_holds_pad,
        .pin_bytes = 6,
    }, 1);
    try testing.expect(std.mem.indexOf(u8, padded, "6 bytes were typed") == null);
    try testing.expect(std.mem.indexOf(u8, padded, "byte FF") != null);
}

test "a PIN was answered and no card signed, so nothing is sealed and the run faults" {
    // **The fault the owner met.** They asked for a card seal, gave a PIN, the
    // PIN was refused, and the command wrote a level 3 seal and reported
    // success. A person scripting a release would never see that the card was
    // not used, which is the silent downgrade `seal.Level` exists to stop, one
    // level up from the record.
    //
    // Three groups, and the table is the whole rule. Only the third refuses.
    //
    // Mutation check: move any outcome from one group to another and its row
    // fails on whether a message came back.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Nothing was tried, so nothing failed. A software seal, and a run that
    // worked.
    const allowed = [_]chock_pcsc.attempt.Outcome{
        .no_transport,
        .no_daemon,
        .not_authorized,
        .protocol_mismatch,
        .no_reader,
        .no_card,
        .no_piv,
        .no_key,
        .no_certificate,
        .key_unreadable,
        .key_unsupported,
        .card_refused,
        // Nobody was at a keyboard to be asked, so nobody answered anything.
        .pin_required,
        .pin_nobody,
        // **Somebody pressed Enter**, which is what the prompt offers as the way
        // to sign with the software key. A chosen fallback is never a failure.
        .pin_declined,
        // The counter is read before anybody types, so a blocked card ends the
        // path before the prompt is drawn and nobody answered anything.
        .pin_blocked,
    };
    for (allowed) |one| {
        try testing.expectEqual(
            @as(?[]u8, null),
            try sealRefusal(arena, .{ .found = one, .require_card = false }),
        );
    }

    // Somebody answered the PIN question and no card key signed. Every one of
    // these is a person who tried to use the card and did not get to.
    const refused = [_]chock_pcsc.attempt.Outcome{
        .pin_too_long,
        .pin_unreadable,
        .pin_too_short,
        .pin_too_long_for_card,
        .pin_holds_pad,
        .pin_wrong,
        .pin_not_enough,
    };
    for (refused) |one| {
        const why = (try sealRefusal(arena, .{ .found = one, .require_card = false })).?;
        // It says nothing was sealed, and it says what to do next. Both, because
        // a refusal that names no next step sends a person back to the same
        // command with the same answer.
        try testing.expect(std.mem.indexOf(u8, why, "nothing was sealed") != null);
        try testing.expect(std.mem.indexOf(u8, why, "Run the command again") != null);
        try testing.expect(std.mem.indexOf(u8, why, "press Enter") != null);
        // **And it never suggests a retry it made itself.** A card blocks after
        // the last try, so a run that tried again by itself is how somebody
        // loses a key.
        try testing.expect(std.mem.indexOf(u8, why, "Nothing here tries again") != null);
        // The reason is the outcome's own sentence, so the words cannot drift
        // from the fact they are about.
        try testing.expect(std.mem.indexOf(u8, why, one.sentence()) != null);
    }

    // A card signed. There is no fallback to refuse, whatever else was measured.
    try testing.expectEqual(
        @as(?[]u8, null),
        try sealRefusal(arena, .{ .found = .ready, .require_card = true }),
    );

    // The count of tries left is on the refusal, because it is the number that
    // decides whether somebody types again at all. It is read without spending
    // one.
    const counted = (try sealRefusal(arena, .{
        .found = .pin_wrong,
        .require_card = false,
        .tries = .{ .left = 2 },
    })).?;
    try testing.expect(std.mem.indexOf(u8, counted, "The card has 2 tries left") != null);
    const one_left = (try sealRefusal(arena, .{
        .found = .pin_wrong,
        .require_card = false,
        .tries = .{ .left = 1 },
    })).?;
    try testing.expect(std.mem.indexOf(u8, one_left, "The card has 1 try left") != null);
    // A card that named no count says no number, rather than a number nobody
    // measured.
    const no_count = (try sealRefusal(arena, .{ .found = .pin_wrong, .require_card = false })).?;
    try testing.expect(std.mem.indexOf(u8, no_count, "tries left") == null);

    // And the number of bytes that were typed reaches the refusal too, so the
    // one line a person reads carries every fact the run measured.
    const typed = (try sealRefusal(arena, .{
        .found = .pin_too_long_for_card,
        .require_card = false,
        .pin_bytes = 12,
    })).?;
    try testing.expect(std.mem.indexOf(u8, typed, "12 bytes were typed") != null);
}

test "--require-card refuses every software seal, including the one nobody chose against" {
    // **What a public release needs.** The honest fallback the rest of this
    // mechanism is built around is exactly what a person sealing a release does
    // not want on that run, and no message can make a level 3 artefact into the
    // level 2 one they asked for. So there is a way to say a card or nothing.
    //
    // Mutation check: return null for `require_card` and every row here fails.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The two the plain rule lets through are the two this exists to stop.
    for ([_]chock_pcsc.attempt.Outcome{ .no_reader, .no_card, .pin_declined, .pin_blocked }) |one| {
        try testing.expectEqual(
            @as(?[]u8, null),
            try sealRefusal(arena, .{ .found = one, .require_card = false }),
        );
        const why = (try sealRefusal(arena, .{ .found = one, .require_card = true })).?;
        try testing.expect(std.mem.indexOf(u8, why, "--require-card was given") != null);
        try testing.expect(std.mem.indexOf(u8, why, "nothing was sealed") != null);
        // It says both ways out: put the card in, or ask for a software seal on
        // purpose.
        try testing.expect(std.mem.indexOf(u8, why, "Put the card in a reader") != null);
        try testing.expect(std.mem.indexOf(u8, why, "leave --require-card out") != null);
    }

    // The transport's own sentence is carried through, because it holds the
    // socket path that no outcome can.
    const detailed = (try sealRefusal(arena, .{
        .found = .no_daemon,
        .require_card = true,
        .detail = "there is no pcscd socket at /run/pcscd/pcscd.comm",
    })).?;
    try testing.expect(std.mem.indexOf(u8, detailed, "/run/pcscd/pcscd.comm") != null);

    // **A failed attempt keeps its own message even here**, because it is the
    // more particular fact and it carries the count of tries left.
    const attempted = (try sealRefusal(arena, .{ .found = .pin_wrong, .require_card = true })).?;
    try testing.expect(std.mem.indexOf(u8, attempted, "--require-card") == null);
    try testing.expect(std.mem.indexOf(u8, attempted, "the PIN question was answered") != null);
}

test "a refused card attempt writes no seal file at all, so the next run is a clean try" {
    // **The half a message cannot state.** Writing the software seal and
    // faulting anyway would leave a file the next run has to deal with and a
    // record that reads like a choice nobody made. With no file, running the
    // command again is a clean try.
    //
    // The guard is in `sealSessions`, before the first write, as well as in
    // `sealMain`, before a key is chosen. This drives the one that guards the
    // write.
    //
    // Mutation check: take the `sealRefusal` call out of `sealSessions` and the
    // seal file appears.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    const code = try sealSessions(arena, testing.io, dir, "/home/somebody/work/parser", id, .{
        .signer = key.signer(),
        .level = .software,
        .card = .pin_too_long_for_card,
        .pin_bytes = 12,
    });
    try testing.expectEqual(Exit.faulted.code(), code);

    // Nothing on standard output, because there is no seal to report. The
    // refusal is a fault of the run, so it is on standard error beside every
    // other one.
    try testing.expectEqualStrings("", said.out());
    try testing.expect(std.mem.indexOf(u8, said.err(), "12 bytes were typed") != null);

    // And no file was written beside the log.
    const path = try sealPathIn(arena, dir, id);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );

    // The log itself is untouched and still readable, so the next run really is
    // a clean try rather than a repair.
    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expect(one.readable);
    try testing.expectEqual(seal.Verdict.absent, one.seal.verdict);
}

test "one seal is not called every seal, because a reader looks for the set and finds one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    const choice = Choice{ .signer = key.signer(), .level = .software, .card = .no_reader };

    const one = try signedWithText(arena, choice, 1);
    try testing.expect(std.mem.indexOf(u8, one, "The seal above") != null);
    try testing.expect(std.mem.indexOf(u8, one, "Every seal above") == null);

    const many = try signedWithText(arena, choice, 2);
    try testing.expect(std.mem.indexOf(u8, many, "Every seal above") != null);

    // The card branch counts the same way, because the fault is in the words
    // and not in which key signed.
    const carded = Choice{ .signer = key.signer(), .level = .card, .card = .ready, .reader = "R" };
    try testing.expect(std.mem.indexOf(u8, try signedWithText(arena, carded, 1), "The seal above") != null);
    try testing.expect(std.mem.indexOf(u8, try signedWithText(arena, carded, 3), "Every seal above") != null);
}

test "a level number is printed with the direction of the scale, because 3 of 3 reads as the top" {
    // A claim about trust has to be exact. "level 3 of 3" alone reads the way
    // three stars out of three does, and level 3 is the weakest of the three,
    // so the row said the opposite of what it meant to somebody who had not
    // read `seal.Level`.
    try testing.expect(std.mem.indexOf(u8, levelRank(.software), "3 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card), "2 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card_attested), "1 of 3") != null);
    // **Each level names its own rank.** "level 3 of 3, and level 1 is the
    // strongest" made a reader hold two numbers and work out which one was
    // theirs, and on a first pass it reads as a contradiction.
    //
    // Mutation check: give two levels the same word and the loop below fails on
    // the pair.
    try testing.expect(std.mem.indexOf(u8, levelRank(.software), "the weakest") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card), "the middle") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card_attested), "the strongest") != null);
    // No level states the rule about another level, which is what made the line
    // need working out.
    try testing.expect(std.mem.indexOf(u8, levelRank(.software), "level 1") == null);
    const ranks = [_][]const u8{ levelRank(.software), levelRank(.card), levelRank(.card_attested) };
    for (ranks, 0..) |one, index| {
        for (ranks[index + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one, other));
    }
    // A reading with no claim at all still prints the weakest, never the
    // strongest: an absent claim is never a permissive answer.
    try testing.expect(std.mem.indexOf(u8, levelRank(null), "3 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(null), "the weakest") != null);
}

test "a card seal names the card on the row, and the fallback line is not printed for it" {
    // The other half of the wiring: `sealSessions` prints the level it was
    // given, so a run that really reached a card says so on every row.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // The signer is a software key, because this machine has no card. **The
    // level is what the caller says it got**, which is exactly the field an
    // attacker cannot reach: it is inside the signed bytes, so a wrong level
    // here would be caught by the reader below rather than believed.
    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    _ = try sealSessions(arena, testing.io, dir, "/home/somebody/work/parser", id, .{
        .signer = key.signer(),
        .level = .card,
        .card = .ready,
        .reader = "Recorded Reader 00 00",
    });
    try testing.expect(std.mem.indexOf(u8, said.out(), "level 2 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "Recorded Reader 00 00") != null);
    // No fallback is claimed on a run that did not fall back.
    try testing.expect(std.mem.indexOf(u8, said.out(), "software key") == null);
    said.clear();

    // And the record carries the level, so `verify` reads it back as a card
    // seal with no attestation behind it.
    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.signed_card, one.seal.verdict);
    try testing.expect(!one.seal.hardwareProved());
}

/// A signer that gives a few signatures and then refuses, with a sentence, the
/// way a card whose PIN policy is `always` does when a prompt after the first
/// one goes wrong.
///
/// **Not a card and not a stand-in for one.** The card path itself is measured
/// against a recorded card in `test/pcsc/verify.zig`, which refuses any command
/// it has no recording of. This is here for the half that belongs to the
/// command: what a person reads, and whether the run goes on asking.
const RefusingSigner = struct {
    key: chock_pcsc.software.Key,
    /// How many signatures to give before the refusal.
    good: usize,
    signed: usize = 0,
    /// The sentence the refusal carries. **The signer's own words**, which is
    /// the whole point of the channel: `seal.SignError` has one member for every
    /// way a card ends a signature.
    why: []const u8,

    fn signer(self: *RefusingSigner) seal.Signer {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = seal.Signer.VTable{
        .publicKey = publicKeyFn,
        .signDigest = signDigestFn,
        .reason = reasonFn,
    };

    fn publicKeyFn(
        ptr: *anyopaque,
        out: *[seal.max_public_key_len]u8,
    ) seal.SignError![]const u8 {
        const self: *RefusingSigner = @ptrCast(@alignCast(ptr));
        out[0..seal.public_key_len].* = self.key.publicKey();
        return out[0..seal.public_key_len];
    }

    fn signDigestFn(
        ptr: *anyopaque,
        digest: [32]u8,
        out: *[seal.max_signature_len]u8,
    ) seal.SignError![]const u8 {
        const self: *RefusingSigner = @ptrCast(@alignCast(ptr));
        if (self.signed >= self.good) return error.Unusable;
        self.signed += 1;
        out[0..seal.signature_len].* = self.key.signDigest(digest) catch return error.Unusable;
        return out[0..seal.signature_len];
    }

    fn reasonFn(ptr: *anyopaque) ?[]const u8 {
        const self: *RefusingSigner = @ptrCast(@alignCast(ptr));
        return if (self.signed >= self.good) self.why else null;
    }
};

test "a signer that refuses part way through says why, and the run stops asking" {
    // **The fault a person met.** A slot whose PIN policy is `always` wants the
    // PIN before every signature, so sealing three logs puts the question up
    // four times. A mistyped line on any of them ended the seal with
    // `error.Unusable` and the row said "Unusable", which tells nobody what
    // they did or what to do next.
    //
    // Two things are measured here. The sentence reaches the row, and the run
    // stops rather than putting the same question up for every log left, which
    // is what would spend a second try and a third on somebody's card.
    //
    // Mutation check: print `@errorName(err)` instead of the reason and the
    // first check fails. Drop the `break` and the row about the log nobody was
    // asked about goes with it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    for (0..3) |i| {
        const id = try std.fmt.allocPrint(arena, "01JQ{c}" ++ "A" ** 21, .{@as(u8, 'A') + @as(u8, @intCast(i))});
        try makeCountedLog(arena, testing.io, dir, id, 2);
    }

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const sentence = chock_pcsc.attempt.Outcome.pin_too_long.sentence();
    var refusing = RefusingSigner{
        .key = try chock_pcsc.software.Key.fromSeed(test_seal_seed),
        .good = 1,
        .why = sentence,
    };
    const code = try sealSessions(arena, testing.io, dir, "/home/somebody/work/parser", "", .{
        .signer = refusing.signer(),
        .level = .card,
        .card = .ready,
        .reader = "Recorded Reader 00 00",
    });
    try testing.expectEqual(Exit.faulted.code(), code);

    // What a person reads: the words for what they did, and never the name of
    // an error type. A refusal is a fault of the run, so it is on standard
    // error beside every other one.
    const complained = said.err();
    const first = std.mem.indexOf(u8, complained, sentence) orelse return error.NoSentenceWasPrinted;
    try testing.expect(std.mem.indexOf(u8, complained, "Unusable") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "Unusable") == null);
    // Said once. **A refusal ends the run**, so the third log is named as not
    // asked about rather than given a second copy of the same sentence.
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, complained[first + sentence.len ..], sentence),
    );
    try testing.expect(std.mem.indexOf(u8, complained, "1 more log was not asked about") != null);
    // One sealed, two not: the one refused and the one never asked about.
    try testing.expect(std.mem.indexOf(u8, complained, "2 of 3 logs were not sealed") != null);
    // And the one that did seal is still on standard output, where a pipe reads
    // the rows.
    try testing.expect(std.mem.indexOf(u8, said.out(), "sealed over") != null);

    // And the signer was asked for one signature after the one it gave, and for
    // no more than that.
    try testing.expectEqual(@as(usize, 1), refusing.signed);
}

test "the level a seal recorded cannot be raised by editing the record" {
    // The silent downgrade this whole mechanism is built against. Somebody
    // takes the card away, Chock signs with a software key and records it, and
    // that same person then edits the record to say a card did it. The level is
    // inside the signed bytes, so the edit shows up as a broken signature and
    // never as a stronger seal.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);
    _ = try sealForTest(arena, dir, id);
    said.clear();

    const path = try sealPathIn(arena, dir, id);
    const record = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        path,
        arena,
        .limited(sidecar.max_bytes),
    );
    // As written, the record says a software key made it.
    try testing.expect(std.mem.indexOf(u8, record, "\"software\"") != null);

    for ([_][]const u8{ "\"card\"", "\"card_attested\"" }) |raised| {
        const edited = try std.mem.replaceOwned(u8, arena, record, "\"software\"", raised);
        {
            var file = try std.Io.Dir.cwd().createFile(testing.io, path, .{ .truncate = true });
            defer file.close(testing.io);
            try file.writeStreamingAll(testing.io, edited);
        }

        const one = (try fold(arena, testing.io, dir, id)).?;
        try testing.expectEqual(seal.Verdict.signature_bad, one.seal.verdict);
        try testing.expect(!one.seal.signed());
        try testing.expect(!one.seal.hardwareProved());
        // **The claim is not even reported**, because a record whose signature
        // does not check out has said nothing a reader may repeat.
        try testing.expectEqual(@as(?seal.Level, null), one.seal.claimed);

        const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
        try testing.expect(code != Exit.finished.code());
        try testing.expect(std.mem.indexOf(u8, said.out(), "does not check out") != null);
        try testing.expect(std.mem.indexOf(u8, said.out(), "level 1 of 3") == null);
        try testing.expect(std.mem.indexOf(u8, said.out(), "level 2 of 3") == null);
        said.clear();
    }
}

test "a seal file somebody truncated is reported, and never read as a seal or as none" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);
    _ = try sealForTest(arena, dir, id);
    said.clear();

    const path = try sealPathIn(arena, dir, id);
    const record = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, arena, .limited(sidecar.max_bytes));
    {
        var file = try std.Io.Dir.cwd().createFile(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, record[0 .. record.len / 3]);
    }

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.malformed, one.seal.verdict);
    try testing.expect(!one.seal.signed());

    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.out(), "could not be read at all") != null);
    // Not silently the same as having no seal, and not a signature either.
    try testing.expect(std.mem.indexOf(u8, said.out(), "no seal:") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), seal.defeats_a_rewrite) == null);
}

test "sealing refuses a session that is running now, because that log's head still moves" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var owner = try chock_proto.log.Log.open(testing.io, path, id);
    var held = try owner.lock(testing.io);

    const code = try sealForTest(arena, dir, id);
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.out(), "running now") != null);
    // Nothing was written beside the log.
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, try sealPathIn(arena, dir, id), .{}),
    );

    try held.unlock(testing.io);
    owner.close(testing.io);
    said.clear();

    // And with the lock gone the same call seals it, so the refusal is about
    // the lock and not about this log.
    try testing.expectEqual(
        Exit.finished.code(),
        try sealForTest(arena, dir, id),
    );
    _ = try std.Io.Dir.cwd().statFile(testing.io, try sealPathIn(arena, dir, id), .{});
}

test "the signing key is made once and read back after, so two runs share one signer" {
    // A key made afresh on every run would leave every earlier seal signed by a
    // key nothing holds any more, and a reader would find as many signers as
    // there are runs.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const data_dir = try scratchDir(arena_state.allocator(), &tmp, "data");

    var memory = MemorySecrets{ .gpa = testing.allocator };
    defer memory.deinit();

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // Nothing stored yet, so this makes a key and keeps it.
    const made = signingKey(testing.allocator, testing.io, data_dir, memory.secrets()).?;
    try testing.expect(std.mem.indexOf(u8, said.err(), "made this installation's signing key") != null);
    said.clear();

    // A second run, reading the store rather than carrying anything in memory.
    const again = signingKey(testing.allocator, testing.io, data_dir, memory.secrets()).?;
    try testing.expectEqualSlices(u8, &made.publicKey(), &again.publicKey());
    // And it did not say it made one this time, which is what tells a read from
    // a fresh key.
    try testing.expect(std.mem.indexOf(u8, said.err(), "made this installation's") == null);
    said.clear();

    // The mutation check: an empty store really does give a different key, so
    // the two answers above are not a constant.
    var empty = MemorySecrets{ .gpa = testing.allocator };
    defer empty.deinit();
    const other = signingKey(testing.allocator, testing.io, data_dir, empty.secrets()).?;
    try testing.expect(!std.mem.eql(u8, &made.publicKey(), &other.publicKey()));
    said.clear();

    // A stored value that is not a key is refused, and nothing is replaced: a
    // fresh key here would orphan every seal the old one wrote, quietly.
    var broken = MemorySecrets{
        .gpa = testing.allocator,
        .name = try testing.allocator.dupe(u8, chock_auth.signing.key_name),
        .value = try testing.allocator.dupe(u8, "not a secret"),
    };
    defer broken.deinit();
    try testing.expectEqual(
        @as(?chock_pcsc.software.Key, null),
        signingKey(testing.allocator, testing.io, data_dir, broken.secrets()),
    );
    try testing.expectEqualStrings("not a secret", broken.value);
    try testing.expect(std.mem.indexOf(u8, said.err(), "could not be reached") != null);
}

test "two logs sealed by one key carry that one public key, and are still two documents" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const first = "01JQ" ++ "A" ** 22;
    const second = "01JQ" ++ "B" ** 22;
    try makeCountedLog(arena, testing.io, dir, first, 1);
    try makeCountedLog(arena, testing.io, dir, second, 1);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // No name, so this seals every log of the project in one run.
    try testing.expectEqual(Exit.finished.code(), try sealForTest(arena, dir, ""));

    const one = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try sealPathIn(arena, dir, first),
        arena,
        .limited(sidecar.max_bytes),
    );
    const two = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        try sealPathIn(arena, dir, second),
        arena,
        .limited(sidecar.max_bytes),
    );

    const marker = "\"key\":\"";
    const at_one = std.mem.indexOf(u8, one, marker).? + marker.len;
    const at_two = std.mem.indexOf(u8, two, marker).? + marker.len;
    try testing.expectEqualStrings(
        one[at_one..][0 .. seal.public_key_len * 2],
        two[at_two..][0 .. seal.public_key_len * 2],
    );

    // And the two seals are different documents, so this did not pass by
    // comparing a file with itself: each names its own session and its own head.
    try testing.expect(!std.mem.eql(u8, one, two));
    try testing.expect(std.mem.indexOf(u8, one, first) != null);
    try testing.expect(std.mem.indexOf(u8, two, second) != null);
    try testing.expectEqual(
        seal.Verdict.signed_software,
        (try fold(arena, testing.io, dir, second)).?.seal.verdict,
    );
}

test "a log from before the chain verifies as unchained, and is still listed and still read" {
    // Every log written before this change carries no chain, and there is no
    // way to give one to a log that already exists. Those sessions stay
    // readable, and the reading says plainly that it can prove nothing about
    // them rather than calling them well.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    // Exactly the bytes an older build wrote: no `prev` member anywhere.
    try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);
    try writeLog(arena, testing.io, dir, id, "{\"chock_log\":1}\n" ++
        "{\"id\":0,\"session\":\"" ++ id ++ "\",\"time_ms\":1," ++
        "\"event\":{\"session.start\":{\"agent_kind\":\"coder\",\"model_alias\":\"main\"," ++
        "\"parent_session\":\"\"}},\"version\":1}\n" ++
        "{\"id\":0,\"session\":\"" ++ id ++ "\",\"time_ms\":2," ++
        "\"event\":{\"usage\":{\"model\":\"qwen3\",\"cost\":{\"free\":{}}}},\"version\":1}\n");

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(chain.Verdict.unchained, one.chain.verdict);
    try testing.expect(!one.chain.edited());
    // Read, not refused: the fold still got the model out of it.
    try testing.expect(one.readable);
    try testing.expect(one.complete);
    try testing.expectEqualStrings("qwen3", one.model);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // A listing of it is an ordinary listing, with no note on the row: an old
    // log is the common case and a marker on every one of them would be a
    // column that says nothing.
    try testing.expectEqual(
        Exit.finished.code(),
        try listSessions(arena, testing.io, dir, "/home/somebody/work/parser"),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "was edited") == null);
    said.clear();

    // **And `verify` is a zero exit that still refuses to call it good.** A
    // reading that cannot prove anything is not a failure of the command, and
    // it is not a pass for the log either.
    try testing.expectEqual(
        Exit.finished.code(),
        try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "no chain at all") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "whether this log was edited") != null);
}

test "verify with no session reads every log of the project" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const good = "01JQ" ++ "A" ** 22;
    const bad = "01JQ" ++ "B" ** 22;
    try makeCountedLog(arena, testing.io, dir, good, 2);
    try makeCountedLog(arena, testing.io, dir, bad, 2);
    try editLog(arena, testing.io, dir, bad, "event number 0", "event number 4");

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // One bad log among many is enough to make the whole run non-zero, and
    // both logs are still named so a person can see which is which.
    const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", "");
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.out(), good) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), bad) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of 2 logs") != null);
}

test "verify refuses a name that is not a session identifier, and one this project never had" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");
    try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    // **A name this build never wrote is never turned into a path**, and a
    // reading of a session that does not exist must not bring one into being:
    // `Log.open` creates the file it is given. `fold` stats first, which is
    // what makes this a refusal rather than a brand new empty log that then
    // verifies clean.
    const missing = "01JQ" ++ "Z" ** 22;
    const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", missing);
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), "has no session") != null);
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, missing }, 0);
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, path, .{}));

    // `seal` is refused the same way, and it never brings a log into being
    // either: `fold` stats before `Log.open`, which creates what it is given.
    try testing.expect(try sealForTest(arena, dir, missing) != Exit.finished.code());
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, path, .{}));

    // `seal` takes an optional session, exactly as `verify` does, and a second
    // name is a mistake for both.
    try testing.expectEqual(Action.seal, (try parseOptions(&.{"seal"})).action);
    const one_named = try parseOptions(&.{ "seal", "01JQ" ++ "A" ** 22 });
    try testing.expectEqual(Action.seal, one_named.action);
    try testing.expectEqualStrings("01JQ" ++ "A" ** 22, one_named.session);
    try testing.expectError(
        error.BadArguments,
        parseOptions(&.{ "seal", "01JQ" ++ "A" ** 22, "01JQ" ++ "B" ** 22 }),
    );

    // And the command line takes a session for `verify` and does not need one.
    try testing.expectEqual(Action.verify, (try parseOptions(&.{"verify"})).action);
    const named = try parseOptions(&.{ "verify", "01JQ" ++ "A" ** 22 });
    try testing.expectEqual(Action.verify, named.action);
    try testing.expectEqualStrings("01JQ" ++ "A" ** 22, named.session);
    // A second name is still a mistake, the same as it is for `remove`.
    try testing.expectError(
        error.BadArguments,
        parseOptions(&.{ "verify", "01JQ" ++ "A" ** 22, "01JQ" ++ "B" ** 22 }),
    );
}

/// A bundle out of `body`, as a `chock_policy.org.Bundle`. Written as a helper
/// so a test names the fact it pins and not the ZON around it.
fn retentionBundle(arena: std.mem.Allocator, body: []const u8) !*const chock_policy.org.Bundle {
    const source = try std.fmt.allocPrintSentinel(arena, ".{{{s}}}", .{body}, 0);
    return chock_policy.org.parse(arena, source, null);
}

test "an installation with no org bundle removes and prunes exactly as it always did" {
    // **The default, and the thing every session of this project depends on.**
    // A bundle is read as a ceiling, so an action no rule names answers `allow`,
    // and an installation nobody gave a bundle has no rules at all.
    //
    // Mutation check: read the bundle as a decision instead of a ceiling, with
    // `evaluateChain`, and every removal on every machine is refused the moment
    // an organisation issues a bundle about anything at all.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // No bundle at all: no parse, no table, no allocation.
    try testing.expectEqual(@as(?[]const u8, null), try retentionRefusal(arena, &.{}, remove_action));
    try testing.expectEqual(@as(?[]const u8, null), try retentionRefusal(arena, &.{}, prune_action));

    // A bundle that narrows something else entirely says nothing about a
    // removal, which is what "a ceiling and not a decision" means.
    const elsewhere = try retentionBundle(arena,
        \\ .rules = .{
        \\   .{ .action = "git.push", .decision = .deny },
        \\   .{ .action = "provider.public.*", .decision = .deny },
        \\ },
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, elsewhere.rules, remove_action),
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, elsewhere.rules, prune_action),
    );
}

test "a retention row in the org bundle refuses a removal, and --yes does not answer it" {
    // **The shape the whole feature takes: a row that stops a removal.** No new
    // field in `chock_policy.org`, no second policy system, and no question a
    // person at the machine can answer their way past.
    //
    // Mutation check: return null for `deny` and this fails; drop the check from
    // `main` and the test below that reads the message still passes, which is
    // why `main`'s own call site is one line and this is the rule.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const keeps = try retentionBundle(arena,
        \\ .subject = "ross@example.org",
        \\ .rules = .{ .{ .action = "session.remove", .decision = .deny } },
    );

    const why = (try retentionRefusal(arena, keeps.rules, remove_action)).?;
    try testing.expect(std.mem.indexOf(u8, why, "requires session logs to be kept") != null);
    // It names the action, so a reader knows which row to look at, and it says
    // plainly that the flag they were about to reach for does not help.
    try testing.expect(std.mem.indexOf(u8, why, remove_action) != null);
    try testing.expect(std.mem.indexOf(u8, why, "--yes does not answer this") != null);

    // **A rule for one is not a rule for the other.** An organisation that lets
    // a person be rid of one session by hand, and never sweep a directory
    // clean, writes one row and not the other, and this is what makes those two
    // separate decisions rather than one.
    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, keeps.rules, prune_action),
    );

    // And the other way round.
    const no_sweeping = try retentionBundle(arena,
        \\ .rules = .{ .{ .action = "session.prune", .decision = .deny } },
    );
    try testing.expect((try retentionRefusal(arena, no_sweeping.rules, prune_action)) != null);
    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, no_sweeping.rules, remove_action),
    );

    // A class pattern covers both with one row, because the action names share a
    // class in the very language `chock.zon` speaks.
    const keeps_everything = try retentionBundle(arena,
        \\ .rules = .{ .{ .action = "session.*", .decision = .deny } },
    );
    try testing.expect((try retentionRefusal(arena, keeps_everything.rules, remove_action)) != null);
    try testing.expect((try retentionRefusal(arena, keeps_everything.rules, prune_action)) != null);
}

test "every decision a retention row can hold is answered, and only two of them let a removal go" {
    try testing.expect(retentionAllows(.allow));
    // `ask` is what this command already does next, so it changes nothing.
    try testing.expect(retentionAllows(.ask));
    try testing.expect(!retentionAllows(.deny));
    // **There is no agent at a `chock sessions` prompt to review anything.** An
    // absent answer is never a permissive answer, so a row that asks for a
    // reviewer refuses rather than falling through to the question.
    try testing.expect(!retentionAllows(.agent_review));
    try testing.expect(!retentionAllows(.agent_then_human));

    // Every member is named above, so adding one is a change somebody makes on
    // purpose in two places.
    const named = [_]chock_policy.table.Decision{
        .allow, .ask, .deny, .agent_review, .agent_then_human,
    };
    try testing.expectEqual(
        @typeInfo(chock_policy.table.Decision).@"enum".fields.len,
        named.len,
    );
    for (named) |one| _ = retentionAllows(one);
}

test "a retention row keeps binding after the bundle it came in has expired" {
    // `chock_policy.org` decides this once for the whole program: an expired
    // bundle keeps binding, in full, because a bundle can only narrow, so
    // dropping one can only widen and can only widen at the moment nobody can be
    // reached to say whether that is right. A retention rule that lapsed on its
    // own would be a record that could be destroyed by keeping a laptop off a
    // network for a week.
    //
    // Mutation check: read `expires_ms` here and this fails, which is the point:
    // nothing in this file reads that date.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const stale = try retentionBundle(arena,
        \\ .expires_ms = 5000,
        \\ .rules = .{ .{ .action = "session.remove", .decision = .deny } },
    );
    try testing.expect(stale.expiredAt(std.math.maxInt(i64)));
    try testing.expect((try retentionRefusal(arena, stale.rules, remove_action)) != null);
}

test "a retention row narrowed to one agent kind is read for the kind a person's session runs under" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const for_main = try retentionBundle(arena,
        \\ .rules = .{ .{ .agent_kind = "main", .action = "session.remove", .decision = .deny } },
    );
    try testing.expect((try retentionRefusal(arena, for_main.rules, remove_action)) != null);

    const for_somebody_else = try retentionBundle(arena,
        \\ .rules = .{ .{ .agent_kind = "reviewer", .action = "session.remove", .decision = .deny } },
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, for_somebody_else.rules, remove_action),
    );
    try testing.expectEqualStrings("main", retention_kind);
}

test "the org bundle is a command line option here too, and it takes a path" {
    const with_bundle = try parseOptions(&.{
        "remove",       "01JQ" ++ "A" ** 22,
        "--org-bundle", "/somewhere/org-policy.zon",
    });
    try testing.expectEqualStrings("/somewhere/org-policy.zon", with_bundle.org_bundle.?);

    // Off unless asked for, and it needs a value.
    try testing.expectEqual(@as(?[]const u8, null), (try parseOptions(&.{})).org_bundle);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "prune", "--org-bundle" }));
}

test "--require-card is a seal option and no other command takes it" {
    // **Only `seal` chooses a key.** A `verify` that took the flag would read as
    // though it had checked something it never looked at, which is a false claim
    // about what a run measured.
    const asked = try parseOptions(&.{ "seal", "--require-card" });
    try testing.expect(asked.require_card);
    try testing.expectEqual(Action.seal, asked.action);

    // Off unless asked for. A machine with no reader is the ordinary case and a
    // software seal there is recorded and honest.
    try testing.expect(!(try parseOptions(&.{"seal"})).require_card);
    try testing.expect(!(try parseOptions(&.{})).require_card);

    for ([_][]const u8{ "list", "verify", "prune" }) |other| {
        try testing.expectError(error.BadArguments, parseOptions(&.{ other, "--require-card" }));
    }
}

test "an exported log is byte for byte the original, and verifies as the copy" {
    // **The whole point of a copy**: a reader at the far end runs the very code
    // that wrote the log, over a file this machine no longer controls. So the
    // copy has to be the log and not a re-encoding of it, which
    // `lib/chock-proto/chain.zig`'s reordered key test says would read as
    // tampering.
    //
    // Mutation check: write the events back out through the encoder instead of
    // copying the stored bytes and the verdict below stops being `intact`.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const dir = try std.fmt.allocPrint(arena, "{s}/sessions", .{root});
    const to = try std.fmt.allocPrint(arena, "{s}/audit", .{root});
    try std.Io.Dir.cwd().createDirPath(io, dir);
    try std.Io.Dir.cwd().createDirPath(io, to);

    const id = "01JQ" ++ "A" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    {
        var backing = chock_proto.storage.JsonLines{
            .log = try chock_proto.log.Log.open(io, log_path, id),
        };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        _ = try locked.append(arena, io, .{ .session_start = .{
            .agent_kind = "main",
            .model_alias = "m",
            .parent_session = "",
        } }, 1000);
        _ = try locked.append(arena, io, .{
            .session_end = .{ .reason = .finished, .detail = "" },
        }, 2000);
        try locked.unlock(io);
    }

    const done = try exportSession(arena, io, dir, to, id);
    try testing.expectEqual(@as(?anyerror, null), done.fault);
    // Two events and the header line.
    try testing.expectEqual(@as(u64, 3), done.lines);
    try testing.expectEqual(chain.Verdict.intact, done.report.verdict);

    const original = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, done.path, arena, .limited(1 << 20));
    try testing.expectEqualStrings(original, copy);
}

test "exporting a log takes nothing away and leaves its lock free" {
    // Mutation check: open the source for writing, or take its lock, and the
    // lock below is refused.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const dir = try std.fmt.allocPrint(arena, "{s}/sessions", .{root});
    const to = try std.fmt.allocPrint(arena, "{s}/audit", .{root});
    try std.Io.Dir.cwd().createDirPath(io, dir);
    try std.Io.Dir.cwd().createDirPath(io, to);

    const id = "01JQ" ++ "B" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    var backing = chock_proto.storage.JsonLines{
        .log = try chock_proto.log.Log.open(io, log_path, id),
    };
    const store = backing.storage();
    defer store.close(io);
    {
        var locked = try store.lock(io);
        _ = try locked.append(arena, io, .{
            .session_end = .{ .reason = .finished, .detail = "" },
        }, 1000);
        try locked.unlock(io);
    }
    const before = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));

    _ = try exportSession(arena, io, dir, to, id);

    const after = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));
    try testing.expectEqualStrings(before, after);
    // The log is still there and its lock is still free, so a session running
    // now would not have been disturbed.
    var locked = try store.lock(io);
    try locked.unlock(io);
}

test "a log somebody edited exports, and the copy says it was edited" {
    // **A copy is not a laundering step.** A log that was already rewritten
    // before anybody copied it is copied faithfully, and the verdict on the copy
    // says so, because the copy carries the very bytes the chain disagrees over.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try chock_proto.log.absoluteDirPath(io, &buffer, tmp.dir);
    const dir = try std.fmt.allocPrint(arena, "{s}/sessions", .{root});
    const to = try std.fmt.allocPrint(arena, "{s}/audit", .{root});
    try std.Io.Dir.cwd().createDirPath(io, dir);
    try std.Io.Dir.cwd().createDirPath(io, to);

    const id = "01JQ" ++ "C" ** 22;
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    {
        var backing = chock_proto.storage.JsonLines{
            .log = try chock_proto.log.Log.open(io, log_path, id),
        };
        const store = backing.storage();
        defer store.close(io);
        var locked = try store.lock(io);
        for (0..3) |turn| {
            _ = try locked.append(arena, io, .{
                .session_end = .{ .reason = .finished, .detail = "" },
            }, @intCast(1000 + turn));
        }
        try locked.unlock(io);
    }

    // One line changed in place, which is the cheap attack and so the realistic
    // one. The line after it now names bytes that are no longer there.
    const whole = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));
    const at = std.mem.indexOf(u8, whole, "\"detail\":\"\"").?;
    const edited = try std.mem.concat(arena, u8, &.{
        whole[0..at],
        "\"detail\":\"x\"",
        whole[at + "\"detail\":\"\"".len ..],
    });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = log_path, .data = edited });

    const done = try exportSession(arena, io, dir, to, id);
    try testing.expectEqual(chain.Verdict.broken, done.report.verdict);
    // And the copy really is the edited file, so the far end reads the same
    // bytes and reaches the same verdict for itself.
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, done.path, arena, .limited(1 << 20));
    try testing.expectEqualStrings(edited, copy);
}

test "export needs somewhere to write, and no other action may name one" {
    // A copy with no destination would have to invent one, and inventing where
    // an audit trail lands is the one thing this command must never do.
    const id = "01JQ" ++ "A" ** 22;

    const whole_project = try parseOptions(&.{ "export", "--to", "/var/audit" });
    try testing.expectEqual(Action.@"export", whole_project.action);
    try testing.expectEqualStrings("/var/audit", whole_project.to.?);
    try testing.expectEqualStrings("", whole_project.session);

    const one = try parseOptions(&.{ "export", id, "--to", "/var/audit" });
    try testing.expectEqualStrings(id, one.session);

    try testing.expectError(error.BadArguments, parseOptions(&.{"export"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "export", "--to" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "list", "--to", "/var/audit" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "prune", "--older-than", "1", "--to", "/x" }));

    // The word a person types is `export`, whatever Zig calls the member.
    try testing.expectEqualStrings("export", @tagName(Action.@"export"));
}

test "nobody at a keyboard is a refusal, decided before a byte is written" {
    // **The rule `lib/chock-core/ask.zig` keeps, read the same way round.** A
    // subagent, a session `chock daemon` started and a piped run all have
    // nobody at a keyboard, and a prompt drawn where nothing can answer it is a
    // hang that holds a card seal for ever.
    //
    // The capture is what proves "before a byte": nothing at all reaches either
    // stream, so no prompt was drawn and no counter was announced.
    //
    // Mutation check: drop the `at_terminal` test at the top of
    // `TerminalPin.askFn` and this fails, because the run tries to read a line
    // and writes the question first.
    var said = tty.Capture{
        .out_sink = undefined,
        .err_sink = undefined,
        .out_tap = undefined,
        .err_tap = undefined,
    };
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    var asking = TerminalPin{ .io = testing.io, .at_terminal = false };
    var buffer: chock_pcsc.pin.Buffer = undefined;
    const answer = asking.asker().ask(.{
        .reader = "Yubico YubiKey OTP+FIDO+CCID 00 00",
        .slot = .digital_signature,
        .tries = .{ .left = 3 },
    }, &buffer);

    try testing.expectEqual(chock_pcsc.pin.Answer.nobody, answer);
    try testing.expectEqualStrings("", said.out());
    try testing.expectEqualStrings("", said.err());
    // And nobody was asked, so no prompt happened at all.
    try testing.expectEqual(@as(usize, 0), asking.asked);
}

test "a read that failed says what happened, and only an empty answer is a decline" {
    // **The fault this closes.** A person who typed a line longer than the
    // prompt reads was told "none was given", which is a false statement about
    // what they did. It is the same mistake as telling a person who gave
    // nothing that their PIN was malformed, pointing the other way.
    //
    // A fact and not a `readSecret`, because a test binary has no terminal to
    // fail at. `tty.secretTermios` is tested the same way and for the same
    // reason.
    //
    // Mutation check: answer `.declined` for any error but `error.Empty` and
    // that row fails.
    const cases = [_]struct { err: tty.SecretError, want: chock_pcsc.pin.Answer }{
        .{ .err = error.Empty, .want = .declined },
        .{ .err = error.NotATerminal, .want = .nobody },
        .{ .err = error.EchoStuck, .want = .unreadable },
        .{ .err = error.Unreadable, .want = .unreadable },
        .{ .err = error.TooLong, .want = .too_long },
    };

    var declines: usize = 0;
    for (cases) |one| {
        const answer = answerFor(one.err);
        try testing.expectEqual(std.meta.activeTag(one.want), std.meta.activeTag(answer));
        if (answer == .declined) declines += 1;
    }
    // Exactly one of them is a person choosing to give nothing. Every other one
    // is something that happened to the read.
    try testing.expectEqual(@as(usize, 1), declines);

    // **Every error the read can answer is decided above**, so a new one cannot
    // arrive later and be rounded to a decline by whoever adds it.
    inline for (@typeInfo(tty.SecretError).error_set.?) |field| {
        var decided = false;
        for (cases) |one| {
            if (std.mem.eql(u8, @errorName(one.err), field.name)) decided = true;
        }
        try testing.expect(decided);
    }
}

test "the count of tries left is said before anybody types, and it names the reader" {
    // The number a person needs to decide whether to try at all. It comes off
    // the card, and this is the line that puts it in front of them.
    var said = tty.Capture{
        .out_sink = undefined,
        .err_sink = undefined,
        .out_tap = undefined,
        .err_tap = undefined,
    };
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    sayTries(.{
        .reader = "Yubico YubiKey OTP+FIDO+CCID 00 00",
        .slot = .digital_signature,
        .tries = .{ .left = 3 },
    });
    try testing.expect(std.mem.indexOf(u8, said.err(), "3 tries left") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "Yubico YubiKey") != null);
    // The consequence is stated, because "3 tries" means nothing to somebody who
    // does not know what the card does after the last one.
    try testing.expect(std.mem.indexOf(u8, said.err(), "PUK") != null);
    // And the way out is stated, so a person who does not have the PIN to hand
    // is not left guessing.
    try testing.expect(std.mem.indexOf(u8, said.err(), "software key instead") != null);

    // One try left is painted as a failure and not as a warning: it is the last
    // one before the card blocks.
    said.clear();
    sayTries(.{ .reader = "", .slot = .digital_signature, .tries = .{ .left = 1 } });
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 try left") != null);

    // A card that named no count says so rather than saying plenty.
    said.clear();
    sayTries(.{ .reader = "", .slot = .digital_signature, .tries = .unknown });
    try testing.expect(std.mem.indexOf(u8, said.err(), "did not say") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "three") != null);

    // And a blocked card is named as needing the PUK, before anybody types into
    // a counter with nothing left to spend.
    said.clear();
    sayTries(.{ .reader = "", .slot = .digital_signature, .tries = .blocked });
    try testing.expect(std.mem.indexOf(u8, said.err(), "no tries left") != null);
}
