//! `chock sessions`: what this project's sessions were, which of them is
//! running right now, and how to be rid of one. Removing one destroys the only
//! account of what an agent did, which is why `remove` asks first.

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

const log_suffix = ".jsonl";
const work_suffix = ".work";
const root_suffix = ".root";

pub const answer_timeout_ms: u64 = 5 * 60 * 1000;

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
    org_bundle: ?[]const u8 = null,
    to: ?[]const u8 = null,
    require_card: bool = false,
};

const Action = enum {
    list,
    verify,
    seal,
    @"export",
    remove,
    prune,

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
    // remove path spawns a bare `git`. Left out, a Nix machine finds no `git`.
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

    if (options.action == .remove and !session_paths.isValidId(options.session)) {
        tty.print(
            .err,
            "chock sessions remove: \"{s}\" is not a session identifier\n",
            .{options.session},
        );
        return Exit.usage.code();
    }

    const org_rules = loadOrgRules(arena, io, &env, options.org_bundle) orelse
        return Exit.refused.code();
    const action = switch (options.action) {
        .remove => remove_action,
        .prune => prune_action,
        .list, .verify, .seal, .@"export" => unreachable,
    };
    if (try retentionRefusal(arena, org_rules, action)) |why| {
        tty.print(.warn, "chock sessions {s}: {s}\n", .{ @tagName(options.action), why });
        return Exit.refused.code();
    }

    if (!canAsk(options.yes, approval.hasTerminal(io))) {
        tty.print(
            .warn,
            "chock sessions: removing a session destroys the only record of what it did, " ++
                "and there is nobody here to ask. Run this at a terminal, or pass --yes.\n",
            .{},
        );
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

pub fn canAsk(assume_yes: bool, at_terminal: bool) bool {
    return assume_yes or at_terminal;
}

pub const remove_action = "session.remove";

pub const prune_action = "session.prune";

pub const retention_kind = "main";

pub const retention_tool = "sessions";

pub const retention_model = "none";

pub fn retentionAllows(decision: chock_policy.table.Decision) bool {
    return switch (decision) {
        .allow => true,
        .ask => true,
        .deny => false,
        .agent_review, .agent_then_human => false,
    };
}

pub fn retentionRefusal(
    arena: std.mem.Allocator,
    org_rules: []const chock_policy.table.Rule,
    action: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    if (org_rules.len == 0) return null;

    const table = chock_policy.table.Table.parseUnder(arena, ".{}", org_rules, null) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
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
        error.NoBundleFile => {
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
    return bundle.rules;
}

pub const Liveness = enum {
    live,
    idle,
    unknown,
};

/// Whether the session whose log is at `log_path` is running. The lock answers
/// this and a timestamp cannot: a killed session leaves a log written a moment
/// ago and no process, and the kernel drops the lock when the last descriptor
/// closes.
pub fn livenessOf(io: std.Io, log_path: [:0]const u8) Liveness {
    var one = probe(io, log_path) orelse return .unknown;
    defer one.release(io);
    return if (one.acquired) .idle else .live;
}

/// Shared, and the choice is load bearing: two probes must not contend.
const probe_lock: std.Io.File.Lock = .shared;

const Probe = struct {
    file: std.Io.File,
    acquired: bool,

    /// The close alone would do it, since the kernel drops a description's locks
    /// when its last descriptor goes. The unlock is written out so the release
    /// does not depend on that.
    fn release(self: *Probe, io: std.Io) void {
        if (self.acquired) self.file.unlock(io);
        self.file.close(io);
        self.* = undefined;
    }
};

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

pub const Readiness = enum {
    ready,
    no_such_session,
    nothing_to_carry_on,
    running,
    unknown,
};

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

    return switch (livenessOf(io, log_path)) {
        .idle => .ready,
        .live => .running,
        .unknown => .unknown,
    };
}

pub const Session = struct {
    id: []const u8,
    started_ms: u64,
    model: []const u8 = "",
    model_count: usize = 0,
    title: []const u8 = "",
    model_alias: []const u8 = "",
    end: ?event.SessionEndReason = null,
    spend: state.Spend = .{},
    live: Liveness = .unknown,
    readable: bool = true,
    complete: bool = true,
    chain: chain.Report = .{},
    seal: seal.Reading = .{},
    header_digest: chain.Digest = [_]u8{'?'} ** chain.digest_len,
    head_digest: chain.Digest = [_]u8{'?'} ** chain.digest_len,
    has_work: bool = false,
    has_root: bool = false,
};

fn holdsAnything(io: std.Io, dir_path: []const u8) bool {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch return false;
    defer dir.close(io);
    var it = dir.iterateAssumeFirstIteration();
    const first = it.next(io) catch return false;
    return first != null;
}

pub fn logPathIn(
    allocator: std.mem.Allocator,
    dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error![:0]u8 {
    std.debug.assert(session_paths.isValidId(id));
    return std.fmt.allocPrintSentinel(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
}

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
        const line_start = replay.at();
        const parsed = replay.next(io) catch {
            one.complete = false;
            one.chain = reader.finish(.undecodable, line_start);
            break;
        } orelse {
            const torn = replay.truncated();
            if (torn) one.complete = false;
            one.chain = reader.finish(if (torn) .torn else .complete, line_start);
            break;
        };
        defer parsed.deinit();
        reader.take(parsed.value.id, replay.line(), parsed.value.prev);

        switch (parsed.value.event) {
            .session_start => |start| {
                if (one.model_alias.len == 0 and start.model_alias.len != 0) {
                    one.model_alias = try allocator.dupe(u8, start.model_alias);
                }
            },
            .session_end => |ended| one.end = try dupeReason(allocator, ended.reason),
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
    one.head_digest = reader.expected;
    one.seal = readSeal(allocator, io, path, one);
    return one;
}

fn readSeal(
    allocator: std.mem.Allocator,
    io: std.Io,
    log_path: []const u8,
    one: Session,
) seal.Reading {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = sidecar.pathFor(&path_buffer, log_path) catch return .{ .verdict = .absent };

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
            .root = null,
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

fn dupeReason(
    allocator: std.mem.Allocator,
    reason: event.SessionEndReason,
) std.mem.Allocator.Error!event.SessionEndReason {
    return switch (reason) {
        .unknown => |name| .{ .unknown = try allocator.dupe(u8, name) },
        else => reason,
    };
}

/// Every session of `dir`, oldest first. A session identifier starts with the
/// millisecond it was made, in an alphabet that sorts in the same order, so the
/// directory listing is already sorted and no index is kept. Caller owns the
/// slice and everything in it.
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

pub const time_text_bytes: usize = 32;

const year_10000_ms: u64 = 253402300800000;

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

pub const title_marker = "      | ";

pub const title_legend = "The indented line under a session is the title the agent gave it, in " ++
    "the agent's own words.";

pub const title_not_text = "(a title that is not text)";

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
        // over UTF-8: every byte of a multi byte character is 0x80 or above.
        const drives_the_terminal = byte < 0x20 or byte == 0x7F;
        try kept.append(allocator, if (drives_the_terminal) '?' else byte);
    }

    const cut = chock_core.notices.cutToCharacter(kept.items, chock_core.Loop.max_title_bytes);
    if (cut.len == kept.items.len) return try allocator.dupe(u8, cut);
    return try std.fmt.allocPrint(allocator, "{s} (the rest of this title is not shown)", .{cut});
}

pub fn stateText(one: Session) []const u8 {
    if (one.live == .live) return "running";
    if (one.end) |reason| return reason.wireName();
    if (one.live == .unknown) return "no end recorded, lock not tested";
    return "no end recorded";
}

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

pub fn chainText(
    allocator: std.mem.Allocator,
    report: chain.Report,
) std.mem.Allocator.Error![]u8 {
    return switch (report.verdict) {
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

fn levelRank(level: ?seal.Level) []const u8 {
    return switch (level orelse .software) {
        .card_attested => "level 1 of 3, the strongest of the three",
        .card => "level 2 of 3, the middle of the three",
        .software => "level 3 of 3, the weakest of the three",
    };
}

fn levelText(level: ?seal.Level) []const u8 {
    return switch (level orelse .software) {
        .card_attested => "a card key, with an attestation saying it was made there and never left",
        .card => "a card key, with no attestation, so nothing here can check that claim",
        .software => "a software key, which proves one key signed and nothing about where it lives",
    };
}

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

    tty.detail("{s}\n{s}\n\n", .{ project_root, dir });

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
        if (!one.readable) tty.out(.warn, "  (this log could not be read)", .{});
        if (one.readable) {
            if (try chainNote(arena, one.chain)) |note| {
                const rank: tty.Rank = if (one.chain.edited()) .err else .warn;
                if (one.chain.edited()) edited_count += 1;
                tty.out(rank, "{s}", .{note});
            }
        }
        tty.out(.plain, "\n", .{});

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
    tty.out(.plain, ".\n", .{});

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
        const rank: tty.Rank = switch (one.chain.verdict) {
            .intact, .partly_chained => .plain,
            .unchained, .torn => .warn,
            .broken, .undecodable, .unreadable => .err,
        };
        tty.out(rank, "{s}  {s}\n", .{ one.id, try chainText(arena, one.chain) });

        if (one.seal.signed()) sealed_count += 1;
        const seal_rank: tty.Rank = switch (one.seal.verdict) {
            .absent, .signed_software, .signed_card, .signed_card_attested => .plain,
            .malformed => .warn,
            .signature_bad, .head_mismatch, .claim_unsupported => .err,
        };
        var indent_buffer: [session_paths.id_length]u8 = @splat(' ');
        const indent = indent_buffer[0..@min(one.id.len, indent_buffer.len)];
        tty.out(seal_rank, "{s}  {s}\n", .{ indent, try sealText(arena, one.seal) });

        if (rank == .err or seal_rank == .err) damaged += 1;
    }

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
    return Exit.faulted.code();
}

const Choice = struct {
    signer: seal.Signer,
    level: seal.Level,
    card: chock_pcsc.attempt.Outcome,
    reader: []const u8 = "",
    detail: []const u8 = "",
    pin_bytes: ?usize = null,
    tries: ?chock_pcsc.piv.Tries = null,
    require_card: bool = false,

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

fn sealSessions(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    project_root: []const u8,
    id: []const u8,
    choice: Choice,
) !u8 {
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

        var held = seal.Held{};
        const written = seal.sign(.{
            .session = one.id,
            .header = one.header_digest,
            .head = one.head_digest,
            .events = one.chain.events,
            .level = level,
        }, signer, &held) catch |err| {
            refused += 1;
            const why = signer.reason() orelse {
                tty.print(.err, "{s}  this log could not be signed: {s}\n", .{ one.id, @errorName(err) });
                continue;
            };
            tty.print(.err, "{s}  this log was not sealed: {s}\n", .{ one.id, why });
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

        tty.out(.plain, "{s}  sealed over {d} {s}, {s}\n", .{
            one.id,
            one.chain.events,
            eventWord(one.chain.events),
            levelRank(level),
        });
    }

    tty.out(.plain, "\n{s}\n", .{try signedWithText(arena, choice, sessions.len - refused)});

    if (refused == 0) return Exit.finished.code();
    tty.print(
        .err,
        "\nchock sessions seal: {d} of {d} {s} not sealed.\n",
        .{ refused, sessions.len, if (sessions.len == 1) "log was" else "logs were" },
    );
    return Exit.faulted.code();
}

fn signedWithText(
    allocator: std.mem.Allocator,
    choice: Choice,
    sealed: usize,
) std.mem.Allocator.Error![]u8 {
    const subject = if (sealed == 1) "The seal above" else "Every seal above";

    if (choice.card == .ready) {
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

    var room: [chock_pcsc.attempt.max_sentence_len]u8 = undefined;
    const why = choice.card.sentenceWith(choice.pin_bytes, &room);

    if (choice.detail.len == 0) return std.fmt.allocPrint(
        allocator,
        "No card key signed on this run, because {s}. " ++
            "{s} was signed with this installation's software key, and that is {s}: {s}.",
        .{ why, subject, levelRank(choice.level), levelText(choice.level) },
    );

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
    // The seal key lives wherever the credentials do, so a machine using the
    // keystore does not leave this one key in a file beside it.
    const config_dir = chock_auth.paths.configDir(arena, env) catch |err| {
        tty.print(.err, "chock sessions seal: the configuration directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };
    var driver = chock_auth.store.Driver{
        .data_dir = data_dir,
        .store = chock_auth.config.credentialStore(arena, io, config_dir),
        .env = env,
    };

    // It must not move, because the attempt below points at it and the signer
    // points at the attempt.
    var transport = chock_pcsc.default(io);
    defer transport.deinit();
    var scratch: [chock_pcsc.piv.max_object_len]u8 = undefined;
    var attempt = chock_pcsc.attempt.Attempt.init(transport.pcsc(), &scratch);
    defer attempt.deinit();

    var asking = TerminalPin{ .io = io, .at_terminal = approval.hasTerminal(io) };
    attempt.asker = asking.asker();
    const found = attempt.open();

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

    const measured = Fallback{
        .found = found,
        .require_card = require_card,
        .tries = attempt.tries,
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

const Fallback = struct {
    found: chock_pcsc.attempt.Outcome,
    require_card: bool,
    tries: ?chock_pcsc.piv.Tries = null,
    pin_bytes: ?usize = null,
    detail: []const u8 = "",
};

fn sealRefusal(
    allocator: std.mem.Allocator,
    fallback: Fallback,
) std.mem.Allocator.Error!?[]u8 {
    if (fallback.found == .ready) return null;

    var room: [chock_pcsc.attempt.max_sentence_len]u8 = undefined;
    const why = fallback.found.sentenceWith(fallback.pin_bytes, &room);

    if (fallback.found.pinAttemptFailed()) {
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

const TerminalPin = struct {
    io: std.Io,
    at_terminal: bool,
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

fn answerFor(err: tty.SecretError) chock_pcsc.pin.Answer {
    return switch (err) {
        error.Empty => .declined,
        error.NotATerminal => .nobody,
        error.EchoStuck, error.Unreadable => .unreadable,
        error.TooLong => .too_long,
    };
}

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

fn transportDetail(
    arena: std.mem.Allocator,
    transport: *chock_pcsc.Driver,
    found: chock_pcsc.attempt.Outcome,
) []const u8 {
    if (comptime !@hasDecl(chock_pcsc.platform, "Failure")) {
        return "";
    } else {
        if (!found.fromTransport()) return "";
        const failure = transport.failure orelse return "";
        return std.fmt.allocPrint(arena, "{f}", .{failure}) catch "";
    }
}

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
            // curve, so a store somebody edited. Never a reason to make a new
            // key: that would quietly orphan every seal the old one wrote.
            tty.print(
                .err,
                "chock sessions seal: the stored signing key is not a key on the curve. " ++
                    "Nothing was signed, and nothing was replaced.\n",
                .{},
            );
            return null;
        };
    }

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

pub const Exported = struct {
    id: []const u8,
    path: []const u8,
    lines: u64,
    report: chain.Report = .{},
    fault: ?anyerror = null,
};

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

fn exportSessions(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    to: []const u8,
) !u8 {
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

    pub fn totalBytes(self: Removal) u64 {
        return self.log_bytes + self.work.bytes + self.root.bytes;
    }
};

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
    WorkspaceKept,
    SandboxRootKept,
    LogKept,
};

pub fn remove(io: std.Io, plan: Removal) RemoveError!void {
    if (plan.has_work) {
        std.Io.Dir.cwd().deleteTree(io, plan.work_path) catch return error.WorkspaceKept;
    }
    if (plan.has_root) {
        std.Io.Dir.cwd().deleteTree(io, plan.root_path) catch return error.SandboxRootKept;
    }
    std.Io.Dir.cwd().deleteTree(io, plan.log_path) catch return error.LogKept;
}

pub fn agreed(io: std.Io, console: approval.Console, question: []const u8) bool {
    approval.writeFiltered(console, io, question);

    var line: [approval.max_answer_bytes]u8 = undefined;
    var filled: usize = 0;
    while (filled < line.len) {
        switch (console.read(io, line[filled..], answer_timeout_ms)) {
            .bytes => |count| {
                if (count == 0) return false;
                const before = filled;
                filled += count;
                const at = std.mem.indexOfScalar(u8, line[before..filled], '\n') orelse continue;
                return approval.saysYes(line[0 .. before + at]);
            },
            .idle, .ended, .canceled => return false,
        }
    }
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
    if (removed == 0) return Exit.usage.code();
    return Exit.finished.code();
}

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

    if (options.action == .remove and options.session.len == 0) return error.BadArguments;
    if (!options.action.takesSession() and options.session.len != 0) return error.BadArguments;
    if (options.action == .prune and options.older_than_days == null) return error.BadArguments;
    if (options.action != .prune and options.older_than_days != null) return error.BadArguments;
    if (options.action == .@"export" and options.to == null) return error.BadArguments;
    if (options.action != .@"export" and options.to != null) return error.BadArguments;
    if (options.action != .seal and options.require_card) return error.BadArguments;
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

const testing = std.testing;

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

fn scratchDir(arena: std.mem.Allocator, tmp: *testing.TmpDir, leaf: []const u8) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ buffer[0..len], leaf });
}

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

    try testing.expectError(error.BadArguments, parseOptions(&.{"remove"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "list", "01JQ" ++ "A" ** 22 }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"prune"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "prune", "--older-than", "not-a-number" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "list", "--older-than", "30" }));

    try testing.expectError(error.BadArguments, parseOptions(&.{"forget-everything"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "a session another process owns reads as live, and the probe leaves its lock alone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);

    try testing.expectEqual(Liveness.idle, livenessOf(testing.io, path));

    var owner = try chock_proto.log.Log.open(testing.io, path, id);
    var held = try owner.lock(testing.io);

    try testing.expectEqual(Liveness.live, livenessOf(testing.io, path));

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

    try held.unlock(testing.io);
    owner.close(testing.io);
    try testing.expectEqual(Liveness.idle, livenessOf(testing.io, path));

    const missing = try std.fmt.allocPrintSentinel(arena, "{s}/never-made" ++ log_suffix, .{dir}, 0);
    try testing.expectEqual(Liveness.unknown, livenessOf(testing.io, missing));
}

test "two probes at the same moment never mistake each other for a running session" {
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
    try testing.expect(second.acquired);

    try testing.expectEqual(Liveness.idle, livenessOf(testing.io, path));
}

test "a live session is never removable, and the refusal is not an exit of zero" {
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

    var fake = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer fake.deinit();

    var owner = try chock_proto.log.Log.open(testing.io, path, id);
    var held = try owner.lock(testing.io);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const code = try removeSession(arena, testing.io, &env, fake.console(), true, dir, project, id);
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "running now") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "lock") != null);
    try testing.expectEqualStrings("", said.out());
    said.clear();
    try testing.expectEqual(@as(usize, 0), fake.reads);

    _ = try std.Io.Dir.cwd().statFile(testing.io, path, .{});
    const work = try std.fmt.allocPrint(arena, "{s}/{s}" ++ work_suffix, .{ dir, id });
    try testing.expect(chock_core.cache.exists(testing.io, work));

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
    const unknown = Session{ .id = "01JQ" ++ "A" ** 22, .started_ms = 0, .live = .unknown };
    try testing.expectEqualStrings("no end recorded, lock not tested", stateText(unknown));

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

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

    try testing.expect(sessions[0].started_ms < sessions[1].started_ms);
    try testing.expect(sessions[1].started_ms < sessions[2].started_ms);

    var buffer: [time_text_bytes]u8 = undefined;
    try testing.expectEqualStrings("2025-08-12 12:00 UTC", timeText(&buffer, sessions[1].started_ms));

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

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        Exit.finished.code(),
        try listSessions(arena, testing.io, dir, "/home/somebody/work/parser"),
    );

    try testing.expect(std.mem.indexOf(u8, said.out(), good) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), broken) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "could not be read") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "/home/somebody/work/parser") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), dir) == null);
    try testing.expectEqualStrings("", said.err());

    said.clear();
    tty.configure(.{ .verbose = true });
    defer tty.configure(.{});
    _ = try listSessions(arena, testing.io, dir, "/home/somebody/work/parser");
    try testing.expect(std.mem.indexOf(u8, said.err(), "/home/somebody/work/parser") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), dir) != null);

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

    try testing.expectEqualStrings("budget_reached", stateText(one));

    try testing.expectEqualStrings("claude-opus-5 and 1 more", try modelText(arena, one));

    const quiet = "01K2F2DKG0" ++ "B" ** 16;
    try makeLog(arena, testing.io, dir, quiet, &.{});
    const nothing = (try fold(arena, testing.io, dir, quiet)).?;
    try testing.expectEqualStrings("", nothing.model);
    try testing.expectEqualStrings("the main alias, unanswered", try modelText(arena, nothing));
    try testing.expectEqualStrings("no end recorded", stateText(nothing));
}

test "a session's title is the last one the agent wrote, and a resumed session keeps it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

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
    const bytes = try readLog(arena, testing.io, dir, id);
    try testing.expect(std.mem.indexOf(u8, bytes, "read the parser tests") != null);
    try testing.expect(std.mem.indexOf(u8, bytes, "\"session.title\"") != null);

    const nameless = "01K2F2DKG0" ++ "X" ** 16;
    try makeLog(arena, testing.io, dir, nameless, &.{});
    const quiet = (try fold(arena, testing.io, dir, nameless)).?;
    try testing.expectEqualStrings("", quiet.title);
    try testing.expectEqual(@as(?[]u8, null), try titleText(arena, quiet.title));
}

test "a hostile title cannot forge a row of the table or drive the terminal" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const nasty = "\x1b[2J\x1b[H\r01M0TMATKB6M4H3GY35KYA68QR  2026-08-24 19:35 UTC  finished" ++
        "\nchock sessions: 0 of these logs were edited\x07";
    const shown = (try titleText(arena, nasty)).?;

    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, 0x1b));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, '\r'));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, 0x07));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, '\n'));
    try testing.expect(std.mem.indexOf(u8, shown, "01M0TMATKB6M4H3GY35KYA68QR") != null);

    const line = try std.fmt.allocPrint(arena, title_marker ++ "{s}\n", .{shown});
    try testing.expect(std.mem.startsWith(u8, line, title_marker));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, line, "\n"));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, line, "\nchock sessions:"));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, line, "\n01M0TMATKB"));

    try testing.expectEqualStrings(title_not_text, (try titleText(arena, "\xff\xfe name")).?);

    const long = "e" ** (chock_core.Loop.max_title_bytes + 40);
    const trimmed = (try titleText(arena, long)).?;
    try testing.expect(trimmed.len < long.len);
    try testing.expect(std.mem.indexOf(u8, trimmed, "not shown") != null);
    const exact = "e" ** chock_core.Loop.max_title_bytes;
    try testing.expectEqualStrings(exact, (try titleText(arena, exact)).?);
}

test "the listing prints a title behind the gutter, and says whose words it is" {
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
    try testing.expect(std.mem.indexOf(u8, text, "\n" ++ title_marker ++
        "wire the session title tool into the loop\n") != null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, title_legend));
    try testing.expect(std.mem.indexOf(u8, text, id) != null);

    const bare = try scratchDir(arena, &tmp, "bare");
    try makeLog(arena, testing.io, bare, "01K2F2DKG0" ++ "W" ** 16, &.{});
    said.clear();
    _ = try listSessions(arena, testing.io, bare, "/project");
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, said.out(), title_legend));
    try testing.expectEqual(@as(?usize, null), std.mem.indexOf(u8, said.out(), title_marker));
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
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});
    var plan = (try planRemoval(arena, testing.io, dir, id)).?;

    plan.has_work = true;
    plan.work_path = try std.fmt.allocPrint(arena, "{s}/inside-a-file", .{plan.log_path});

    try testing.expectError(error.WorkspaceKept, remove(testing.io, plan));

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

    var wrote: tty.Capture = undefined;
    wrote.start(testing.io, testing.allocator);
    defer wrote.stop(testing.io);

    const refusals = [_][]const u8{ "n\n", "\n", "sure\n", "yes please\n" };
    for (refusals) |said| {
        var no = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{said} };
        defer no.deinit();
        const code = try removeSession(arena, testing.io, &env, no.console(), true, dir, project, id);
        try testing.expectEqual(Exit.refused.code(), code);
        try testing.expect(std.mem.indexOf(u8, no.shown.items, "only record") != null);
        _ = try std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{});
    }

    var nobody = FakeConsole{ .gpa = arena, .replies = &.{.ended} };
    defer nobody.deinit();
    try testing.expectEqual(
        Exit.refused.code(),
        try removeSession(arena, testing.io, &env, nobody.console(), true, dir, project, id),
    );
    _ = try std.Io.Dir.cwd().statFile(testing.io, plan.log_path, .{});

    try testing.expect(std.mem.indexOf(u8, wrote.err(), "nothing was removed") != null);

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
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "removed 1 of 1") != null);
}

test "a removal with nobody to ask and no --yes never happens" {
    try testing.expect(!canAsk(false, false));
    try testing.expect(canAsk(false, true));
    try testing.expect(canAsk(true, false));
    try testing.expect(canAsk(true, true));

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

    const now = 1_130 * day_ms;

    const over_ninety = try prunable(arena, &sessions, now, 90);
    try testing.expectEqual(@as(usize, 1), over_ninety.len);
    try testing.expectEqualStrings(old.id, over_ninety[0].id);

    const over_ten = try prunable(arena, &sessions, now, 10);
    try testing.expectEqual(@as(usize, 2), over_ten.len);
    for (over_ten) |one| try testing.expect(!std.mem.eql(u8, one.id, old_and_running.id));

    const exactly = try prunable(arena, &.{old}, old.started_ms + 90 * day_ms, 90);
    try testing.expectEqual(@as(usize, 1), exactly.len);
    const one_short = try prunable(arena, &.{old}, old.started_ms + 90 * day_ms - 1, 90);
    try testing.expectEqual(@as(usize, 0), one_short.len);

    const none = try prunable(arena, &sessions, now, 10_000);
    try testing.expectEqual(@as(usize, 0), none.len);

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

    const older = "01JQAAAAAA" ++ "A" ** 16;
    const newer = "01K2F2DKG0" ++ "B" ** 16;
    try makeLog(arena, testing.io, dir, older, &.{});
    try makeLog(arena, testing.io, dir, newer, &.{});

    const project = try scratchDir(arena, &tmp, "project");
    try std.Io.Dir.createDirAbsolute(testing.io, project, .default_dir);
    var env = std.process.Environ.Map.init(arena);

    const now = session_paths.startedMs(newer) + 30 * day_ms;

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
    try testing.expect(std.mem.indexOf(u8, no.shown.items, "[y/N]") != null);
    try testing.expect(std.mem.indexOf(u8, wrote.out(), "1 of 2") != null);
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "nothing was removed") != null);
    wrote.clear();

    var yes = FakeConsole{ .gpa = arena, .replies = &.{.{ .bytes = 0 }}, .lines = &.{"y\n"} };
    defer yes.deinit();
    try testing.expectEqual(
        Exit.finished.code(),
        try pruneSessions(arena, testing.io, &env, yes.console(), true, dir, project, now, 90),
    );

    const left = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 1), left.len);
    try testing.expectEqualStrings(newer, left[0].id);

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
    try testing.expect(std.mem.indexOf(u8, wrote.err(), dir) != null);
    try testing.expect(std.mem.indexOf(u8, wrote.err(), "90 days") != null);
    try testing.expectEqualStrings("", wrote.out());
    try testing.expectEqual(@as(usize, 0), never.reads);
}

test "asking about a session this project never had removes nothing and creates no log" {
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
    try testing.expect(std.mem.indexOf(u8, wrote.err(), missing) != null);
    try testing.expectEqualStrings("", wrote.out());
}

test "only a session log is read, and a file that is not one is left alone" {
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

    const plan = (try planRemoval(arena, testing.io, dir, id)).?;
    try testing.expect(plan.has_work);
}

test "every chain sentence reads as English at one event and at none" {
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

    for (std.enums.values(chain.Verdict)) |verdict| {
        const said = try chainText(arena, .{ .verdict = verdict, .events = 3, .chained = 2, .at = 90, .after = 40 });
        try testing.expect(said.len != 0);
    }
}

test "a time is printed in UTC, and a number that is not a time says so" {
    var buffer: [time_text_bytes]u8 = undefined;
    try testing.expectEqualStrings("1970-01-01 00:00 UTC", timeText(&buffer, 0));
    try testing.expectEqualStrings("2025-08-12 12:00 UTC", timeText(&buffer, 1755000000000));
    try testing.expectEqualStrings("2025-08-24 01:46 UTC", timeText(&buffer, 1756000000000));

    const far = timeText(&buffer, std.math.maxInt(u50));
    try testing.expect(std.mem.indexOf(u8, far, "no session was started") != null);
}

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

fn tearLog(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8) !u64 {
    const bytes = try readLog(arena, io, dir, id);
    const at = bytes.len;
    const torn = try std.fmt.allocPrint(arena, "{s}{{\"id\":0,\"sessi", .{bytes});
    try writeLog(arena, io, dir, id, torn);
    return at;
}

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
        previous = chain.of(bytes[start..end]);
        start = end + 1;
    }
    try writeLog(arena, io, dir, id, bytes);
}

const test_seal_seed = [_]u8{0x5e} ** 32;

fn sealForTest(arena: std.mem.Allocator, dir: []const u8, id: []const u8) !u8 {
    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    return sealSessions(arena, testing.io, dir, "/home/somebody/work/parser", id, .{
        .signer = key.signer(),
        .level = .software,
        .card = .no_reader,
    });
}

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

fn sealPathIn(arena: std.mem.Allocator, dir: []const u8, id: []const u8) ![]u8 {
    return std.fmt.allocPrint(arena, "{s}/{s}" ++ log_suffix ++ sidecar.suffix, .{ dir, id });
}

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
    try testing.expectEqual(@as(u64, 4), one.chain.events);
    try testing.expectEqual(@as(u64, 4), one.chain.chained);
    try testing.expect(!one.chain.edited());
    try testing.expect(one.complete);

    try testing.expectEqual(@as(?[]u8, null), try chainNote(arena, one.chain));
}

test "an edited log and a torn log are two different rows, and the listing does not exit zero" {
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
    try testing.expect(!torn.chain.edited());
    try testing.expectEqual(fragment_at, torn.chain.at);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const code = try listSessions(arena, testing.io, dir, "/home/somebody/work/parser");
    try testing.expect(code != Exit.finished.code());

    try testing.expect(std.mem.indexOf(u8, said.out(), "this log was edited") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "the log ends mid write") != null);
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

    try testing.expect(std.mem.indexOf(u8, said.out(), "changed after it was written") != null);
    var at_buffer: [32]u8 = undefined;
    const at_text = try std.fmt.bufPrint(&at_buffer, "{d}", .{one.chain.at});
    try testing.expect(std.mem.indexOf(u8, said.out(), at_text) != null);
    var after_buffer: [32]u8 = undefined;
    const after_text = try std.fmt.bufPrint(&after_buffer, "{d}", .{one.chain.after});
    try testing.expect(std.mem.indexOf(u8, said.out(), after_text) != null);

    try testing.expect(std.mem.indexOf(u8, said.err(), "did not check out") != null);
}

test "verify says a chain is not a signature, on a clean run as well as a bad one" {
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
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
    try testing.expectEqualStrings("", said.err());
    said.clear();

    try editLog(arena, testing.io, dir, id, "event number 0", "event number 5");
    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
}

test "a log this command sealed verifies with only the key in the seal, and the row names the level" {
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

    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.out(), "no seal") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), seal.defeats_a_rewrite) == null);
    said.clear();

    try testing.expectEqual(
        Exit.finished.code(),
        try sealForTest(arena, dir, id),
    );
    const before = try readLog(arena, testing.io, dir, id);
    try testing.expect(std.mem.indexOf(u8, before, "chock_seal") == null);
    _ = try std.Io.Dir.cwd().statFile(testing.io, try sealPathIn(arena, dir, id), .{});
    said.clear();

    try testing.expectEqual(
        Exit.finished.code(),
        try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), "level 3 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "a software key") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "ECDSA P-256") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), seal.defeats_a_rewrite) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) == null);
    try testing.expectEqualStrings("", said.err());

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.signed_software, one.seal.verdict);
    try testing.expect(one.seal.signed());
    try testing.expect(!one.seal.hardwareProved());
}

test "a log whose chain was repaired by hand passes the chain and fails the seal" {
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
    try testing.expectEqual(chain.Verdict.intact, one.chain.verdict);
    try testing.expect(!one.chain.edited());
    try testing.expectEqual(seal.Verdict.head_mismatch, one.seal.verdict);
    try testing.expectEqual(@as(?seal.Field, .head), one.seal.mismatched);
    try testing.expect(!one.seal.signed());

    const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.out(), "the chain holds over all 4 events") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "about a different log") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), chain.not_a_signature) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of 1 log did not check out") != null);
    said.clear();

    try editLog(arena, testing.io, dir, id, "event number 0", "event number 8");
    const both = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(chain.Verdict.broken, both.chain.verdict);
    try testing.expectEqual(seal.Verdict.head_mismatch, both.seal.verdict);
    _ = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", id);
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 of 1 log did not check out") != null);
}

test "an absent seal is printed as absent and never as a pass, and deleting one is visible" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
    try makeCountedLog(arena, testing.io, dir, id, 2);

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
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var key = try chock_pcsc.software.Key.fromSeed(test_seal_seed);
    const cases = [_]struct { outcome: chock_pcsc.attempt.Outcome, words: []const u8 }{
        .{ .outcome = .no_reader, .words = "no reader is attached" },
        .{ .outcome = .no_card, .words = "holds no card" },
        .{ .outcome = .no_key, .words = "it says its signature slot holds no key" },
        .{ .outcome = .no_certificate, .words = "holds no certificate" },
        .{ .outcome = .key_unsupported, .words = "cannot sign with" },
        .{ .outcome = .pin_required, .words = "nobody to ask" },
        .{ .outcome = .pin_declined, .words = "none was given" },
        .{ .outcome = .pin_too_long, .words = "bytes were typed" },
        .{ .outcome = .pin_unreadable, .words = "could not be read" },
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
        try testing.expect(std.mem.indexOf(u8, line, "links no PC/SC") == null);
        const why = std.mem.indexOf(u8, line, one.words).?;
        const what = std.mem.indexOf(u8, line, "software key").?;
        try testing.expect(why < what);
    }

    const detailed = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .software,
        .card = .no_daemon,
        .detail = "there is no pcscd socket at /run/pcscd/pcscd.comm",
    }, 4);
    try testing.expect(std.mem.indexOf(u8, detailed, "/run/pcscd/pcscd.comm") != null);

    const carded = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .card,
        .card = .ready,
        .reader = "Yubico YubiKey OTP+FIDO+CCID 00 00",
    }, 4);
    try testing.expect(std.mem.indexOf(u8, carded, "Yubico YubiKey OTP+FIDO+CCID 00 00") != null);
    try testing.expect(std.mem.indexOf(u8, carded, "9C") != null);
    try testing.expect(std.mem.indexOf(u8, carded, "software key") == null);

    const nameless = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .card,
        .card = .ready,
    }, 4);
    try testing.expect(std.mem.indexOf(u8, nameless, "9C") != null);
    try testing.expect(std.mem.indexOf(u8, nameless, "\"\"") == null);
}

test "the line says the number of bytes that were typed, and only where a length refused them" {
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
    try testing.expect(std.mem.indexOf(u8, counted, "Bytes are not characters") != null);
    try testing.expect(std.mem.indexOf(u8, counted, "more than one PIN") != null);

    const uncounted = try signedWithText(arena, .{
        .signer = key.signer(),
        .level = .software,
        .card = .pin_too_long_for_card,
    }, 1);
    try testing.expect(std.mem.indexOf(u8, uncounted, "because more bytes were typed") != null);
    try testing.expect(std.mem.indexOf(u8, uncounted, "six to eight bytes") == null);

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
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

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
        .pin_required,
        .pin_nobody,
        .pin_declined,
        .pin_blocked,
    };
    for (allowed) |one| {
        try testing.expectEqual(
            @as(?[]u8, null),
            try sealRefusal(arena, .{ .found = one, .require_card = false }),
        );
    }

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
        try testing.expect(std.mem.indexOf(u8, why, "nothing was sealed") != null);
        try testing.expect(std.mem.indexOf(u8, why, "Run the command again") != null);
        try testing.expect(std.mem.indexOf(u8, why, "press Enter") != null);
        try testing.expect(std.mem.indexOf(u8, why, "Nothing here tries again") != null);
        try testing.expect(std.mem.indexOf(u8, why, one.sentence()) != null);
    }

    try testing.expectEqual(
        @as(?[]u8, null),
        try sealRefusal(arena, .{ .found = .ready, .require_card = true }),
    );

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
    const no_count = (try sealRefusal(arena, .{ .found = .pin_wrong, .require_card = false })).?;
    try testing.expect(std.mem.indexOf(u8, no_count, "tries left") == null);

    const typed = (try sealRefusal(arena, .{
        .found = .pin_too_long_for_card,
        .require_card = false,
        .pin_bytes = 12,
    })).?;
    try testing.expect(std.mem.indexOf(u8, typed, "12 bytes were typed") != null);
}

test "--require-card refuses every software seal, including the one nobody chose against" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for ([_]chock_pcsc.attempt.Outcome{ .no_reader, .no_card, .pin_declined, .pin_blocked }) |one| {
        try testing.expectEqual(
            @as(?[]u8, null),
            try sealRefusal(arena, .{ .found = one, .require_card = false }),
        );
        const why = (try sealRefusal(arena, .{ .found = one, .require_card = true })).?;
        try testing.expect(std.mem.indexOf(u8, why, "--require-card was given") != null);
        try testing.expect(std.mem.indexOf(u8, why, "nothing was sealed") != null);
        try testing.expect(std.mem.indexOf(u8, why, "Put the card in a reader") != null);
        try testing.expect(std.mem.indexOf(u8, why, "leave --require-card out") != null);
    }

    const detailed = (try sealRefusal(arena, .{
        .found = .no_daemon,
        .require_card = true,
        .detail = "there is no pcscd socket at /run/pcscd/pcscd.comm",
    })).?;
    try testing.expect(std.mem.indexOf(u8, detailed, "/run/pcscd/pcscd.comm") != null);

    const attempted = (try sealRefusal(arena, .{ .found = .pin_wrong, .require_card = true })).?;
    try testing.expect(std.mem.indexOf(u8, attempted, "--require-card") == null);
    try testing.expect(std.mem.indexOf(u8, attempted, "the PIN question was answered") != null);
}

test "a refused card attempt writes no seal file at all, so the next run is a clean try" {
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

    try testing.expectEqualStrings("", said.out());
    try testing.expect(std.mem.indexOf(u8, said.err(), "12 bytes were typed") != null);

    const path = try sealPathIn(arena, dir, id);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );

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

    const carded = Choice{ .signer = key.signer(), .level = .card, .card = .ready, .reader = "R" };
    try testing.expect(std.mem.indexOf(u8, try signedWithText(arena, carded, 1), "The seal above") != null);
    try testing.expect(std.mem.indexOf(u8, try signedWithText(arena, carded, 3), "Every seal above") != null);
}

test "a level number is printed with the direction of the scale, because 3 of 3 reads as the top" {
    try testing.expect(std.mem.indexOf(u8, levelRank(.software), "3 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card), "2 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card_attested), "1 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.software), "the weakest") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card), "the middle") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.card_attested), "the strongest") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(.software), "level 1") == null);
    const ranks = [_][]const u8{ levelRank(.software), levelRank(.card), levelRank(.card_attested) };
    for (ranks, 0..) |one, index| {
        for (ranks[index + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one, other));
    }
    try testing.expect(std.mem.indexOf(u8, levelRank(null), "3 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, levelRank(null), "the weakest") != null);
}

test "a card seal names the card on the row, and the fallback line is not printed for it" {
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
    _ = try sealSessions(arena, testing.io, dir, "/home/somebody/work/parser", id, .{
        .signer = key.signer(),
        .level = .card,
        .card = .ready,
        .reader = "Recorded Reader 00 00",
    });
    try testing.expect(std.mem.indexOf(u8, said.out(), "level 2 of 3") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "Recorded Reader 00 00") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "software key") == null);
    said.clear();

    const one = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(seal.Verdict.signed_card, one.seal.verdict);
    try testing.expect(!one.seal.hardwareProved());
}

const RefusingSigner = struct {
    key: chock_pcsc.software.Key,
    good: usize,
    signed: usize = 0,
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

    const complained = said.err();
    const first = std.mem.indexOf(u8, complained, sentence) orelse return error.NoSentenceWasPrinted;
    try testing.expect(std.mem.indexOf(u8, complained, "Unusable") == null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "Unusable") == null);
    try testing.expectEqual(
        @as(?usize, null),
        std.mem.indexOf(u8, complained[first + sentence.len ..], sentence),
    );
    try testing.expect(std.mem.indexOf(u8, complained, "1 more log was not asked about") != null);
    try testing.expect(std.mem.indexOf(u8, complained, "2 of 3 logs were not sealed") != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "sealed over") != null);

    try testing.expectEqual(@as(usize, 1), refusing.signed);
}

test "the level a seal recorded cannot be raised by editing the record" {
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
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, try sealPathIn(arena, dir, id), .{}),
    );

    try held.unlock(testing.io);
    owner.close(testing.io);
    said.clear();

    try testing.expectEqual(
        Exit.finished.code(),
        try sealForTest(arena, dir, id),
    );
    _ = try std.Io.Dir.cwd().statFile(testing.io, try sealPathIn(arena, dir, id), .{});
}

test "the signing key is made once and read back after, so two runs share one signer" {
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

    const made = signingKey(testing.allocator, testing.io, data_dir, memory.secrets()).?;
    try testing.expect(std.mem.indexOf(u8, said.err(), "made this installation's signing key") != null);
    said.clear();

    const again = signingKey(testing.allocator, testing.io, data_dir, memory.secrets()).?;
    try testing.expectEqualSlices(u8, &made.publicKey(), &again.publicKey());
    try testing.expect(std.mem.indexOf(u8, said.err(), "made this installation's") == null);
    said.clear();

    var empty = MemorySecrets{ .gpa = testing.allocator };
    defer empty.deinit();
    const other = signingKey(testing.allocator, testing.io, data_dir, empty.secrets()).?;
    try testing.expect(!std.mem.eql(u8, &made.publicKey(), &other.publicKey()));
    said.clear();

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

    try testing.expect(!std.mem.eql(u8, one, two));
    try testing.expect(std.mem.indexOf(u8, one, first) != null);
    try testing.expect(std.mem.indexOf(u8, two, second) != null);
    try testing.expectEqual(
        seal.Verdict.signed_software,
        (try fold(arena, testing.io, dir, second)).?.seal.verdict,
    );
}

test "a log from before the chain verifies as unchained, and is still listed and still read" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "A" ** 22;
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
    try testing.expect(one.readable);
    try testing.expect(one.complete);
    try testing.expectEqualStrings("qwen3", one.model);

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectEqual(
        Exit.finished.code(),
        try listSessions(arena, testing.io, dir, "/home/somebody/work/parser"),
    );
    try testing.expect(std.mem.indexOf(u8, said.out(), id) != null);
    try testing.expect(std.mem.indexOf(u8, said.out(), "was edited") == null);
    said.clear();

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

    const missing = "01JQ" ++ "Z" ** 22;
    const code = try verifySessions(arena, testing.io, dir, "/home/somebody/work/parser", missing);
    try testing.expect(code != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), "has no session") != null);
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}" ++ log_suffix, .{ dir, missing }, 0);
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, path, .{}));

    try testing.expect(try sealForTest(arena, dir, missing) != Exit.finished.code());
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(testing.io, path, .{}));

    try testing.expectEqual(Action.seal, (try parseOptions(&.{"seal"})).action);
    const one_named = try parseOptions(&.{ "seal", "01JQ" ++ "A" ** 22 });
    try testing.expectEqual(Action.seal, one_named.action);
    try testing.expectEqualStrings("01JQ" ++ "A" ** 22, one_named.session);
    try testing.expectError(
        error.BadArguments,
        parseOptions(&.{ "seal", "01JQ" ++ "A" ** 22, "01JQ" ++ "B" ** 22 }),
    );

    try testing.expectEqual(Action.verify, (try parseOptions(&.{"verify"})).action);
    const named = try parseOptions(&.{ "verify", "01JQ" ++ "A" ** 22 });
    try testing.expectEqual(Action.verify, named.action);
    try testing.expectEqualStrings("01JQ" ++ "A" ** 22, named.session);
    try testing.expectError(
        error.BadArguments,
        parseOptions(&.{ "verify", "01JQ" ++ "A" ** 22, "01JQ" ++ "B" ** 22 }),
    );
}

fn retentionBundle(arena: std.mem.Allocator, body: []const u8) !*const chock_policy.org.Bundle {
    const source = try std.fmt.allocPrintSentinel(arena, ".{{{s}}}", .{body}, 0);
    return chock_policy.org.parse(arena, source, null);
}

test "an installation with no org bundle removes and prunes exactly as it always did" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(@as(?[]const u8, null), try retentionRefusal(arena, &.{}, remove_action));
    try testing.expectEqual(@as(?[]const u8, null), try retentionRefusal(arena, &.{}, prune_action));

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
    try testing.expect(std.mem.indexOf(u8, why, remove_action) != null);
    try testing.expect(std.mem.indexOf(u8, why, "--yes does not answer this") != null);

    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, keeps.rules, prune_action),
    );

    const no_sweeping = try retentionBundle(arena,
        \\ .rules = .{ .{ .action = "session.prune", .decision = .deny } },
    );
    try testing.expect((try retentionRefusal(arena, no_sweeping.rules, prune_action)) != null);
    try testing.expectEqual(
        @as(?[]const u8, null),
        try retentionRefusal(arena, no_sweeping.rules, remove_action),
    );

    const keeps_everything = try retentionBundle(arena,
        \\ .rules = .{ .{ .action = "session.*", .decision = .deny } },
    );
    try testing.expect((try retentionRefusal(arena, keeps_everything.rules, remove_action)) != null);
    try testing.expect((try retentionRefusal(arena, keeps_everything.rules, prune_action)) != null);
}

test "every decision a retention row can hold is answered, and only two of them let a removal go" {
    try testing.expect(retentionAllows(.allow));
    try testing.expect(retentionAllows(.ask));
    try testing.expect(!retentionAllows(.deny));
    try testing.expect(!retentionAllows(.agent_review));
    try testing.expect(!retentionAllows(.agent_then_human));

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

    try testing.expectEqual(@as(?[]const u8, null), (try parseOptions(&.{})).org_bundle);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "prune", "--org-bundle" }));
}

test "--require-card is a seal option and no other command takes it" {
    const asked = try parseOptions(&.{ "seal", "--require-card" });
    try testing.expect(asked.require_card);
    try testing.expectEqual(Action.seal, asked.action);

    try testing.expect(!(try parseOptions(&.{"seal"})).require_card);
    try testing.expect(!(try parseOptions(&.{})).require_card);

    for ([_][]const u8{ "list", "verify", "prune" }) |other| {
        try testing.expectError(error.BadArguments, parseOptions(&.{ other, "--require-card" }));
    }
}

test "an exported log is byte for byte the original, and verifies as the copy" {
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
    try testing.expectEqual(@as(u64, 3), done.lines);
    try testing.expectEqual(chain.Verdict.intact, done.report.verdict);

    const original = try std.Io.Dir.cwd().readFileAlloc(io, log_path, arena, .limited(1 << 20));
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, done.path, arena, .limited(1 << 20));
    try testing.expectEqualStrings(original, copy);
}

test "exporting a log takes nothing away and leaves its lock free" {
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
    var locked = try store.lock(io);
    try locked.unlock(io);
}

test "a log somebody edited exports, and the copy says it was edited" {
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
    const copy = try std.Io.Dir.cwd().readFileAlloc(io, done.path, arena, .limited(1 << 20));
    try testing.expectEqualStrings(edited, copy);
}

test "export needs somewhere to write, and no other action may name one" {
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

    try testing.expectEqualStrings("export", @tagName(Action.@"export"));
}

test "nobody at a keyboard is a refusal, decided before a byte is written" {
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
    try testing.expectEqual(@as(usize, 0), asking.asked);
}

test "a read that failed says what happened, and only an empty answer is a decline" {
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
    try testing.expectEqual(@as(usize, 1), declines);

    inline for (@typeInfo(tty.SecretError).error_set.?) |field| {
        var decided = false;
        for (cases) |one| {
            if (std.mem.eql(u8, @errorName(one.err), field.name)) decided = true;
        }
        try testing.expect(decided);
    }
}

test "the count of tries left is said before anybody types, and it names the reader" {
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
    try testing.expect(std.mem.indexOf(u8, said.err(), "PUK") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "software key instead") != null);

    said.clear();
    sayTries(.{ .reader = "", .slot = .digital_signature, .tries = .{ .left = 1 } });
    try testing.expect(std.mem.indexOf(u8, said.err(), "1 try left") != null);

    said.clear();
    sayTries(.{ .reader = "", .slot = .digital_signature, .tries = .unknown });
    try testing.expect(std.mem.indexOf(u8, said.err(), "did not say") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "three") != null);

    said.clear();
    sayTries(.{ .reader = "", .slot = .digital_signature, .tries = .blocked });
    try testing.expect(std.mem.indexOf(u8, said.err(), "no tries left") != null);
}
