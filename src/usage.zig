//! `chock usage`: what a session cost.
//!
//! The same shape `src/cache.zig`, `src/memory.zig` and `src/workspace.zig`
//! have, and deliberately not a fourth shape: a user who has learned one of
//! these commands has learned all four. Nothing here starts a session, opens a
//! sandbox, or touches the project.
//!
//! ## A provider that cannot report a cost is an ordinary answer here
//!
//! A capability has more than two states, and `unsupported` is a fact about the
//! provider that is known before the first request. What that means for the
//! cost is this: **a provider with no usage capability reports its cost as
//! unknown, and it does not need a case of its own.** Every turn of such a
//! session carries an `unknown` cost, so it reaches this command as unknown,
//! and the report says so plainly and names the models. That is not an error,
//! it is not an empty report, and it is never an invented number.
//!
//! ## What this command is not
//!
//! **It does not reconcile against a provider's own analytics, and if that is
//! ever added here it reconciles and never enforces.** ai&'s analytics API is
//! rate limited and cached for 120 seconds, and a cap checked against a number
//! that can be two minutes stale is not a cap. Enforcement stays on the running
//! total the loop folds from each turn's own cost, which is exact and
//! immediate, and any reconciliation stays behind a command and off the turn
//! path.

const std = @import("std");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const state = chock_proto.state;
const event = chock_proto.event;

/// What a session log is called: the session identifier, then this. Read from
/// `session.zig`'s own layout, which is the file that builds the name in the
/// first place.
const log_suffix = ".jsonl";

const usage_text =
    \\Usage: chock usage [list|show <session>] [options]
    \\
    \\With no subcommand, says what every session of this project spent.
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
        tty.print(.err, "chock usage: the session directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    return switch (options.action) {
        .list => listSessions(arena, io, dir),
        .show => showSession(arena, io, dir, options.session),
    };
}

/// What one model spent inside one session. A session mixes models across
/// turns, so a total that does not say which model spent what cannot be
/// checked, and the `usage` event carries the model name for that.
pub const ByModel = struct {
    /// The model as it went on the wire. Empty for a turn whose event named
    /// none, which is what a log written before the loop stamped the model
    /// holds.
    model: []const u8,
    spend: state.Spend = .{},
    /// Which price table produced the money in `spend`, from the first turn
    /// that named one. Empty when the provider reported the numbers itself, or
    /// when nothing here was priced. A wrong price is then a fact somebody can
    /// find rather than a number nobody can explain.
    price_table_version: []const u8 = "",
};

/// What one session spent, folded from the `usage` events its own log holds.
pub const Spent = struct {
    /// The session identifier, which is the log's own name without its
    /// suffix.
    id: []const u8,
    spend: state.Spend = .{},
    /// One entry per model this session used, in the order each was first
    /// seen.
    models: []const ByModel = &.{},
    /// False when the log could not be read all the way to its end: a torn
    /// tail from a crash mid write, or a line that would not decode. **The
    /// numbers are then a floor and not a total**, and the report says so,
    /// because a short answer that looks whole is worse than no answer.
    complete: bool = true,
};

/// How the money of a `Spend` reads. Six answers and no fewer: the three
/// states of `Cost`, a session that mixed them, a session nobody measured at
/// all, and a session whose turns disagreed about the currency.
///
/// **`free` and `unknown` are two members and never one.** That is the whole
/// point of the three state cost, carried up to the place a person reads it.
pub const Verdict = enum {
    /// The log holds no `usage` event at all. A session that was started and
    /// never got a reply looks like this, and it is not a session that cost
    /// nothing.
    nothing,
    /// Every turn was free. A measured fact, and a session that can run under
    /// a cap without trouble.
    free,
    /// Every turn that was not free had a price, so the money is the whole
    /// cost.
    priced,
    /// Some turns were priced or free and at least one was not. The money
    /// below is real and it is not the total.
    partly_unknown,
    /// No turn had a price. **Never a zero**: this is what a provider whose
    /// usage capability is `unsupported` gives, and what a model the price
    /// table has never heard of gives.
    unknown,
    /// Turns reported money in two currencies, so adding them gives a number
    /// in no currency at all.
    mixed_currency,
};

/// How the money of `spend` reads. Checked in this order on purpose: a mixed
/// currency makes `amount` meaningless whatever else is true, and an unknown
/// turn makes it incomplete whatever else is true.
pub fn verdictOf(spend: state.Spend) Verdict {
    if (spend.turns == 0) return .nothing;
    if (spend.mixed_currency) return .mixed_currency;
    if (spend.unpriced_turns == spend.turns) return .unknown;
    if (spend.unpriced_turns != 0) return .partly_unknown;
    if (spend.free_turns == spend.turns) return .free;
    return .priced;
}

/// "turn" for one and "turns" for any other count. A report a person reads
/// says "1 turn", and a line that says "1 turns" reads as a program talking.
fn turnWord(count: u64) []const u8 {
    return if (count == 1) "turn" else "turns";
}

/// The money in `spend`, with the currency it is in. Caller owns the result.
///
/// **A figure with no currency beside it is not money**, and this is not a
/// hypothetical: ai& sends `X-Cost` and `X-Cost-Currency` apart, so a reply
/// that carried the first and not the second reaches the log as a value with
/// an empty currency. Sessions of this project hold such events today. Printed
/// as a bare number, that reads as dollars to anyone who assumes dollars, so
/// the number is printed with the fact that nobody named its unit.
fn moneyText(allocator: std.mem.Allocator, spend: state.Spend) std.mem.Allocator.Error![]u8 {
    if (spend.currency.len == 0) {
        return std.fmt.allocPrint(
            allocator,
            "{d:.4}, in a currency the provider did not name",
            .{spend.amount},
        );
    }
    return std.fmt.allocPrint(allocator, "{d:.4} {s}", .{ spend.amount, spend.currency });
}

/// The money of `spend` as one phrase, for a line a person reads. Caller owns
/// the result.
///
/// **A verdict that carries no number prints no number.** Not "0.00", and not
/// an empty column that a reader fills in with zero: the words say which of
/// the three states this is.
pub fn costText(allocator: std.mem.Allocator, spend: state.Spend) std.mem.Allocator.Error![]u8 {
    return switch (verdictOf(spend)) {
        .nothing => allocator.dupe(u8, "no turn recorded"),
        .free => allocator.dupe(u8, "free"),
        .unknown => std.fmt.allocPrint(
            allocator,
            "cost not known, for all {d} {s}",
            .{ spend.turns, turnWord(spend.turns) },
        ),
        .priced => moneyText(allocator, spend),
        .partly_unknown => std.fmt.allocPrint(
            allocator,
            "{s}, and {d} {s} whose cost is not known",
            .{ try moneyText(allocator, spend), spend.unpriced_turns, turnWord(spend.unpriced_turns) },
        ),
        .mixed_currency => allocator.dupe(u8, "two currencies, so there is no one total"),
    };
}

/// Every session of `dir`, oldest first, with what each one spent. Caller owns
/// the slice and every string in it, which for a real caller is an arena.
///
/// **Oldest first**, because a session identifier starts with its own
/// timestamp: see `session.zig`'s own `newId`. The list a user reads is then
/// in the order the sessions ran.
///
/// A session directory that cannot be read at all answers an empty list. A
/// project that never ran a session has no such directory, and that is an
/// ordinary state rather than a fault.
pub fn list(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
) std.mem.Allocator.Error![]Spent {
    var handle = std.Io.Dir.openDirAbsolute(io, dir, .{ .iterate = true }) catch return &.{};
    defer handle.close(io);

    var found: std.ArrayList(Spent) = .empty;
    var walker = handle.iterate();
    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, log_suffix)) continue;
        const stem = entry.name[0 .. entry.name.len - log_suffix.len];
        // A name this build did not write is never turned into a path: the
        // same rule `session.zig` keeps, and the reason `isValidId` exists.
        if (!session_paths.isValidId(stem)) continue;

        const spent = try fold(allocator, io, dir, stem) orelse continue;
        try found.append(allocator, spent);
    }

    const sessions = try found.toOwnedSlice(allocator);
    std.mem.sort(Spent, sessions, {}, olderFirst);
    return sessions;
}

fn olderFirst(_: void, a: Spent, b: Spent) bool {
    return std.mem.order(u8, a.id, b.id) == .lt;
}

/// Fold every `usage` event of one session's log. Null when this project has
/// no session of that identifier.
///
/// **The file is checked before the log is opened, and that is not a
/// nicety.** `chock_proto.log.Log.open` creates the file and writes a header
/// into it when there is none, which is right for `chock run` and wrong for a
/// command that only reads: asking about a session that never existed would
/// otherwise bring one into being, empty, and report that it cost nothing.
pub fn fold(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
) std.mem.Allocator.Error!?Spent {
    std.debug.assert(session_paths.isValidId(id));
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/{s}" ++ log_suffix, .{ dir, id }, 0);
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return null;

    const log = chock_proto.log.Log.open(io, path, id) catch return null;
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const store = backing.storage();
    defer store.close(io);

    var spent = Spent{ .id = try allocator.dupe(u8, id) };
    var models: std.ArrayList(ByModel) = .empty;

    var replay = store.replay(allocator, io, 0) catch {
        spent.complete = false;
        return spent;
    };
    defer replay.deinit();

    while (true) {
        const parsed = replay.next(io) catch {
            // A line that will not decode stops the fold here. Everything
            // before it is real, and `complete` is what stops the caller
            // reading a floor as a total.
            spent.complete = false;
            break;
        } orelse {
            // A torn tail is a crash mid write, not a clean end of log, and
            // an event may have gone with it.
            if (replay.truncated()) spent.complete = false;
            break;
        };
        defer parsed.deinit();
        if (parsed.value.event != .usage) continue;

        // The currency, the model name and the table version are borrowed
        // from the envelope, which is released at the end of this loop body,
        // so each is copied into the caller's allocator first. `Spend.add`
        // keeps the currency it is given, exactly as `state.Session.apply`
        // does, and for the same reason.
        var turn = parsed.value.event.usage;
        if (turn.cost == .known) turn.cost = .{ .known = .{
            .value = turn.cost.known.value,
            .currency = try allocator.dupe(u8, turn.cost.known.currency),
        } };

        spent.spend.add(turn);

        const row = try modelRow(allocator, &models, turn.model);
        row.spend.add(turn);
        if (row.price_table_version.len == 0 and turn.price_table_version.len != 0) {
            row.price_table_version = try allocator.dupe(u8, turn.price_table_version);
        }
    }

    spent.models = try models.toOwnedSlice(allocator);
    return spent;
}

/// The row for `model`, added at the end when this is the first turn to name
/// it. The returned pointer is used before anything else is appended, so no
/// later growth of the list can move the row out from under it.
fn modelRow(
    allocator: std.mem.Allocator,
    models: *std.ArrayList(ByModel),
    model: []const u8,
) std.mem.Allocator.Error!*ByModel {
    for (models.items) |*row| {
        if (std.mem.eql(u8, row.model, model)) return row;
    }
    try models.append(allocator, .{ .model = try allocator.dupe(u8, model) });
    return &models.items[models.items.len - 1];
}

/// What every session in `sessions` spent together. The currency rule is
/// `state.Spend.merge`'s, so a project whose sessions were billed in two
/// currencies gets a total that says it is not one.
pub fn totalOf(sessions: []const Spent) state.Spend {
    var total = state.Spend{};
    for (sessions) |one| total.merge(one.spend);
    return total;
}

fn listSessions(arena: std.mem.Allocator, io: std.Io, dir: []const u8) !u8 {
    const sessions = try list(arena, io, dir);
    if (sessions.len == 0) {
        tty.print(.plain, "chock usage: this project has no sessions ({s})\n", .{dir});
        return Exit.finished.code();
    }

    // A `--verbose` line. Where the logs are kept answers no question about
    // what the sessions cost.
    tty.detail("{s}\n\n", .{dir});
    for (sessions) |one| {
        tty.out(.plain, "{s}  {d:>4} turns  {d:>9} in  {d:>8} out  {s}{s}\n", .{
            one.id,
            one.spend.turns,
            one.spend.input_tokens,
            one.spend.output_tokens,
            try costText(arena, one.spend),
            if (one.complete) "" else "  (the log ends mid write, so this is a floor)",
        });
    }

    const total = totalOf(sessions);
    tty.out(.plain, "\n{d} {s}, {d} {s}: {d} priced, {d} free, {d} with no price\n", .{
        sessions.len,
        if (sessions.len == 1) "session" else "sessions",
        total.turns,
        turnWord(total.turns),
        total.pricedTurns(),
        total.free_turns,
        total.unpriced_turns,
    });
    tty.out(.plain, "{s}\n", .{try costText(arena, total)});
    printCaveat(total);
    return Exit.finished.code();
}

fn showSession(arena: std.mem.Allocator, io: std.Io, dir: []const u8, id: []const u8) !u8 {
    if (id.len == 0) {
        tty.print(.err, "chock usage show: which session?\n", .{});
        return Exit.usage.code();
    }
    if (!session_paths.isValidId(id)) {
        tty.print(.err, "chock usage show: \"{s}\" is not a session identifier\n", .{id});
        return Exit.usage.code();
    }

    const spent = try fold(arena, io, dir, id) orelse {
        tty.print(.err, "chock usage show: this project has no session {s} ({s})\n", .{ id, dir });
        // Never `finished`: a command that did nothing must not report
        // success. See `src/main.zig`'s own top comment.
        return Exit.usage.code();
    };

    // The identifier is the answer's heading. The log path under it is a
    // `--verbose` line: `tty.options_text` names the log path as exactly that.
    tty.out(.plain, "{s}\n", .{spent.id});
    tty.detail("{s}/{s}{s}\n", .{ dir, spent.id, log_suffix });
    tty.out(.plain, "\n", .{});
    for (spent.models) |row| {
        tty.out(.plain, "  {s}  {d} {s}  {s}\n", .{
            if (row.model.len == 0) "(the log names no model)" else row.model,
            row.spend.turns,
            turnWord(row.spend.turns),
            try costText(arena, row.spend),
        });
        // Which table produced the money above, so a wrong price is a fact
        // somebody can find rather than a number nobody can explain. The
        // version is recorded, and this is where a person reads it.
        if (row.price_table_version.len != 0) {
            tty.out(.plain, "    priced by table {s}\n", .{row.price_table_version});
        }
    }

    tty.out(.plain, "\n  {d} in, {d} out, {d} cache write, {d} cache read\n", .{
        spent.spend.input_tokens,
        spent.spend.output_tokens,
        spent.spend.cache_creation_input_tokens,
        spent.spend.cache_read_input_tokens,
    });
    tty.out(.plain, "  {d} {s}: {d} priced, {d} free, {d} with no price\n", .{
        spent.spend.turns,
        turnWord(spent.spend.turns),
        spent.spend.pricedTurns(),
        spent.spend.free_turns,
        spent.spend.unpriced_turns,
    });
    tty.out(.plain, "  {s}\n", .{try costText(arena, spent.spend)});
    if (!spent.complete) {
        tty.print(.warn, "  The log ends mid write, so these numbers are a floor.\n", .{});
    }
    printCaveat(spent.spend);
    return Exit.finished.code();
}

/// The one sentence a number that is not a total needs beside it.
///
/// **Printed for the unknown cases and for nothing else.** A caveat under
/// every report is a caveat nobody reads, and the cases that carry a real
/// total do not need one.
fn printCaveat(spend: state.Spend) void {
    switch (verdictOf(spend)) {
        .unknown, .partly_unknown => tty.print(.warn,
            \\
            \\A turn with no price is not a turn that cost nothing. The provider
            \\reported no cost and the price table names no price for the model, so
            \\the number above leaves those turns out. A budget in chock.zon is not
            \\enforced over them either, and chock run says so when a session starts.
            \\
        , .{}),
        .mixed_currency => tty.print(.warn,
            \\
            \\Turns were billed in more than one currency. Chock does not hold an
            \\exchange rate and will not invent one, so there is no single total to
            \\print. Read the sessions one at a time with: chock usage show <session>
            \\
        , .{}),
        .nothing, .free, .priced => {},
    }
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
/// `chock run`, `chock cache`, `chock memory` and `chock workspace` make**,
/// for the same reason: a session directory is keyed by the project's real
/// path, so a spelling this command resolved differently would read a
/// different directory from the one the session wrote.
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
    try testing.expectError(error.BadArguments, parseOptions(&.{"total"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "show", "a", "b" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

/// A session directory holding one log per identifier, each carrying the usage
/// events it was given. This is what makes the tests below assert numbers: the
/// events go in by hand, so what comes out is checkable to the token.
fn makeLog(
    arena: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    turns: []const event.Usage,
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
    for (turns) |turn| _ = try locked.append(arena, io, .{ .usage = turn }, 0);
}

fn scratchDir(arena: std.mem.Allocator, tmp: *testing.TmpDir, leaf: []const u8) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ buffer[0..len], leaf });
}

test "a free session and an unpriced session are two different answers, and neither is a number" {
    // The fault the three state cost exists to stop, carried all the way to
    // what a person reads. Both of these have an `amount` of zero. A report
    // that printed the amount would show "0.0000 USD" for both, and a user
    // would read the second one as a session that cost nothing.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const local = "01JQ" ++ "A" ** 22;
    const unpriced = "01JQ" ++ "B" ** 22;
    try makeLog(arena, testing.io, dir, local, &.{
        .{ .input_tokens = 100, .output_tokens = 10, .model = "qwen3", .cost = .free },
        .{ .input_tokens = 200, .output_tokens = 20, .model = "qwen3", .cost = .free },
    });
    try makeLog(arena, testing.io, dir, unpriced, &.{
        .{ .input_tokens = 300, .output_tokens = 30, .model = "glm4.7-flash:A3B", .cost = .unknown },
    });

    const free = (try fold(arena, testing.io, dir, local)).?;
    try testing.expectEqual(@as(u64, 2), free.spend.turns);
    try testing.expectEqual(@as(u64, 2), free.spend.free_turns);
    try testing.expectEqual(@as(u64, 0), free.spend.unpriced_turns);
    try testing.expectEqual(@as(u64, 300), free.spend.input_tokens);
    try testing.expectEqual(@as(u64, 30), free.spend.output_tokens);
    try testing.expectEqual(Verdict.free, verdictOf(free.spend));

    const nobody_priced = (try fold(arena, testing.io, dir, unpriced)).?;
    try testing.expectEqual(@as(u64, 1), nobody_priced.spend.turns);
    try testing.expectEqual(@as(u64, 0), nobody_priced.spend.free_turns);
    try testing.expectEqual(@as(u64, 1), nobody_priced.spend.unpriced_turns);
    try testing.expectEqual(Verdict.unknown, verdictOf(nobody_priced.spend));

    try testing.expect(verdictOf(free.spend) != verdictOf(nobody_priced.spend));
    const free_text = try costText(arena, free.spend);
    const unknown_text = try costText(arena, nobody_priced.spend);
    try testing.expect(!std.mem.eql(u8, free_text, unknown_text));
    try testing.expectEqualStrings("free", free_text);

    // And the unpriced one carries no figure at all: not "0", not "0.0000".
    // A digit in that sentence is a number a reader can mistake for a total,
    // except the turn count, which is a count and not money.
    try testing.expect(std.mem.indexOf(u8, unknown_text, "0.0000") == null);
    try testing.expect(std.mem.indexOf(u8, unknown_text, "not known") != null);
    try testing.expectEqualStrings("cost not known, for all 1 turn", unknown_text);
}

test "a priced session reports the money the log holds, model by model" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "C" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{
        .{
            .input_tokens = 1000,
            .output_tokens = 100,
            .cache_creation_input_tokens = 40,
            .cache_read_input_tokens = 900,
            .model = "claude-opus-5",
            .price_table_version = "2026-08-21",
            .cost = .{ .known = .{ .value = 0.25, .currency = "USD" } },
        },
        .{
            .input_tokens = 2000,
            .output_tokens = 200,
            .model = "claude-opus-5",
            .price_table_version = "2026-08-21",
            .cost = .{ .known = .{ .value = 0.75, .currency = "USD" } },
        },
        // A second model, free, in the same session. A session may mix models,
        // and a total that cannot say which model spent what cannot be checked.
        .{ .input_tokens = 50, .model = "qwen3", .cost = .free },
    });

    const spent = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(@as(u64, 3), spent.spend.turns);
    try testing.expectEqual(@as(u64, 2), spent.spend.pricedTurns());
    try testing.expectEqual(@as(u64, 1), spent.spend.free_turns);
    try testing.expectEqual(@as(u64, 0), spent.spend.unpriced_turns);
    try testing.expectEqual(@as(u64, 3050), spent.spend.input_tokens);
    try testing.expectEqual(@as(u64, 300), spent.spend.output_tokens);
    try testing.expectEqual(@as(u64, 40), spent.spend.cache_creation_input_tokens);
    try testing.expectEqual(@as(u64, 900), spent.spend.cache_read_input_tokens);
    try testing.expectApproxEqAbs(@as(f64, 1.00), spent.spend.amount, 1e-12);
    try testing.expectEqualStrings("USD", spent.spend.currency);
    // A free turn beside two priced ones does not make the session unpriced,
    // and the money is still the whole cost.
    try testing.expectEqual(Verdict.priced, verdictOf(spent.spend));
    try testing.expect(spent.spend.enforceable());
    try testing.expectEqualStrings("1.0000 USD", try costText(arena, spent.spend));

    try testing.expectEqual(@as(usize, 2), spent.models.len);
    try testing.expectEqualStrings("claude-opus-5", spent.models[0].model);
    try testing.expectApproxEqAbs(@as(f64, 1.00), spent.models[0].spend.amount, 1e-12);
    try testing.expectEqual(@as(u64, 2), spent.models[0].spend.turns);
    try testing.expectEqualStrings("2026-08-21", spent.models[0].price_table_version);
    try testing.expectEqualStrings("qwen3", spent.models[1].model);
    try testing.expectEqual(@as(u64, 1), spent.models[1].spend.free_turns);
    try testing.expectEqual(Verdict.free, verdictOf(spent.models[1].spend));
    try testing.expectEqualStrings("", spent.models[1].price_table_version);
}

test "one unpriced turn among priced ones leaves the money real and the total incomplete" {
    // The case a report is most likely to get wrong: there is a figure, and it
    // is not the cost of the session. This is the same class of fault as a
    // policy resolving an unnamed action to allow.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "D" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .model = "claude-opus-5", .cost = .{ .known = .{ .value = 0.50, .currency = "USD" } } },
        .{ .model = "a-model-nobody-priced", .cost = .unknown },
    });

    const spent = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(Verdict.partly_unknown, verdictOf(spent.spend));
    try testing.expectApproxEqAbs(@as(f64, 0.50), spent.spend.amount, 1e-12);
    try testing.expectEqual(@as(u64, 1), spent.spend.unpriced_turns);
    try testing.expect(!spent.spend.enforceable());

    // The figure is printed, and the sentence beside it says it is not the
    // whole cost. A report that printed "0.5000 USD" alone would be read as
    // the cost of the session.
    const text = try costText(arena, spent.spend);
    try testing.expectEqualStrings("0.5000 USD, and 1 turn whose cost is not known", text);
}

test "two sessions billed in different currencies give no total, rather than a wrong one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const dollars = "01JQ" ++ "E" ** 22;
    const euros = "01JQ" ++ "F" ** 22;
    try makeLog(arena, testing.io, dir, dollars, &.{
        .{ .model = "claude-opus-5", .cost = .{ .known = .{ .value = 1.25, .currency = "USD" } } },
    });
    try makeLog(arena, testing.io, dir, euros, &.{
        .{ .model = "claude-opus-5", .cost = .{ .known = .{ .value = 2.00, .currency = "EUR" } } },
    });

    const sessions = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 2), sessions.len);
    try testing.expectEqualStrings(dollars, sessions[0].id);
    try testing.expectEqualStrings(euros, sessions[1].id);
    // Each session on its own is a real total.
    try testing.expectEqual(Verdict.priced, verdictOf(sessions[0].spend));
    try testing.expectEqual(Verdict.priced, verdictOf(sessions[1].spend));

    const total = totalOf(sessions);
    try testing.expectEqual(@as(u64, 2), total.turns);
    try testing.expectEqual(Verdict.mixed_currency, verdictOf(total));
    try testing.expect(!total.enforceable());
    // 1.25 and 2.00 are not 3.25 of anything, and the report says so instead
    // of printing that number.
    const text = try costText(arena, total);
    try testing.expect(std.mem.indexOf(u8, text, "3.25") == null);
    try testing.expect(std.mem.indexOf(u8, text, "two currencies") != null);
}

test "a session that got no reply is told apart from one that cost nothing" {
    // A log with a start and no usage event at all. Reading that as free
    // would be the same mistake as reading unknown as zero, one level up.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "G" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{});

    const spent = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(@as(u64, 0), spent.spend.turns);
    try testing.expectEqual(Verdict.nothing, verdictOf(spent.spend));
    try testing.expect(verdictOf(spent.spend) != .free);
    try testing.expectEqualStrings("no turn recorded", try costText(arena, spent.spend));
}

test "asking about a session that never ran makes no log and does not report success" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");
    try std.Io.Dir.createDirAbsolute(testing.io, dir, .default_dir);

    const never = "01JQ" ++ "H" ** 22;
    try testing.expectEqual(@as(?Spent, null), try fold(arena, testing.io, dir, never));

    const path = try std.fmt.allocPrint(arena, "{s}/{s}" ++ log_suffix, .{ dir, never });
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(testing.io, path, .{}),
    );

    // And the command says so rather than exiting 0: a command that did
    // nothing must not report success. See `src/main.zig`'s own top comment.
    //
    // **Each refusal names what was asked for**, and each is captured rather
    // than let through to the test binary's own standard error: see
    // `tty.Capture`, and `test/proto/lock.zig`.
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expect((try showSession(arena, testing.io, dir, never)) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), never) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), dir) != null);

    // **A path that is not a session identifier is refused as that**, and the
    // words it is refused with must not be the words for a session that is
    // simply not there: one is a mistake to correct and the other is a fact
    // about this project.
    said.clear();
    try testing.expect((try showSession(arena, testing.io, dir, "../../etc/passwd")) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), "not a session identifier") != null);

    said.clear();
    try testing.expect((try showSession(arena, testing.io, dir, "")) != Exit.finished.code());
    try testing.expect(said.err().len != 0);
    // Every one of them is a diagnostic, so none reached the rows a pipe reads.
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
    const missing = try scratchDir(arena, &tmp, "never-ran");

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const sessions = try list(arena, testing.io, missing);
    try testing.expectEqual(@as(usize, 0), sessions.len);
    try testing.expectEqual(Exit.finished.code(), try listSessions(arena, testing.io, missing));
    // **It names the directory it found nothing in.** A person who ran Chock in
    // the wrong project reads the same words as a person whose project is
    // genuinely new, unless the path is on the line.
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);
}

test "only a session log is read, and a file that is not one is left alone" {
    // A session directory also holds a workspace and a sandbox root, and it
    // can hold a file no build of Chock wrote. None of those is a session,
    // and folding one would put a made up row in the report.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "J" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .model = "claude-opus-5", .cost = .{ .known = .{ .value = 0.10, .currency = "USD" } } },
    });
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
        try std.fmt.allocPrint(arena, "{s}/{s}.work", .{ dir, id }),
        .default_dir,
    );

    const sessions = try list(arena, testing.io, dir);
    try testing.expectEqual(@as(usize, 1), sessions.len);
    try testing.expectEqualStrings(id, sessions[0].id);
    try testing.expectApproxEqAbs(@as(f64, 0.10), totalOf(sessions).amount, 1e-12);
}

test "a cost the provider gave no currency for is not printed as a bare number" {
    // Measured, not hypothetical. ai& sends `X-Cost` and `X-Cost-Currency`
    // apart, and this project's own session logs hold `usage` events reading
    // {"known":{"value":0.00021565,"currency":""}}. A report that printed
    // "0.0002" alone reads as dollars to anybody who assumes dollars.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try scratchDir(arena, &tmp, "sessions");

    const id = "01JQ" ++ "K" ** 22;
    try makeLog(arena, testing.io, dir, id, &.{
        .{ .model = "deepseek-v4-flash", .cost = .{ .known = .{ .value = 0.00021565, .currency = "" } } },
    });

    const spent = (try fold(arena, testing.io, dir, id)).?;
    try testing.expectEqual(@as(u64, 1), spent.spend.pricedTurns());
    try testing.expectApproxEqAbs(@as(f64, 0.00021565), spent.spend.amount, 1e-12);
    try testing.expectEqualStrings("", spent.spend.currency);

    const text = try costText(arena, spent.spend);
    try testing.expectEqualStrings("0.0002, in a currency the provider did not name", text);
    // The number is still there, so nothing is hidden, and it is not left
    // standing on its own where a reader supplies the unit.
    try testing.expect(std.mem.indexOf(u8, text, "0.0002") != null);
    try testing.expect(!std.mem.endsWith(u8, text, "0.0002"));
}

test "every verdict has its own words, so no two states read alike" {
    // Six states and six sentences. Two that read the same would put a user
    // back where the three state cost started: unable to tell a measured zero
    // from an absence.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const samples = [_]state.Spend{
        .{},
        .{ .turns = 2, .free_turns = 2 },
        .{ .turns = 2, .amount = 1.5, .currency = "USD" },
        .{ .turns = 2, .unpriced_turns = 1, .amount = 1.5, .currency = "USD" },
        .{ .turns = 2, .unpriced_turns = 2 },
        .{ .turns = 2, .amount = 1.5, .currency = "USD", .mixed_currency = true },
    };
    const expected = [_]Verdict{ .nothing, .free, .priced, .partly_unknown, .unknown, .mixed_currency };
    try testing.expectEqual(@typeInfo(Verdict).@"enum".fields.len, expected.len);

    var texts: [samples.len][]const u8 = undefined;
    for (samples, expected, 0..) |sample, want, index| {
        try testing.expectEqual(want, verdictOf(sample));
        texts[index] = try costText(arena, sample);
        for (texts[0..index]) |earlier| try testing.expect(!std.mem.eql(u8, earlier, texts[index]));
    }
}
