//! `chock usage`: what a session cost.

const std = @import("std");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const state = chock_proto.state;
const event = chock_proto.event;

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

pub const ByModel = struct {
    model: []const u8,
    spend: state.Spend = .{},
    price_table_version: []const u8 = "",
};

pub const Spent = struct {
    id: []const u8,
    spend: state.Spend = .{},
    models: []const ByModel = &.{},
    // False when the log could not be read to its end: the numbers above are then a floor and not a total.
    complete: bool = true,
};

pub const Verdict = enum {
    nothing,
    free,
    priced,
    partly_unknown,
    // Never a zero: this is what a provider with no usage capability gives, or a model the price table has never heard of.
    unknown,
    mixed_currency,
};

pub fn verdictOf(spend: state.Spend) Verdict {
    if (spend.turns == 0) return .nothing;
    if (spend.mixed_currency) return .mixed_currency;
    if (spend.unpriced_turns == spend.turns) return .unknown;
    if (spend.unpriced_turns != 0) return .partly_unknown;
    if (spend.free_turns == spend.turns) return .free;
    return .priced;
}

fn turnWord(count: u64) []const u8 {
    return if (count == 1) "turn" else "turns";
}

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
            spent.complete = false;
            break;
        } orelse {
            if (replay.truncated()) spent.complete = false;
            break;
        };
        defer parsed.deinit();
        if (parsed.value.event != .usage) continue;

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
        return Exit.usage.code();
    };

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

    try testing.expectError(error.BadArguments, parseOptions(&.{"show"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{"total"}));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "show", "a", "b" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{"--project"}));
    try testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

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
    try testing.expectEqual(Verdict.priced, verdictOf(sessions[0].spend));
    try testing.expectEqual(Verdict.priced, verdictOf(sessions[1].spend));

    const total = totalOf(sessions);
    try testing.expectEqual(@as(u64, 2), total.turns);
    try testing.expectEqual(Verdict.mixed_currency, verdictOf(total));
    try testing.expect(!total.enforceable());
    const text = try costText(arena, total);
    try testing.expect(std.mem.indexOf(u8, text, "3.25") == null);
    try testing.expect(std.mem.indexOf(u8, text, "two currencies") != null);
}

test "a session that got no reply is told apart from one that cost nothing" {
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

    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expect((try showSession(arena, testing.io, dir, never)) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), never) != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), dir) != null);

    said.clear();
    try testing.expect((try showSession(arena, testing.io, dir, "../../etc/passwd")) != Exit.finished.code());
    try testing.expect(std.mem.indexOf(u8, said.err(), "not a session identifier") != null);

    said.clear();
    try testing.expect((try showSession(arena, testing.io, dir, "")) != Exit.finished.code());
    try testing.expect(said.err().len != 0);
    try testing.expectEqualStrings("", said.out());
}

test "a project that never ran a session lists nothing rather than failing" {
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
    try testing.expect(std.mem.indexOf(u8, said.err(), missing) != null);
}

test "only a session log is read, and a file that is not one is left alone" {
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

// Not hypothetical: ai& sends X-Cost and X-Cost-Currency apart, so a bare printed number would read as dollars to anyone who assumes dollars.
test "a cost the provider gave no currency for is not printed as a bare number" {
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
    try testing.expect(std.mem.indexOf(u8, text, "0.0002") != null);
    try testing.expect(!std.mem.endsWith(u8, text, "0.0002"));
}

test "every verdict has its own words, so no two states read alike" {
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
