//! A read-only, recursive view of one real subagent tree.

const std = @import("std");
const chock_proto = @import("chock-proto");

const tty = @import("tty.zig");

const event = chock_proto.event;
const state = chock_proto.state;

pub const Format = enum {
    human,
    compact,
    json,
};

pub const Outcome = enum { shown, not_found, invalid };

const ParentEdge = struct {
    parent: []const u8 = "",
    agent_kind: []const u8 = "",
    reason: []const u8 = "",
    budget_max_cost: f64 = 0,
    budget_currency: []const u8 = "",
    outcome: ?event.AgentOutcome = null,
};

const Totals = struct {
    nodes: usize = 0,
    running: usize = 0,
    incomplete: usize = 0,
    spend: state.Spend = .{},
};

pub fn show(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    format: Format,
) !Outcome {
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    const outcome = try render(arena, gpa, io, dir, id, format, &text.writer);
    tty.out(.plain, "{s}", .{text.written()});
    return outcome;
}

fn render(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    format: Format,
    writer: *std.Io.Writer,
) !Outcome {
    var visited: std.StringHashMapUnmanaged(void) = .empty;
    defer visited.deinit(gpa);
    var totals = Totals{};
    const found = try renderNode(arena, gpa, io, dir, id, .{}, 0, format, writer, &visited, &totals);
    if (!found) return .not_found;

    if (format == .human) {
        try writer.print("\n{d} sessions; {d} running; {d} without a terminal record", .{
            totals.nodes,
            totals.running,
            totals.incomplete,
        });
        if (totals.spend.turns != 0) {
            try writer.print("; {d} input + {d} output tokens", .{
                totals.spend.input_tokens + totals.spend.cache_creation_input_tokens + totals.spend.cache_read_input_tokens,
                totals.spend.output_tokens,
            });
            if (totals.spend.enforceable() and totals.spend.currency.len != 0) {
                try writer.print("; {d:.4} {s}", .{ totals.spend.amount, totals.spend.currency });
            }
        }
        try writer.writeByte('\n');
    }
    return if (totals.incomplete == 0) .shown else .invalid;
}

fn renderNode(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    id: []const u8,
    edge: ParentEdge,
    depth: usize,
    format: Format,
    writer: *std.Io.Writer,
    visited: *std.StringHashMapUnmanaged(void),
    totals: *Totals,
) !bool {
    if (visited.contains(id)) {
        try writeMissing(writer, format, depth, id, edge, "cycle");
        totals.incomplete += 1;
        return true;
    }

    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            if (depth != 0) {
                try writeMissing(writer, format, depth, id, edge, "missing log");
                totals.nodes += 1;
                totals.incomplete += @intFromBool(edge.outcome == null);
                return true;
            }
            return false;
        },
        else => {
            try writeMissing(writer, format, depth, id, edge, @errorName(err));
            totals.nodes += 1;
            totals.incomplete += 1;
            return true;
        },
    };

    const owned_id = try arena.dupe(u8, id);
    try visited.put(gpa, owned_id, {});

    var session = state.Session.init(arena);
    const opened = chock_proto.log.Log.open(io, path, id) catch |err| {
        try writeMissing(writer, format, depth, id, edge, @errorName(err));
        totals.nodes += 1;
        totals.incomplete += 1;
        return true;
    };
    var backing = chock_proto.storage.JsonLines{ .log = opened };
    const storage = backing.storage();
    defer storage.close(io);
    var replay = storage.replay(gpa, io, 0) catch |err| {
        try writeMissing(writer, format, depth, id, edge, @errorName(err));
        totals.nodes += 1;
        totals.incomplete += 1;
        return true;
    };
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try session.apply(parsed.value);
    }

    const live = isLive(io, path);
    const terminal = edge.outcome != null or session.ended;
    totals.nodes += 1;
    totals.running += @intFromBool(live);
    totals.incomplete += @intFromBool(!live and !terminal);
    totals.spend.merge(session.spend);

    try writeNode(writer, format, depth, id, edge, session, live);
    for (session.children.items) |child| {
        _ = try renderNode(arena, gpa, io, dir, child.session, .{
            .parent = id,
            .agent_kind = child.agent_kind,
            .reason = child.reason,
            .budget_max_cost = child.budget_max_cost,
            .budget_currency = child.budget_currency,
            .outcome = child.outcome,
        }, depth + 1, format, writer, visited, totals);
    }
    return true;
}

fn writeNode(
    writer: *std.Io.Writer,
    format: Format,
    depth: usize,
    id: []const u8,
    edge: ParentEdge,
    session: state.Session,
    live: bool,
) !void {
    const agent = if (edge.agent_kind.len != 0) edge.agent_kind else session.agent_kind;
    const status = statusName(edge.outcome, session, live);
    switch (format) {
        .human => {
            try indent(writer, depth);
            try writer.print("{s}  {s}  {s}", .{ id, agent, status });
            if (edge.budget_max_cost > 0) try writer.print("  budget {d:.4} {s}", .{
                edge.budget_max_cost,
                edge.budget_currency,
            });
            if (session.spend.turns != 0) {
                try writer.print("  {d} in/{d} out", .{
                    session.spend.input_tokens + session.spend.cache_creation_input_tokens + session.spend.cache_read_input_tokens,
                    session.spend.output_tokens,
                });
                if (session.spend.enforceable() and session.spend.currency.len != 0) {
                    try writer.print("  {d:.4} {s}", .{ session.spend.amount, session.spend.currency });
                }
            }
            try writer.writeByte('\n');
            if (edge.reason.len != 0) {
                try indent(writer, depth + 1);
                try writer.print("{s}\n", .{edge.reason});
            }
        },
        .compact => try writer.print("{d} {s} parent={s} agent={s} status={s} budget={d} {s} input={d} output={d}\n", .{
            depth,
            id,
            edge.parent,
            agent,
            status,
            edge.budget_max_cost,
            edge.budget_currency,
            session.spend.input_tokens + session.spend.cache_creation_input_tokens + session.spend.cache_read_input_tokens,
            session.spend.output_tokens,
        }),
        .json => {
            const row = .{
                .depth = depth,
                .session = id,
                .parent = edge.parent,
                .agent_kind = agent,
                .status = status,
                .reason = edge.reason,
                .budget_max_cost = edge.budget_max_cost,
                .budget_currency = edge.budget_currency,
                .input_tokens = session.spend.input_tokens,
                .output_tokens = session.spend.output_tokens,
                .cache_creation_input_tokens = session.spend.cache_creation_input_tokens,
                .cache_read_input_tokens = session.spend.cache_read_input_tokens,
                .cost = session.spend.amount,
                .currency = session.spend.currency,
            };
            try std.json.Stringify.value(row, .{}, writer);
            try writer.writeByte('\n');
        },
    }
}

fn writeMissing(
    writer: *std.Io.Writer,
    format: Format,
    depth: usize,
    id: []const u8,
    edge: ParentEdge,
    problem: []const u8,
) !void {
    const status = if (edge.outcome) |outcome| outcome.wireName() else problem;
    switch (format) {
        .human => {
            try indent(writer, depth);
            try writer.print("{s}  {s}  {s} ({s})\n", .{ id, edge.agent_kind, status, problem });
        },
        .compact => try writer.print("{d} {s} parent={s} agent={s} status={s} problem={s}\n", .{
            depth, id, edge.parent, edge.agent_kind, status, problem,
        }),
        .json => {
            try std.json.Stringify.value(.{
                .depth = depth,
                .session = id,
                .parent = edge.parent,
                .agent_kind = edge.agent_kind,
                .status = status,
                .problem = problem,
            }, .{}, writer);
            try writer.writeByte('\n');
        },
    }
}

fn statusName(outcome: ?event.AgentOutcome, session: state.Session, live: bool) []const u8 {
    if (live) return "running";
    if (outcome) |one| return one.wireName();
    if (session.ended) return session.end_reason.wireName();
    return "missing terminal record";
}

fn indent(writer: *std.Io.Writer, depth: usize) !void {
    var left = depth;
    while (left != 0) : (left -= 1) try writer.writeAll("  ");
}

fn isLive(io: std.Io, path: [:0]const u8) bool {
    const fd = std.posix.openatZ(std.posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    var file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    defer file.close(io);
    const acquired = file.tryLock(io, .shared) catch return false;
    if (acquired) file.unlock(io);
    return !acquired;
}

fn makeTestLog(
    arena: std.mem.Allocator,
    dir: []const u8,
    id: []const u8,
    events: []const event.Event,
) !void {
    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, id }, 0);
    const log = try chock_proto.log.Log.open(std.testing.io, path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const storage = backing.storage();
    defer storage.close(std.testing.io);
    var locked = try storage.lock(std.testing.io);
    defer locked.unlock(std.testing.io) catch {};
    for (events) |one| _ = try locked.append(arena, std.testing.io, one, 0);
}

test "tree keeps sibling outcomes separate and reconciles delegated usage" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const dir = try arena.dupe(u8, path_buffer[0..path_len]);

    const parent = "01T0" ++ @as([22]u8, @splat('A'));
    const worker = "01T0" ++ @as([22]u8, @splat('B'));
    const crashed = "01T0" ++ @as([22]u8, @splat('C'));
    const parent_events = [_]event.Event{
        .{ .session_start = .{ .agent_kind = "coder", .model_alias = "main", .parent_session = "" } },
        .{ .session_spawn = .{
            .child_session = worker,
            .child_agent_kind = "worker",
            .reason = "implement",
            .budget_max_cost = 2.5,
            .budget_currency = "USD",
        } },
        .{ .session_spawn = .{
            .child_session = crashed,
            .child_agent_kind = "reviewer",
            .reason = "review",
            .budget_max_cost = 1.25,
            .budget_currency = "USD",
        } },
        .{ .agent_complete = .{
            .child_session = worker,
            .child_agent_kind = "worker",
            .outcome = .finished,
            .result = "done",
            .scratchpad_path = "",
        } },
        .{ .agent_complete = .{
            .child_session = crashed,
            .child_agent_kind = "reviewer",
            .outcome = .died,
            .result = "exited before session.end",
            .scratchpad_path = "",
        } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    };
    try makeTestLog(arena, dir, parent, &parent_events);

    const worker_events = [_]event.Event{
        .{ .session_start = .{ .agent_kind = "worker", .model_alias = "main", .parent_session = parent } },
        .{ .usage = .{
            .input_tokens = 100,
            .output_tokens = 25,
            .cost = .{ .known = .{ .value = 0.75, .currency = "USD" } },
        } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    };
    try makeTestLog(arena, dir, worker, &worker_events);

    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();
    const result = try render(arena, gpa, std.testing.io, dir, parent, .json, &output.writer);
    try std.testing.expectEqual(Outcome.shown, result);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"status\":\"finished\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"status\":\"died\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"budget_max_cost\":2.5") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"input_tokens\":100") != null);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, output.written(), "\n"));
}

test "an idle child without agent.complete makes the tree an audit gap" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(std.testing.io, &path_buffer);
    const dir = try arena.dupe(u8, path_buffer[0..path_len]);
    const parent = "01T1" ++ @as([22]u8, @splat('A'));
    const child = "01T1" ++ @as([22]u8, @splat('B'));
    const events = [_]event.Event{
        .{ .session_start = .{ .agent_kind = "coder", .model_alias = "main", .parent_session = "" } },
        .{ .session_spawn = .{ .child_session = child, .child_agent_kind = "worker", .reason = "unfinished" } },
        .{ .session_end = .{ .reason = .finished, .detail = "" } },
    };
    try makeTestLog(arena, dir, parent, &events);

    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();
    const result = try render(arena, gpa, std.testing.io, dir, parent, .compact, &output.writer);
    try std.testing.expectEqual(Outcome.invalid, result);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "status=missing log") != null);
}
