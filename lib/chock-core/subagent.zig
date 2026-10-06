//! One subagent: a child process with a session of its own, and the
//! answer its parent reads back out of the child's own log.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const chock_cost = @import("chock-cost");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const scratchpad = @import("scratchpad.zig");

pub const Shape = union(enum) {
    prose,
    schema: []const []const u8,
};

pub const Request = struct {
    agent_kind: []const u8,
    task: []const u8,
    shape: Shape = .prose,
    reason: []const u8,
    budget: ?chock_cost.budget.Budget = null,
};

pub const Prepared = struct {
    child_session: []u8,
    log_path: []u8,
    scratchpad_path: []u8,
};

pub fn freePrepared(allocator: std.mem.Allocator, prepared: Prepared) void {
    allocator.free(prepared.child_session);
    allocator.free(prepared.log_path);
    allocator.free(prepared.scratchpad_path);
}

pub const Report = struct {
    outcome: event.AgentOutcome,
    result: []u8,
};

pub fn freeReport(allocator: std.mem.Allocator, report: Report) void {
    allocator.free(report.result);
    if (report.outcome == .unknown) allocator.free(report.outcome.unknown);
}

pub const Error = error{
    ChildNotStarted,
} || std.mem.Allocator.Error;

pub const Spawner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        prepare: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            request: Request,
        ) Error!Prepared,
        run: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            request: Request,
            prepared: Prepared,
        ) Error!Report,
    };

    pub fn prepare(
        self: Spawner,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: Request,
    ) Error!Prepared {
        return self.vtable.prepare(self.ptr, allocator, io, request);
    }

    pub fn run(
        self: Spawner,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: Request,
        prepared: Prepared,
    ) Error!Report {
        return self.vtable.run(self.ptr, allocator, io, request, prepared);
    }
};

pub const max_reason_bytes: usize = 200;

pub fn reasonFor(task: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, task, " \t\r\n");
    const first_line = trimmed[0 .. std.mem.indexOfScalar(u8, trimmed, '\n') orelse trimmed.len];
    if (first_line.len <= max_reason_bytes) return first_line;
    return first_line[0..max_reason_bytes];
}

pub fn taskFor(
    allocator: std.mem.Allocator,
    task: []const u8,
    shape: Shape,
) std.mem.Allocator.Error![]u8 {
    const fields = switch (shape) {
        .prose => return allocator.dupe(u8, task),
        .schema => |named| named,
    };

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    try text.appendSlice(allocator, task);
    try text.appendSlice(
        allocator,
        "\n\nAnswer with one JSON object and nothing else: no explanation before it, no code " ++
            "fence around it. The object must hold these members:",
    );
    for (fields) |field| try text.print(allocator, "\n  \"{s}\"", .{field});
    try text.appendSlice(
        allocator,
        "\nPut anything longer than a sentence in a file in your scratchpad and name the path " ++
            "in the object instead.",
    );
    return text.toOwnedSlice(allocator);
}

pub fn checkShape(
    allocator: std.mem.Allocator,
    shape: Shape,
    answer: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    const fields = switch (shape) {
        .prose => return null,
        .schema => |named| named,
    };

    const trimmed = std.mem.trim(u8, answer, " \t\r\n");
    if (trimmed.len == 0) {
        return try allocator.dupe(u8, "the subagent answered with nothing at all");
    }

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return try std.fmt.allocPrint(
            allocator,
            "the subagent was asked for one JSON object and its answer is not JSON at all",
            .{},
        );
    };
    defer parsed.deinit();

    const object = switch (parsed.value) {
        .object => |members| members,
        else => return try std.fmt.allocPrint(
            allocator,
            "the subagent was asked for one JSON object and answered with a {s}",
            .{@tagName(parsed.value)},
        ),
    };

    for (fields) |field| {
        if (object.get(field) == null) {
            return try std.fmt.allocPrint(
                allocator,
                "the subagent's answer has no \"{s}\" member, and the spawn asked for one",
                .{field},
            );
        }
    }
    return null;
}

pub const max_result_bytes: usize = 16 * 1024;

pub fn readReport(
    allocator: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    shape: Shape,
) std.mem.Allocator.Error!Report {
    var answer: std.ArrayList(u8) = .empty;
    defer answer.deinit(allocator);
    var ended: ?event.SessionEndReason = null;
    var end_detail: std.ArrayList(u8) = .empty;
    defer end_detail.deinit(allocator);

    var replay = storage.replay(allocator, io, 0) catch |err| {
        return diedBecause(allocator, "the child's log could not be read ({t})", .{err});
    };
    defer replay.deinit();

    while (true) {
        const step = replay.next(io) catch |err| {
            return diedBecause(allocator, "the child's log stops partway through ({t})", .{err});
        };
        const parsed = step orelse break;
        defer parsed.deinit();

        switch (parsed.value.event) {
            .session_end => |end| {
                ended = end.reason;
                end_detail.clearRetainingCapacity();
                try end_detail.appendSlice(allocator, end.detail);
            },
            .message => |said| {
                if (said.role != .assistant) continue;
                answer.clearRetainingCapacity();
                for (said.content) |part| {
                    if (part == .text) try answer.appendSlice(allocator, part.text);
                }
            },
            else => {},
        }
    }

    const reason = ended orelse return diedBecause(
        allocator,
        "the child's log has no session.end, so the child was stopped or it died before it " ++
            "could say why",
        .{},
    );

    const text = std.mem.trim(u8, answer.items, " \t\r\n");
    const kept = text[0..@min(text.len, max_result_bytes)];

    switch (reason) {
        .finished => {
            if (try checkShape(allocator, shape, kept)) |complaint| {
                defer allocator.free(complaint);
                return .{
                    .outcome = .refused,
                    .result = try std.fmt.allocPrint(allocator, "{s}. It said: {s}", .{ complaint, kept }),
                };
            }
            return .{ .outcome = .finished, .result = try allocator.dupe(u8, kept) };
        },
        .no_progress => return .{
            .outcome = .no_progress,
            .result = try std.fmt.allocPrint(
                allocator,
                "the subagent stopped making progress and repeated the same call. What it had said " ++
                    "by then: {s}",
                .{kept},
            ),
        },
        .budget_reached => return .{
            .outcome = .budget,
            .result = try std.fmt.allocPrint(
                allocator,
                "the subagent used the whole budget it was given at spawn. What it had said by " ++
                    "then: {s}",
                .{kept},
            ),
        },
        .rate_limited => return .{
            .outcome = .rate_limited,
            .result = try std.fmt.allocPrint(
                allocator,
                "the subagent was rate limited by the model backend and gave up after waiting: " ++
                    "{s}. Asking again later is expected to work. What it had said by then: {s}",
                .{ end_detail.items, kept },
            ),
        },
        else => return .{
            .outcome = .refused,
            .result = try std.fmt.allocPrint(
                allocator,
                "the subagent's session ended {s}: {s}. What it had said by then: {s}",
                .{ reason.wireName(), end_detail.items, kept },
            ),
        },
    }
}

fn diedBecause(
    allocator: std.mem.Allocator,
    comptime format: []const u8,
    args: anytype,
) std.mem.Allocator.Error!Report {
    return .{ .outcome = .died, .result = try std.fmt.allocPrint(allocator, format, args) };
}

pub fn budgetSlice(
    cap: ?chock_cost.budget.Budget,
    spend: chock_proto.state.Spend,
    committed: f64,
    children_left: usize,
) ?chock_cost.budget.Budget {
    const budget = cap orelse return null;
    std.debug.assert(children_left >= 1);

    const left = budget.max_cost - spentAgainst(budget, spend) - committed;
    if (left <= 0) return null;
    return .{
        .max_cost = left / @as(f64, @floatFromInt(children_left)),
        .currency = budget.currency,
    };
}

pub fn nothingLeft(
    cap: ?chock_cost.budget.Budget,
    spend: chock_proto.state.Spend,
    committed: f64,
) bool {
    const budget = cap orelse return false;
    return budget.max_cost - spentAgainst(budget, spend) - committed <= 0;
}

fn spentAgainst(budget: chock_cost.budget.Budget, spend: chock_proto.state.Spend) f64 {
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, budget.currency)) return 0;
    return spend.amount;
}

pub fn committedToChildren(
    children: []const chock_proto.state.Child,
    cap: ?chock_cost.budget.Budget,
) f64 {
    const budget = cap orelse return 0;
    var total: f64 = 0;
    for (children) |child| {
        if (child.budget_currency.len != 0 and !std.mem.eql(u8, child.budget_currency, budget.currency)) {
            continue;
        }
        total += child.budget_max_cost;
    }
    return total;
}

pub fn spentAlready(cap: ?chock_cost.budget.Budget, spend: chock_proto.state.Spend) bool {
    const budget = cap orelse return false;
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, budget.currency)) return false;
    return spend.amount >= budget.max_cost;
}

pub const Mode = enum {
    wait,
    carry_on,
};

pub const Completion = struct {
    child_session: []const u8,
    agent_kind: []const u8,
    outcome: event.AgentOutcome,
    result: []const u8,
    scratchpad_path: []const u8,
};

pub fn freeCompletions(allocator: std.mem.Allocator, list: []Completion) void {
    for (list) |one| freeCompletion(allocator, one);
    allocator.free(list);
}

fn freeCompletion(allocator: std.mem.Allocator, one: Completion) void {
    allocator.free(one.child_session);
    allocator.free(one.agent_kind);
    allocator.free(one.result);
    allocator.free(one.scratchpad_path);
    if (one.outcome == .unknown) allocator.free(one.outcome.unknown);
}

const Lock = struct {
    held: std.atomic.Value(bool) = .init(false),

    fn lock(self: *Lock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *Lock) void {
        self.held.store(false, .release);
    }
};

pub const Table = struct {
    gpa: std.mem.Allocator,
    spawner: Spawner,

    mutex: Lock = .{},
    started: usize = 0,
    completed: usize = 0,
    finished: std.ArrayList(Completion) = .empty,
    threads: std.ArrayList(std.Thread) = .empty,
    lost: ?Diagnostic = null,

    pub fn takeLost(self: *Table) ?Diagnostic {
        self.mutex.lock();
        defer self.mutex.unlock();
        const taken = self.lost;
        self.lost = null;
        return taken;
    }

    fn noteLost(self: *Table, comptime tag: std.meta.Tag(Diagnostic)) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        diagnostic.note(&self.lost, tag);
    }

    pub fn deinit(self: *Table) void {
        self.waitAll();
        if (self.take(self.gpa)) |taken| freeCompletions(self.gpa, taken) else |_| {}
        self.threads.deinit(self.gpa);
        self.finished.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn waitAll(self: *Table) void {
        while (true) {
            self.mutex.lock();
            const thread = self.threads.pop();
            self.mutex.unlock();
            if (thread) |one| one.join() else return;
        }
    }

    pub fn startedCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started;
    }

    pub fn runningCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started - self.completed;
    }

    pub fn start(
        self: *Table,
        io: std.Io,
        request: Request,
        prepared: Prepared,
    ) std.mem.Allocator.Error!void {
        const job = try self.gpa.create(Job);
        errdefer self.gpa.destroy(job);
        job.* = .{ .table = self, .io = io, .arena = .init(std.heap.page_allocator) };
        errdefer job.arena.deinit();

        const arena = job.arena.allocator();
        job.request = .{
            .agent_kind = try arena.dupe(u8, request.agent_kind),
            .task = try arena.dupe(u8, request.task),
            .shape = try copyShape(arena, request.shape),
            .reason = try arena.dupe(u8, request.reason),
            .budget = request.budget,
        };
        job.prepared = .{
            .child_session = try arena.dupe(u8, prepared.child_session),
            .log_path = try arena.dupe(u8, prepared.log_path),
            .scratchpad_path = try arena.dupe(u8, prepared.scratchpad_path),
        };

        const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch return error.OutOfMemory;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.started += 1;
        self.threads.append(self.gpa, thread) catch {
            diagnostic.note(&self.lost, .subagent_thread_not_tracked);
        };
    }

    pub fn take(self: *Table, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Completion {
        self.mutex.lock();
        defer self.mutex.unlock();

        const taken = try self.finished.toOwnedSlice(self.gpa);
        if (allocator.ptr == self.gpa.ptr and allocator.vtable == self.gpa.vtable) return taken;

        defer freeCompletions(self.gpa, taken);
        var copies = try allocator.alloc(Completion, taken.len);
        var made: usize = 0;
        errdefer freeCompletions(allocator, copies[0..made]);
        for (taken, 0..) |one, index| {
            copies[index] = .{
                .child_session = try allocator.dupe(u8, one.child_session),
                .agent_kind = try allocator.dupe(u8, one.agent_kind),
                .outcome = if (one.outcome == .unknown)
                    .{ .unknown = try allocator.dupe(u8, one.outcome.unknown) }
                else
                    one.outcome,
                .result = try allocator.dupe(u8, one.result),
                .scratchpad_path = try allocator.dupe(u8, one.scratchpad_path),
            };
            made = index + 1;
        }
        return copies;
    }

    fn record(self: *Table, completion: Completion) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.completed += 1;
        self.finished.append(self.gpa, completion) catch {
            diagnostic.note(&self.lost, .subagent_record_not_kept);
        };
    }
};

fn copyShape(allocator: std.mem.Allocator, shape: Shape) std.mem.Allocator.Error!Shape {
    const named = switch (shape) {
        .prose => return .prose,
        .schema => |fields| fields,
    };
    const copies = try allocator.alloc([]const u8, named.len);
    for (named, 0..) |one, index| copies[index] = try allocator.dupe(u8, one);
    return .{ .schema = copies };
}

const Job = struct {
    table: *Table,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    request: Request = undefined,
    prepared: Prepared = undefined,

    fn run(self: *Job) void {
        const allocator = self.arena.allocator();
        const report = self.table.spawner.run(allocator, self.io, self.request, self.prepared) catch |err| {
            return self.finish(.died, switch (err) {
                error.ChildNotStarted => "the subagent's process could not be started",
                error.OutOfMemory => "the subagent ran and this process ran out of memory reading " ++
                    "what it said",
            });
        };
        self.finish(report.outcome, report.result);
    }

    fn finish(self: *Job, outcome: event.AgentOutcome, result: []const u8) void {
        const gpa = self.table.gpa;
        var made = Completion{
            .child_session = "",
            .agent_kind = "",
            .outcome = .died,
            .result = "",
            .scratchpad_path = "",
        };
        made.child_session = gpa.dupe(u8, self.prepared.child_session) catch return self.giveUp(made);
        made.agent_kind = gpa.dupe(u8, self.request.agent_kind) catch return self.giveUp(made);
        made.result = gpa.dupe(u8, result) catch return self.giveUp(made);
        made.scratchpad_path = gpa.dupe(u8, self.prepared.scratchpad_path) catch return self.giveUp(made);
        made.outcome = if (outcome == .unknown)
            .{ .unknown = gpa.dupe(u8, outcome.unknown) catch return self.giveUp(made) }
        else
            outcome;

        self.table.record(made);
        self.release();
    }

    fn giveUp(self: *Job, partial: Completion) void {
        freeCompletion(self.table.gpa, partial);
        self.table.noteLost(.subagent_record_not_built);
        self.release();
    }

    fn release(self: *Job) void {
        const gpa = self.table.gpa;
        self.arena.deinit();
        gpa.destroy(self);
    }
};

pub const flag = struct {
    pub const project = "--project";
    pub const session = "--session";
    pub const agent_kind = "--agent-kind";
    pub const parent_session = "--parent-session";
    pub const parent_kind = "--parent-kind";
    pub const spawn_reason = "--spawn-reason";
    pub const scratchpad = "--scratchpad";
    pub const max_cost = "--max-cost";
    pub const currency = "--currency";
    pub const provider = "--provider";
    pub const model = "--model";
};

pub const Command = struct {
    exe_path: []const u8,
    project_root: []const u8,
    parent_session: []const u8,
    parent_chain: []const event.SpawnLink = &.{},
    provider: []const u8 = "",
    model: []const u8 = "",

    pub fn chainBelow(
        allocator: std.mem.Allocator,
        above: []const event.SpawnLink,
        agent_kind: []const u8,
        reason: []const u8,
    ) std.mem.Allocator.Error![]event.SpawnLink {
        const out = try allocator.alloc(event.SpawnLink, above.len + 1);
        @memcpy(out[0..above.len], above);
        out[above.len] = .{ .agent_kind = agent_kind, .reason = reason };
        return out;
    }
};

pub fn commandLine(
    allocator: std.mem.Allocator,
    command: Command,
    request: Request,
    prepared: Prepared,
) std.mem.Allocator.Error![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    errdefer freeCommandLine(allocator, argv.items);
    errdefer argv.deinit(allocator);

    try append(allocator, &argv, command.exe_path);
    try append(allocator, &argv, "run");
    try appendPair(allocator, &argv, flag.project, command.project_root);
    try appendPair(allocator, &argv, flag.session, prepared.child_session);
    try appendPair(allocator, &argv, flag.agent_kind, request.agent_kind);
    try appendPair(allocator, &argv, flag.parent_session, command.parent_session);
    for (command.parent_chain) |link| {
        try appendPair(allocator, &argv, flag.parent_kind, link.agent_kind);
        try appendPair(allocator, &argv, flag.spawn_reason, link.reason);
    }
    if (prepared.scratchpad_path.len != 0) {
        try appendPair(allocator, &argv, flag.scratchpad, prepared.scratchpad_path);
    }
    if (request.budget) |slice| {
        const amount = try std.fmt.allocPrint(allocator, "{d}", .{slice.max_cost});
        errdefer allocator.free(amount);
        try append(allocator, &argv, flag.max_cost);
        try argv.append(allocator, amount);
        try appendPair(allocator, &argv, flag.currency, slice.currency);
    }
    if (command.provider.len != 0) try appendPair(allocator, &argv, flag.provider, command.provider);
    if (command.model.len != 0) try appendPair(allocator, &argv, flag.model, command.model);

    try append(allocator, &argv, "--");
    const task = try taskFor(allocator, request.task, request.shape);
    errdefer allocator.free(task);
    try argv.append(allocator, task);

    return argv.toOwnedSlice(allocator);
}

pub fn freeCommandLine(allocator: std.mem.Allocator, argv: []const []const u8) void {
    for (argv) |one| allocator.free(one);
    allocator.free(argv);
}

fn append(
    allocator: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    text: []const u8,
) std.mem.Allocator.Error!void {
    const owned = try allocator.dupe(u8, text);
    errdefer allocator.free(owned);
    try argv.append(allocator, owned);
}

fn appendPair(
    allocator: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    name: []const u8,
    value: []const u8,
) std.mem.Allocator.Error!void {
    try append(allocator, argv, name);
    try append(allocator, argv, value);
}

pub fn childDir(
    allocator: std.mem.Allocator,
    parent_dir: []const u8,
    child_session: []const u8,
) (std.mem.Allocator.Error || scratchpad.LeafError)![]u8 {
    const leaf = try scratchpad.leafFor(allocator, .{ .child = child_session });
    defer allocator.free(leaf);
    const session_leaf = std.fs.path.dirname(leaf).?;
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent_dir, session_leaf });
}

const testing = std.testing;

const ChildLog = struct {
    tmp: std.testing.TmpDir,
    path: [:0]u8,
    backing: chock_proto.storage.JsonLines,

    fn init(allocator: std.mem.Allocator, id: []const u8) !ChildLog {
        var tmp = testing.tmpDir(.{});
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/child.jsonl", .{buffer[0..len]}, 0);
        return .{
            .tmp = tmp,
            .path = path,
            .backing = .{ .log = try chock_proto.log.Log.open(testing.io, path, id) },
        };
    }

    fn deinit(self: *ChildLog, allocator: std.mem.Allocator) void {
        self.backing.log.close(testing.io);
        allocator.free(self.path);
        self.tmp.cleanup();
    }

    fn append(self: *ChildLog, allocator: std.mem.Allocator, one: event.Event) !void {
        const storage = self.backing.storage();
        var locked = try storage.lock(testing.io);
        defer locked.unlock(testing.io) catch {};
        _ = try locked.append(allocator, testing.io, one, 1000);
    }

    fn say(self: *ChildLog, allocator: std.mem.Allocator, text: []const u8) !void {
        const content = [_]event.ContentPart{.{ .text = text }};
        try self.append(allocator, .{ .message = .{ .role = .assistant, .content = &content } });
    }

    fn report(self: *ChildLog, allocator: std.mem.Allocator, shape: Shape) !Report {
        return readReport(allocator, testing.io, self.backing.storage(), shape);
    }
};

test "a child with no session.end reads as died, and never as finished" {
    const gpa = testing.allocator;
    var log = try ChildLog.init(gpa, "01CHILDAA");
    defer log.deinit(gpa);

    try log.append(gpa, .{ .session_start = .{
        .agent_kind = "reviewer",
        .model_alias = "local",
        .parent_session = "01PARENTA",
    } });
    try log.say(gpa, "I read the first file and");

    const died = try log.report(gpa, .prose);
    defer freeReport(gpa, died);
    try testing.expectEqual(event.AgentOutcome.died, died.outcome);
    try testing.expect(std.mem.indexOf(u8, died.result, "session.end") != null);

    try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    const finished = try log.report(gpa, .prose);
    defer freeReport(gpa, finished);
    try testing.expectEqual(event.AgentOutcome.finished, finished.outcome);
    try testing.expectEqualStrings("I read the first file and", finished.result);
}

test "each way a child session can end is its own outcome, and the answer comes back with it" {
    const gpa = testing.allocator;

    const cases = [_]struct { reason: event.SessionEndReason, want: event.AgentOutcome }{
        .{ .reason = .finished, .want = .finished },
        .{ .reason = .no_progress, .want = .no_progress },
        .{ .reason = .budget_reached, .want = .budget },
        .{ .reason = .errored, .want = .refused },
        .{ .reason = .canceled_by_user, .want = .refused },
        .{ .reason = .turn_limit, .want = .refused },
        .{ .reason = .rate_limited, .want = .rate_limited },
    };

    for (cases) |one| {
        var log = try ChildLog.init(gpa, "01CHILDAA");
        defer log.deinit(gpa);
        try log.say(gpa, "the parser is in src/parse.zig");
        try log.append(gpa, .{ .session_end = .{ .reason = one.reason, .detail = "why" } });

        const report = try log.report(gpa, .prose);
        defer freeReport(gpa, report);
        try testing.expectEqual(one.want, report.outcome);
        try testing.expect(std.mem.indexOf(u8, report.result, "src/parse.zig") != null);
    }
}

test "only the child's own last words are the answer, and a tool result is not one" {
    const gpa = testing.allocator;
    var log = try ChildLog.init(gpa, "01CHILDAA");
    defer log.deinit(gpa);

    try log.say(gpa, "first I will read the file");
    const tool_said = [_]event.ContentPart{.{ .text = "the whole file, thousands of bytes" }};
    try log.append(gpa, .{ .message = .{ .role = .tool, .content = &tool_said } });
    const asked = [_]event.ContentPart{.{ .text = "the task the parent wrote" }};
    try log.append(gpa, .{ .message = .{ .role = .user, .content = &asked } });
    try log.say(gpa, "the parser refuses an empty file");
    try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });

    const report = try log.report(gpa, .prose);
    defer freeReport(gpa, report);
    try testing.expectEqualStrings("the parser refuses an empty file", report.result);
}

test "a schema the child did not answer is refused, and the near miss still comes back" {
    const gpa = testing.allocator;
    const wanted = [_][]const u8{ "verdict", "path" };
    const shape = Shape{ .schema = &wanted };

    {
        var log = try ChildLog.init(gpa, "01CHILDAA");
        defer log.deinit(gpa);
        try log.say(gpa, "It looks fine to me, honestly.");
        try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });

        const report = try log.report(gpa, shape);
        defer freeReport(gpa, report);
        try testing.expectEqual(event.AgentOutcome.refused, report.outcome);
        try testing.expect(std.mem.indexOf(u8, report.result, "not JSON") != null);
        try testing.expect(std.mem.indexOf(u8, report.result, "It looks fine") != null);
    }

    {
        var log = try ChildLog.init(gpa, "01CHILDAA");
        defer log.deinit(gpa);
        try log.say(gpa, "{\"verdict\":\"safe\"}");
        try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });

        const report = try log.report(gpa, shape);
        defer freeReport(gpa, report);
        try testing.expectEqual(event.AgentOutcome.refused, report.outcome);
        try testing.expect(std.mem.indexOf(u8, report.result, "\"path\"") != null);
    }

    {
        var log = try ChildLog.init(gpa, "01CHILDAA");
        defer log.deinit(gpa);
        try log.say(gpa, "  {\"verdict\":\"safe\",\"path\":\"/run/chock/scratch/notes.md\"}\n");
        try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });

        const report = try log.report(gpa, shape);
        defer freeReport(gpa, report);
        try testing.expectEqual(event.AgentOutcome.finished, report.outcome);
        try testing.expectEqualStrings(
            "{\"verdict\":\"safe\",\"path\":\"/run/chock/scratch/notes.md\"}",
            report.result,
        );
    }
}

test "the same answer is accepted as prose and refused as a schema" {
    const gpa = testing.allocator;
    var log = try ChildLog.init(gpa, "01CHILDAA");
    defer log.deinit(gpa);
    try log.say(gpa, "the review found two faults, both in the parser");
    try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });

    const as_prose = try log.report(gpa, .prose);
    defer freeReport(gpa, as_prose);
    try testing.expectEqual(event.AgentOutcome.finished, as_prose.outcome);

    const wanted = [_][]const u8{"verdict"};
    const as_schema = try log.report(gpa, .{ .schema = &wanted });
    defer freeReport(gpa, as_schema);
    try testing.expectEqual(event.AgentOutcome.refused, as_schema.outcome);
}

test "the slices a parent hands out never add up to more than it has left" {
    const cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };
    const spent = chock_proto.state.Spend{ .amount = 1.0, .currency = "USD", .turns = 3 };

    var handed_out: f64 = 0;
    var children_left: usize = 4;
    while (children_left >= 1) : (children_left -= 1) {
        const slice = budgetSlice(cap, spent, handed_out, children_left).?;
        handed_out += slice.max_cost;
        try testing.expectEqualStrings("USD", slice.currency);
        if (children_left == 1) break;
    }
    try testing.expectApproxEqAbs(@as(f64, 4.0), handed_out, 0.000001);

    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetSlice(null, spent, 0, 4));
    try testing.expect(!nothingLeft(null, spent, 0));

    const all_gone = chock_proto.state.Spend{ .amount = 5.5, .currency = "USD", .turns = 9 };
    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetSlice(cap, all_gone, 0, 4));
    try testing.expect(nothingLeft(cap, all_gone, 0));

    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetSlice(cap, spent, 4.0, 4));
    try testing.expect(nothingLeft(cap, spent, 4.0));

    const only_one = budgetSlice(cap, spent, 0, 1).?;
    try testing.expectEqual(@as(f64, 4.0), only_one.max_cost);
}

test "what a parent has committed comes off its own log, so a resumed parent counts it" {
    const cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };
    const children = [_]chock_proto.state.Child{
        .{ .session = "01A", .agent_kind = "reviewer", .reason = "one", .budget_max_cost = 1.0, .budget_currency = "USD" },
        .{ .session = "01B", .agent_kind = "reviewer", .reason = "two", .budget_max_cost = 1.5, .budget_currency = "USD" },
        .{ .session = "01C", .agent_kind = "reviewer", .reason = "three", .budget_max_cost = 90.0, .budget_currency = "JPY" },
        .{ .session = "01D", .agent_kind = "reviewer", .reason = "four" },
    };
    try testing.expectEqual(@as(f64, 2.5), committedToChildren(&children, cap));
    try testing.expectEqual(@as(f64, 0), committedToChildren(&children, null));
}

test "the command line names the parent, and the task is the last argument" {
    const gpa = testing.allocator;
    const prepared = Prepared{
        .child_session = try gpa.dupe(u8, "01CHILDAA"),
        .log_path = try gpa.dupe(u8, "/tmp/chock/01CHILDAA.jsonl"),
        .scratchpad_path = try gpa.dupe(u8, "/tmp/chock/01PARENTA/agents/01CHILDAA"),
    };
    defer freePrepared(gpa, prepared);

    const chain = [_]event.SpawnLink{
        .{ .agent_kind = "main", .reason = "split the work" },
        .{ .agent_kind = "coder", .reason = "review the parser" },
    };
    const argv = try commandLine(gpa, .{
        .exe_path = "/nix/store/aaa/bin/chock",
        .project_root = "/home/ross/project",
        .parent_session = "01PARENTA",
        .parent_chain = &chain,
        .provider = "local",
        .model = "glm4.7-flash:A3B",
    }, .{
        .agent_kind = "reviewer",
        .task = "-read the parser and say what is wrong",
        .reason = "review the parser",
        .budget = .{ .max_cost = 1.25, .currency = "USD" },
    }, prepared);
    defer freeCommandLine(gpa, argv);

    try testing.expectEqualStrings("/nix/store/aaa/bin/chock", argv[0]);
    try testing.expectEqualStrings("run", argv[1]);

    try testing.expectEqualStrings("01PARENTA", valueOf(argv, flag.parent_session).?);
    try testing.expectEqualStrings("reviewer", valueOf(argv, flag.agent_kind).?);
    try testing.expectEqualStrings("01CHILDAA", valueOf(argv, flag.session).?);
    try testing.expectEqualStrings("/home/ross/project", valueOf(argv, flag.project).?);
    try testing.expectEqualStrings("1.25", valueOf(argv, flag.max_cost).?);
    try testing.expectEqualStrings("USD", valueOf(argv, flag.currency).?);
    try testing.expectEqualStrings("local", valueOf(argv, flag.provider).?);

    var kinds: [2][]const u8 = undefined;
    var reasons: [2][]const u8 = undefined;
    var links: usize = 0;
    for (argv, 0..) |one, index| {
        if (!std.mem.eql(u8, one, flag.parent_kind)) continue;
        kinds[links] = argv[index + 1];
        try testing.expectEqualStrings(flag.spawn_reason, argv[index + 2]);
        reasons[links] = argv[index + 3];
        links += 1;
    }
    try testing.expectEqual(@as(usize, 2), links);
    try testing.expectEqualStrings("main", kinds[0]);
    try testing.expectEqualStrings("split the work", reasons[0]);
    try testing.expectEqualStrings("coder", kinds[1]);
    try testing.expectEqualStrings("review the parser", reasons[1]);

    try testing.expectEqualStrings("--", argv[argv.len - 2]);
    try testing.expectEqualStrings("-read the parser and say what is wrong", argv[argv.len - 1]);
}

test "the chain a child is given is its parent's chain with its parent on the end" {
    const gpa = testing.allocator;

    const first = try Command.chainBelow(gpa, &.{}, "main", "split the work");
    defer gpa.free(first);
    try testing.expectEqual(@as(usize, 1), first.len);
    try testing.expectEqualStrings("main", first[0].agent_kind);
    try testing.expectEqualStrings("split the work", first[0].reason);

    const second = try Command.chainBelow(gpa, first, "coder", "review the parser");
    defer gpa.free(second);
    try testing.expectEqual(@as(usize, 2), second.len);
    try testing.expectEqualStrings("main", second[0].agent_kind);
    try testing.expectEqualStrings("coder", second[1].agent_kind);
    try testing.expectEqualStrings("review the parser", second[1].reason);

    try testing.expectEqual(@as(usize, 1), first.len);
}

test "a schema is asked for in the task the child reads, and prose asks for nothing" {
    const gpa = testing.allocator;

    const plain = try taskFor(gpa, "review the parser", .prose);
    defer gpa.free(plain);
    try testing.expectEqualStrings("review the parser", plain);

    const wanted = [_][]const u8{ "verdict", "notes_path" };
    const asked = try taskFor(gpa, "review the parser", .{ .schema = &wanted });
    defer gpa.free(asked);
    try testing.expect(std.mem.startsWith(u8, asked, "review the parser"));
    try testing.expect(std.mem.indexOf(u8, asked, "\"verdict\"") != null);
    try testing.expect(std.mem.indexOf(u8, asked, "\"notes_path\"") != null);
    try testing.expect(std.mem.indexOf(u8, asked, "one JSON object") != null);
}

test "the reason is one short line of the task, and a task with no newline still gives one" {
    try testing.expectEqualStrings("review the parser", reasonFor("review the parser\nand say why"));
    try testing.expectEqualStrings("review the parser", reasonFor("  review the parser  "));
    try testing.expectEqual(max_reason_bytes, reasonFor("x" ** 400).len);
}

test "a child's directory is inside its parent's scratchpad and cannot climb out of it" {
    const gpa = testing.allocator;

    const dir = try childDir(gpa, "/tmp/chock/01PARENTA", "01CHILDAA");
    defer gpa.free(dir);
    try testing.expectEqualStrings("/tmp/chock/01PARENTA/agents/01CHILDAA", dir);

    const leaf = try scratchpad.leafFor(gpa, .{ .child = "01CHILDAA" });
    defer gpa.free(leaf);
    const joined = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, scratchpad.scratch_leaf });
    defer gpa.free(joined);
    const from_leaf = try std.fmt.allocPrint(gpa, "/tmp/chock/01PARENTA/{s}", .{leaf});
    defer gpa.free(from_leaf);
    try testing.expectEqualStrings(joined, from_leaf);

    try testing.expectError(error.BadChildId, childDir(gpa, "/tmp/chock/01PARENTA", "../../etc"));
}

fn valueOf(argv: []const []const u8, name: []const u8) ?[]const u8 {
    for (argv, 0..) |one, index| {
        if (std.mem.eql(u8, one, name) and index + 1 < argv.len) return argv[index + 1];
    }
    return null;
}

test "a child that has finished stops being a running child, however its record is drained" {
    const gpa = testing.allocator;
    var table = Table{ .gpa = gpa, .spawner = undefined };
    defer table.threads.deinit(gpa);
    defer table.finished.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), table.runningCount());

    table.started = 2;
    try testing.expectEqual(@as(usize, 2), table.runningCount());

    table.record(.{
        .child_session = try gpa.dupe(u8, "01CHILD"),
        .agent_kind = try gpa.dupe(u8, "reviewer"),
        .outcome = .finished,
        .result = try gpa.dupe(u8, "a second reading of the diff"),
        .scratchpad_path = try gpa.dupe(u8, ""),
    });
    try testing.expectEqual(@as(usize, 1), table.runningCount());

    const drained = try table.take(gpa);
    freeCompletions(gpa, drained);
    try testing.expectEqual(@as(usize, 1), table.runningCount());

    table.record(.{
        .child_session = try gpa.dupe(u8, "01CHILE"),
        .agent_kind = try gpa.dupe(u8, "reviewer"),
        .outcome = .finished,
        .result = try gpa.dupe(u8, ""),
        .scratchpad_path = try gpa.dupe(u8, ""),
    });
    try testing.expectEqual(@as(usize, 0), table.runningCount());
    try testing.expectEqual(@as(usize, 2), table.startedCount());

    const rest = try table.take(gpa);
    freeCompletions(gpa, rest);
}

test "a record the table could not keep reaches the caller, and no longer only a terminal" {
    var table = Table{ .gpa = testing.allocator, .spawner = undefined };
    try testing.expectEqual(@as(?Diagnostic, null), table.takeLost());

    table.noteLost(.subagent_record_not_kept);
    table.noteLost(.subagent_thread_not_tracked);

    const lost = table.takeLost().?;
    try testing.expectEqual(Diagnostic.subagent_record_not_kept, lost);

    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "a subagent finished and its record could not be kept",
        try std.fmt.bufPrint(&buffer, "{f}", .{lost}),
    );

    try testing.expectEqual(@as(?Diagnostic, null), table.takeLost());
}

test "a rate limited child is not reported as a refused one" {
    const gpa = testing.allocator;

    var log = try ChildLog.init(gpa, "01CHILDRL");
    defer log.deinit(gpa);
    try log.say(gpa, "I had found three call sites so far");
    try log.append(gpa, .{ .session_end = .{
        .reason = .rate_limited,
        .detail = "gave up after 6 attempts: status 429 (rate_limited)",
    } });

    const report = try log.report(gpa, .prose);
    defer freeReport(gpa, report);

    try testing.expectEqual(event.AgentOutcome.rate_limited, report.outcome);
    try testing.expect(report.outcome != .refused);

    try testing.expect(std.mem.indexOf(u8, report.result, "rate limited") != null);
    try testing.expect(std.mem.indexOf(u8, report.result, "again later") != null);
    try testing.expect(std.mem.indexOf(u8, report.result, "three call sites") != null);
}
