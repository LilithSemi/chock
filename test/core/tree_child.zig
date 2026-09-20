//! A real agent in a real tree: a process that reads the command line its
//! parent wrote, keeps a session log of its own, and starts children of its own
//! the same way its parent started it. The spawn chain, the depth, the width
//! and the slice are written the way `src/run.zig` writes them, because a
//! helper that improved on any of them makes a test pass for the wrong reason.
//!
//! The task is a script, one instruction per line:
//!
//! * `say <text>` writes one turn of this agent's own.
//! * `promise <action> <ceiling> <reason...>` appends `policy.self`.
//! * `spend <amount> <currency>` appends a `usage` event.
//! * `rendezvous <count> [tries]` waits for `count` agents to reach this line.
//! * `churn <n>` writes `n` turns of its own.
//! * `report-budget` says what slice this agent was given.
//! * `report-chain <action>` reports the policy answer for this kind alone and
//!   for the chain its parent stated.
//! * `spawn <kind>` starts one child and waits. Its task is the lines below
//!   that begin with `>`, with one `>` taken off each.
//! * `background <kind>` starts one child and carries on.
//! * `join` waits for every background child and appends `agent.complete`.
//!
//! Every `report-` line and every `rendezvous` adds a word to one summary, and
//! the summary is the last thing this agent says, because a parent reads back
//! the last thing its child said.
const std = @import("std");
const chock_core = @import("chock-core");
const chock_cost = @import("chock-cost");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const subagent = chock_core.subagent;
const flag = subagent.flag;

pub const session_dir_variable = "CHOCK_TEST_SESSION_DIR";

/// The identifier shape `src/session.zig` makes. `promisesFor` refuses any other.
pub const id_length: usize = 26;
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A count of tries and never a length of time. A line may name a smaller one.
const rendezvous_tries: usize = 200_000;

const rendezvous_prefix = "rv-";

pub const order_leaf = "order";

pub fn main(init: std.process.Init.Minimal) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded = std.Io.Threaded.init(arena, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    const args = try init.args.toSlice(arena);
    var env = try init.environ.createMap(arena);

    const dir = env.get(session_dir_variable) orelse {
        std.debug.print("tree_child: {s} names no directory\n", .{session_dir_variable});
        return 2;
    };

    const session = valueOf(args, flag.session) orelse {
        std.debug.print("tree_child: the parent named no session\n", .{});
        return 2;
    };

    var agent = Agent{
        .arena = arena,
        .io = io,
        .environ = init.environ,
        .env = &env,
        .exe_path = args[0],
        .session_dir = dir,
        .session = session,
        .project = valueOf(args, flag.project) orelse "",
        .agent_kind = valueOf(args, flag.agent_kind) orelse "",
        .parent_session = valueOf(args, flag.parent_session) orelse "",
        .parent_chain = try chainFrom(arena, args),
        .budget = budgetFrom(args),
        .storage = undefined,
    };

    const path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ dir, session }, 0);
    var log = try chock_proto.log.Log.open(io, path, session);
    defer log.close(io);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    agent.storage = backing.storage();

    // A session that already said it started does not say so twice.
    if (!agent.hasStarted()) {
        try agent.append(.{
            .session_start = .{
                .agent_kind = agent.agent_kind,
                .model_alias = "test",
                .parent_session = agent.parent_session,
                .spawn_chain = agent.parent_chain,
            },
        });
    }

    const task = args[args.len - 1];
    try agent.say(.user, task);

    agent.runScript(task) catch |err| {
        try agent.say(.assistant, try std.fmt.allocPrint(arena, "the script failed: {t}", .{err}));
        try agent.append(.{ .session_end = .{ .reason = .errored, .detail = @errorName(err) } });
        agent.tearDown();
        return 1;
    };

    if (agent.summary.items.len != 0) try agent.say(.assistant, agent.summary.items);
    try agent.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });

    agent.tearDown();
    return 0;
}

const Agent = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    exe_path: []const u8,
    session_dir: []const u8,
    session: []const u8,
    project: []const u8,
    agent_kind: []const u8,
    parent_session: []const u8,
    parent_chain: []const event.SpawnLink,
    budget: ?chock_cost.budget.Budget,
    storage: chock_proto.storage.Storage,
    table: ?*subagent.Table = null,
    summary: std.ArrayList(u8) = .empty,

    fn runScript(self: *Agent, task: []const u8) !void {
        var rest = task;
        while (rest.len != 0) {
            const end = std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len;
            const line = std.mem.trim(u8, rest[0..end], " \t\r");
            rest = if (end == rest.len) "" else rest[end + 1 ..];
            if (line.len == 0) continue;

            const word = firstWord(line);
            const tail = std.mem.trim(u8, line[word.len..], " \t");

            if (std.mem.eql(u8, word, "say")) {
                try self.say(.assistant, tail);
            } else if (std.mem.eql(u8, word, "promise")) {
                try self.promise(tail);
            } else if (std.mem.eql(u8, word, "spend")) {
                try self.spend(tail);
            } else if (std.mem.eql(u8, word, "rendezvous")) {
                try self.rendezvous(tail);
            } else if (std.mem.eql(u8, word, "churn")) {
                try self.churn(tail);
            } else if (std.mem.eql(u8, word, "report-budget")) {
                try self.reportBudget();
            } else if (std.mem.eql(u8, word, "report-chain")) {
                try self.reportChain(tail);
            } else if (std.mem.eql(u8, word, "join")) {
                try self.join();
            } else if (std.mem.eql(u8, word, "spawn") or std.mem.eql(u8, word, "background")) {
                const block = takeBlock(&rest);
                const child_task = try unindent(self.arena, block);
                try self.startChild(tail, child_task, std.mem.eql(u8, word, "background"));
            } else {
                return error.UnknownInstruction;
            }
        }
    }

    fn promise(self: *Agent, tail: []const u8) !void {
        const action = firstWord(tail);
        const after_action = std.mem.trim(u8, tail[action.len..], " \t");
        const ceiling = firstWord(after_action);
        const reason = std.mem.trim(u8, after_action[ceiling.len..], " \t");

        const decision = chock_policy.ratchet.ceilingNamed(ceiling) orelse
            return error.UnknownCeiling;
        const one = [_]event.SelfRestriction{.{
            .action = action,
            .ceiling = chock_core.self_policy.wireCeiling(decision),
            .reason = reason,
        }};
        try self.append(.{ .policy_self = .{ .restrictions = &one } });
    }

    fn spend(self: *Agent, tail: []const u8) !void {
        const amount_text = firstWord(tail);
        const currency = std.mem.trim(u8, tail[amount_text.len..], " \t");
        const amount = std.fmt.parseFloat(f64, amount_text) catch return error.BadAmount;
        try self.append(.{ .usage = .{
            .input_tokens = 1,
            .output_tokens = 1,
            .cost = .{ .known = .{ .value = amount, .currency = currency } },
            .model = "test-model",
            .model_alias = "test",
        } });
    }

    fn churn(self: *Agent, tail: []const u8) !void {
        const turns = std.fmt.parseInt(usize, firstWord(tail), 10) catch return error.BadCount;
        var done: usize = 0;
        while (done < turns) : (done += 1) try self.say(.assistant, "working");
    }

    fn reportBudget(self: *Agent) !void {
        try self.note(if (self.budget) |one|
            try std.fmt.allocPrint(self.arena, "budget={d}{s}", .{ one.max_cost, one.currency })
        else
            "budget=none");
    }

    fn reportChain(self: *Agent, action: []const u8) !void {
        const table = chock_policy.table.Table.load(self.arena, self.io, self.project, null) catch
            return error.PolicyNotRead;
        defer chock_policy.table.Table.destroy(self.arena, table);

        const key = chock_policy.table.Key{
            .agent_kind = self.agent_kind,
            .model = "test-model",
            .tool = "request_action",
            .action = action,
        };

        var chain: std.ArrayList([]const u8) = .empty;
        for (self.parent_chain) |link| try chain.append(self.arena, link.agent_kind);
        try chain.append(self.arena, self.agent_kind);

        try self.note(try std.fmt.allocPrint(
            self.arena,
            "alone={s} chain={s} links={d}",
            .{
                @tagName(table.evaluateKindAlone(key)),
                @tagName(table.evaluateChain(chain.items, key, null)),
                chain.items.len,
            },
        ));
    }

    fn rendezvous(self: *Agent, tail: []const u8) !void {
        const count_text = firstWord(tail);
        const wanted = std.fmt.parseInt(usize, count_text, 10) catch return error.BadCount;
        const bound_text = std.mem.trim(u8, tail[count_text.len..], " \t");
        const bound = if (bound_text.len == 0)
            rendezvous_tries
        else
            std.fmt.parseInt(usize, bound_text, 10) catch return error.BadCount;

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const mine = std.fmt.bufPrintZ(
            &buffer,
            "{s}/{s}{s}",
            .{ self.project, rendezvous_prefix, self.session },
        ) catch return error.PathTooLong;
        {
            var file = std.Io.Dir.cwd().createFile(self.io, mine, .{}) catch
                return error.RendezvousNotMade;
            file.close(self.io);
        }

        var tries: usize = 0;
        while (tries < bound) : (tries += 1) {
            if (self.arrived() >= wanted) return self.note("rendezvous=met");
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
        try self.note("rendezvous=missed");
    }

    fn arrived(self: *Agent) usize {
        var dir = std.Io.Dir.cwd().openDir(self.io, self.project, .{ .iterate = true }) catch return 0;
        defer dir.close(self.io);
        var walker = dir.iterate();
        var seen: usize = 0;
        while (walker.next(self.io) catch return seen) |entry| {
            if (std.mem.startsWith(u8, entry.name, rendezvous_prefix)) seen += 1;
        }
        return seen;
    }

    /// Everything before the child runs is in the order `Loop.runSpawn` keeps.
    fn startChild(self: *Agent, kind: []const u8, task: []const u8, background: bool) !void {
        const limits = chock_policy.subagents.load(self.arena, self.io, self.project, null) catch
            chock_policy.subagents.Limits{};

        // Folded from the log on disk, so a resumed run pays nothing twice.
        var folded = chock_proto.state.Session.init(self.arena);
        defer folded.deinit();
        try self.fold(&folded);

        const standing = chock_policy.subagents.Standing{
            .depth = self.depth(),
            .width = folded.children.items.len,
        };
        if (chock_policy.subagents.check(limits, standing)) |refusal| {
            return self.note(try std.fmt.allocPrint(
                self.arena,
                "refused={s} depth={d} width={d}",
                .{ refusal.limitName(), standing.depth, standing.width },
            ));
        }

        const committed = subagent.committedToChildren(folded.children.items, self.budget);
        const children_left = limits.max_width - @as(u16, @intCast(standing.width));
        const slice = subagent.budgetSlice(self.budget, folded.spend, committed, children_left);
        if (slice == null and subagent.nothingLeft(self.budget, folded.spend, committed)) {
            return self.note("refused=budget");
        }

        const request = subagent.Request{
            .agent_kind = kind,
            .task = task,
            .reason = subagent.reasonFor(task),
            .budget = slice,
        };

        const prepared = try self.prepare(request);
        try self.append(.{ .session_spawn = .{
            .child_session = prepared.child_session,
            .child_agent_kind = request.agent_kind,
            .reason = request.reason,
            .budget_max_cost = if (slice) |one| one.max_cost else 0,
            .budget_currency = if (slice) |one| one.currency else "",
        } });

        if (background) {
            const table = try self.childTable();
            try table.start(self.io, request, prepared);
            return;
        }

        const report = try self.runToTheEnd(self.arena, request, prepared);
        try self.append(.{ .agent_complete = .{
            .child_session = prepared.child_session,
            .child_agent_kind = request.agent_kind,
            .outcome = report.outcome,
            .result = report.result,
            .scratchpad_path = prepared.scratchpad_path,
        } });
    }

    /// End this agent last of all. Every agent writes one line into one order
    /// file as its very last act, so the lines are a total order of endings.
    fn tearDown(self: *Agent) void {
        if (self.table) |table| table.deinit();
        self.table = null;

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrintZ(
            &buffer,
            "{s}/{s}",
            .{ self.project, order_leaf },
        ) catch return;
        // Under an exclusive lock, or two agents that end together collide.
        var file = std.Io.Dir.cwd().createFile(
            self.io,
            path,
            .{ .truncate = false, .lock = .exclusive },
        ) catch return;
        defer file.close(self.io);
        if (self.session.len != id_length) return;
        var line: [id_length + 1]u8 = undefined;
        @memcpy(line[0..id_length], self.session);
        line[id_length] = '\n';
        const at = file.stat(self.io) catch return;
        file.writePositionalAll(self.io, &line, at.size) catch return;
    }

    /// A child cannot write its parent's log, so the parent appends completions.
    fn join(self: *Agent) !void {
        const table = self.table orelse return;
        table.waitAll();
        const finished = try table.take(self.arena);
        defer subagent.freeCompletions(self.arena, finished);
        for (finished) |one| {
            try self.append(.{ .agent_complete = .{
                .child_session = one.child_session,
                .child_agent_kind = one.agent_kind,
                .outcome = one.outcome,
                .result = one.result,
                .scratchpad_path = one.scratchpad_path,
            } });
        }
        try self.note(try std.fmt.allocPrint(self.arena, "joined={d}", .{finished.len}));
    }

    /// Backed by the page allocator, never this agent's arena. A child's thread
    /// allocates from it while another may be inside a spawn.
    fn childTable(self: *Agent) !*subagent.Table {
        if (self.table) |one| return one;
        const table = try std.heap.page_allocator.create(subagent.Table);
        table.* = .{ .gpa = std.heap.page_allocator, .spawner = self.spawner() };
        self.table = table;
        return table;
    }

    fn spawner(self: *Agent) subagent.Spawner {
        return .{ .ptr = self, .vtable = &spawner_vtable };
    }

    const spawner_vtable = subagent.Spawner.VTable{ .prepare = prepareFn, .run = runFn };

    fn prepareFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
    ) subagent.Error!subagent.Prepared {
        _ = io;
        _ = request;
        _ = allocator;
        _ = ptr;
        return error.ChildNotStarted;
    }

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        request: subagent.Request,
        prepared: subagent.Prepared,
    ) subagent.Error!subagent.Report {
        _ = io;
        const self: *Agent = @ptrCast(@alignCast(ptr));
        return self.runToTheEnd(allocator, request, prepared) catch error.ChildNotStarted;
    }

    fn prepare(self: *Agent, request: subagent.Request) !subagent.Prepared {
        _ = request;
        const id = try self.newId();
        return .{
            .child_session = id,
            .log_path = try std.fmt.allocPrint(self.arena, "{s}/{s}.jsonl", .{ self.session_dir, id }),
            .scratchpad_path = try self.arena.dupe(u8, ""),
        };
    }

    fn runToTheEnd(
        self: *Agent,
        out: std.mem.Allocator,
        request: subagent.Request,
        prepared: subagent.Prepared,
    ) !subagent.Report {
        // A background child runs this on the table's thread, so these are its own.
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const io = threaded.io();

        const chain = try subagent.Command.chainBelow(
            arena,
            self.parent_chain,
            self.agent_kind,
            request.reason,
        );
        const argv = try subagent.commandLine(arena, .{
            .exe_path = self.exe_path,
            .project_root = self.project,
            .parent_session = self.session,
            .parent_chain = chain,
        }, request, prepared);

        var child = std.process.spawn(io, .{
            .argv = argv,
            .environ_map = self.env,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .inherit,
        }) catch return error.ChildNotStarted;
        _ = child.wait(io) catch {};

        const path = try std.fmt.allocPrintSentinel(
            arena,
            "{s}/{s}.jsonl",
            .{ self.session_dir, prepared.child_session },
            0,
        );
        const log = chock_proto.log.Log.open(io, path, prepared.child_session) catch
            return error.ChildNotStarted;
        var backing = chock_proto.storage.JsonLines{ .log = log };
        defer backing.storage().close(io);

        const report = try subagent.readReport(arena, io, backing.storage(), request.shape);
        // Copied into the caller's allocator before this thread's arena goes.
        return .{
            .outcome = report.outcome,
            .result = try out.dupe(u8, report.result),
        };
    }

    fn depth(self: *Agent) usize {
        return self.parent_chain.len + 1;
    }

    fn hasStarted(self: *Agent) bool {
        var replay = self.storage.replay(self.arena, self.io, 0) catch return false;
        defer replay.deinit();
        while (replay.next(self.io) catch return false) |parsed| {
            defer parsed.deinit();
            if (parsed.value.event == .session_start) return true;
        }
        return false;
    }

    fn fold(self: *Agent, session: *chock_proto.state.Session) !void {
        var replay = try self.storage.replay(self.arena, self.io, 0);
        defer replay.deinit();
        while (try replay.next(self.io)) |parsed| {
            defer parsed.deinit();
            try session.apply(parsed.value);
        }
    }

    fn append(self: *Agent, one: event.Event) !void {
        var locked = try self.storage.lock(self.io);
        defer locked.unlock(self.io) catch {};
        _ = try locked.append(
            self.arena,
            self.io,
            one,
            std.Io.Timestamp.now(self.io, .real).toMilliseconds(),
        );
    }

    fn say(self: *Agent, role: event.Role, text: []const u8) !void {
        const content = [_]event.ContentPart{.{ .text = text }};
        try self.append(.{ .message = .{ .role = role, .content = &content } });
    }

    fn note(self: *Agent, text: []const u8) !void {
        if (self.summary.items.len != 0) try self.summary.append(self.arena, ' ');
        try self.summary.appendSlice(self.arena, text);
    }

    fn newId(self: *Agent) ![]u8 {
        var random: [id_length]u8 = undefined;
        self.io.random(&random);
        const out = try self.arena.alloc(u8, id_length);
        for (random, out) |byte, *slot| slot.* = crockford[byte & 0x1f];
        return out;
    }
};

fn firstWord(line: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
    return line[0..end];
}

/// Lines of `rest` that begin with `>`. `rest` is left after the block.
fn takeBlock(rest: *[]const u8) []const u8 {
    const whole = rest.*;
    var taken: usize = 0;
    while (taken < whole.len) {
        const end = std.mem.indexOfScalarPos(u8, whole, taken, '\n') orelse whole.len;
        const line = std.mem.trim(u8, whole[taken..end], " \t\r");
        if (line.len != 0 and line[0] != '>') break;
        taken = if (end == whole.len) whole.len else end + 1;
    }
    rest.* = whole[taken..];
    return whole[0..taken];
}

fn unindent(arena: std.mem.Allocator, block: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, block, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const without = std.mem.trimStart(u8, line[1..], " ");
        if (out.items.len != 0) try out.append(arena, '\n');
        try out.appendSlice(arena, without);
    }
    return out.toOwnedSlice(arena);
}

fn chainFrom(
    arena: std.mem.Allocator,
    args: []const []const u8,
) std.mem.Allocator.Error![]const event.SpawnLink {
    var chain: std.ArrayList(event.SpawnLink) = .empty;
    var index: usize = 0;
    while (index + 1 < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], flag.parent_kind)) {
            try chain.append(arena, .{ .agent_kind = args[index + 1], .reason = "" });
        } else if (std.mem.eql(u8, args[index], flag.spawn_reason) and chain.items.len != 0) {
            chain.items[chain.items.len - 1].reason = args[index + 1];
        }
    }
    return chain.toOwnedSlice(arena);
}

fn valueOf(args: []const []const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |one, index| {
        if (std.mem.eql(u8, one, name) and index + 1 < args.len) return args[index + 1];
    }
    return null;
}

fn budgetFrom(args: []const []const u8) ?chock_cost.budget.Budget {
    const amount = valueOf(args, flag.max_cost) orelse return null;
    const value = std.fmt.parseFloat(f64, amount) catch return null;
    return .{
        .max_cost = value,
        .currency = valueOf(args, flag.currency) orelse chock_cost.budget.default_currency,
    };
}
