//! A real agent in a real tree: a process that reads the command line its
//! parent wrote, keeps a session log of its own in a real session directory,
//! and **starts children of its own the same way its parent started it.**
//!
//! `test/core/subagent_child.zig` is one child and stops there. Everything
//! above one child was claimed and never run: two children at once, a
//! grandchild, a slice of a slice, and a parent that resumed. This program is
//! what makes those real, because every one of them needs an agent that is a
//! parent and a child at the same time.
//!
//! **This is not `chock run`, and it is deliberately not.** A real child needs
//! a model, a credential, a workspace and a sandbox, and none of those is under
//! test. What is under test is the tree: **the command line each level writes
//! for the level below it, the log each level keeps, the money each level hands
//! down, and the count each level keeps of its own children.** Everything on
//! that side is the real thing: real processes, real argument vectors from
//! `chock_core.subagent.commandLine`, real logs through `chock_proto.log.Log`
//! in a real session directory, real limits from `chock_policy.subagents`, and
//! real slices from `chock_core.subagent.budgetSlice`.
//!
//! ## What it copies from `src/run.zig`, and why it must copy rather than improve
//!
//! Three things here are written the way `chock run` writes them:
//!
//! * **The spawn chain is every agent above this one**, rebuilt from the
//!   repeated `--parent-kind` and `--spawn-reason` pairs its parent wrote, and
//!   handed on with this agent added at the end by
//!   `chock_core.subagent.Command.chainBelow`.
//! * **Depth is the length of that chain plus one**, which is what
//!   `chock_core.Loop.runSpawn` and `src/run.zig`'s `reviewerFor` both compute.
//! * **The width and the slice come from this agent's own log**, folded from
//!   disk before each spawn, which is what makes a resumed agent count what it
//!   already promised.
//!
//! **A helper that quietly did any of these better than the program would be a
//! helper a test passes against for the wrong reason.** The chain used to be
//! one link on both sides, and running this tree is what showed what that
//! costs: see `test/core/tree.zig`.
//!
//! ## The task is a small script, because the task is what a parent writes
//!
//! A parent writes the task and this program stands in for the model that reads
//! it. One instruction per line:
//!
//! * `say <text>` writes one turn of this agent's own.
//! * `promise <action> <ceiling> <reason...>` appends `policy.self`, so an
//!   ancestor can bind everything below it.
//! * `spend <amount> <currency>` appends a `usage` event, so this agent has
//!   really spent money before it divides what is left.
//! * `rendezvous <count>` does not come back until `count` agents of this tree
//!   have reached the same line. **A handshake and never a pause**: nothing
//!   here waits for a length of time, and the bound is a count of tries.
//! * `churn <n>` writes `n` turns of its own, so an agent has a measured amount
//!   of real work to be part way through. A count of appends, never a wait.
//! * `report-budget` says what slice this agent was given.
//! * `report-chain <action>` says what the policy table answers for this
//!   agent's own kind alone and for the chain its parent stated.
//! * `spawn <kind>` starts one child and waits for it. The child's own task is
//!   the lines below it that begin with `>`, with one `>` taken off each.
//! * `background <kind>` starts one child the same way and carries straight on.
//! * `join` waits for every background child and appends `agent.complete` for
//!   each one.
//!
//! Every `report-` line and every `rendezvous` adds a word to one summary, and
//! **the summary is the last thing this agent says**, because the last thing an
//! agent says is what its parent reads back: see
//! `chock_core.subagent.readReport`.
//!
//! Where the logs go comes from the environment, not from the command line,
//! because a real child works that out from the project and its own identifier
//! through `src/session.zig`, which is program code and not library code.
//! Everything a parent decides still arrives the way a parent sends it.

const std = @import("std");
const chock_core = @import("chock-core");
const chock_cost = @import("chock-cost");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const subagent = chock_core.subagent;
const flag = subagent.flag;

/// The directory every session of this tree keeps its log in, named by the
/// test. One directory for the whole tree, which is what a real project has:
/// see `src/session.zig`'s own `projectDir`.
pub const session_dir_variable = "CHOCK_TEST_SESSION_DIR";

/// How many characters a session identifier has, and the alphabet it is
/// written in. The same pair `src/session.zig` uses, because `promisesFor`
/// refuses an identifier that is not one of these before it builds a path from
/// it, and a tree whose identifiers that check refuses would prove nothing.
pub const id_length: usize = 26;
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How many times a `rendezvous` looks for its siblings before it gives up.
///
/// **A count of tries and never a length of time**, so a busier machine does
/// not change what this reaches. It is a release valve: a healthy run finds the
/// others after a handful of tries, and a tree that really ran one child at a
/// time fails the test that is waiting rather than hanging it.
///
/// A `rendezvous` line may name a smaller bound of its own. **Only a test that
/// wants the giving up uses that**, because there the sibling was never started
/// and no number of tries would find it.
const rendezvous_tries: usize = 200_000;

/// The leading part of the file one agent makes to say it has arrived. The rest
/// is the agent's own session identifier, so no two agents make the same file.
const rendezvous_prefix = "rv-";

/// The one file every agent of the tree writes its own line into, as its very
/// last act. **The order of a teardown, with no clock in it**: see
/// `Agent.tearDown`.
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

    // **A resumed agent appends to the log it already has.** The header is
    // written once by `Log.open`, and a session that already said it started
    // does not say so twice: that is what makes the second run of one session
    // a resume rather than a second session with the same name.
    if (!agent.hasStarted()) {
        try agent.append(.{
            .session_start = .{
                .agent_kind = agent.agent_kind,
                .model_alias = "test",
                // The child's own half of the two way link. `promisesFor` walks
                // upward on exactly this field.
                .parent_session = agent.parent_session,
                // The kinds above this one, written the way `src/run.zig`
                // writes them. A stand-in that left this out would let a test
                // over a real tree pass while the log a person exports says
                // nothing about the chain the policy table folds.
                .spawn_chain = agent.parent_chain,
            },
        });
    }

    // The task is the last argument, after `--`, which is where `chock run`
    // reads a session's first message from.
    const task = args[args.len - 1];
    try agent.say(.user, task);

    agent.runScript(task) catch |err| {
        try agent.say(.assistant, try std.fmt.allocPrint(arena, "the script failed: {t}", .{err}));
        try agent.append(.{ .session_end = .{ .reason = .errored, .detail = @errorName(err) } });
        agent.tearDown();
        return 1;
    };

    // The summary last, because the last thing an agent says is the answer its
    // parent reads: see `chock_core.subagent.readReport`. **An agent with
    // nothing to report says nothing**, so its own last `say` stays its answer
    // rather than being buried under a word this program invented.
    if (agent.summary.items.len != 0) try agent.say(.assistant, agent.summary.items);
    try agent.append(.{ .session_end = .{ .reason = .finished, .detail = "" } });

    // **The table goes last, and it waits.** `src/run.zig` owns the table for
    // the same reason and tears it down in the same place: a child that
    // outlived its parent would be an agent with no parent writing into a
    // scratchpad the parent is about to remove. See `Agent.tearDown`.
    agent.tearDown();
    return 0;
}

/// One agent of the tree: everything its parent told it, plus its own log.
const Agent = struct {
    arena: std.mem.Allocator,
    io: std.Io,
    environ: std.process.Environ,
    env: *std.process.Environ.Map,
    /// This program itself, which is what a child of this agent runs. Taken
    /// from `args[0]`, the way `src/run.zig` takes `exe_path` from its own.
    exe_path: []const u8,
    session_dir: []const u8,
    session: []const u8,
    project: []const u8,
    agent_kind: []const u8,
    parent_session: []const u8,
    /// Every agent above this one, root first, read back off the command line
    /// the way `src/run.zig`'s own parser reads it.
    parent_chain: []const event.SpawnLink,
    /// The slice this agent was given, or null for one with no cap.
    budget: ?chock_cost.budget.Budget,
    storage: chock_proto.storage.Storage,
    /// Every child started with `background`, and never one started with
    /// `spawn`. Built on the first `background` line and not before, so an
    /// agent that starts none pays for none.
    table: ?*subagent.Table = null,
    /// What this agent says at the end. See this file's own top comment.
    summary: std.ArrayList(u8) = .empty,

    fn runScript(self: *Agent, task: []const u8) !void {
        // The lines of the block a `spawn` or a `background` takes are read by
        // the instruction itself, so this loop has to be able to give them
        // back. A cursor over the whole task, rather than an iterator, is what
        // makes that possible.
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

    /// Do a measured amount of real work: `n` turns, each one a lock, an
    /// append and an unlock of this agent's own log.
    ///
    /// **A count of appends and never a length of time.** It exists so a parent
    /// that did not wait for this agent would really still be running when this
    /// one is only part way through, which is what makes the teardown order
    /// something a test can read rather than something it races.
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

    /// What the policy table answers for this agent's own kind alone, and for
    /// the chain its parent stated. Both, so a test can show that the two
    /// differ, and so a test can show at which depth they stop differing.
    ///
    /// **The chain comes from the command line and from nowhere else**, and it
    /// is built here exactly the way `src/run.zig`'s own `spawnChain` builds
    /// it: every `--parent-kind` a parent wrote, root first, with this agent's
    /// own kind on the end. See this file's own top comment on why this copies
    /// rather than improves.
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

    /// Do not come back until `count` agents of this tree have reached this
    /// line. **The proof that two children really ran at once**, with no clock
    /// in it: an agent that gave up says so, in its own answer, and the test
    /// waiting on it fails on the word rather than passing on a tree that ran
    /// one child at a time.
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
            // Give the processor to the sibling that has the real work rather
            // than spinning on it.
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
        try self.note("rendezvous=missed");
    }

    /// How many agents of this tree have said they arrived.
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

    /// Start one child, as a real process, with the real argument vector.
    ///
    /// **Everything before the child runs is in the order `Loop.runSpawn`
    /// keeps**: the limits are checked, the slice is divided out of this
    /// agent's own log, `session.spawn` is appended, and only then does
    /// anything start. A crash between any two of those still leaves proof that
    /// the child was asked for, and that is what a parent that resumes counts.
    fn startChild(self: *Agent, kind: []const u8, task: []const u8, background: bool) !void {
        const limits = chock_policy.subagents.load(self.arena, self.io, self.project, null) catch
            chock_policy.subagents.Limits{};

        // **Folded from this agent's own log on disk, and never from a counter
        // kept in memory.** That is the whole of the resume story: a second run
        // of this session reads the children and the spending the first run
        // wrote, so it cannot hand the same money out twice.
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

    /// End this agent, last of all: wait for every child it did not wait for,
    /// then write this agent's own line into the order file.
    ///
    /// **The order file is how a test reads the order of a teardown with no
    /// clock in it.** Every agent of the tree writes one line at the end of one
    /// file, as its very last act, so the lines are a total order of process
    /// endings. A tree whose levels wait reads deepest first. See
    /// `test/core/tree.zig`.
    fn tearDown(self: *Agent) void {
        if (self.table) |table| table.deinit();
        self.table = null;

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrintZ(
            &buffer,
            "{s}/{s}",
            .{ self.project, order_leaf },
        ) catch return;
        // Kept whole under an exclusive lock, the same way a session log is
        // appended to: two agents that ended at the same moment would otherwise
        // write over each other and the order would be a shorter file rather
        // than a wrong one.
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

    /// Wait for every background child, then append the completion of each.
    ///
    /// **The parent appends them, because a child cannot write its parent's
    /// log.** The same rule the whole design keeps: one writer per log, and the
    /// parent is the process that started the child.
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

    /// The table this agent's background children run on.
    ///
    /// **Backed by the page allocator and never by this agent's arena.** A
    /// child's own thread allocates from it while another thread may be inside
    /// a spawn, and `fork` carries only the calling thread: see
    /// `chock_core.subagent.Table.gpa`, which is the rule this obeys.
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
        // `startChild` prepares before it appends `session.spawn`, which is the
        // order the log keeps, so the table is never the thing that prepares.
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

    /// Choose the child's identifier and say where its log will be. Nothing is
    /// created: a child that never starts leaves nothing behind, and a log that
    /// was never opened is exactly the `died` this parent then reads.
    fn prepare(self: *Agent, request: subagent.Request) !subagent.Prepared {
        _ = request;
        const id = try self.newId();
        return .{
            .child_session = id,
            .log_path = try std.fmt.allocPrint(self.arena, "{s}/{s}.jsonl", .{ self.session_dir, id }),
            .scratchpad_path = try self.arena.dupe(u8, ""),
        };
    }

    /// Start the child, wait for it, and read its own log the way a parent
    /// does. **The log is the answer and the exit status is not**, which is why
    /// nothing here looks at one.
    fn runToTheEnd(
        self: *Agent,
        out: std.mem.Allocator,
        request: subagent.Request,
        prepared: subagent.Prepared,
    ) !subagent.Report {
        // The allocator this thread uses, and the `Io` it spawns through, are
        // its own: a background child runs this on a thread of the table's, and
        // the arena above belongs to the main thread.
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{ .environ = self.environ });
        defer threaded.deinit();
        const io = threaded.io();

        // This agent's own chain with this agent on the end, which is what
        // `src/run.zig`'s own `SubagentSpawner` builds. See this file's own top
        // comment on why this copies rather than improves.
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
        // The report is read in this thread's own arena and the caller keeps it,
        // so it is copied into the caller's allocator before the arena goes.
        // **The allocator the seam was given**, which is what a `Spawner` owes
        // its caller: see `chock_core.subagent.Spawner`.
        return .{
            .outcome = report.outcome,
            .result = try out.dupe(u8, report.result),
        };
    }

    /// How deep this agent is, counting the agent a person started as 1.
    ///
    /// **The length of the spawn chain plus one**, which is what
    /// `chock_core.Loop.runSpawn` computes and what `src/run.zig`'s own
    /// `spawnChain` feeds it: one link per agent above this one, and none for
    /// the agent a person started.
    fn depth(self: *Agent) usize {
        return self.parent_chain.len + 1;
    }

    /// Whether this log already says the session started, which is what tells a
    /// resumed run from a first one.
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

    /// Add one word to the answer this agent ends with.
    fn note(self: *Agent, text: []const u8) !void {
        if (self.summary.items.len != 0) try self.summary.append(self.arena, ' ');
        try self.summary.appendSlice(self.arena, text);
    }

    /// A fresh session identifier of the shape `src/session.zig` makes, so
    /// `promisesFor` accepts it and builds a path from it. Random throughout,
    /// because nothing here sorts sessions by name.
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

/// Take the block that belongs to the instruction just read: every line of
/// `rest` that begins with `>`, up to the first one that does not. `rest` is
/// left at the line after the block.
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

/// The block, with one `>` and one space taken off each line. Empty lines are
/// dropped, so a block that is only whitespace becomes an empty task.
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

/// Every agent above this one, root first, out of the repeated `--parent-kind`
/// and `--spawn-reason` pairs a parent writes. **Read exactly the way
/// `src/run.zig`'s own parser reads them**: a `--parent-kind` opens a link and
/// the `--spawn-reason` after it fills that link in.
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

/// The slice this agent was given, out of the two flags a parent writes for
/// one. Null when the parent named no cap, which is what a project with none
/// gives every session of its tree.
fn budgetFrom(args: []const []const u8) ?chock_cost.budget.Budget {
    const amount = valueOf(args, flag.max_cost) orelse return null;
    const value = std.fmt.parseFloat(f64, amount) catch return null;
    return .{
        .max_cost = value,
        .currency = valueOf(args, flag.currency) orelse chock_cost.budget.default_currency,
    };
}
