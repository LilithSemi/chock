//! One subagent: a child process with a session of its own, and the answer
//! its parent reads back out of the child's own log.
//!
//! ## A subagent is a child process, and that is not a preference
//!
//! `Sandbox.spawn` calls `fork`, and **`fork` carries only the calling
//! thread**, so an agent tree built from threads deadlocks the moment a child
//! runs a tool. `chock daemon` already answers this the same way, with one
//! process per session, and a subagent is a session with a parent and nothing
//! more. Two more things fall out of it: a child that crashes takes down one
//! process, and **the parent builds the child's confinement**, so a child
//! cannot widen its own by construction rather than by a check it might skip.
//!
//! ## Each session keeps its own log, and the two are linked both ways
//!
//! The parent appends `session.spawn` naming the child, and the child's own
//! `session.start` names the parent. **A subagent's turns are never in its
//! parent's log.** Each session stays independently replayable, which is what
//! `chockd` serves and what a resume reads, and the tree is rebuilt from the
//! links.
//!
//! `AgentComplete` is the third link: the parent is told that the child
//! finished, and **the parent appends that**, because the child cannot write
//! the parent's log. The parent holds the exclusive lock on it for the whole
//! session, which is the one writer rule the whole design keeps, and the
//! parent is the process that started the child, so the parent is what sees it
//! end.
//!
//! ## The log is how the parent learns the outcome, not a second channel
//!
//! A session log ends with `session.end` or it does not, and a log with no
//! `session.end` is a child that died. `readReport` is the whole of that
//! reading. **No pipe, no status file, and no exit code**: a child that was
//! killed between two turns and a child that never started both leave a log
//! that says so, and an exit code cannot tell a refused turn from a crash.
//!
//! ## The budget is a slice, given at spawn
//!
//! The cap covers the whole tree, and 36 agents each under a per agent cap
//! spend 36 times the cap. Each agent is in its own process with no shared
//! memory, and the cap has to be enforced before a request goes out, so the
//! answer that needs no inter process communication at all is the one taken
//! here: **the parent hands each child a slice of what the parent has left,
//! and a child can never hold more than its slice.** See `budgetSlice`.
//!
//! **The approval is the release valve.** A child that uses its whole slice
//! ends `budget_reached`, which is already an `approval.request` for
//! `budget.raise` in the child's own log, and the parent is told `budget`
//! rather than `finished`. So the rigidity of a slice becomes a decision the
//! parent makes, not a dead end.
//!
//! ## The result is prose or a schema, and the caller chooses
//!
//! `Shape`. **Prose when a person will read it, a schema when the parent will
//! branch on it.** A parent that has to re-read English to decide is a parent
//! that gets it wrong sometimes.
//!
//! Two things this settles, because both have more than one defensible
//! answer:
//!
//! * **How a child is made to produce a schema**: the parent writes the
//!   requirement into the task the child is given, in `taskFor`, and the
//!   parent alone checks the answer, in `checkShape`. **Nothing in the child
//!   decides whether the child complied.** A hidden tool the child calls to
//!   hand back a typed value would put that decision inside the child and
//!   would need a tool list that differs per agent kind, which is a larger
//!   change than this one.
//! * **What happens when the answer does not match**: the outcome is
//!   `refused`, the raw answer is still carried back, and **nothing is
//!   retried**. A retry doubles the money for the case that is usually a child
//!   asked the wrong question, and the parent is the one that can tell.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
/// Why a piece of the loop's own scaffolding could not be made or kept. One
/// type for the whole module: see `chock-core/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;
const chock_cost = @import("chock-cost");
const chock_proto = @import("chock-proto");

const event = chock_proto.event;
const scratchpad = @import("scratchpad.zig");

/// What shape of answer the parent asked for.
pub const Shape = union(enum) {
    /// Whatever the child said, as it said it.
    prose,
    /// One JSON object holding at least these members. The parent named them,
    /// so the parent can read them without guessing.
    schema: []const []const u8,
};

/// What the parent asks for when it starts one subagent.
///
/// Every string is borrowed for the length of the call. A `Spawner` that keeps
/// one past that copies it.
pub const Request = struct {
    /// The kind the child runs as, which selects the policy it runs under.
    /// **The child's policy is the intersection with every kind above it**, and
    /// the parent is what states the chain: see `commandLine`.
    agent_kind: []const u8,
    /// Everything the child is told. It reads nothing else: not the parent's
    /// conversation, not the files the parent read.
    task: []const u8,
    shape: Shape = .prose,
    /// Why the parent started it, for `session.spawn` and for the spawn chain
    /// an approval carries. See `reasonFor`.
    reason: []const u8,
    /// What the child may spend, which is a slice of what the parent has left.
    /// Null for a parent with no cap of its own. See `budgetSlice`.
    budget: ?chock_cost.budget.Budget = null,
};

/// What a `Spawner` built before the child ran. The caller owns every string
/// and frees them with `freePrepared`.
///
/// **This exists so the parent can append `session.spawn` before the child
/// starts.** An event is written before the act it describes happens, which is
/// the rule the whole log keeps: a crash between the two then leaves proof
/// that the child was asked for.
pub const Prepared = struct {
    /// The child's own session identifier, made by the parent.
    child_session: []u8,
    /// The child's own log, on the host. The parent reads this to learn the
    /// outcome.
    log_path: []u8,
    /// The child's own scratchpad, on the host. Empty for a session with none.
    scratchpad_path: []u8,
};

pub fn freePrepared(allocator: std.mem.Allocator, prepared: Prepared) void {
    allocator.free(prepared.child_session);
    allocator.free(prepared.log_path);
    allocator.free(prepared.scratchpad_path);
}

/// What the parent was told when the child ended. The caller owns `result` and
/// frees it with `freeReport`.
pub const Report = struct {
    outcome: event.AgentOutcome,
    /// The child's answer, or a sentence saying why there is none.
    result: []u8,
};

pub fn freeReport(allocator: std.mem.Allocator, report: Report) void {
    allocator.free(report.result);
    if (report.outcome == .unknown) allocator.free(report.outcome.unknown);
}

pub const Error = error{
    /// The child could not be started at all, or could not be waited for. The
    /// reason is whatever the `Spawner` reports. **Not a session that ended
    /// badly**, which is an outcome and not an error: see `readReport`.
    ChildNotStarted,
} || std.mem.Allocator.Error;

/// What actually starts a subagent.
///
/// **A seam, for the same reason `Loop.ToolRunner` is one.** The real
/// implementation forks and runs `chock run`, which needs a single threaded
/// caller and a session directory and a credential, and none of that can
/// happen inside an ordinary test binary. `lib/chock-core/Loop.zig` therefore
/// takes one of these rather than starting a process itself, and the tests of
/// the loop drive a double that starts nothing.
///
/// **Two calls and not one**, because the parent appends `session.spawn`
/// between them: see `Prepared`.
pub const Spawner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Choose the child's session identifier and build the directories it
        /// needs. Nothing runs yet.
        prepare: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            request: Request,
        ) Error!Prepared,
        /// Run the child to its end and read its log. Called once per
        /// `prepare`.
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

/// How much of the task text becomes the `reason` of the `session.spawn` event
/// and of the spawn chain link.
///
/// The reason is read by a person, and by a user answering an approval that a
/// subagent three levels down raised, so it has to be short. The task itself
/// is in the child's own log, in full, as the child's first message.
pub const max_reason_bytes: usize = 200;

/// The reason the parent gives for one spawn, taken from the task it wrote.
/// Borrowed from `task`.
///
/// **The tool does not ask the model for a reason of its own.** A second field
/// beside the task would be a second chance to say the same thing, paid for on
/// every turn the tool list is sent, and a model that wrote a task and a reason
/// that disagree would leave the log saying one thing and the child doing
/// another.
pub fn reasonFor(task: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, task, " \t\r\n");
    const first_line = trimmed[0 .. std.mem.indexOfScalar(u8, trimmed, '\n') orelse trimmed.len];
    if (first_line.len <= max_reason_bytes) return first_line;
    return first_line[0..max_reason_bytes];
}

/// What the child is actually given as its first message: the parent's task,
/// and, for a schema, the requirement that the last turn is one JSON object
/// holding the members the parent named. The caller owns the result.
///
/// **The requirement is in the task and not in the child's system prompt.** A
/// system prompt is built once per session and is the same for every agent;
/// this is one caller's requirement for one child, and it belongs where the
/// rest of that caller's instructions are.
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

/// Whether `answer` is the shape `shape` asked for. Null when it is. A
/// sentence, owned by the caller, when it is not.
///
/// **The parent checks, and the child is never asked whether it complied.**
/// See this file's own top comment.
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

/// How much of a child's answer the parent carries back into its own log and
/// its own context.
///
/// **The parent pays for every byte of this on every later turn.** A child that
/// wrote a page has already written it into its own log, and the scratchpad
/// path beside the answer is how the parent reads the rest of it. Sixteen
/// kibibytes is a quarter of what one tool result may carry, which is the right
/// proportion for a value that is meant to be a verdict.
pub const max_result_bytes: usize = 16 * 1024;

/// Read the child's log and say how the child ended and what it answered. The
/// caller owns the result and frees it with `freeReport`.
///
/// **A log with no `session.end` is a child that died.** That is the whole
/// mechanism, and it needs no second channel: a process that was killed, or one
/// that never reached its first turn, leaves exactly that. A torn last line
/// from an interrupted append is already handled one level down, by
/// `chock_proto.storage`, so a child killed mid write reads the same way.
///
/// A log this cannot read at all is also `died`, and says so. The alternative,
/// returning an error, would make an unreadable child log end the **parent's**
/// session, and the parent has real work left whatever became of the child.
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
            // Everything up to the fault is still read. A log that stops
            // partway is a child that stopped partway, which is the case this
            // whole function is here to name.
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
                // The last thing the child said in its own voice. A `tool`
                // role message is a tool's answer and a `user` role one is the
                // task or a notice from the harness, so neither is the child's.
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
                // Refused, and the answer is still carried back: a parent that
                // can read the near miss can decide whether to ask again, and a
                // parent given nothing cannot. Nothing is retried here: see
                // this file's own top comment.
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

/// What one more child may spend: the parent's own cap, less what the parent
/// has spent and less every slice it has already handed out, divided by how
/// many more children its limits still let it start.
///
/// **Both subtractions are needed, and dropping either one is an overspend.**
/// The parent's own `usage` events say nothing about what a child spent, so a
/// slice measured against the parent's spending alone would be handed out
/// whole to every child. `committed` is what closes that, and it is folded
/// from the parent's own `session.spawn` events, so a parent that resumed
/// counts the slices it gave before the resume as well.
///
/// **Divided by the children still allowed, so the slices cannot add up to
/// more than what is left.** A parent with a cap of 5 that has spent 1 and may
/// start 4 more children gives each of them 1. Nothing has to be told about
/// any other process for that to hold, which is the whole reason this shape
/// was chosen: there is no shared memory between the processes of a tree and no
/// channel to build one over.
///
/// **A parent with no cap gives no cap**, because there is nothing to divide.
/// That is the honest reading of a project that set none, and the same answer
/// the parent's own session already runs under.
///
/// Null is also the answer when nothing is left, and the caller must not start
/// a child on it. `nothingLeft` says which of the two a null means.
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

/// Whether a null from `budgetSlice` means there is nothing left, rather than
/// there being no cap at all. Two very different facts, and a caller that read
/// them the same way would start a child with no cap on a session that has
/// already spent everything it had.
pub fn nothingLeft(
    cap: ?chock_cost.budget.Budget,
    spend: chock_proto.state.Spend,
    committed: f64,
) bool {
    const budget = cap orelse return false;
    return budget.max_cost - spentAgainst(budget, spend) - committed <= 0;
}

/// What the parent has spent, measured against this cap.
///
/// A total in another currency cannot be taken off a cap written in this one,
/// and inventing a rate here would be worse than not enforcing at all: the
/// same rule `Loop.refuseForBudget` keeps one level up.
fn spentAgainst(budget: chock_cost.budget.Budget, spend: chock_proto.state.Spend) f64 {
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, budget.currency)) return 0;
    return spend.amount;
}

/// What the parent has already handed to its children, from the slices its own
/// `session.spawn` events recorded. Every child counted in another currency is
/// left out, for the reason `spentAgainst` gives.
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

/// Whether a null from `budgetSlice` means the parent has nothing left, rather
/// than the parent having no cap at all.
pub fn spentAlready(cap: ?chock_cost.budget.Budget, spend: chock_proto.state.Spend) bool {
    const budget = cap orelse return false;
    if (spend.currency.len != 0 and !std.mem.eql(u8, spend.currency, budget.currency)) return false;
    return spend.amount >= budget.max_cost;
}

/// The two shapes a spawn takes, and **the spawn says which one it wants**.
///
/// Picking one for the caller gets it wrong half the time: the two answer
/// different questions and both are useful.
pub const Mode = enum {
    /// "Review this and tell me." The parent has nothing to do until the
    /// answer arrives, so the answer is the result of the call itself and the
    /// parent's turn stops for as long as the child runs.
    wait,
    /// "Go and do that while I work." The parent's turn carries straight on
    /// and the answer arrives at the top of a later turn.
    ///
    /// **This is what makes a tree worth having.** Six children waited on one
    /// at a time is a sequence with extra processes.
    carry_on,
};

/// One child that finished, as the parent's log records it and as the parent
/// is then told it.
///
/// The same four things `event.AgentComplete` carries, because that is the
/// event the drain appends from this. Every string is owned by the allocator
/// `Table.take` was given, and freed with `freeCompletions`.
pub const Completion = struct {
    child_session: []const u8,
    agent_kind: []const u8,
    outcome: event.AgentOutcome,
    result: []const u8,
    scratchpad_path: []const u8,
};

/// Free a slice `Table.take` returned.
pub fn freeCompletions(allocator: std.mem.Allocator, list: []Completion) void {
    for (list) |one| freeCompletion(allocator, one);
    allocator.free(list);
}

/// Free one completion. Every string may be empty, which is what a completion
/// only half built holds, so this is safe on a partial one.
fn freeCompletion(allocator: std.mem.Allocator, one: Completion) void {
    allocator.free(one.child_session);
    allocator.free(one.agent_kind);
    allocator.free(one.result);
    allocator.free(one.scratchpad_path);
    if (one.outcome == .unknown) allocator.free(one.outcome.unknown);
}

/// The lock the table's own bookkeeping is kept under.
///
/// **Small on purpose**, and the same shape `chock_core.tasks`'s own `Lock`
/// takes, for the same reason: `std.Io.Mutex.lock` takes an `Io` and answers
/// `Cancelable!void`, and a thread recording a child it has already waited for
/// has no answer to "you were canceled". Every critical section here is one
/// append or one pop of a list.
const Lock = struct {
    held: std.atomic.Value(bool) = .init(false),

    fn lock(self: *Lock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            // Give the other thread the processor rather than spinning on it.
            // A yield this platform refuses leaves the spin, which is correct
            // and only slower.
            std.Thread.yield() catch std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *Lock) void {
        self.held.store(false, .release);
    }
};

/// Every child of one session that its parent did not wait for.
///
/// **Built on the shape `chock_core.tasks.Table` already proved**: the work
/// runs on a thread of its own, the parent drains at a safe point, and the
/// drain appends a typed record plus a message, so acting on a result always
/// leaves a trace of having been told. A child is a heavier thing than a
/// background command and the bookkeeping is the same.
///
/// **Owned by the caller that owns the session**, which is `src/run.zig`, for
/// the reason `tasks.Table` gives: a child outlives the tool call that started
/// it.
///
/// **`prepare` is not done here.** The parent runs it on its own thread and
/// appends `session.spawn` from what it answered, before anything starts, so
/// the width count is right the moment the child exists and a crash between
/// the two still leaves proof that the child was asked for. See
/// `chock_core.Loop`'s own `runSpawn`.
pub const Table = struct {
    /// The allocator the records and the thread list are kept in.
    ///
    /// **Give this one no fork ever inherits a lock from.** A child's own
    /// thread allocates from it while another thread may be inside
    /// `Sandbox.spawn`, and `fork` carries only the calling thread, so a lock
    /// held at that moment is copied into the child as held for ever.
    /// `src/run.zig` gives `std.heap.page_allocator`, the same answer
    /// `tasks.Table.gpa` already gives.
    gpa: std.mem.Allocator,
    spawner: Spawner,

    /// Guards everything below it. Taken by a child's own thread when it
    /// finishes, and by the loop when it drains.
    mutex: Lock = .{},
    started: usize = 0,
    /// How many children have finished, over the whole session. **Never goes
    /// down, and it is not `finished.items.len`**: that list is drained by
    /// every `take`. See `runningCount`, which is the only reader.
    completed: usize = 0,
    finished: std.ArrayList(Completion) = .empty,
    threads: std.ArrayList(std.Thread) = .empty,
    /// The first thing this table lost, for the caller to report.
    ///
    /// **A field and not a print.** Both sites that fill it run on a
    /// child's own thread, under the mutex, at the one moment the
    /// allocator has already refused, so there is no error to give back
    /// and nothing to allocate a message in. `takeLost` is where the
    /// caller reads it; `src/run.zig` does that when the session ends.
    lost: ?Diagnostic = null,

    /// The first thing this table lost, and null once it has been taken.
    /// **The first, not the last**: a record that could not be kept and a
    /// thread that could not be tracked both mean the allocator refused,
    /// and the first refusal is the one that explains the run.
    pub fn takeLost(self: *Table) ?Diagnostic {
        self.mutex.lock();
        defer self.mutex.unlock();
        const taken = self.lost;
        self.lost = null;
        return taken;
    }

    /// Record a loss from a thread that does not already hold the mutex.
    ///
    /// **A tag and not a value.** Every loss this table records is noted
    /// after an allocator refused, so none of them may carry a string. See
    /// `chock-core/diagnostic.zig`, where a tag that carries one is a compile
    /// error.
    fn noteLost(self: *Table, comptime tag: std.meta.Tag(Diagnostic)) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        diagnostic.note(&self.lost, tag);
    }

    /// Wait for every child still running, then free everything.
    ///
    /// **It waits, and that is not optional.** A thread of this table holds a
    /// child process that writes into a session directory below this process's
    /// own scratchpad, which is about to be removed. Leaving one running past
    /// the end of the session would leave an agent with no parent writing into
    /// a path that is gone.
    pub fn deinit(self: *Table) void {
        self.waitAll();
        // Whatever finished and was never drained. The table's own allocator
        // owns it, so this is the last chance anything has to free it.
        if (self.take(self.gpa)) |taken| freeCompletions(self.gpa, taken) else |_| {}
        self.threads.deinit(self.gpa);
        self.finished.deinit(self.gpa);
        self.* = undefined;
    }

    /// Wait for every child that is still running. Takes no lock while it
    /// waits: a thread that is finishing needs the lock to record itself.
    pub fn waitAll(self: *Table) void {
        while (true) {
            self.mutex.lock();
            const thread = self.threads.pop();
            self.mutex.unlock();
            if (thread) |one| one.join() else return;
        }
    }

    /// How many children this table has started. Never goes down.
    ///
    /// **The width limit does not read this.** Width is folded from the
    /// parent's own `session.spawn` events, so a session that resumed counts
    /// the children it really has: see `Loop`'s own `runSpawn`.
    pub fn startedCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started;
    }

    /// How many children are running right now.
    ///
    /// **What a handover asks about.** A child has its own process, its own
    /// log and its own lock, so it survives this process. What does not survive
    /// is the parent's own record of it: this process is what writes the
    /// `agent.complete` that pairs with the `session.spawn` already in the log.
    /// A session handed over while one ran would leave that pair open for ever,
    /// and the new owner would never tell the agent what its child answered.
    /// See `chock_broker.handover`, which refuses for exactly this count.
    ///
    /// Counted from two totals and never from the thread list, for the reason
    /// `tasks.Table.runningCount` gives.
    pub fn runningCount(self: *Table) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.started - self.completed;
    }

    /// Run `request` to its end on a thread of this table's own, from the
    /// `prepared` the parent already has.
    ///
    /// **Every part of both is copied.** A `Request` and a `Prepared` are
    /// borrowed for the length of the call that built them, and this outlives
    /// that by definition.
    pub fn start(
        self: *Table,
        io: std.Io,
        request: Request,
        prepared: Prepared,
    ) std.mem.Allocator.Error!void {
        const job = try self.gpa.create(Job);
        errdefer self.gpa.destroy(job);
        // Backed by the page allocator directly, never by `self.gpa`: this
        // arena is used by the child's own thread, beside a thread that may be
        // inside `Sandbox.spawn`. See `Table.gpa`.
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
            // The child is already running and its thread will record its own
            // completion, so the only thing lost is the join in `waitAll`.
            // Kept rather than swallowed, and kept rather than printed: see
            // `lost`.
            diagnostic.note(&self.lost, .subagent_thread_not_tracked);
        };
    }

    /// Every child that has finished since the last call. The caller owns the
    /// result and frees it with `freeCompletions`.
    ///
    /// **Answers an empty slice when nothing finished**, which is the ordinary
    /// case and costs one lock. `Loop` calls this at every safe point.
    pub fn take(self: *Table, allocator: std.mem.Allocator) std.mem.Allocator.Error![]Completion {
        self.mutex.lock();
        defer self.mutex.unlock();

        const taken = try self.finished.toOwnedSlice(self.gpa);
        if (allocator.ptr == self.gpa.ptr and allocator.vtable == self.gpa.vtable) return taken;

        // A caller with an allocator of its own gets its own copies, so a turn
        // arena can hold them and the table's own allocator is never freed
        // from two places.
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

    /// Called by a child's own thread once the child has ended.
    fn record(self: *Table, completion: Completion) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        // Before the append, and outside its `catch`: this child has stopped
        // running whether or not its record could be kept. See
        // `tasks.Table.record` for the same rule and the same reason.
        self.completed += 1;
        self.finished.append(self.gpa, completion) catch {
            // The record is what the log is built from, so losing one is
            // worth keeping. The child's own log is still on disk either way.
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

/// One child the parent did not wait for, alive from `Table.start` until its
/// own thread ends. Everything it reads is in its own arena, so nothing it
/// touches belongs to the tool call that started it.
const Job = struct {
    table: *Table,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    request: Request = undefined,
    prepared: Prepared = undefined,

    fn run(self: *Job) void {
        const allocator = self.arena.allocator();
        // **Every way this can fail is a `died` and never a gap.** The child was
        // already recorded as spawned, in the parent's own `session.spawn`, so a
        // failure that appended nothing would leave the parent's log saying a
        // child was asked for and never saying what became of it. `died` is what
        // a child that never said anything means, and both of these are that.
        const report = self.table.spawner.run(allocator, self.io, self.request, self.prepared) catch |err| {
            return self.finish(.died, switch (err) {
                error.ChildNotStarted => "the subagent's process could not be started",
                error.OutOfMemory => "the subagent ran and this process ran out of memory reading " ++
                    "what it said",
            });
        };
        self.finish(report.outcome, report.result);
    }

    /// Record the completion in the table's own allocator, then free the whole
    /// job. Nothing of the arena survives this call.
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

    /// The allocator ran out while the completion was being copied out of the
    /// arena. Free the half that was made and say so: a completion that is
    /// never recorded is a `session.spawn` with no `agent.complete` after it,
    /// and the child's own log is then the only record of what happened.
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

/// The flags `chock run` reads for a session that is somebody's subagent.
///
/// **Written here, beside `commandLine`, and read by `src/run.zig`'s own
/// parser.** The parent builds the command line and the child parses it, so a
/// name spelled twice is a name that can quietly stop matching, and the fault
/// would be a child that ran with no parent in its chain at all.
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

/// Everything the parent knows that the child has to be told on its command
/// line. Every string is borrowed for the length of the call.
pub const Command = struct {
    /// The `chock` program itself, which is what the child runs.
    exe_path: []const u8,
    project_root: []const u8,
    /// The parent's own session. **The immediate parent alone**, because a
    /// reader that wants the ones above it climbs `session.start.parent_session`
    /// out of the logs: see `src/run.zig`'s own `promisesFor`.
    parent_session: []const u8,
    /// **Every agent above this child, root first**, and why each one started
    /// the agent below it. The last link is the immediate parent, and its
    /// reason is why this child is being started.
    ///
    /// **The whole chain and not one link.** The parent states the chain and
    /// the child cannot state one for itself, which is what makes the
    /// intersection structural: `chock_policy.table`'s own `evaluateChain`
    /// folds every kind in the chain, so a child can hold no permission a kind
    /// above it lacks. **One link was a real fault**, found by running a tree
    /// three deep: a grandchild folded its own kind and its parent's, the
    /// grandparent's row of `chock.zon` was not in the answer at all, and every
    /// agent below the first reported depth 2, so `max_depth` bounded nothing.
    /// See `test/core/tree.zig`.
    ///
    /// Empty for the agent a person started, which has nobody above it.
    parent_chain: []const event.SpawnLink = &.{},
    /// The provider instance and the model on the wire, passed through so the
    /// child talks to what the parent talks to rather than to whatever the
    /// configuration happens to default to.
    provider: []const u8 = "",
    model: []const u8 = "",

    /// The chain one more level down: this command's own chain, with the
    /// parent that wrote it added at the end. The caller owns the slice.
    ///
    /// **One function, because a caller that built this by hand is the caller
    /// that forgets to add itself**, and the fault would be silent: the child
    /// would run under a chain one link short and hold whatever the level it
    /// dropped denies.
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

/// The argument vector that starts one child. The caller owns the slice and
/// every string in it, and frees them with `freeCommandLine`.
///
/// The task is the last argument, after `--`, which is where `chock run` reads
/// the session's first message from. Every part of it comes from the parent.
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
    // **One pair per link, root first.** `src/run.zig`'s own parser reads them
    // back in this order and rebuilds the chain from them, so the order is part
    // of what a child is told and not a detail of this loop.
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

    // The task is the message, and it comes last so nothing after it can be
    // read as a flag. A task that begins with a dash is the case this is for.
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

/// Where a child's own session directory sits: inside its parent's scratchpad,
/// under `agents/`. Caller owns the result.
///
/// The one place that path is built. `lib/chock-core/scratchpad.zig` owns the
/// layout and the check on the identifier, and this joins the parent's own
/// directory to it, so no caller ever builds a path below the scratchpad from
/// parts of its own.
pub fn childDir(
    allocator: std.mem.Allocator,
    parent_dir: []const u8,
    child_session: []const u8,
) (std.mem.Allocator.Error || scratchpad.LeafError)![]u8 {
    const leaf = try scratchpad.leafFor(allocator, .{ .child = child_session });
    defer allocator.free(leaf);
    // `leafFor` answers the scratch directory itself, and a child needs the
    // session directory above it, which is what `makeLayout` is given.
    const session_leaf = std.fs.path.dirname(leaf).?;
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ parent_dir, session_leaf });
}

const testing = std.testing;

/// A child log built by hand, in a fresh temp directory, so a test can say
/// exactly what the child left behind and read it back through the real
/// storage. **Nothing here writes a log by hand**: every line goes through
/// `chock_proto.log.Log`, so a test cannot pass against a format the real
/// reader would refuse.
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
    // The fact that makes a second channel unnecessary. A child that was
    // killed between two turns leaves exactly this, and a parent that read it
    // as a finished child with an empty answer would act on nothing.
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

    // The same log, once the child says how it ended, is a different answer
    // entirely. So the reading turns on the `session.end` and on nothing else.
    try log.append(gpa, .{ .session_end = .{ .reason = .finished, .detail = "" } });
    const finished = try log.report(gpa, .prose);
    defer freeReport(gpa, finished);
    try testing.expectEqual(event.AgentOutcome.finished, finished.outcome);
    try testing.expectEqualStrings("I read the first file and", finished.result);
}

test "each way a child session can end is its own outcome, and the answer comes back with it" {
    // A parent branches on the member, so each ending has to reach it as its
    // own member. Folding a budget into a refusal would have the parent give
    // up where it could have given a larger slice.
    const gpa = testing.allocator;

    const cases = [_]struct { reason: event.SessionEndReason, want: event.AgentOutcome }{
        .{ .reason = .finished, .want = .finished },
        .{ .reason = .no_progress, .want = .no_progress },
        .{ .reason = .budget_reached, .want = .budget },
        .{ .reason = .errored, .want = .refused },
        .{ .reason = .canceled_by_user, .want = .refused },
        .{ .reason = .turn_limit, .want = .refused },
    };

    for (cases) |one| {
        var log = try ChildLog.init(gpa, "01CHILDAA");
        defer log.deinit(gpa);
        try log.say(gpa, "the parser is in src/parse.zig");
        try log.append(gpa, .{ .session_end = .{ .reason = one.reason, .detail = "why" } });

        const report = try log.report(gpa, .prose);
        defer freeReport(gpa, report);
        try testing.expectEqual(one.want, report.outcome);
        // Whatever the ending, what the child managed to say is carried back.
        // A parent given only "it failed" has to start again from nothing.
        try testing.expect(std.mem.indexOf(u8, report.result, "src/parse.zig") != null);
    }
}

test "only the child's own last words are the answer, and a tool result is not one" {
    // The answer is what the child said in its own voice, last. A tool result
    // travels as a `tool` role message and would otherwise become the answer of
    // every child whose last act was a tool call.
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
    // Decided rather than retried: a child that cannot produce the shape is
    // usually a child that was asked the wrong question, and only the parent
    // can tell. So the parent is given the answer it did get.
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
        // JSON, an object, and one member short. The member that is missing is
        // named, because a parent reading this decides whether to ask again.
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
        // Whitespace around the object is not a failure to comply. The answer
        // that comes back is the object itself, which is what a parent parses.
        try testing.expectEqualStrings(
            "{\"verdict\":\"safe\",\"path\":\"/run/chock/scratch/notes.md\"}",
            report.result,
        );
    }
}

test "the same answer is accepted as prose and refused as a schema" {
    // The caller chooses, and the choice is what decides. Nothing about the
    // child changes between these two readings of one log.
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
    // The whole reason this shape was chosen. There is no shared memory
    // between the processes of a tree, so the arithmetic has to hold with no
    // agent telling any other agent anything.
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
    // Four children, and the four slices together are exactly what was left.
    // The parent's own spending says nothing about what a child spent, so the
    // slices already handed out are what keeps this from being handed out four
    // times over.
    try testing.expectApproxEqAbs(@as(f64, 4.0), handed_out, 0.000001);

    // A parent with no cap divides nothing, and a parent with nothing left has
    // nothing to give. The two nulls are different facts.
    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetSlice(null, spent, 0, 4));
    try testing.expect(!nothingLeft(null, spent, 0));

    const all_gone = chock_proto.state.Spend{ .amount = 5.5, .currency = "USD", .turns = 9 };
    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetSlice(cap, all_gone, 0, 4));
    try testing.expect(nothingLeft(cap, all_gone, 0));

    // And a parent that spent little and promised everything has nothing left
    // either, which is the half a cap measured against spending alone misses.
    try testing.expectEqual(@as(?chock_cost.budget.Budget, null), budgetSlice(cap, spent, 4.0, 4));
    try testing.expect(nothingLeft(cap, spent, 4.0));

    // One child allowed gets everything that is left, which is the case a
    // division would get wrong if it counted the parent as a child.
    const only_one = budgetSlice(cap, spent, 0, 1).?;
    try testing.expectEqual(@as(f64, 4.0), only_one.max_cost);
}

test "what a parent has committed comes off its own log, so a resumed parent counts it" {
    // A slice is a promise, and a parent that resumed and counted from zero
    // would hand the same money out twice. The number is folded from the
    // parent's own `session.spawn` events, which is where a resume finds it.
    const cap = chock_cost.budget.Budget{ .max_cost = 5.0, .currency = "USD" };
    const children = [_]chock_proto.state.Child{
        .{ .session = "01A", .agent_kind = "reviewer", .reason = "one", .budget_max_cost = 1.0, .budget_currency = "USD" },
        .{ .session = "01B", .agent_kind = "reviewer", .reason = "two", .budget_max_cost = 1.5, .budget_currency = "USD" },
        // A child from a session billed in another currency cannot be taken
        // off a cap written in this one, the same rule the parent's own
        // spending follows.
        .{ .session = "01C", .agent_kind = "reviewer", .reason = "three", .budget_max_cost = 90.0, .budget_currency = "JPY" },
        // A child that was given no cap at all adds nothing.
        .{ .session = "01D", .agent_kind = "reviewer", .reason = "four" },
    };
    try testing.expectEqual(@as(f64, 2.5), committedToChildren(&children, cap));
    try testing.expectEqual(@as(f64, 0), committedToChildren(&children, null));
}

test "the command line names the parent, and the task is the last argument" {
    // The parent states the chain and the child cannot state one for itself:
    // that is what makes the intersection structural rather than a check the
    // child performs on itself. A command line missing `--parent-kind` is a
    // child that runs with its own kind alone.
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

    // **Every agent above this one, root first, each with the reason it
    // started the one below it.** A chain that arrived one link short would be
    // a grandchild folding its parent's kind and not its grandparent's, which
    // is the fault `test/core/tree.zig` found by running a tree.
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

    // The task is last, after `--`, so a task that begins with a dash is a
    // message and never an option.
    try testing.expectEqualStrings("--", argv[argv.len - 2]);
    try testing.expectEqualStrings("-read the parser and say what is wrong", argv[argv.len - 1]);
}

test "the chain a child is given is its parent's chain with its parent on the end" {
    const gpa = testing.allocator;

    // The agent a person started has nobody above it, so its own children get a
    // chain of exactly one link.
    const first = try Command.chainBelow(gpa, &.{}, "main", "split the work");
    defer gpa.free(first);
    try testing.expectEqual(@as(usize, 1), first.len);
    try testing.expectEqualStrings("main", first[0].agent_kind);
    try testing.expectEqualStrings("split the work", first[0].reason);

    // And each level below adds exactly one, in order, so the root stays first.
    const second = try Command.chainBelow(gpa, first, "coder", "review the parser");
    defer gpa.free(second);
    try testing.expectEqual(@as(usize, 2), second.len);
    try testing.expectEqualStrings("main", second[0].agent_kind);
    try testing.expectEqualStrings("coder", second[1].agent_kind);
    try testing.expectEqualStrings("review the parser", second[1].reason);

    // The chain it was given is untouched, so a parent that starts two children
    // does not give the second one the first one's link.
    try testing.expectEqual(@as(usize, 1), first.len);
}

test "a schema is asked for in the task the child reads, and prose asks for nothing" {
    // The child is made to produce the shape by being told, in the one place
    // it reads. Nothing in the child decides whether it complied: see this
    // file's own top comment.
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
    // The reason is read by a person answering an approval a subagent raised,
    // so it is bounded. The task itself is in the child's own log in full.
    try testing.expectEqualStrings("review the parser", reasonFor("review the parser\nand say why"));
    try testing.expectEqualStrings("review the parser", reasonFor("  review the parser  "));
    try testing.expectEqual(max_reason_bytes, reasonFor("x" ** 400).len);
}

test "a child's directory is inside its parent's scratchpad and cannot climb out of it" {
    // A child identifier reaches a path here, and a value that reached a path
    // unchecked is a path traversal. The check is `scratchpad.leafFor`'s own,
    // read from there rather than written a second time.
    const gpa = testing.allocator;

    const dir = try childDir(gpa, "/tmp/chock/01PARENTA", "01CHILDAA");
    defer gpa.free(dir);
    try testing.expectEqualStrings("/tmp/chock/01PARENTA/agents/01CHILDAA", dir);

    // And the scratch directory the child ends up with is the one
    // `scratchpad.leafFor` names for that child, so the parent's idea of where
    // the child writes and the child's own cannot differ.
    const leaf = try scratchpad.leafFor(gpa, .{ .child = "01CHILDAA" });
    defer gpa.free(leaf);
    const joined = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, scratchpad.scratch_leaf });
    defer gpa.free(joined);
    const from_leaf = try std.fmt.allocPrint(gpa, "/tmp/chock/01PARENTA/{s}", .{leaf});
    defer gpa.free(from_leaf);
    try testing.expectEqualStrings(joined, from_leaf);

    try testing.expectError(error.BadChildId, childDir(gpa, "/tmp/chock/01PARENTA", "../../etc"));
}

/// The value that follows `name` in an argument vector, or null. Only a test
/// reads a command line back: the child is `chock run`, and its own parser is
/// what reads one for real.
fn valueOf(argv: []const []const u8, name: []const u8) ?[]const u8 {
    for (argv, 0..) |one, index| {
        if (std.mem.eql(u8, one, name) and index + 1 < argv.len) return argv[index + 1];
    }
    return null;
}

test "a child that has finished stops being a running child, however its record is drained" {
    // The count has to come from two totals and never from `finished.items.len`
    // or from `threads`. `finished` is emptied by every `take`, and a thread is
    // removed from `threads` only by `waitAll`. Mutation check: answer
    // `finished.items.len`, and the second reading below says nothing is
    // running while a child still is; answer `threads.items.len`, and the last
    // reading says one is running after both have ended, so that session
    // refuses every handover for the rest of its life.
    const gpa = testing.allocator;
    var table = Table{ .gpa = gpa, .spawner = undefined };
    defer table.threads.deinit(gpa);
    defer table.finished.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), table.runningCount());

    // Two children spawned. `Table.start` counts them here and then starts a
    // thread each; this test drives the bookkeeping without a real child
    // process, which is what `Spawner` is the seam for.
    table.started = 2;
    try testing.expectEqual(@as(usize, 2), table.runningCount());

    // The first finishes. `record` is what a child's own thread calls.
    table.record(.{
        .child_session = try gpa.dupe(u8, "01CHILD"),
        .agent_kind = try gpa.dupe(u8, "reviewer"),
        .outcome = .finished,
        .result = try gpa.dupe(u8, "a second reading of the diff"),
        .scratchpad_path = try gpa.dupe(u8, ""),
    });
    try testing.expectEqual(@as(usize, 1), table.runningCount());

    // Drained, which is what the loop does at every turn boundary. The count
    // does not go back up.
    const drained = try table.take(gpa);
    freeCompletions(gpa, drained);
    try testing.expectEqual(@as(usize, 1), table.runningCount());

    // The second finishes and nothing is running, which is the one state that
    // permits a handover.
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
    // The point of the whole change for this table. Both losses happen on a
    // child's own thread at the one moment the allocator has already refused,
    // so there is no error to give back and nothing to allocate a message in.
    // The value is kept instead, and `takeLost` is how a caller reads it.
    var table = Table{ .gpa = testing.allocator, .spawner = undefined };
    try testing.expectEqual(@as(?Diagnostic, null), table.takeLost());

    table.noteLost(.subagent_record_not_kept);
    // **The first, not the last.** Both losses mean the allocator refused,
    // and the first refusal is the one that explains the run.
    table.noteLost(.subagent_thread_not_tracked);

    const lost = table.takeLost().?;
    try testing.expectEqual(Diagnostic.subagent_record_not_kept, lost);

    var buffer: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "a subagent finished and its record could not be kept",
        try std.fmt.bufPrint(&buffer, "{f}", .{lost}),
    );

    // Taken once. A caller that reads it a second time is told nothing,
    // rather than the same loss over again.
    try testing.expectEqual(@as(?Diagnostic, null), table.takeLost());
}
